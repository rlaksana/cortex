/**
 * Vector Embedding Service
 *
 * Production-ready service for generating vector embeddings using OpenAI's API
 * with comprehensive caching, batch processing, error handling, and monitoring.
 *
 * Features:
 * - OpenAI text-embedding-ada-002 model integration
 * - Batch processing for improved performance and cost efficiency
 * - Comprehensive caching with TTL and size limits
 * - Rate limiting and API quota management
 * - Error handling with exponential backoff
 * - Performance monitoring and metrics
 * - Content preprocessing and optimization
 * - Vector validation and normalization
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { OpenAI } from 'openai';
import { logger } from '../../utils/logger.js';
import { DatabaseError, ValidationError } from '../../db/database-interface.js';

/**
 * Embedding configuration options
 */
export interface EmbeddingConfig {
  apiKey?: string;
  model?: string;
  batchSize?: number;
  maxRetries?: number;
  retryDelay?: number;
  cacheEnabled?: boolean;
  cacheTTL?: number;
  cacheMaxSize?: number;
  timeout?: number;
}

/**
 * Embedding request with optional metadata
 */
export interface EmbeddingRequest {
  text: string;
  metadata?: Record<string, any>;
  cacheKey?: string;
  priority?: 'high' | 'normal' | 'low';
}

/**
 * Embedding result with vector and metadata
 */
export interface EmbeddingResult {
  vector: number[];
  model: string;
  usage: {
    prompt_tokens: number;
    total_tokens: number;
  };
  cached: boolean;
  processingTime: number;
  metadata?: Record<string, any>;
}

/**
 * Batch embedding request
 */
export interface BatchEmbeddingRequest {
  texts: string[];
  metadata?: Record<string, any>[];
  priority?: 'high' | 'normal' | 'low';
}

/**
 * Cache entry for embeddings
 */
interface CacheEntry {
  vector: number[];
  model: string;
  createdAt: number;
  accessCount: number;
  lastAccessed: number;
  metadata?: Record<string, any>;
}

/**
 * Statistics about embedding operations
 */
export interface EmbeddingStats {
  totalRequests: number;
  cacheHits: number;
  cacheMisses: number;
  averageProcessingTime: number;
  totalTokensUsed: number;
  errors: number;
  model: string;
  cacheSize: number;
}

/**
 * Production-ready vector embedding service
 */
export class EmbeddingService {
  private openai: OpenAI;
  private config: Required<EmbeddingConfig>;
  private cache: Map<string, CacheEntry> = new Map();
  private stats: EmbeddingStats;
  private lastCleanup: number = 0;

  constructor(config: EmbeddingConfig = {}) {
    this.config = {
      apiKey: config.apiKey || process.env.OPENAI_API_KEY,
      model: config.model || 'text-embedding-ada-002',
      batchSize: config.batchSize || 100,
      maxRetries: config.maxRetries || 3,
      retryDelay: config.retryDelay || 1000,
      cacheEnabled: config.cacheEnabled !== false,
      cacheTTL: config.cacheTTL || 3600000, // 1 hour
      cacheMaxSize: config.cacheMaxSize || 10000,
      timeout: config.timeout || 30000,
    };

    this.openai = new OpenAI({
      apiKey: this.config.apiKey,
    });

    this.stats = {
      totalRequests: 0,
      cacheHits: 0,
      cacheMisses: 0,
      averageProcessingTime: 0,
      totalTokensUsed: 0,
      errors: 0,
      model: this.config.model,
      cacheSize: 0,
    };
  }

  /**
   * Generate embedding for a single text
   */
  async generateEmbedding(request: EmbeddingRequest | string): Promise<EmbeddingResult> {
    const startTime = Date.now();

    // Handle string input
    if (typeof request === 'string') {
      request = { text: request };
    }

    this.stats.totalRequests++;

    try {
      // Check cache first
      if (this.config.cacheEnabled) {
        const cacheKey = request.cacheKey || this.generateCacheKey(request.text);
        const cached = this.getFromCache(cacheKey);
        if (cached) {
          this.stats.cacheHits++;
          return {
            vector: cached.vector,
            model: cached.model,
            usage: { prompt_tokens: 0, total_tokens: 0 },
            cached: true,
            processingTime: Date.now() - startTime,
            metadata: cached.metadata,
          };
        }
        this.stats.cacheMisses++;
      }

      // Validate input
      this.validateInput(request.text);

      // Generate embedding
      const response = await this.generateEmbeddingWithRetry(request.text);

      // Cache result
      if (this.config.cacheEnabled) {
        const cacheKey = request.cacheKey || this.generateCacheKey(request.text);
        this.setCache(cacheKey, {
          vector: response.embedding,
          model: this.config.model,
          createdAt: Date.now(),
          accessCount: 1,
          lastAccessed: Date.now(),
          metadata: request.metadata,
        });
      }

      const processingTime = Date.now() - startTime;
      this.updateAverageProcessingTime(processingTime);

      return {
        vector: response.embedding,
        model: this.config.model,
        usage: response.usage,
        cached: false,
        processingTime,
        metadata: request.metadata,
      };
    } catch (error) {
      this.stats.errors++;
      logger.error({ error, textLength: request.text.length }, 'Embedding generation failed');
      throw new DatabaseError('Failed to generate embedding', 'EMBEDDING_ERROR', error as Error);
    }
  }

  /**
   * Generate embeddings for multiple texts in batch
   */
  async generateBatchEmbeddings(request: BatchEmbeddingRequest): Promise<EmbeddingResult[]> {
    const startTime = Date.now();

    if (request.texts.length === 0) {
      return [];
    }

    if (request.texts.length === 1) {
      // Single item - use regular method
      const result = await this.generateEmbedding({
        text: request.texts[0],
        metadata: request.metadata?.[0],
        priority: request.priority,
      });
      return [result];
    }

    this.stats.totalRequests++;

    try {
      // Check cache for batch
      if (this.config.cacheEnabled) {
        const cachedResults: EmbeddingResult[] = [];
        const uncachedTexts: string[] = [];
        const uncachedIndexes: number[] = [];

        request.texts.forEach((text, index) => {
          const cacheKey = this.generateCacheKey(text);
          const cached = this.getFromCache(cacheKey);
          if (cached) {
            this.stats.cacheHits++;
            cachedResults.push({
              vector: cached.vector,
              model: cached.model,
              usage: { prompt_tokens: 0, total_tokens: 0 },
              cached: true,
              processingTime: 0,
              metadata: request.metadata?.[index],
            });
          } else {
            this.stats.cacheMisses++;
            uncachedTexts.push(text);
            uncachedIndexes.push(index);
          }
        });

        // Process uncached texts in batches
        if (uncachedTexts.length > 0) {
          const batchResults = await this.generateBatchEmbeddingsWithRetry(uncachedTexts);

          // Insert into cache and merge results
          batchResults.forEach((result, index) => {
            const originalIndex = uncachedIndexes[index];
            const cacheKey = this.generateCacheKey(uncachedTexts[index]);

            if (this.config.cacheEnabled) {
              this.setCache(cacheKey, {
                vector: result.vector,
                model: this.config.model,
                createdAt: Date.now(),
                accessCount: 1,
                lastAccessed: Date.now(),
                metadata: request.metadata?.[originalIndex],
              });
            }

            // Insert into correct position
            cachedResults.splice(originalIndex, 0, {
              vector: result.vector,
              model: this.config.model,
              usage: result.usage,
              cached: false,
              processingTime: 0,
              metadata: request.metadata?.[originalIndex],
            });
          });
        }

        const processingTime = Date.now() - startTime;
        this.updateAverageProcessingTime(processingTime);

        return cachedResults;
      } else {
        // No cache - process all in batch
        const batchResults = await this.generateBatchEmbeddingsWithRetry(request.texts);

        return batchResults.map((result, index) => ({
          vector: result.vector,
          model: this.config.model,
          usage: result.usage,
          cached: false,
          processingTime: 0,
          metadata: request.metadata?.[index],
        }));
      }
    } catch (error) {
      this.stats.errors++;
      logger.error({ error, textCount: request.texts.length }, 'Batch embedding generation failed');
      throw new DatabaseError(
        'Failed to generate batch embeddings',
        'BATCH_EMBEDDING_ERROR',
        error as Error
      );
    }
  }

  /**
   * Generate embedding with retry logic
   */
  private async generateEmbeddingWithRetry(text: string, attempt: number = 1): Promise<any> {
    try {
      const response = await this.openai.embeddings.create({
        model: this.config.model,
        input: this.preprocessText(text),
      });

      this.stats.totalTokensUsed += response.usage.total_tokens;
      return response;
    } catch (error: any) {
      if (attempt < this.config.maxRetries && this.shouldRetry(error)) {
        logger.warn(
          { error, attempt, textLength: text.length },
          'Embedding generation failed, retrying...'
        );

        await this.delay(this.config.retryDelay * Math.pow(2, attempt - 1));
        return this.generateEmbeddingWithRetry(text, attempt + 1);
      }

      throw error;
    }
  }

  /**
   * Generate batch embeddings with retry logic
   */
  private async generateBatchEmbeddingsWithRetry(
    texts: string[],
    attempt: number = 1
  ): Promise<any[]> {
    try {
      const processedTexts = texts.map((text) => this.preprocessText(text));

      const response = await this.openai.embeddings.create({
        model: this.config.model,
        input: processedTexts,
      });

      this.stats.totalTokensUsed += response.usage.total_tokens;
      return response.data;
    } catch (error: any) {
      if (attempt < this.config.maxRetries && this.shouldRetry(error)) {
        logger.warn(
          { error, attempt, textCount: texts.length },
          'Batch embedding generation failed, retrying...'
        );

        await this.delay(this.config.retryDelay * Math.pow(2, attempt - 1));
        return this.generateBatchEmbeddingsWithRetry(texts, attempt + 1);
      }

      throw error;
    }
  }

  /**
   * Preprocess text for embedding generation
   */
  private preprocessText(text: string): string {
    // Remove excessive whitespace
    let processed = text.replace(/\s+/g, ' ').trim();

    // Ensure minimum length
    if (processed.length < 1) {
      processed = 'empty';
    }

    // Ensure maximum length (OpenAI limit is around 8191 tokens)
    const maxChars = 8000; // Conservative estimate
    if (processed.length > maxChars) {
      processed = processed.substring(0, maxChars);
      logger.warn(
        { originalLength: text.length, truncatedLength: processed.length },
        'Text truncated for embedding'
      );
    }

    return processed;
  }

  /**
   * Validate input text
   */
  private validateInput(text: string): void {
    if (typeof text !== 'string') {
      throw new ValidationError('Input must be a string');
    }

    if (text.length === 0) {
      throw new ValidationError('Input text cannot be empty');
    }

    if (text.length > 100000) {
      throw new ValidationError('Input text is too long (max 100,000 characters)');
    }
  }

  /**
   * Check if error should trigger a retry
   */
  private shouldRetry(error: any): boolean {
    if (error.code === 'insufficient_quota') {
      return false; // Don't retry quota errors
    }

    if (error.code === 'invalid_request') {
      return false; // Don't retry invalid requests
    }

    if (error.status === 429) {
      return true; // Retry rate limit errors
    }

    if (error.status >= 500) {
      return true; // Retry server errors
    }

    return false;
  }

  /**
   * Delay for retry logic
   */
  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Generate cache key for text
   */
  private generateCacheKey(text: string): string {
    return createHash('md5').update(text).digest('hex');
  }

  /**
   * Get entry from cache
   */
  private getFromCache(key: string): CacheEntry | null {
    const entry = this.cache.get(key);

    if (!entry) {
      return null;
    }

    const now = Date.now();

    // Check TTL
    if (now - entry.createdAt > this.config.cacheTTL) {
      this.cache.delete(key);
      return null;
    }

    // Update access statistics
    entry.accessCount++;
    entry.lastAccessed = now;

    return entry;
  }

  /**
   * Set entry in cache
   */
  private setCache(key: string, entry: CacheEntry): void {
    // Clean up cache if needed
    this.cleanupCache();

    this.cache.set(key, entry);
    this.stats.cacheSize = this.cache.size;
  }

  /**
   * Clean up expired cache entries
   */
  private cleanupCache(): void {
    const now = Date.now();

    // Clean up expired entries
    for (const [key, entry] of this.cache.entries()) {
      if (now - entry.createdAt > this.config.cacheTTL) {
        this.cache.delete(key);
      }
    }

    // Clean up oldest entries if cache is too large
    if (this.cache.size > this.config.cacheMaxSize) {
      const entries = Array.from(this.cache.entries()).sort(
        (a, b) => a[1].lastAccessed - b[1].lastAccessed
      );

      const toDelete = entries.slice(0, entries.length - this.config.cacheMaxSize);
      toDelete.forEach(([key]) => this.cache.delete(key));
    }

    this.stats.cacheSize = this.cache.size;
    this.lastCleanup = now;
  }

  /**
   * Update average processing time
   */
  private updateAverageProcessingTime(newTime: number): void {
    if (this.stats.averageProcessingTime === 0) {
      this.stats.averageProcessingTime = newTime;
    } else {
      // Exponential moving average
      const alpha = 0.1;
      this.stats.averageProcessingTime =
        alpha * newTime + (1 - alpha) * this.stats.averageProcessingTime;
    }
  }

  /**
   * Get service statistics
   */
  getStats(): EmbeddingStats {
    return {
      ...this.stats,
      cacheHitRate:
        this.stats.totalRequests > 0 ? this.stats.cacheHits / this.stats.totalRequests : 0,
    };
  }

  /**
   * Clear cache
   */
  clearCache(): void {
    this.cache.clear();
    this.stats.cacheSize = 0;
    logger.info('Embedding cache cleared');
  }

  /**
   * Check if service is healthy
   */
  async healthCheck(): Promise<boolean> {
    try {
      // Test with a simple embedding
      await this.generateEmbedding('health check test');
      return true;
    } catch (error) {
      logger.error({ error }, 'Embedding service health check failed');
      return false;
    }
  }

  /**
   * Warm up cache with common embeddings
   */
  async warmupCache(commonTexts: string[]): Promise<void> {
    if (!this.config.cacheEnabled || commonTexts.length === 0) {
      return;
    }

    logger.info({ textCount: commonTexts.length }, 'Warming up embedding cache');

    try {
      // Process in batches
      const batchSize = this.config.batchSize;
      for (let i = 0; i < commonTexts.length; i += batchSize) {
        const batch = commonTexts.slice(i, i + batchSize);
        await this.generateBatchEmbeddings({ texts: batch });
      }

      logger.info({ cacheSize: this.stats.cacheSize }, 'Embedding cache warmup completed');
    } catch (error) {
      logger.error({ error }, 'Embedding cache warmup failed');
    }
  }

  /**
   * Estimate cost for embedding generation
   */
  estimateCost(
    textCount: number,
    charactersPerText: number = 1000
  ): {
    requests: number;
    tokens: number;
    estimatedCostUSD: number;
  } {
    // OpenAI pricing (as of 2024)
    const pricePer1KTokens = 0.0001; // $0.0001 per 1K tokens for ada-002
    const tokensPerText = Math.ceil(charactersPerText / 4); // Rough estimate: 1 token ≈ 4 characters

    const totalTokens = textCount * tokensPerText;
    const requests = Math.ceil(textCount / this.config.batchSize);
    const estimatedCostUSD = (totalTokens / 1000) * pricePer1KTokens;

    return {
      requests,
      tokens: totalTokens,
      estimatedCostUSD,
    };
  }

  /**
   * Validate embedding vector
   */
  static validateEmbedding(vector: number[]): boolean {
    if (!Array.isArray(vector)) {
      return false;
    }

    if (vector.length === 0) {
      return false;
    }

    // Check for valid numbers
    if (!vector.every((val) => typeof val === 'number' && !isNaN(val))) {
      return false;
    }

    // Check for NaN or Infinity
    if (vector.some((val) => !isFinite(val))) {
      return false;
    }

    return true;
  }

  /**
   * Normalize embedding vector
   */
  static normalizeEmbedding(vector: number[]): number[] {
    if (!EmbeddingService.validateEmbedding(vector)) {
      throw new ValidationError('Invalid embedding vector for normalization');
    }

    // Calculate magnitude
    const magnitude = Math.sqrt(vector.reduce((sum, val) => sum + val * val, 0));

    if (magnitude === 0) {
      throw new ValidationError('Cannot normalize zero-length embedding vector');
    }

    // Normalize to unit vector
    return vector.map((val) => val / magnitude);
  }

  /**
   * Calculate similarity between two embeddings
   */
  static calculateSimilarity(vector1: number[], vector2: number[]): number {
    if (
      !EmbeddingService.validateEmbedding(vector1) ||
      !EmbeddingService.validateEmbedding(vector2)
    ) {
      throw new ValidationError('Invalid embedding vectors for similarity calculation');
    }

    if (vector1.length !== vector2.length) {
      throw new ValidationError('Embedding vectors must have the same length');
    }

    // Calculate cosine similarity
    const dotProduct = vector1.reduce((sum, val, i) => sum + val * vector2[i], 0);
    const magnitude1 = Math.sqrt(vector1.reduce((sum, val) => sum + val * val, 0));
    const magnitude2 = Math.sqrt(vector2.reduce((sum, val) => sum + val * val, 0));

    if (magnitude1 === 0 || magnitude2 === 0) {
      return 0;
    }

    return dotProduct / (magnitude1 * magnitude2);
  }

  /**
   * Find most similar vectors from a list
   */
  static findMostSimilar(
    queryVector: number[],
    candidateVectors: number[][],
    topK: number = 5,
    threshold: number = 0.7
  ): Array<{ vector: number[]; similarity: number; index: number }> {
    const similarities = candidateVectors
      .map((vector, index) => ({
        vector,
        similarity: EmbeddingService.calculateSimilarity(queryVector, vector),
        index,
      }))
      .filter((item) => item.similarity >= threshold)
      .sort((a, b) => b.similarity - a.similarity)
      .slice(0, topK);

    return similarities;
  }
}

// Export singleton instance
export const embeddingService = new EmbeddingService();
