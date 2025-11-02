/**
 * Mock Embedding Service for Testing
 *
 * Provides deterministic embeddings for testing without requiring real OpenAI API calls
 */

import { vi } from 'vitest';
import type {
  EmbeddingConfig,
  EmbeddingRequest,
  EmbeddingResult,
  BatchEmbeddingRequest,
  EmbeddingStats,
} from '../../src/services/embeddings/embedding-service.js';
import { DatabaseError } from '../../src/db/database-interface.js';

export interface MockEmbeddingConfig {
  shouldFail?: boolean;
  failMethod?: 'single' | 'batch' | 'both';
  dimension?: number;
  latency?: number;
  cacheEnabled?: boolean;
}

export class MockEmbeddingService {
  private config: Required<MockEmbeddingConfig>;
  private stats: EmbeddingStats;

  constructor(config: MockEmbeddingConfig = {}) {
    this.config = {
      shouldFail: false,
      failMethod: 'both',
      dimension: 1536,
      latency: 0,
      cacheEnabled: true,
      ...config,
    };

    this.stats = {
      totalRequests: 0,
      cacheHits: 0,
      cacheMisses: 0,
      averageProcessingTime: 0,
      totalTokensUsed: 0,
      errors: 0,
      model: 'text-embedding-ada-002',
      cacheSize: 0,
      cacheHitRate: 0,
    };
  }

  /**
   * Generate a deterministic embedding vector based on text content
   */
  private generateDeterministicVector(text: string): number[] {
    const vector = new Array(this.config.dimension).fill(0);

    // Create a simple hash-based embedding for determinism
    let hash = 0;
    for (let i = 0; i < text.length; i++) {
      const char = text.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash; // Convert to 32-bit integer
    }

    // Use hash to seed the vector
    const seed = Math.abs(hash);
    for (let i = 0; i < this.config.dimension; i++) {
      // Simple pseudo-random based on seed and position
      const value = Math.sin(seed * (i + 1)) * 0.5 + 0.5;
      vector[i] = value;
    }

    // Normalize the vector
    const magnitude = Math.sqrt(vector.reduce((sum, val) => sum + val * val, 0));
    if (magnitude > 0) {
      return vector.map((val) => val / magnitude);
    }

    return vector;
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

    // Simulate latency
    if (this.config.latency > 0) {
      await new Promise((resolve) => setTimeout(resolve, this.config.latency));
    }

    // Check if should fail
    if (
      this.config.shouldFail &&
      (this.config.failMethod === 'single' || this.config.failMethod === 'both')
    ) {
      this.stats.errors++;
      throw new DatabaseError('Mock embedding service failed', 'INVALID_EMBEDDING_RESPONSE');
    }

    try {
      // Validate input
      if (!request.text || typeof request.text !== 'string') {
        throw new Error('Invalid text input for embedding');
      }

      // Generate deterministic vector
      const vector = this.generateDeterministicVector(request.text);

      // Validate vector
      if (!Array.isArray(vector) || vector.length === 0) {
        throw new Error('Generated vector is invalid');
      }

      const processingTime = Date.now() - startTime;
      this.updateAverageProcessingTime(processingTime);

      return {
        vector,
        model: 'text-embedding-ada-002',
        usage: {
          prompt_tokens: Math.ceil(request.text.length / 4),
          total_tokens: Math.ceil(request.text.length / 4),
        },
        cached: false,
        processingTime,
        ...(request.metadata && { metadata: request.metadata }),
      };
    } catch (error) {
      this.stats.errors++;
      throw error;
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
      const metadata = request.metadata?.[0];
      const embedRequest: EmbeddingRequest = {
        text: request.texts[0],
        ...(metadata && { metadata }),
        ...(request.priority && { priority: request.priority }),
      };
      const result = await this.generateEmbedding(embedRequest);
      return [result];
    }

    this.stats.totalRequests++;

    // Simulate latency
    if (this.config.latency > 0) {
      await new Promise((resolve) => setTimeout(resolve, this.config.latency));
    }

    // Check if should fail
    if (
      this.config.shouldFail &&
      (this.config.failMethod === 'batch' || this.config.failMethod === 'both')
    ) {
      this.stats.errors++;
      throw new Error('Mock batch embedding service failed');
    }

    try {
      const results: EmbeddingResult[] = request.texts.map((text, index) => {
        const vector = this.generateDeterministicVector(text);
        const metadata = request.metadata?.[index];

        return {
          vector,
          model: 'text-embedding-ada-002',
          usage: {
            prompt_tokens: Math.ceil(text.length / 4),
            total_tokens: Math.ceil(text.length / 4),
          },
          cached: false,
          processingTime: 0,
          ...(metadata && { metadata }),
        };
      });

      const processingTime = Date.now() - startTime;
      this.updateAverageProcessingTime(processingTime);

      return results;
    } catch (error) {
      this.stats.errors++;
      throw error;
    }
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
   * Clear cache (no-op for mock)
   */
  clearCache(): void {
    // Mock service doesn't actually cache, but keep interface consistent
  }

  /**
   * Check if service is healthy
   */
  async healthCheck(): Promise<boolean> {
    try {
      await this.generateEmbedding('health check test');
      return true;
    } catch (_error) {
      return false;
    }
  }

  /**
   * Warm up cache (no-op for mock)
   */
  async warmupCache(_commonTexts: string[]): Promise<void> {
    // Mock service doesn't actually cache, but keep interface consistent
  }

  /**
   * Static validation methods (pass-through to real service logic)
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

  static normalizeEmbedding(vector: number[]): number[] {
    if (!MockEmbeddingService.validateEmbedding(vector)) {
      throw new Error('Invalid embedding vector for normalization');
    }

    // Calculate magnitude
    const magnitude = Math.sqrt(vector.reduce((sum, val) => sum + val * val, 0));

    if (magnitude === 0) {
      throw new Error('Cannot normalize zero-length embedding vector');
    }

    // Normalize to unit vector
    return vector.map((val) => val / magnitude);
  }

  static calculateSimilarity(vector1: number[], vector2: number[]): number {
    if (
      !MockEmbeddingService.validateEmbedding(vector1) ||
      !MockEmbeddingService.validateEmbedding(vector2)
    ) {
      throw new Error('Invalid embedding vectors for similarity calculation');
    }

    if (vector1.length !== vector2.length) {
      throw new Error('Embedding vectors must have the same length');
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

  static findMostSimilar(
    queryVector: number[],
    candidateVectors: number[][],
    topK: number = 5,
    threshold: number = 0.7
  ): Array<{ vector: number[]; similarity: number; index: number }> {
    const similarities = candidateVectors
      .map((vector, index) => ({
        vector,
        similarity: MockEmbeddingService.calculateSimilarity(queryVector, vector),
        index,
      }))
      .filter((item) => item.similarity >= threshold)
      .sort((a, b) => b.similarity - a.similarity)
      .slice(0, topK);

    return similarities;
  }
}

/**
 * Helper function to create a mock embedding service
 */
export function createMockEmbeddingService(config: MockEmbeddingConfig = {}): MockEmbeddingService {
  return new MockEmbeddingService(config);
}
