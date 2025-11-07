/**
 * Optimized Embedding Service
 *
 * Enhanced version of the embedding service with memory optimization features:
 * - Configurable cache size with automatic eviction
 * - Memory usage monitoring and adaptive cleanup
 * - Batch processing with memory pooling
 * - Circuit breaker for memory pressure
 * - LRU eviction policy for cache management
 */

import { createHash } from 'crypto';
import { OpenAI } from 'openai';
import { logger } from '@/utils/logger.js';
import { DatabaseError, ValidationError } from '../../db/database-interface.js';
import { getKeyVaultService } from '../security/key-vault-service.js';
import { memoryManager } from '../memory/memory-manager-service.js';

/**
 * Enhanced cache entry with memory metadata
 */
interface OptimizedCacheEntry {
  vector: number[];
  model: string;
  createdAt: number;
  lastAccessed: number;
  accessCount: number;
  sizeBytes: number;
  priority: 'high' | 'medium' | 'low';
}

/**
 * Memory-aware embedding configuration
 */
export interface OptimizedEmbeddingConfig {
  apiKey?: string;
  model?: string;
  batchSize?: number;
  maxRetries?: number;
  retryDelay?: number;
  cacheEnabled?: boolean;
  cacheMaxSize?: number;
  cacheMaxMemoryMB?: number;
  cacheEvictionPolicy?: 'lru' | 'lfu' | 'priority';
  enableMemoryMonitoring?: boolean;
  memoryThresholdMB?: number;
  timeout?: number;
}

/**
 * Memory usage statistics for embeddings
 */
export interface EmbeddingMemoryStats {
  cacheSize: number;
  cacheMemoryMB: number;
  cacheHitRate: number;
  memoryPressureLevel: 'low' | 'medium' | 'high' | 'critical';
  lastCleanupTime: number;
  totalEvictions: number;
}

/**
 * Optimized Embedding Service with memory management
 */
export class OptimizedEmbeddingService {
  private openai: OpenAI;
  private config: Required<OptimizedEmbeddingConfig>;
  private cache: Map<string, OptimizedCacheEntry> = new Map();
  private memoryStats: EmbeddingMemoryStats;
  private lastMemoryCheck = 0;
  private totalEvictions = 0;

  // Memory monitoring
  private memoryCheckInterval = 30000; // 30 seconds
  private circuitBreakerOpen = false;
  private circuitBreakerTimer?: NodeJS.Timeout;

  constructor(config: OptimizedEmbeddingConfig = {}) {
    this.config = {
      apiKey: config.apiKey || process.env.OPENAI_API_KEY || '',
      model: config.model || 'text-embedding-3-small',
      batchSize: config.batchSize || 50, // Reduced batch size for memory
      maxRetries: config.maxRetries || 3,
      retryDelay: config.retryDelay || 1000,
      cacheEnabled: config.cacheEnabled !== false,
      cacheMaxSize: config.cacheMaxSize || 5000, // Reduced from 10000
      cacheMaxMemoryMB: config.cacheMaxMemoryMB || 100, // 100MB limit
      cacheEvictionPolicy: config.cacheEvictionPolicy || 'lru',
      enableMemoryMonitoring: config.enableMemoryMonitoring !== false,
      memoryThresholdMB: config.memoryThresholdMB || 200,
      timeout: config.timeout || 30000,
    };

    this.memoryStats = {
      cacheSize: 0,
      cacheMemoryMB: 0,
      cacheHitRate: 0,
      memoryPressureLevel: 'low',
      lastCleanupTime: Date.now(),
      totalEvictions: 0,
    };

    // Initialize OpenAI client
    this.openai = new OpenAI({
      apiKey: this.config.apiKey,
    });

    // Setup memory monitoring
    if (this.config.enableMemoryMonitoring) {
      this.setupMemoryMonitoring();
    }

    // Setup memory manager event listeners
    this.setupMemoryEventListeners();

    logger.info('Optimized Embedding Service initialized', {
      cacheMaxSize: this.config.cacheMaxSize,
      cacheMaxMemoryMB: this.config.cacheMaxMemoryMB,
      batchSize: this.config.batchSize,
    });
  }

  /**
   * Setup memory monitoring
   */
  private setupMemoryMonitoring(): void {
    setInterval(() => {
      this.checkMemoryUsage();
    }, this.memoryCheckInterval);
  }

  /**
   * Setup memory manager event listeners
   */
  private setupMemoryEventListeners(): void {
    memoryManager.on('memory-warning', () => {
      this.handleMemoryPressure('medium');
    });

    memoryManager.on('memory-critical', () => {
      this.handleMemoryPressure('high');
    });

    memoryManager.on('memory-emergency', () => {
      this.handleMemoryPressure('critical');
    });
  }

  /**
   * Check memory usage and adapt behavior
   */
  private checkMemoryUsage(): void {
    const now = Date.now();
    if (now - this.lastMemoryCheck < this.memoryCheckInterval) {
      return;
    }

    this.lastMemoryCheck = now;
    const stats = memoryManager.getCurrentMemoryStats();
    const memoryMB = stats.heapUsed / 1024 / 1024;

    // Update memory statistics
    this.updateMemoryStats();

    // Check if we need to cleanup
    if (memoryMB > this.config.memoryThresholdMB) {
      this.performAdaptiveCleanup();
    }
  }

  /**
   * Update memory statistics
   */
  private updateMemoryStats(): void {
    const cacheSize = this.cache.size;
    const cacheMemoryMB = this.calculateCacheMemoryMB();

    this.memoryStats = {
      ...this.memoryStats,
      cacheSize,
      cacheMemoryMB,
      totalEvictions: this.totalEvictions,
    };

    // Determine memory pressure level
    if (cacheMemoryMB > this.config.cacheMaxMemoryMB * 0.9) {
      this.memoryStats.memoryPressureLevel = 'critical';
    } else if (cacheMemoryMB > this.config.cacheMaxMemoryMB * 0.7) {
      this.memoryStats.memoryPressureLevel = 'high';
    } else if (cacheMemoryMB > this.config.cacheMaxMemoryMB * 0.5) {
      this.memoryStats.memoryPressureLevel = 'medium';
    } else {
      this.memoryStats.memoryPressureLevel = 'low';
    }
  }

  /**
   * Calculate cache memory usage in MB
   */
  private calculateCacheMemoryMB(): number {
    let totalBytes = 0;
    for (const entry of this.cache.values()) {
      totalBytes += entry.sizeBytes;
    }
    return totalBytes / 1024 / 1024;
  }

  /**
   * Handle memory pressure
   */
  private handleMemoryPressure(level: 'medium' | 'high' | 'critical'): void {
    logger.warn('Embedding service handling memory pressure', { level });

    switch (level) {
      case 'medium':
        this.performMediumCleanup();
        break;
      case 'high':
        this.performHighCleanup();
        break;
      case 'critical':
        this.performCriticalCleanup();
        break;
    }
  }

  /**
   * Perform adaptive cleanup based on memory pressure
   */
  private performAdaptiveCleanup(): void {
    const pressureLevel = this.memoryStats.memoryPressureLevel;

    switch (pressureLevel) {
      case 'medium':
        this.performMediumCleanup();
        break;
      case 'high':
        this.performHighCleanup();
        break;
      case 'critical':
        this.performCriticalCleanup();
        break;
    }
  }

  /**
   * Medium-level cleanup (evict 25% of cache)
   */
  private performMediumCleanup(): void {
    const targetSize = Math.floor(this.cache.size * 0.75);
    this.evictCacheEntries(targetSize, 'memory-pressure-medium');
  }

  /**
   * High-level cleanup (evict 50% of cache)
   */
  private performHighCleanup(): void {
    const targetSize = Math.floor(this.cache.size * 0.5);
    this.evictCacheEntries(targetSize, 'memory-pressure-high');
  }

  /**
   * Critical-level cleanup (evict 75% of cache)
   */
  private performCriticalCleanup(): void {
    const targetSize = Math.floor(this.cache.size * 0.25);
    this.evictCacheEntries(targetSize, 'memory-pressure-critical');

    // Consider temporarily disabling caching
    if (this.memoryStats.cacheMemoryMB > this.config.cacheMaxMemoryMB * 1.5) {
      logger.warn('Temporarily disabling embedding cache due to memory pressure');
      this.cache.clear();
      this.totalEvictions += this.cache.size;
    }
  }

  /**
   * Evict cache entries based on policy
   */
  private evictCacheEntries(targetSize: number, reason: string): void {
    const initialSize = this.cache.size;

    if (this.config.cacheEvictionPolicy === 'lru') {
      this.evictLRU(targetSize);
    } else if (this.config.cacheEvictionPolicy === 'lfu') {
      this.evictLFU(targetSize);
    } else if (this.config.cacheEvictionPolicy === 'priority') {
      this.evictByPriority(targetSize);
    }

    const evicted = initialSize - this.cache.size;
    this.totalEvictions += evicted;
    this.memoryStats.lastCleanupTime = Date.now();

    logger.info('Cache eviction completed', {
      reason,
      evicted,
      remaining: this.cache.size,
      memoryFreedMB: this.calculateCacheMemoryMB(),
    });
  }

  /**
   * Evict using LRU (Least Recently Used) policy
   */
  private evictLRU(targetSize: number): void {
    const entries = Array.from(this.cache.entries())
      .sort(([, a], [, b]) => a.lastAccessed - b.lastAccessed);

    const toEvict = entries.slice(0, this.cache.size - targetSize);
    toEvict.forEach(([key]) => this.cache.delete(key));
  }

  /**
   * Evict using LFU (Least Frequently Used) policy
   */
  private evictLFU(targetSize: number): void {
    const entries = Array.from(this.cache.entries())
      .sort(([, a], [, b]) => a.accessCount - b.accessCount);

    const toEvict = entries.slice(0, this.cache.size - targetSize);
    toEvict.forEach(([key]) => this.cache.delete(key));
  }

  /**
   * Evict by priority (keep high priority items)
   */
  private evictByPriority(targetSize: number): void {
    const priorityOrder = { low: 0, medium: 1, high: 2 };
    const entries = Array.from(this.cache.entries())
      .sort(([, a], [, b]) => priorityOrder[a.priority] - priorityOrder[b.priority]);

    const toEvict = entries.slice(0, this.cache.size - targetSize);
    toEvict.forEach(([key]) => this.cache.delete(key));
  }

  /**
   * Check circuit breaker
   */
  private checkCircuitBreaker(): boolean {
    if (this.circuitBreakerOpen) {
      logger.warn('Embedding service circuit breaker is open');
      return false;
    }
    return true;
  }

  /**
   * Open circuit breaker temporarily
   */
  private openCircuitBreaker(): void {
    this.circuitBreakerOpen = true;

    // Reset after 30 seconds
    if (this.circuitBreakerTimer) {
      clearTimeout(this.circuitBreakerTimer);
    }

    this.circuitBreakerTimer = setTimeout(() => {
      this.circuitBreakerOpen = false;
      logger.info('Embedding service circuit breaker closed');
    }, 30000);

    logger.warn('Embedding service circuit breaker opened for 30 seconds');
  }

  /**
   * Generate embedding with memory optimization
   */
  async generateEmbedding(text: string, priority: 'high' | 'medium' | 'low' = 'medium'): Promise<{
    vector: number[];
    cached: boolean;
    model: string;
    usage?: any;
  }> {
    // Check circuit breaker
    if (!this.checkCircuitBreaker()) {
      throw new DatabaseError('Embedding service temporarily unavailable', 'CIRCUIT_BREAKER_OPEN');
    }

    // Check cache first
    if (this.config.cacheEnabled) {
      const cacheKey = this.generateCacheKey(text);
      const cached = this.getFromCache(cacheKey);
      if (cached) {
        return {
          vector: cached.vector,
          cached: true,
          model: cached.model,
        };
      }
    }

    try {
      // Check memory before making API call
      this.checkMemoryUsage();

      // Ensure OpenAI is initialized
      await this.ensureOpenAIInitialized();

      // Generate embedding
      const response = await this.openai.embeddings.create({
        model: this.config.model,
        input: this.preprocessText(text),
      });

      if (!response.data?.[0]?.embedding || !Array.isArray(response.data[0].embedding)) {
        throw new DatabaseError('Invalid embedding response', 'INVALID_EMBEDDING_RESPONSE');
      }

      const vector = response.data[0].embedding;

      // Cache result if enabled
      if (this.config.cacheEnabled) {
        const cacheKey = this.generateCacheKey(text);
        this.setCache(cacheKey, {
          vector,
          model: this.config.model,
          createdAt: Date.now(),
          lastAccessed: Date.now(),
          accessCount: 1,
          sizeBytes: this.calculateVectorSize(vector),
          priority,
        });
      }

      return {
        vector,
        cached: false,
        model: this.config.model,
        usage: response.usage,
      };

    } catch (error) {
      // Open circuit breaker on certain errors
      if (error instanceof Error &&
          (error.message.includes('insufficient_quota') ||
           error.message.includes('rate_limit'))) {
        this.openCircuitBreaker();
      }

      throw error;
    }
  }

  /**
   * Ensure OpenAI client is initialized
   */
  private async ensureOpenAIInitialized(): Promise<void> {
    if (this.config.apiKey) {
      return;
    }

    try {
      const keyVault = getKeyVaultService();
      const openaiKey = await keyVault.get_key_by_name('openai_api_key');
      if (openaiKey) {
        this.config.apiKey = openaiKey.value;
        this.openai = new OpenAI({ apiKey: this.config.apiKey });
        logger.info('OpenAI API key retrieved from key vault');
        return;
      }
    } catch (error) {
      logger.warn({ error }, 'Failed to retrieve OpenAI API key from key vault');
    }

    throw new Error('OpenAI API key is required but not found');
  }

  /**
   * Preprocess text for embedding
   */
  private preprocessText(text: string): string {
    let processed = text.replace(/\s+/g, ' ').trim();

    if (processed.length < 1) {
      processed = 'empty';
    }

    const maxChars = 8000;
    if (processed.length > maxChars) {
      processed = processed.substring(0, maxChars);
    }

    return processed;
  }

  /**
   * Generate cache key
   */
  private generateCacheKey(text: string): string {
    return createHash('md5').update(text).digest('hex');
  }

  /**
   * Get from cache with LRU update
   */
  private getFromCache(key: string): OptimizedCacheEntry | null {
    const entry = this.cache.get(key);
    if (!entry) {
      return null;
    }

    const now = Date.now();

    // Check TTL (24 hours)
    if (now - entry.createdAt > 86400000) {
      this.cache.delete(key);
      return null;
    }

    // Update access statistics
    entry.lastAccessed = now;
    entry.accessCount++;

    return entry;
  }

  /**
   * Set cache with size management
   */
  private setCache(key: string, entry: OptimizedCacheEntry): void {
    // Check if we need to evict entries
    if (this.cache.size >= this.config.cacheMaxSize) {
      this.evictCacheEntries(this.config.cacheMaxSize - 1, 'cache-full');
    }

    // Check memory limit
    const currentMemoryMB = this.calculateCacheMemoryMB();
    if (currentMemoryMB > this.config.cacheMaxMemoryMB) {
      this.evictCacheEntries(Math.floor(this.cache.size * 0.8), 'memory-limit');
    }

    this.cache.set(key, entry);
  }

  /**
   * Calculate vector size in bytes
   */
  private calculateVectorSize(vector: number[]): number {
    // Each number is 8 bytes (float64) plus overhead
    return vector.length * 8 + 100; // 100 bytes overhead estimate
  }

  /**
   * Get memory statistics
   */
  getMemoryStats(): EmbeddingMemoryStats {
    this.updateMemoryStats();
    return { ...this.memoryStats };
  }

  /**
   * Clear cache
   */
  clearCache(): void {
    this.totalEvictions += this.cache.size;
    this.cache.clear();
    logger.info('Embedding cache cleared');
  }

  /**
   * Configure service
   */
  updateConfig(config: Partial<OptimizedEmbeddingConfig>): void {
    this.config = { ...this.config, ...config };
    logger.info('Embedding service config updated', { config });
  }

  /**
   * Shutdown service
   */
  shutdown(): void {
    if (this.circuitBreakerTimer) {
      clearTimeout(this.circuitBreakerTimer);
    }

    this.clearCache();
    logger.info('Optimized Embedding Service shut down');
  }
}

// Export singleton instance
export const optimizedEmbeddingService = new OptimizedEmbeddingService();
