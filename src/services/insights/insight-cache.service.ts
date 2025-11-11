
/**
 * Insight Cache Service
 *
 * Advanced caching service for insights with semantic similarity hashing,
 * intelligent cache invalidation, and performance optimization.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { createHash } from 'crypto';

import { logger } from '@/utils/logger.js';

import type { InsightTypeUnion } from '../../types/insight-interfaces.js';

export interface InsightCacheConfig {
  ttlSeconds: number;
  maxSize: number;
  enableSemanticHashing: boolean;
  similarityThreshold: number;
  compressionEnabled: boolean;
  metricsEnabled: boolean;
}

export interface CacheEntry {
  id: string;
  insights: InsightTypeUnion[];
  createdAt: Date;
  expiresAt: Date;
  accessCount: number;
  lastAccessed: Date;
  semanticHash: string;
  itemIds: string[];
  strategies: string[];
  confidence: number;
  size: number;
  compressed: boolean;
}

export interface CacheStats {
  totalEntries: number;
  totalSize: number;
  hitRate: number;
  missRate: number;
  evictionCount: number;
  compressionSavings: number;
  averageAccessTime: number;
  semanticHashes: number;
  staleEntries: number;
}

export interface CacheMetrics {
  hits: number;
  misses: number;
  sets: number;
  deletes: number;
  evictions: number;
  compressions: number;
  decompressions: number;
  semanticHashes: number;
  totalAccessTime: number;
  accessCount: number;
}

/**
 * Insight Cache Service
 */
export class InsightCacheService {
  private cache = new Map<string, CacheEntry>();
  private semanticIndex = new Map<string, Set<string>>();
  private config: InsightCacheConfig;
  private metrics: CacheMetrics;
  private cleanupTimer?: NodeJS.Timeout;

  constructor(config: Partial<InsightCacheConfig> = {}) {
    this.config = {
      ttlSeconds: 3600, // 1 hour default
      maxSize: 1000, // 1000 entries default
      enableSemanticHashing: true,
      similarityThreshold: 0.8,
      compressionEnabled: true,
      metricsEnabled: true,
      ...config,
    };

    this.metrics = this.initializeMetrics();
    this.startCleanupTimer();
    logger.info('Insight Cache Service initialized', { config: this.config });
  }

  /**
   * Get insights from cache
   */
  async get(key: string): Promise<InsightTypeUnion[] | null> {
    const startTime = Date.now();

    try {
      // Check for exact match first
      const entry = this.cache.get(key);
      if (entry && this.isValidEntry(entry)) {
        this.updateAccessStats(entry);
        this.metrics.hits++;
        this.metrics.totalAccessTime += Date.now() - startTime;
        this.metrics.accessCount++;

        if (entry.compressed) {
          this.metrics.decompressions++;
          return this.decompressInsights(entry.insights);
        }

        logger.debug('Cache hit', { key, entryId: entry.id });
        return entry.insights;
      }

      // Check for semantic similarity if enabled
      if (this.config.enableSemanticHashing) {
        const similarKey = this.findSimilarKey(key);
        if (similarKey) {
          const similarEntry = this.cache.get(similarKey);
          if (similarEntry && this.isValidEntry(similarEntry)) {
            this.updateAccessStats(similarEntry);
            this.metrics.hits++;
            this.metrics.semanticHashes++;
            this.metrics.totalAccessTime += Date.now() - startTime;
            this.metrics.accessCount++;

            logger.debug('Semantic cache hit', {
              originalKey: key,
              similarKey,
              entryId: similarEntry.id,
            });

            return similarEntry.compressed
              ? this.decompressInsights(similarEntry.insights)
              : similarEntry.insights;
          }
        }
      }

      this.metrics.misses++;
      this.metrics.totalAccessTime += Date.now() - startTime;
      this.metrics.accessCount++;

      logger.debug('Cache miss', { key });
      return null;
    } catch (error) {
      logger.error({ error, key }, 'Cache get failed');
      this.metrics.misses++;
      return null;
    }
  }

  /**
   * Set insights in cache
   */
  async set(
    key: string,
    insights: InsightTypeUnion[],
    metadata: {
      itemIds: string[];
      strategies: string[];
      confidence: number;
    } = { itemIds: [], strategies: [], confidence: 0.5 }
  ): Promise<void> {
    try {
      // Check cache size and evict if necessary
      await this.ensureCacheSize();

      const now = new Date();
      const expiresAt = new Date(now.getTime() + this.config.ttlSeconds * 1000);

      // Process insights
      let processedInsights = insights;
      let compressed = false;
      let size = this.calculateSize(insights);

      // Compress if enabled and beneficial
      if (this.config.compressionEnabled && size > 1024) {
        processedInsights = await this.compressInsights(insights);
        compressed = true;
        this.metrics.compressions++;
        const compressedSize = this.calculateSize(processedInsights);
        size = Math.min(size, compressedSize);
      }

      // Generate semantic hash
      const semanticHash = this.config.enableSemanticHashing
        ? this.generateSemanticHash(insights, metadata)
        : this.generateSimpleHash(insights.map(i => JSON.stringify(i)));

      const entry: CacheEntry = {
        id: this.generateEntryId(),
        insights: processedInsights,
        createdAt: now,
        expiresAt,
        accessCount: 0,
        lastAccessed: now,
        semanticHash,
        itemIds: metadata.itemIds,
        strategies: metadata.strategies,
        confidence: metadata.confidence,
        size,
        compressed,
      };

      this.cache.set(key, entry);

      // Update semantic index
      if (this.config.enableSemanticHashing) {
        this.updateSemanticIndex(semanticHash, key);
      }

      this.metrics.sets++;
      logger.debug('Cache set', {
        key,
        entryId: entry.id,
        insightCount: insights.length,
        compressed,
        size,
      });
    } catch (error) {
      logger.error({ error, key }, 'Cache set failed');
    }
  }

  /**
   * Delete entry from cache
   */
  async delete(key: string): Promise<boolean> {
    try {
      const entry = this.cache.get(key);
      if (entry) {
        // Remove from semantic index
        if (this.config.enableSemanticHashing) {
          this.removeFromSemanticIndex(entry.semanticHash, key);
        }

        this.cache.delete(key);
        this.metrics.deletes++;
        logger.debug('Cache delete', { key, entryId: entry.id });
        return true;
      }

      return false;
    } catch (error) {
      logger.error({ error, key }, 'Cache delete failed');
      return false;
    }
  }

  /**
   * Clear all cache entries
   */
  async clear(): Promise<void> {
    try {
      this.cache.clear();
      this.semanticIndex.clear();
      this.metrics = this.initializeMetrics();
      logger.info('Cache cleared');
    } catch (error) {
      logger.error({ error }, 'Cache clear failed');
    }
  }

  /**
   * Get cache statistics
   */
  getStats(): CacheStats {
    const totalEntries = this.cache.size;
    const totalSize = Array.from(this.cache.values()).reduce((sum, entry) => sum + entry.size, 0);

    const totalRequests = this.metrics.hits + this.metrics.misses;
    const hitRate = totalRequests > 0 ? this.metrics.hits / totalRequests : 0;
    const missRate = totalRequests > 0 ? this.metrics.misses / totalRequests : 0;

    const averageAccessTime =
      this.metrics.accessCount > 0 ? this.metrics.totalAccessTime / this.metrics.accessCount : 0;

    const staleEntries = Array.from(this.cache.values()).filter(
      (entry) => !this.isValidEntry(entry)
    ).length;

    return {
      totalEntries,
      totalSize,
      hitRate,
      missRate,
      evictionCount: this.metrics.evictions,
      compressionSavings:
        this.metrics.compressions > 0
          ? this.metrics.compressions * 0.3 // Estimate 30% savings
          : 0,
      averageAccessTime,
      semanticHashes: this.metrics.semanticHashes,
      staleEntries,
    };
  }

  /**
   * Reset cache metrics
   */
  resetMetrics(): void {
    this.metrics = this.initializeMetrics();
    logger.info('Cache metrics reset');
  }

  /**
   * Cleanup expired entries
   */
  async cleanup(): Promise<number> {
    let cleanedCount = 0;

    try {
      const now = new Date();
      const keysToDelete: string[] = [];

      for (const [key, entry] of this.cache.entries()) {
        if (entry.expiresAt <= now) {
          keysToDelete.push(key);
        }
      }

      for (const key of keysToDelete) {
        await this.delete(key);
        cleanedCount++;
      }

      if (cleanedCount > 0) {
        logger.info('Cache cleanup completed', { cleanedCount, remaining: this.cache.size });
      }
    } catch (error) {
      logger.error({ error }, 'Cache cleanup failed');
    }

    return cleanedCount;
  }

  /**
   * Find similar keys using semantic hashing
   */
  private findSimilarKey(key: string): string | null {
    try {
      const keyHash = this.generateSimpleHash([key]);
      const similarEntries = this.semanticIndex.get(keyHash);

      if (!similarEntries || similarEntries.size === 0) {
        return null;
      }

      // Return the most recently accessed similar key
      let bestKey: string | null = null;
      let bestScore = -1;

      for (const similarKey of similarEntries) {
        if (similarKey === key) continue;

        const entry = this.cache.get(similarKey);
        if (entry && this.isValidEntry(entry)) {
          // Score based on recency and access frequency
          const recencyScore = Date.now() - entry.lastAccessed.getTime();
          const frequencyScore = entry.accessCount;
          const combinedScore = frequencyScore - recencyScore / (1000 * 60 * 60); // Decay by hours

          if (combinedScore > bestScore) {
            bestScore = combinedScore;
            bestKey = similarKey;
          }
        }
      }

      return bestKey;
    } catch (error) {
      logger.error({ error, key }, 'Similar key lookup failed');
      return null;
    }
  }

  /**
   * Update semantic index
   */
  private updateSemanticIndex(semanticHash: string, key: string): void {
    if (!this.semanticIndex.has(semanticHash)) {
      this.semanticIndex.set(semanticHash, new Set());
    }
    this.semanticIndex.get(semanticHash)!.add(key);
    this.metrics.semanticHashes++;
  }

  /**
   * Remove from semantic index
   */
  private removeFromSemanticIndex(semanticHash: string, key: string): void {
    const entries = this.semanticIndex.get(semanticHash);
    if (entries) {
      entries.delete(key);
      if (entries.size === 0) {
        this.semanticIndex.delete(semanticHash);
      }
    }
  }

  /**
   * Generate semantic hash for insights
   */
  private generateSemanticHash(
    insights: InsightTypeUnion[],
    metadata: { itemIds: string[]; strategies: string[]; confidence: number }
  ): string {
    try {
      const hashData = {
        // Hash insight types and key characteristics
        types: insights.map((i) => i.type).sort(),
        categories: insights.map((i) => i.category).sort(),
        averageConfidence: insights.reduce((sum, i) => sum + i.confidence, 0) / insights.length,
        // Hash input metadata
        itemCount: metadata.itemIds.length,
        itemTypes: metadata.itemIds.sort(),
        strategies: metadata.strategies.sort(),
        confidence: metadata.confidence,
      };

      return this.generateSimpleHash([JSON.stringify(hashData), metadata.itemIds.join(','), metadata.strategies.join(',')]);
    } catch (error) {
      logger.error({ error }, 'Semantic hash generation failed');
      return this.generateSimpleHash([Date.now().toString()]);
    }
  }

  /**
   * Generate simple hash
   */
  private generateSimpleHash(data: string[]): string {
    return createHash('sha256').update(data.sort().join('|')).digest('hex').substring(0, 16);
  }

  /**
   * Generate entry ID
   */
  private generateEntryId(): string {
    return `cache_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Check if entry is valid
   */
  private isValidEntry(entry: CacheEntry): boolean {
    return entry.expiresAt > new Date();
  }

  /**
   * Update access statistics
   */
  private updateAccessStats(entry: CacheEntry): void {
    entry.accessCount++;
    entry.lastAccessed = new Date();
  }

  /**
   * Calculate insight size
   */
  private calculateSize(insights: InsightTypeUnion[]): number {
    try {
      return JSON.stringify(insights).length;
    } catch (error) {
      logger.error({ error }, 'Size calculation failed');
      return 1024; // Default estimate
    }
  }

  /**
   * Compress insights
   */
  private async compressInsights(insights: InsightTypeUnion[]): Promise<InsightTypeUnion[]> {
    try {
      // Simple compression: remove redundant fields and optimize structure
      return insights.map((insight): InsightTypeUnion => ({
        ...insight,
        // Keep essential fields, remove verbose metadata for caching
        metadata: {
          generated_at: (insight as any).metadata?.['generated_at'] || new Date().toISOString(),
          generated_by: (insight as any).metadata?.['generated_by'] || 'system',
          processing_time_ms: (insight as any).metadata?.['processing_time_ms'] || 0,
          data_sources: (insight as any).metadata?.['data_sources'] || [],
        },
      }));
    } catch (error) {
      logger.error({ error }, 'Insight compression failed');
      return insights;
    }
  }

  /**
   * Decompress insights
   */
  private async decompressInsights(insights: InsightTypeUnion[]): Promise<InsightTypeUnion[]> {
    try {
      // Return insights as-is since compression is lightweight
      return insights;
    } catch (error) {
      logger.error({ error }, 'Insight decompression failed');
      return insights;
    }
  }

  /**
   * Ensure cache doesn't exceed max size
   */
  private async ensureCacheSize(): Promise<void> {
    if (this.cache.size < this.config.maxSize) {
      return;
    }

    try {
      // Sort entries by access score (frequency + recency)
      const entries = Array.from(this.cache.entries())
        .map(([key, entry]) => ({
          key,
          entry,
          score: this.calculateEvictionScore(entry),
        }))
        .sort((a, b) => a.score - b.score); // Lowest score first

      // Evict entries until under limit
      const evictCount = Math.floor(this.config.maxSize * 0.1); // Evict 10%
      const toEvict = entries.slice(0, Math.min(evictCount, entries.length));

      for (const { key, entry } of toEvict) {
        await this.delete(key);
        this.metrics.evictions++;
        logger.debug('Cache eviction', {
          key,
          entryId: entry.id,
          score: this.calculateEvictionScore(entry),
        });
      }
    } catch (error) {
      logger.error({ error }, 'Cache eviction failed');
    }
  }

  /**
   * Calculate eviction score (lower = more likely to evict)
   */
  private calculateEvictionScore(entry: CacheEntry): number {
    const now = Date.now();
    const ageHours = (now - entry.createdAt.getTime()) / (1000 * 60 * 60);
    const lastAccessHours = (now - entry.lastAccessed.getTime()) / (1000 * 60 * 60);

    // Score based on access frequency, recency, and size
    const frequencyScore = entry.accessCount;
    const recencyScore = Math.max(0, 24 - lastAccessHours); // Higher if accessed recently
    const agePenalty = Math.max(0, ageHours - 168); // Penalty for entries older than 1 week
    const sizePenalty = entry.size / 1024; // Penalty for larger entries

    return frequencyScore + recencyScore - agePenalty - sizePenalty;
  }

  /**
   * Initialize metrics
   */
  private initializeMetrics(): CacheMetrics {
    return {
      hits: 0,
      misses: 0,
      sets: 0,
      deletes: 0,
      evictions: 0,
      compressions: 0,
      decompressions: 0,
      semanticHashes: 0,
      totalAccessTime: 0,
      accessCount: 0,
    };
  }

  /**
   * Start cleanup timer
   */
  private startCleanupTimer(): void {
    // Run cleanup every 15 minutes
    this.cleanupTimer = setInterval(
      async () => {
        await this.cleanup();
      },
      15 * 60 * 1000
    );
  }

  /**
   * Destroy cache service
   */
  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = undefined;
    }
    this.cache.clear();
    this.semanticIndex.clear();
    logger.info('Insight Cache Service destroyed');
  }
}
