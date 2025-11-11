/**
 * In-Memory Fallback Storage
 *
 * Provides in-memory fallback storage for critical knowledge operations when
 * Qdrant is unavailable. Implements LRU eviction, TTL support, and persistence
 * for graceful degradation scenarios.
 *
 * @author Cortex Team
 * @version 2.0.1
 */

import * as crypto from 'crypto';

import { EventEmitter } from 'events';

import { logger } from '@/utils/logger.js';

import type { ExpiryTimeLabel } from '../../constants/expiry-times.js';
import type {
  BatchSummary,
  ItemResult,
  KnowledgeItem,
  SearchQuery,
  SearchResult,
  StoreError,
  StoreResult,
} from '../../types/core-interfaces.js';
import { calculateItemExpiry } from '../../utils/expiry-utils.js';

/**
 * In-memory storage configuration
 */
export interface InMemoryFallbackConfig {
  // Storage limits
  maxItems: number;
  maxMemoryUsageMB: number;

  // TTL settings
  defaultTTL: number; // minutes
  cleanupIntervalMs: number;

  // Persistence settings
  enablePersistence: boolean;
  persistencePath?: string;

  // Performance settings
  evictionPolicy: 'lru' | 'lfu' | 'ttl';
  compressionEnabled: boolean;

  // Deduplication settings
  enableDeduplication: boolean;
  maxDuplicateCheck: number;
}

/**
 * Storage entry with metadata
 */
interface StorageEntry {
  item: KnowledgeItem;
  createdAt: number;
  lastAccessed: number;
  accessCount: number;
  expiresAt: number;
  contentHash: string;
  size: number; // bytes
}

/**
 * Search result for in-memory storage
 */
interface InMemorySearchResult {
  item: KnowledgeItem;
  score: number;
  matchType: 'exact' | 'fuzzy' | 'semantic';
}

/**
 * Degradation metrics
 */
export interface DegradationMetrics {
  totalOperations: number;
  fallbackOperations: number;
  successfulFallbackOps: number;
  failedFallbackOps: number;
  itemsStored: number;
  itemsEvicted: number;
  memoryUsageMB: number;
  averageResponseTime: number;
  errorRate: number;
  uptimePercentage: number;
  lastFallbackTime: number;
  currentFallbackDuration: number;
}

/**
 * In-Memory Fallback Storage
 */
export class InMemoryFallbackStorage extends EventEmitter {
  private config: InMemoryFallbackConfig;
  private storage: Map<string, StorageEntry> = new Map();
  private isInitialized = false;
  private cleanupInterval: NodeJS.Timeout | null = null;

  // Metrics tracking
  private metrics: DegradationMetrics = {
    totalOperations: 0,
    fallbackOperations: 0,
    successfulFallbackOps: 0,
    failedFallbackOps: 0,
    itemsStored: 0,
    itemsEvicted: 0,
    memoryUsageMB: 0,
    averageResponseTime: 0,
    errorRate: 0,
    uptimePercentage: 100,
    lastFallbackTime: 0,
    currentFallbackDuration: 0,
  };

  // Performance tracking
  private responseTimeHistory: number[] = [];
  private operationStartTime = 0;

  constructor(config?: Partial<InMemoryFallbackConfig>) {
    super();

    this.config = {
      maxItems: 10000,
      maxMemoryUsageMB: 100,
      defaultTTL: 30, // 30 minutes
      cleanupIntervalMs: 60000, // 1 minute
      enablePersistence: false,
      evictionPolicy: 'lru',
      compressionEnabled: false,
      enableDeduplication: true,
      maxDuplicateCheck: 1000,
      ...config,
    };

    logger.info('In-memory fallback storage initialized', {
      maxItems: this.config.maxItems,
      maxMemoryUsage: this.config.maxMemoryUsageMB,
      defaultTTL: this.config.defaultTTL,
    });
  }

  /**
   * Initialize the in-memory storage
   */
  async initialize(): Promise<void> {
    if (this.isInitialized) {
      return;
    }

    try {
      // Load persisted data if enabled
      if (this.config.enablePersistence && this.config.persistencePath) {
        await this.loadPersistedData();
      }

      // Start cleanup interval
      this.startCleanupInterval();

      this.isInitialized = true;
      this.operationStartTime = Date.now();

      logger.info('In-memory fallback storage initialized successfully');
      this.emit('initialized');

    } catch (error) {
      logger.error({ error }, 'Failed to initialize in-memory fallback storage');
      throw error;
    }
  }

  /**
   * Store items in memory with fallback behavior
   */
  async store(items: KnowledgeItem[]): Promise<{
    items: ItemResult[];
    summary: BatchSummary;
    meta: {
      strategy: 'in-memory-fallback';
      degraded: true;
      source: 'in-memory-fallback';
      execution_time_ms: number;
      confidence_score: number;
      truncated: boolean;
      fallback_reason: string;
    };
  }> {
    const startTime = Date.now();
    const itemResults: ItemResult[] = [];
    let stored = 0;
    let skipped = 0;
    let errors = 0;

    try {
      logger.debug({ itemCount: items.length }, 'Storing items in in-memory fallback');

      for (let i = 0; i < items.length; i++) {
        const item = items[i];

        try {
          // Check if we have space
          if (!this.ensureSpace()) {
            // No space available, skip item
            skipped++;
            itemResults.push({
              input_index: i,
              status: 'business_rule_blocked',
              kind: item.kind,
              reason: 'In-memory storage full - item evicted',
              created_at: new Date().toISOString(),
            });
            continue;
          }

          // Check for duplicates if enabled
          if (this.config.enableDeduplication) {
            const contentHash = this.generateContentHash(item);
            const existing = this.findByContentHash(contentHash);

            if (existing) {
              skipped++;
              itemResults.push({
                input_index: i,
                status: 'skipped_dedupe',
                kind: item.kind,
                reason: 'Duplicate content in in-memory storage',
                existing_id: existing.id,
                created_at: new Date().toISOString(),
              });
              continue;
            }
          }

          // Create storage entry
          const entry: StorageEntry = {
            item: {
              ...item,
              id: item.id || `mem_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
              created_at: item.created_at || new Date().toISOString(),
              updated_at: new Date().toISOString(),
            },
            createdAt: Date.now(),
            lastAccessed: Date.now(),
            accessCount: 0,
            expiresAt: this.calculateExpiryTime(item),
            contentHash: this.generateContentHash(item),
            size: this.calculateItemSize(item),
          };

          // Store item
          this.storage.set(entry.item.id!, entry);
          stored++;

          itemResults.push({
            input_index: i,
            status: 'stored',
            kind: item.kind,
            id: entry.item.id,
            created_at: entry.item.created_at,
            content: item.content,
          });

        } catch (error) {
          errors++;
          itemResults.push({
            input_index: i,
            status: 'validation_error',
            kind: item.kind,
            reason: error instanceof Error ? error.message : 'Unknown error',
            error_code: 'STORE_ERROR',
          });
        }
      }

      // Update metrics
      this.updateMetrics(Date.now() - startTime, true);
      this.metrics.itemsStored += stored;

      // Generate summary
      const summary: BatchSummary = {
        stored,
        skipped_dedupe: itemResults.filter(item => item.status === 'skipped_dedupe').length,
        business_rule_blocked: itemResults.filter(item => item.status === 'business_rule_blocked').length,
        validation_error: errors,
        total: items.length,
      };

      logger.debug(
        { stored, skipped, errors, total: items.length },
        'In-memory fallback store operation completed'
      );

      return {
        items: itemResults,
        summary,
        meta: {
          strategy: 'in-memory-fallback',
          degraded: true,
          source: 'in-memory-fallback',
          execution_time_ms: Date.now() - startTime,
          confidence_score: 0.6, // Lower confidence for fallback
          truncated: false,
          fallback_reason: 'Qdrant database unavailable - using in-memory storage',
        },
      };

    } catch (error) {
      this.updateMetrics(Date.now() - startTime, false);
      this.metrics.failedFallbackOps++;

      logger.error({ error, itemCount: items.length }, 'In-memory fallback store operation failed');
      throw error;
    }
  }

  /**
   * Search items in memory with basic matching
   */
  async search(query: SearchQuery): Promise<{
    results: SearchResult[];
    items: SearchResult[];
    total_count: number;
    meta: {
      strategy: 'in-memory-fallback';
      degraded: true;
      source: 'in-memory-fallback';
      execution_time_ms: number;
      confidence_score: number;
      truncated: boolean;
      fallback_reason: string;
    };
  }> {
    const startTime = Date.now();

    try {
      logger.debug({ query }, 'Searching in in-memory fallback storage');

      const results: InMemorySearchResult[] = [];
      const searchTerm = query.query.toLowerCase();

      // Simple text-based search
      for (const [id, entry] of this.storage) {
        if (this.isExpired(entry)) {
          continue;
        }

        // Update access tracking
        entry.lastAccessed = Date.now();
        entry.accessCount++;

        // Check if item matches search
        const score = this.calculateSearchScore(entry.item, searchTerm);
        if (score > 0.1) { // Minimum relevance threshold
          results.push({
            item: entry.item,
            score,
            matchType: score > 0.8 ? 'exact' : score > 0.5 ? 'fuzzy' : 'semantic',
          });
        }
      }

      // Sort by relevance score
      results.sort((a, b) => b.score - a.score);

      // Apply filters
      let filteredResults = results;

      // Filter by scope if specified
      if (query.scope) {
        filteredResults = filteredResults.filter(result =>
          this.matchesScope(result.item.scope, query.scope!)
        );
      }

      // Filter by types if specified
      if (query.types && query.types.length > 0) {
        filteredResults = filteredResults.filter(result =>
          query.types!.includes(result.item.kind)
        );
      }

      // Limit results
      const limitedResults = filteredResults.slice(0, query.limit || 50);

      // Convert to SearchResult format
      const searchResults: SearchResult[] = limitedResults.map(result => ({
        id: result.item.id!,
        kind: result.item.kind,
        scope: result.item.scope,
        data: result.item.data,
        created_at: result.item.created_at!,
        confidence_score: result.score,
        match_type: result.matchType,
        highlight: this.generateHighlight(result.item, searchTerm),
      }));

      this.updateMetrics(Date.now() - startTime, true);

      logger.debug(
        { results: searchResults.length, query: query.query },
        'In-memory fallback search completed'
      );

      return {
        results: searchResults,
        items: searchResults,
        total_count: searchResults.length,
        meta: {
          strategy: 'in-memory-fallback',
          degraded: true,
          source: 'in-memory-fallback',
          execution_time_ms: Date.now() - startTime,
          confidence_score: searchResults.length > 0
            ? searchResults.reduce((sum, r) => sum + r.confidence_score, 0) / searchResults.length
            : 0,
          truncated: false,
          fallback_reason: 'Qdrant database unavailable - using in-memory search',
        },
      };

    } catch (error) {
      this.updateMetrics(Date.now() - startTime, false);
      this.metrics.failedFallbackOps++;

      logger.error({ error, query }, 'In-memory fallback search operation failed');
      throw error;
    }
  }

  /**
   * Get items by IDs
   */
  async findById(ids: string[]): Promise<KnowledgeItem[]> {
    const items: KnowledgeItem[] = [];

    for (const id of ids) {
      const entry = this.storage.get(id);
      if (entry && !this.isExpired(entry)) {
        entry.lastAccessed = Date.now();
        entry.accessCount++;
        items.push(entry.item);
      }
    }

    return items;
  }

  /**
   * Delete items by IDs
   */
  async delete(ids: string[]): Promise<{ deleted: number; errors: StoreError[] }> {
    let deleted = 0;
    const errors: StoreError[] = [];

    for (const id of ids) {
      if (this.storage.delete(id)) {
        deleted++;
      } else {
        errors.push({
          index: ids.indexOf(id),
          error_code: 'DELETE_ERROR',
          message: `Item not found: ${id}`,
        });
      }
    }

    return { deleted, errors };
  }

  /**
   * Get current metrics
   */
  getMetrics(): DegradationMetrics {
    // Update real-time metrics
    this.metrics.memoryUsageMB = this.calculateMemoryUsage();
    this.metrics.currentFallbackDuration = Date.now() - this.metrics.lastFallbackTime;

    // Calculate uptime percentage
    const totalRuntime = Date.now() - this.operationStartTime;
    const fallbackTime = this.metrics.fallbackOperations * this.metrics.averageResponseTime;
    this.metrics.uptimePercentage = totalRuntime > 0
      ? ((totalRuntime - fallbackTime) / totalRuntime) * 100
      : 100;

    return { ...this.metrics };
  }

  /**
   * Check if storage is healthy
   */
  isHealthy(): boolean {
    const memoryUsage = this.calculateMemoryUsage();
    return memoryUsage < this.config.maxMemoryUsageMB * 0.9; // 90% threshold
  }

  /**
   * Clear all stored items
   */
  clear(): void {
    this.storage.clear();
    logger.info('In-memory fallback storage cleared');
    this.emit('cleared');
  }

  /**
   * Shutdown the storage
   */
  async shutdown(): Promise<void> {
    try {
      // Stop cleanup interval
      if (this.cleanupInterval) {
        clearInterval(this.cleanupInterval);
        this.cleanupInterval = null;
      }

      // Persist data if enabled
      if (this.config.enablePersistence && this.config.persistencePath) {
        await this.persistData();
      }

      logger.info('In-memory fallback storage shut down');
      this.emit('shutdown');

    } catch (error) {
      logger.error({ error }, 'Error during in-memory fallback storage shutdown');
      throw error;
    }
  }

  // === Private Helper Methods ===

  /**
   * Generate content hash for deduplication
   */
  private generateContentHash(item: KnowledgeItem): string {
    const content = this.extractContentForHashing(item);
    return crypto.createHash('sha256').update(content).digest('hex');
  }

  /**
   * Extract content for hashing
   */
  private extractContentForHashing(item: KnowledgeItem): string {
    const parts: string[] = [];
    parts.push(item.kind);
    parts.push(JSON.stringify(item.scope));
    parts.push(JSON.stringify(item.data));
    return parts.join('|');
  }

  /**
   * Find item by content hash
   */
  private findByContentHash(hash: string): KnowledgeItem | null {
    for (const entry of this.storage.values()) {
      if (entry.contentHash === hash && !this.isExpired(entry)) {
        return entry.item;
      }
    }
    return null;
  }

  /**
   * Calculate expiry time for an item
   */
  private calculateExpiryTime(item: KnowledgeItem): number {
    // Use item's expiry if available
    if (item.data.expiry_at) {
      try {
        return new Date(item.data.expiry_at).getTime();
      } catch {
        // Fall through to default TTL
      }
    }

    // Use default TTL
    return Date.now() + (this.config.defaultTTL * 60 * 1000);
  }

  /**
   * Calculate item size in bytes
   */
  private calculateItemSize(item: KnowledgeItem): number {
    return JSON.stringify(item).length * 2; // Rough estimate
  }

  /**
   * Check if entry is expired
   */
  private isExpired(entry: StorageEntry): boolean {
    return Date.now() > entry.expiresAt;
  }

  /**
   * Ensure storage has space, evict items if necessary
   */
  private ensureSpace(): boolean {
    // Check item count limit
    if (this.storage.size >= this.config.maxItems) {
      if (!this.evictItems()) {
        return false;
      }
    }

    // Check memory usage limit
    const memoryUsage = this.calculateMemoryUsage();
    if (memoryUsage >= this.config.maxMemoryUsageMB) {
      if (!this.evictItems()) {
        return false;
      }
    }

    return true;
  }

  /**
   * Evict items based on policy
   */
  private evictItems(): boolean {
    const entries = Array.from(this.storage.entries());

    // Sort based on eviction policy
    switch (this.config.evictionPolicy) {
      case 'lru':
        entries.sort(([, a], [, b]) => a.lastAccessed - b.lastAccessed);
        break;
      case 'lfu':
        entries.sort(([, a], [, b]) => a.accessCount - b.accessCount);
        break;
      case 'ttl':
        entries.sort(([, a], [, b]) => a.expiresAt - b.expiresAt);
        break;
    }

    // Remove expired items first
    let evicted = 0;
    for (const [id, entry] of entries) {
      if (this.isExpired(entry)) {
        this.storage.delete(id);
        evicted++;
      }
    }

    // If still need space, remove additional items
    if (evicted === 0) {
      const toRemove = Math.min(10, entries.length); // Remove up to 10 items
      for (let i = 0; i < toRemove; i++) {
        const [id] = entries[i];
        this.storage.delete(id);
        evicted++;
      }
    }

    this.metrics.itemsEvicted += evicted;

    return evicted > 0;
  }

  /**
   * Calculate search score
   */
  private calculateSearchScore(item: KnowledgeItem, searchTerm: string): number {
    const content = this.extractContentForHashing(item).toLowerCase();

    // Exact match gets highest score
    if (content.includes(searchTerm)) {
      return 1.0;
    }

    // Partial matches based on word similarity
    const searchWords = searchTerm.split(' ');
    const contentWords = content.split(' ');

    let matches = 0;
    for (const searchWord of searchWords) {
      for (const contentWord of contentWords) {
        if (contentWord.includes(searchWord) || searchWord.includes(contentWord)) {
          matches++;
          break;
        }
      }
    }

    return matches / searchWords.length;
  }

  /**
   * Check if item matches scope
   */
  private matchesScope(itemScope: any, queryScope: any): boolean {
    if (queryScope.project && itemScope.project !== queryScope.project) return false;
    if (queryScope.branch && itemScope.branch !== queryScope.branch) return false;
    if (queryScope.org && itemScope.org !== queryScope.org) return false;
    return true;
  }

  /**
   * Generate highlight text
   */
  private generateHighlight(item: KnowledgeItem, searchTerm: string): string[] {
    const content = this.extractContentForHashing(item);
    const index = content.toLowerCase().indexOf(searchTerm.toLowerCase());

    if (index === -1) {
      return [];
    }

    const start = Math.max(0, index - 50);
    const end = Math.min(content.length, index + searchTerm.length + 50);
    const highlight = content.substring(start, end);

    return [`...${highlight}...`];
  }

  /**
   * Update metrics
   */
  private updateMetrics(responseTime: number, success: boolean): void {
    this.metrics.totalOperations++;
    this.metrics.fallbackOperations++;

    if (success) {
      this.metrics.successfulFallbackOps++;
    } else {
      this.metrics.failedFallbackOps++;
    }

    // Update response time history
    this.responseTimeHistory.push(responseTime);
    if (this.responseTimeHistory.length > 100) {
      this.responseTimeHistory.shift();
    }

    // Calculate average response time
    this.metrics.averageResponseTime = this.responseTimeHistory.reduce((a, b) => a + b, 0) / this.responseTimeHistory.length;

    // Update error rate
    this.metrics.errorRate = (this.metrics.failedFallbackOps / this.metrics.fallbackOperations) * 100;

    // Track fallback time
    if (this.metrics.fallbackOperations === 1) {
      this.metrics.lastFallbackTime = Date.now();
    }
  }

  /**
   * Calculate memory usage in MB
   */
  private calculateMemoryUsage(): number {
    let totalSize = 0;

    for (const entry of this.storage.values()) {
      totalSize += entry.size;
    }

    // Add overhead for Map structure
    totalSize += this.storage.size * 100; // Rough overhead estimate

    return totalSize / (1024 * 1024); // Convert to MB
  }

  /**
   * Start cleanup interval
   */
  private startCleanupInterval(): void {
    this.cleanupInterval = setInterval(() => {
      this.cleanupExpiredItems();
    }, this.config.cleanupIntervalMs);
  }

  /**
   * Clean up expired items
   */
  private cleanupExpiredItems(): void {
    let cleaned = 0;

    for (const [id, entry] of this.storage) {
      if (this.isExpired(entry)) {
        this.storage.delete(id);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      logger.debug({ cleaned }, 'Cleaned up expired items from in-memory storage');
      this.emit('cleanup', { cleaned });
    }
  }

  /**
   * Persist data to disk (if enabled)
   */
  private async persistData(): Promise<void> {
    // This would implement file-based persistence
    // For now, just log the operation
    logger.debug({ itemCount: this.storage.size }, 'Persisting in-memory storage data');
  }

  /**
   * Load persisted data from disk (if enabled)
   */
  private async loadPersistedData(): Promise<void> {
    // This would implement file-based loading
    // For now, just log the operation
    logger.debug('Loading persisted in-memory storage data');
  }
}

// Export singleton instance
export const inMemoryFallbackStorage = new InMemoryFallbackStorage();
