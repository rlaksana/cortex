/**
 * LRU Cache with Memory Limits for Cortex MCP
 *
 * Provides memory-bounded LRU caching with automatic cleanup,
 * size limits, and memory usage monitoring.
 */

export interface CacheNode<K, V> {
  key: K;
  value: V;
  size: number;
  prev: CacheNode<K, V> | null;
  next: CacheNode<K, V> | null;
  ttl?: number; // Time to live in milliseconds
  createdAt: number;
  lastAccessed: number;
}

export interface CacheOptions {
  maxSize: number; // Maximum number of items
  maxMemoryBytes: number; // Maximum memory usage in bytes
  ttlMs?: number; // Default TTL for items
  cleanupIntervalMs?: number; // Cleanup interval for expired items
  sizeEstimator?: (value: any) => number; // Function to estimate item size
}

export interface CacheStats {
  itemCount: number;
  memoryUsageBytes: number;
  maxMemoryBytes: number;
  hitRate: number;
  totalHits: number;
  totalMisses: number;
  expiredItems: number;
  evictedItems: number;
}

/**
 * Memory-bounded LRU Cache implementation
 */
export class LRUCache<K, V> {
  private head: CacheNode<K, V> | null = null;
  private tail: CacheNode<K, V> | null = null;
  private cache = new Map<K, CacheNode<K, V>>();
  private currentMemoryUsage = 0;
  private stats = {
    hits: 0,
    misses: 0,
    expired: 0,
    evicted: 0,
  };
  private cleanupTimer: NodeJS.Timeout | null = null;

  constructor(private options: CacheOptions) {
    this.startCleanupTimer();
  }

  /**
   * Get a value from the cache
   */
  get(key: K): V | undefined {
    const node = this.cache.get(key);

    if (!node) {
      this.stats.misses++;
      return undefined;
    }

    // Check if item has expired
    if (this.isExpired(node)) {
      this.delete(key);
      this.stats.expired++;
      this.stats.misses++;
      return undefined;
    }

    // Update access time and move to front
    node.lastAccessed = Date.now();
    this.moveToFront(node);
    this.stats.hits++;

    return node.value;
  }

  /**
   * Set a value in the cache
   */
  set(key: K, value: V, ttlMs?: number): void {
    // Delete existing entry if present
    if (this.cache.has(key)) {
      this.delete(key);
    }

    // Estimate size of the new item
    const size = this.estimateSize(value);

    // Check if single item exceeds memory limit
    if (size > this.options.maxMemoryBytes) {
      throw new Error(
        `Item size (${size} bytes) exceeds cache memory limit (${this.options.maxMemoryBytes} bytes)`
      );
    }

    // Create new node
    const node: CacheNode<K, V> = {
      key,
      value,
      size,
      prev: null,
      next: null,
      ...(ttlMs !== undefined
        ? { ttl: ttlMs }
        : this.options.ttlMs !== undefined
          ? { ttl: this.options.ttlMs }
          : {}),
      createdAt: Date.now(),
      lastAccessed: Date.now(),
    };

    // Add to cache and front of list
    this.cache.set(key, node);
    this.addToFront(node);
    this.currentMemoryUsage += size;

    // Evict items if necessary
    this.evictIfNecessary();
  }

  /**
   * Check if key exists in cache
   */
  has(key: K): boolean {
    const node = this.cache.get(key);
    if (!node) return false;

    if (this.isExpired(node)) {
      this.delete(key);
      this.stats.expired++;
      return false;
    }

    return true;
  }

  /**
   * Delete a key from cache
   */
  delete(key: K): boolean {
    const node = this.cache.get(key);
    if (!node) return false;

    this.cache.delete(key);
    this.removeFromList(node);
    this.currentMemoryUsage -= node.size;
    return true;
  }

  /**
   * Clear all items from cache
   */
  clear(): void {
    this.cache.clear();
    this.head = null;
    this.tail = null;
    this.currentMemoryUsage = 0;
    this.stats = { hits: 0, misses: 0, expired: 0, evicted: 0 };
  }

  /**
   * Get cache statistics
   */
  getStats(): CacheStats {
    const totalRequests = this.stats.hits + this.stats.misses;
    return {
      itemCount: this.cache.size,
      memoryUsageBytes: this.currentMemoryUsage,
      maxMemoryBytes: this.options.maxMemoryBytes,
      hitRate: totalRequests > 0 ? (this.stats.hits / totalRequests) * 100 : 0,
      totalHits: this.stats.hits,
      totalMisses: this.stats.misses,
      expiredItems: this.stats.expired,
      evictedItems: this.stats.evicted,
    };
  }

  /**
   * Get all keys in cache (from most recent to least recent)
   */
  keys(): K[] {
    const keys: K[] = [];
    let current = this.head;
    while (current) {
      keys.push(current.key);
      current = current.next;
    }
    return keys;
  }

  /**
   * Clean up expired items manually
   */
  cleanupExpired(): number {
    let cleanedCount = 0;

    for (const [key, node] of Array.from(this.cache.entries())) {
      if (this.isExpired(node)) {
        this.delete(key);
        this.stats.expired++;
        cleanedCount++;
      }
    }

    return cleanedCount;
  }

  /**
   * Destroy the cache and cleanup timers
   */
  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    this.clear();
  }

  /**
   * Move node to front of list (most recently used)
   */
  private moveToFront(node: CacheNode<K, V>): void {
    this.removeFromList(node);
    this.addToFront(node);
  }

  /**
   * Add node to front of list
   */
  private addToFront(node: CacheNode<K, V>): void {
    node.prev = null;
    node.next = this.head;

    if (this.head) {
      this.head.prev = node;
    } else {
      this.tail = node; // First node in list
    }

    this.head = node;
  }

  /**
   * Remove node from list
   */
  private removeFromList(node: CacheNode<K, V>): void {
    if (node.prev) {
      node.prev.next = node.next;
    } else {
      this.head = node.next; // Removing head
    }

    if (node.next) {
      node.next.prev = node.prev;
    } else {
      this.tail = node.prev; // Removing tail
    }
  }

  /**
   * Remove and return the least recently used item
   */
  private removeLRU(): CacheNode<K, V> | null {
    if (!this.tail) return null;

    const lru = this.tail;
    this.removeFromList(lru);
    this.cache.delete(lru.key);
    this.currentMemoryUsage -= lru.size;
    this.stats.evicted++;

    return lru;
  }

  /**
   * Check if item has expired
   */
  private isExpired(node: CacheNode<K, V>): boolean {
    if (!node.ttl) return false;
    return Date.now() - node.createdAt > node.ttl;
  }

  /**
   * Estimate size of a value
   */
  private estimateSize(value: V): number {
    if (this.options.sizeEstimator) {
      return this.options.sizeEstimator(value);
    }

    // Default estimation based on type
    if (value === null || value === undefined) {
      return 0;
    }

    if (typeof value === 'string') {
      return value.length * 2; // UTF-16 characters
    }

    if (typeof value === 'number') {
      return 8; // 64-bit number
    }

    if (typeof value === 'boolean') {
      return 4;
    }

    if (typeof value === 'object') {
      try {
        return JSON.stringify(value).length * 2;
      } catch {
        return 1024; // Fallback estimate for circular references
      }
    }

    return 8; // Default estimate
  }

  /**
   * Evict items if cache exceeds limits
   */
  private evictIfNecessary(): void {
    // Evict by size limit
    while (this.cache.size >= this.options.maxSize) {
      const evicted = this.removeLRU();
      if (!evicted) break;
    }

    // Evict by memory limit
    while (this.currentMemoryUsage > this.options.maxMemoryBytes) {
      const evicted = this.removeLRU();
      if (!evicted) break;
    }
  }

  /**
   * Start cleanup timer for expired items
   */
  private startCleanupTimer(): void {
    if (!this.options.cleanupIntervalMs) return;

    this.cleanupTimer = setInterval(() => {
      const cleaned = this.cleanupExpired();
      if (cleaned > 0) {
        // Optional: Log cleanup activity
        console.debug(`LRU Cache: Cleaned up ${cleaned} expired items`);
      }
    }, this.options.cleanupIntervalMs);
  }
}

/**
 * Cache factory with predefined configurations
 */
export class CacheFactory {
  /**
   * Create a cache optimized for search results
   */
  static createSearchCache(maxItems: number = 1000): LRUCache<string, any> {
    return new LRUCache<string, any>({
      maxSize: maxItems,
      maxMemoryBytes: 50 * 1024 * 1024, // 50MB
      ttlMs: 5 * 60 * 1000, // 5 minutes
      cleanupIntervalMs: 60 * 1000, // 1 minute
    });
  }

  /**
   * Create a cache optimized for embeddings
   */
  static createEmbeddingCache(maxItems: number = 500): LRUCache<string, number[]> {
    return new LRUCache<string, number[]>({
      maxSize: maxItems,
      maxMemoryBytes: 100 * 1024 * 1024, // 100MB
      ttlMs: 60 * 60 * 1000, // 1 hour
      cleanupIntervalMs: 5 * 60 * 1000, // 5 minutes
      sizeEstimator: (embedding: number[]) => embedding.length * 8, // 8 bytes per float
    });
  }

  /**
   * Create a cache optimized for user sessions
   */
  static createSessionCache(maxItems: number = 10000): LRUCache<string, any> {
    return new LRUCache<string, any>({
      maxSize: maxItems,
      maxMemoryBytes: 20 * 1024 * 1024, // 20MB
      ttlMs: 30 * 60 * 1000, // 30 minutes
      cleanupIntervalMs: 10 * 60 * 1000, // 10 minutes
    });
  }

  /**
   * Create a cache optimized for frequently accessed configuration
   */
  static createConfigCache(): LRUCache<string, any> {
    return new LRUCache<string, any>({
      maxSize: 500,
      maxMemoryBytes: 10 * 1024 * 1024, // 10MB
      ttlMs: 24 * 60 * 60 * 1000, // 24 hours
      cleanupIntervalMs: 60 * 60 * 1000, // 1 hour
    });
  }
}
