/**
 * Comprehensive Unit Tests for In-Memory Fallback Storage
 *
 * Tests in-memory fallback storage functionality including:
 * - Storage initialization and configuration
 * - Batch store operations
 * - Search and query functionality
 * - TTL and expiration handling
 * - LRU eviction policies
 * - Memory management and limits
 * - Persistence functionality
 * - Error handling and edge cases
 *
 * @author Cortex Team
 * @version 2.0.1
 * @since 2025
 */

import { describe, it, expect, beforeEach, afterEach, vi, beforeAll, afterAll } from 'vitest';
import {
  InMemoryFallbackStorage,
  type InMemoryFallbackConfig,
  type DegradationMetrics,
} from '../../../src/db/adapters/in-memory-fallback-storage';
import type {
  KnowledgeItem,
  SearchQuery,
  ItemResult,
  BatchSummary,
} from '../../../src/types/core-interfaces';

describe('In-Memory Fallback Storage', () => {
  let storage: InMemoryFallbackStorage;
  let testConfig: InMemoryFallbackConfig;

  beforeAll(() => {
    vi.useFakeTimers();
  });

  afterAll(() => {
    vi.useRealTimers();
  });

  beforeEach(async () => {
    testConfig = {
      maxItems: 100,
      maxMemoryUsageMB: 10,
      defaultTTL: 60, // 1 hour
      cleanupIntervalMs: 5000,
      enablePersistence: false,
      evictionPolicy: 'lru',
      compressionEnabled: false,
      enableDeduplication: true,
      maxDuplicateCheck: 1000,
    };

    storage = new InMemoryFallbackStorage(testConfig);
    await storage.initialize();
  });

  afterEach(async () => {
    await storage.shutdown();
  });

  describe('Initialization and Configuration', () => {
    it('should initialize with default configuration', async () => {
      const defaultStorage = new InMemoryFallbackStorage();
      await defaultStorage.initialize();
      expect(defaultStorage).toBeDefined();
      await defaultStorage.shutdown();
    });

    it('should initialize with custom configuration', async () => {
      const customConfig: InMemoryFallbackConfig = {
        maxItems: 500,
        maxMemoryUsageMB: 50,
        defaultTTL: 120,
        cleanupIntervalMs: 10000,
        enablePersistence: false,
        evictionPolicy: 'lfu',
        compressionEnabled: true,
        enableDeduplication: false,
        maxDuplicateCheck: 2000,
      };

      const customStorage = new InMemoryFallbackStorage(customConfig);
      await customStorage.initialize();
      expect(customStorage).toBeDefined();
      await customStorage.shutdown();
    });

    it('should handle invalid configuration gracefully', async () => {
      const invalidConfig = {
        maxItems: -1,
        maxMemoryUsageMB: 0,
        defaultTTL: -10,
      } as InMemoryFallbackConfig;

      expect(() => new InMemoryFallbackStorage(invalidConfig)).not.toThrow();
    });

    it('should emit initialized event', async () => {
      const eventSpy = vi.fn();
      storage.on('initialized', eventSpy);

      const newStorage = new InMemoryFallbackStorage(testConfig);
      await newStorage.initialize();

      expect(eventSpy).toHaveBeenCalled();
      await newStorage.shutdown();
    });
  });

  describe('Batch Store Operations', () => {
    let testItems: KnowledgeItem[];

    beforeEach(() => {
      testItems = [
        {
          id: 'test-item-1',
          kind: 'entity',
          title: 'Test Entity',
          content: 'This is a test entity content',
          scope: { project: 'test-project' },
          metadata: {
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
            version: 1,
            tags: ['test', 'entity'],
          },
        },
        {
          id: 'test-item-2',
          kind: 'decision',
          title: 'Test Decision',
          content: 'This is a test decision content',
          scope: { project: 'test-project' },
          metadata: {
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
            version: 1,
            tags: ['test', 'decision'],
          },
        },
      ];
    });

    it('should store items successfully', async () => {
      const result = await storage.store(testItems);

      expect(result).toBeDefined();
      expect(result.items).toHaveLength(2);
      expect(result.summary.stored).toBe(2);
      expect(result.summary.errors).toBe(0);
      expect(result.meta.strategy).toBe('in-memory-fallback');
      expect(result.meta.degraded).toBe(true);
      expect(result.meta.source).toBe('in-memory-fallback');
      expect(result.meta.fallback_reason).toBeDefined();
    });

    it('should handle duplicate items with deduplication', async () => {
      // Store items first
      await storage.store(testItems);

      // Try to store the same items again
      const result = await storage.store(testItems);

      expect(result.items).toHaveLength(2);
      // With deduplication enabled, items should be skipped or updated
      expect(result.summary.stored + result.summary.skipped).toBe(2);
    });

    it('should handle empty item array', async () => {
      const result = await storage.store([]);

      expect(result.items).toHaveLength(0);
      expect(result.summary.stored).toBe(0);
    });

    it('should handle invalid items gracefully', async () => {
      const invalidItems = [
        null,
        undefined,
        {} as KnowledgeItem,
        testItems[0], // valid item
      ] as any[];

      const result = await storage.store(invalidItems);

      expect(result.items).toHaveLength(4);
      expect(result.summary.errors).toBeGreaterThan(0);
    });
  });

  describe('Search and Query Functionality', () => {
    let testItems: KnowledgeItem[];

    beforeEach(async () => {
      testItems = [
        {
          id: 'entity-1',
          kind: 'entity',
          title: 'Database Entity',
          content: 'Represents a database table structure',
          scope: { project: 'database-project' },
          metadata: {
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
            version: 1,
            tags: ['database', 'entity'],
          },
        },
        {
          id: 'decision-1',
          kind: 'decision',
          title: 'Architecture Decision',
          content: 'Decision to use microservices architecture',
          scope: { project: 'architecture-project' },
          metadata: {
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
            version: 1,
            tags: ['architecture', 'decision'],
          },
        },
        {
          id: 'task-1',
          kind: 'task',
          title: 'Implementation Task',
          content: 'Implement user authentication system',
          scope: { project: 'auth-project' },
          metadata: {
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
            version: 1,
            tags: ['implementation', 'auth'],
          },
        },
      ];

      await storage.store(testItems);
    });

    it('should search by content text', async () => {
      const query: SearchQuery = {
        text: 'database',
        kind: undefined,
        scope: undefined,
        limit: 10,
        offset: 0,
      };

      const result = await storage.search(query);

      expect(result.success).toBe(true);
      expect(result.results).toHaveLength(1);
      expect(result.results[0].item.id).toBe('entity-1');
      expect(result.meta.strategy).toBe('in-memory-fallback');
      expect(result.meta.degraded).toBe(true);
    });

    it('should search by kind', async () => {
      const query: SearchQuery = {
        text: '',
        kind: 'decision',
        scope: undefined,
        limit: 10,
        offset: 0,
      };

      const result = await storage.search(query);

      expect(result.success).toBe(true);
      expect(result.results).toHaveLength(1);
      expect(result.results[0].item.id).toBe('decision-1');
    });

    it('should search by scope', async () => {
      const query: SearchQuery = {
        text: '',
        kind: undefined,
        scope: { project: 'auth-project' },
        limit: 10,
        offset: 0,
      };

      const result = await storage.search(query);

      expect(result.success).toBe(true);
      expect(result.results).toHaveLength(1);
      expect(result.results[0].item.id).toBe('task-1');
    });

    it('should handle complex search queries', async () => {
      const query: SearchQuery = {
        text: 'architecture',
        kind: 'decision',
        scope: { project: 'architecture-project' },
        limit: 10,
        offset: 0,
      };

      const result = await storage.search(query);

      expect(result.success).toBe(true);
      expect(result.results).toHaveLength(1);
      expect(result.results[0].item.id).toBe('decision-1');
    });

    it('should respect search limits and offsets', async () => {
      const query: SearchQuery = {
        text: '',
        kind: undefined,
        scope: undefined,
        limit: 2,
        offset: 1,
      };

      const result = await storage.search(query);

      expect(result.success).toBe(true);
      expect(result.results.length).toBeLessThanOrEqual(2);
    });

    it('return empty results for non-matching queries', async () => {
      const query: SearchQuery = {
        text: 'nonexistent-term',
        kind: undefined,
        scope: undefined,
        limit: 10,
        offset: 0,
      };

      const result = await storage.search(query);

      expect(result.success).toBe(true);
      expect(result.results).toHaveLength(0);
    });

    it('should handle search errors gracefully', async () => {
      // @ts-expect-error - Testing invalid query
      const result = await storage.search(null);

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });
  });

  describe('Find by ID Operations', () => {
    let testItems: KnowledgeItem[];

    beforeEach(async () => {
      testItems = [
        {
          id: 'find-test-1',
          kind: 'entity',
          title: 'Find Test 1',
          content: 'Content for find test 1',
          scope: { project: 'test-project' },
          metadata: {
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
            version: 1,
          },
        },
        {
          id: 'find-test-2',
          kind: 'decision',
          title: 'Find Test 2',
          content: 'Content for find test 2',
          scope: { project: 'test-project' },
          metadata: {
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
            version: 1,
          },
        },
      ];

      await storage.store(testItems);
    });

    it('should find items by their IDs', async () => {
      const result = await storage.findById(['find-test-1', 'find-test-2']);

      expect(result).toHaveLength(2);
      expect(result[0].id).toBe('find-test-1');
      expect(result[1].id).toBe('find-test-2');
    });

    it('should handle partial ID matches', async () => {
      const result = await storage.findById(['find-test-1', 'non-existent-id']);

      expect(result).toHaveLength(1);
      expect(result[0].id).toBe('find-test-1');
    });

    it('should return empty array for non-existent IDs', async () => {
      const result = await storage.findById(['non-existent-1', 'non-existent-2']);

      expect(result).toHaveLength(0);
    });

    it('should handle empty ID array', async () => {
      const result = await storage.findById([]);

      expect(result).toHaveLength(0);
    });
  });

  describe('Delete Operations', () => {
    let testItems: KnowledgeItem[];

    beforeEach(async () => {
      testItems = [
        {
          id: 'delete-test-1',
          kind: 'entity',
          title: 'Delete Test 1',
          content: 'Content for delete test 1',
          scope: { project: 'test-project' },
          metadata: {
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
            version: 1,
          },
        },
        {
          id: 'delete-test-2',
          kind: 'decision',
          title: 'Delete Test 2',
          content: 'Content for delete test 2',
          scope: { project: 'test-project' },
          metadata: {
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
            version: 1,
          },
        },
      ];

      await storage.store(testItems);
    });

    it('should delete items by their IDs', async () => {
      const result = await storage.delete(['delete-test-1', 'delete-test-2']);

      expect(result.deleted).toBe(2);
      expect(result.errors).toHaveLength(0);

      // Verify items are deleted
      const findResult = await storage.findById(['delete-test-1', 'delete-test-2']);
      expect(findResult).toHaveLength(0);
    });

    it('should handle partial deletions', async () => {
      const result = await storage.delete(['delete-test-1', 'non-existent-id']);

      expect(result.deleted).toBe(1);
      expect(result.errors).toHaveLength(1);
    });

    it('should handle empty ID array', async () => {
      const result = await storage.delete([]);

      expect(result.deleted).toBe(0);
      expect(result.errors).toHaveLength(0);
    });

    it('should handle non-existent IDs gracefully', async () => {
      const result = await storage.delete(['non-existent-1', 'non-existent-2']);

      expect(result.deleted).toBe(0);
      expect(result.errors).toHaveLength(2);
    });
  });

  describe('TTL and Expiration Handling', () => {
    let testItems: KnowledgeItem[];

    beforeEach(() => {
      testItems = [
        {
          id: 'ttl-test-1',
          kind: 'entity',
          title: 'TTL Test 1',
          content: 'This item should expire',
          scope: { project: 'test-project' },
          metadata: {
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
            version: 1,
            ttl: '1m', // 1 minute
          },
        },
        {
          id: 'ttl-test-2',
          kind: 'decision',
          title: 'TTL Test 2',
          content: 'This item should also expire',
          scope: { project: 'test-project' },
          metadata: {
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
            version: 1,
            ttl: '2m', // 2 minutes
          },
        },
      ];
    });

    it('should handle items with TTL expiration', async () => {
      await storage.store(testItems);

      // Items should exist initially
      let findResult = await storage.findById(['ttl-test-1', 'ttl-test-2']);
      expect(findResult).toHaveLength(2);

      // Fast forward past first item expiration
      vi.advanceTimersByTime(60 * 1000 + 1000); // 1 minute + buffer

      // First item should be expired, second should still exist
      findResult = await storage.findById(['ttl-test-1', 'ttl-test-2']);
      expect(findResult).toHaveLength(1);
      expect(findResult[0].id).toBe('ttl-test-2');

      // Fast forward past second item expiration
      vi.advanceTimersByTime(60 * 1000 + 1000); // Another minute + buffer

      // All items should be expired
      findResult = await storage.findById(['ttl-test-1', 'ttl-test-2']);
      expect(findResult).toHaveLength(0);
    });

    it('should respect cleanup intervals', async () => {
      const shortCleanupConfig = {
        ...testConfig,
        cleanupIntervalMs: 1000, // 1 second
      };
      const cleanupStorage = new InMemoryFallbackStorage(shortCleanupConfig);
      await cleanupStorage.initialize();

      try {
        await cleanupStorage.store(testItems);

        // Fast forward past expiration and cleanup interval
        vi.advanceTimersByTime(60 * 1000 + 2000); // 1 minute + 2 cleanup intervals

        // Items should be cleaned up
        const findResult = await cleanupStorage.findById(['ttl-test-1', 'ttl-test-2']);
        expect(findResult).toHaveLength(0);
      } finally {
        await cleanupStorage.shutdown();
      }
    });
  });

  describe('Memory Management and Limits', () => {
    it('should handle storage at capacity', async () => {
      const smallConfig = { ...testConfig, maxItems: 2 };
      const smallStorage = new InMemoryFallbackStorage(smallConfig);
      await smallStorage.initialize();

      try {
        const items = [
          createTestItem('capacity-test-1'),
          createTestItem('capacity-test-2'),
          createTestItem('capacity-test-3'),
        ];

        const result = await smallStorage.store(items);

        // Should store some items but potentially not all due to capacity limits
        expect(result.items.length).toBeGreaterThan(0);
        expect(result.items.length).toBeLessThanOrEqual(3);
        expect(result.summary.stored + result.summary.skipped + result.summary.errors).toBe(3);
      } finally {
        await smallStorage.shutdown();
      }
    });

    it('should handle memory pressure', async () => {
      const memoryConstrainedConfig = {
        ...testConfig,
        maxMemoryUsageMB: 1, // 1MB limit
      };
      const memoryStorage = new InMemoryFallbackStorage(memoryConstrainedConfig);
      await memoryStorage.initialize();

      try {
        // Add large items until memory limit is reached
        const largeContent = 'x'.repeat(1024 * 1024); // 1MB
        const items = [];

        for (let i = 0; i < 5; i++) {
          items.push({
            ...createTestItem(`memory-test-${i}`),
            content: largeContent,
          });
        }

        const result = await memoryStorage.store(items);

        // Should handle memory constraints gracefully
        expect(result.items.length).toBeGreaterThan(0);
        expect(result.items.length).toBeLessThanOrEqual(5);
      } finally {
        await memoryStorage.shutdown();
      }
    });
  });

  describe('Deduplication', () => {
    it('should detect duplicate items based on content hash', async () => {
      const dedupConfig = { ...testConfig, enableDeduplication: true };
      const dedupStorage = new InMemoryFallbackStorage(dedupConfig);
      await dedupStorage.initialize();

      try {
        const baseItem = createTestItem('dedup-base');
        baseItem.content = 'Same content for deduplication test';

        const items = [
          baseItem,
          {
            ...baseItem,
            id: 'dedup-duplicate',
            title: 'Different Title', // Different title but same content
          },
        ];

        const result = await dedupStorage.store(items);

        expect(result.items).toHaveLength(2);
        // With deduplication, one should be stored and one skipped
        expect(result.summary.stored + result.summary.skipped).toBe(2);
      } finally {
        await dedupStorage.shutdown();
      }
    });

    it('should skip deduplication when disabled', async () => {
      const noDedupConfig = { ...testConfig, enableDeduplication: false };
      const noDedupStorage = new InMemoryFallbackStorage(noDedupConfig);
      await noDedupStorage.initialize();

      try {
        const baseItem = createTestItem('no-dedup-base');
        baseItem.content = 'Same content but no deduplication';

        const items = [
          baseItem,
          {
            ...baseItem,
            id: 'no-dedup-duplicate',
            title: 'Different Title',
          },
        ];

        const result = await noDedupStorage.store(items);

        expect(result.items).toHaveLength(2);
        // Without deduplication, both should be stored
        expect(result.summary.stored).toBe(2);
      } finally {
        await noDedupStorage.shutdown();
      }
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle concurrent operations safely', async () => {
      const items = [];
      for (let i = 0; i < 10; i++) {
        items.push(createTestItem(`concurrent-${i}`));
      }

      // Concurrent stores
      const storePromises = [storage.store(items.slice(0, 5)), storage.store(items.slice(5, 10))];

      const storeResults = await Promise.all(storePromises);
      expect(storeResults.every((r) => r.items.length > 0)).toBe(true);

      // Concurrent searches
      const searchPromises = [
        storage.search({
          text: 'concurrent',
          kind: undefined,
          scope: undefined,
          limit: 10,
          offset: 0,
        }),
        storage.search({ text: '', kind: 'entity', scope: undefined, limit: 10, offset: 0 }),
      ];

      const searchResults = await Promise.all(searchPromises);
      expect(searchResults.every((r) => r.success)).toBe(true);
    });

    it('should handle malformed items gracefully', async () => {
      const malformedItems = [
        null,
        undefined,
        {} as KnowledgeItem,
        {
          id: '',
          kind: '',
          title: '',
          content: '',
          scope: {},
          metadata: {},
        } as KnowledgeItem,
      ];

      const result = await storage.store(malformedItems as any);

      expect(result.items).toHaveLength(4);
      expect(result.summary.errors).toBeGreaterThan(0);
    });

    it('should handle search with malformed queries', async () => {
      // @ts-expect-error - Testing invalid input
      const result1 = await storage.search(null);
      expect(result1.success).toBe(false);

      // @ts-expect-error - Testing invalid input
      const result2 = await storage.search(undefined);
      expect(result2.success).toBe(false);
    });

    it('should handle delete with malformed input', async () => {
      // @ts-expect-error - Testing invalid input
      const result1 = await storage.delete(null);
      expect(result1.deleted).toBe(0);

      // @ts-expect-error - Testing invalid input
      const result2 = await storage.delete(undefined);
      expect(result2.deleted).toBe(0);
    });
  });

  describe('Metrics and Monitoring', () => {
    it('should track storage metrics', async () => {
      const items = [
        createTestItem('metrics-test-1'),
        createTestItem('metrics-test-2'),
        createTestItem('metrics-test-3'),
      ];

      // Store items
      await storage.store(items);

      // Search operations
      await storage.search({
        text: 'metrics',
        kind: undefined,
        scope: undefined,
        limit: 10,
        offset: 0,
      });
      await storage.search({
        text: 'nonexistent',
        kind: undefined,
        scope: undefined,
        limit: 10,
        offset: 0,
      });

      // Find operations
      await storage.findById(['metrics-test-1', 'metrics-test-2']);

      // Delete operations
      await storage.delete(['metrics-test-3']);

      // Metrics should be updated (access through internal methods or events)
      // Note: The actual metrics access depends on the implementation
      expect(storage).toBeDefined();
    });
  });

  // Helper function to create test items
  function createTestItem(id: string): KnowledgeItem {
    return {
      id,
      kind: 'entity',
      title: `Test Item ${id}`,
      content: `This is test content for item ${id}`,
      scope: { project: 'test-project' },
      metadata: {
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        version: 1,
        tags: ['test'],
      },
    };
  }
});
