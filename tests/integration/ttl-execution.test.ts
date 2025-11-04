/**
 * TTL Policy Execution Tests
 *
 * Tests TTL (Time To Live) policy execution with real cleanup verification:
 * - TTL configuration and policy application
 * - Automatic expiration and cleanup
 * - TTL policy enforcement across different item types
 * - Cleanup job execution and verification
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { MemoryStoreManager } from '../../src/memory-store-manager.js';
import { CleanupWorkerService } from '../../src/services/cleanup-worker.service.js';
import type { MemoryStoreResponse, TTLConfig } from '../../src/types/core-interfaces.js';

// Mock time utilities for testing
const mockTime = vi.hoisted(() => ({
  currentTime: Date.now(),
  advanceTime: (ms: number) => {
    mockTime.currentTime += ms;
    vi.setSystemTime(mockTime.currentTime);
  },
}));

vi.mock('node:crypto', async () => {
  const actual = await vi.importActual('node:crypto');
  return {
    ...actual,
    randomUUID: () => `test-uuid-${mockTime.currentTime}`,
  };
});

describe('TTL Policy Execution', () => {
  let memoryStore: MemoryStoreManager;
  let cleanupService: CleanupWorkerService;
  let testItems: Array<{
    id: string;
    content: string;
    kind: string;
    scope?: Record<string, string>;
    ttl_config?: TTLConfig;
  }>;

  beforeEach(async () => {
    // Reset time
    mockTime.currentTime = Date.now();
    vi.setSystemTime(mockTime.currentTime);

    // Initialize memory store with TTL enabled
    memoryStore = new MemoryStoreManager({
      vector: {
        provider: 'qdrant',
        connectionString: process.env.QDRANT_CONNECTION_STRING || 'localhost:6333',
      },
      ttl: {
        enabled: true,
        defaultPolicy: 'default',
        policies: {
          default: {
            policy: 'default',
            expires_at: new Date(mockTime.currentTime + 24 * 60 * 60 * 1000), // 24 hours
          },
          short: {
            policy: 'short',
            expires_at: new Date(mockTime.currentTime + 60 * 60 * 1000), // 1 hour
          },
          long: {
            policy: 'long',
            expires_at: new Date(mockTime.currentTime + 7 * 24 * 60 * 60 * 1000), // 7 days
          },
          session: {
            policy: 'session',
            expires_at: new Date(mockTime.currentTime + 30 * 60 * 1000), // 30 minutes
          },
        },
        cleanup: {
          enabled: true,
          interval: 5 * 60 * 1000, // 5 minutes
          batchSize: 100,
        },
      },
    });

    await memoryStore.initialize();

    // Initialize cleanup service
    cleanupService = new CleanupWorkerService(memoryStore, {
      enabled: true,
      interval: 1000, // 1 second for testing
      dryRun: false,
      batchSize: 10,
    });

    // Create test items with different TTL policies
    testItems = [
      {
        id: 'item-default-ttl',
        content: 'Item with default TTL policy',
        kind: 'observation',
        ttl_config: {
          policy: 'default',
          expires_at: new Date(mockTime.currentTime + 24 * 60 * 60 * 1000),
        },
      },
      {
        id: 'item-short-ttl',
        content: 'Item with short TTL policy',
        kind: 'observation',
        ttl_config: {
          policy: 'short',
          expires_at: new Date(mockTime.currentTime + 60 * 60 * 1000),
        },
      },
      {
        id: 'item-long-ttl',
        content: 'Item with long TTL policy',
        kind: 'entity',
        ttl_config: {
          policy: 'long',
          expires_at: new Date(mockTime.currentTime + 7 * 24 * 60 * 60 * 1000),
        },
      },
      {
        id: 'item-session-ttl',
        content: 'Item with session TTL policy',
        kind: 'todo',
        ttl_config: {
          policy: 'session',
          expires_at: new Date(mockTime.currentTime + 30 * 60 * 1000),
        },
      },
      {
        id: 'item-custom-ttl',
        content: 'Item with custom expiration time',
        kind: 'decision',
        ttl_config: {
          policy: 'default',
          expires_at: new Date(mockTime.currentTime + 2 * 60 * 60 * 1000), // 2 hours
        },
      },
      {
        id: 'item-no-ttl',
        content: 'Item without TTL configuration',
        kind: 'observation',
        // No ttl_config - should use default
      },
    ];

    // Store test items
    const storeResult = await memoryStore.store(testItems);
    expect(storeResult.success).toBe(true);
  });

  afterEach(async () => {
    if (cleanupService) {
      await cleanupService.stop();
    }
    if (memoryStore) {
      await memoryStore.shutdown();
    }
    vi.useRealTimers();
  });

  describe('TTL Configuration and Application', () => {
    it('should apply TTL policies correctly during storage', async () => {
      // Verify items were stored with TTL metadata
      for (const item of testItems) {
        const result = await memoryStore.find({
          query: item.id,
          types: [item.kind],
          limit: 1,
        });

        expect(result.success).toBe(true);
        expect(result.items).toHaveLength(1);

        const storedItem = result.items[0];
        expect(storedItem.metadata?.ttl_policy).toBeDefined();

        if (item.ttl_config) {
          expect(storedItem.metadata?.ttl_policy).toBe(item.ttl_config.policy);
          expect(storedItem.metadata?.expires_at).toBeDefined();
        } else {
          // Should use default policy
          expect(storedItem.metadata?.ttl_policy).toBe('default');
        }
      }
    });

    it('should store TTL metadata with correct expiration times', async () => {
      const shortTTLItem = testItems.find(item => item.id === 'item-short-ttl')!;
      const result = await memoryStore.find({
        query: shortTTLItem.id,
        types: ['observation'],
        limit: 1,
      });

      expect(result.success).toBe(true);
      const storedItem = result.items[0];

      const expectedExpiration = new Date(mockTime.currentTime + 60 * 60 * 1000);
      const actualExpiration = new Date(storedItem.metadata?.expires_at);

      // Allow small time difference (within 1 second)
      const timeDiff = Math.abs(actualExpiration.getTime() - expectedExpiration.getTime());
      expect(timeDiff).toBeLessThan(1000);

      expect(storedItem.metadata?.ttl_policy).toBe('short');
    });

    it('should handle items without explicit TTL configuration', async () => {
      const noTTLItem = testItems.find(item => item.id === 'item-no-ttl')!;
      const result = await memoryStore.find({
        query: noTTLItem.id,
        types: ['observation'],
        limit: 1,
      });

      expect(result.success).toBe(true);
      const storedItem = result.items[0];

      // Should apply default TTL policy
      expect(storedItem.metadata?.ttl_policy).toBe('default');
      expect(storedItem.metadata?.expires_at).toBeDefined();

      const expectedExpiration = new Date(mockTime.currentTime + 24 * 60 * 60 * 1000);
      const actualExpiration = new Date(storedItem.metadata?.expires_at);
      const timeDiff = Math.abs(actualExpiration.getTime() - expectedExpiration.getTime());
      expect(timeDiff).toBeLessThan(1000);
    });
  });

  describe('Automatic Expiration and Cleanup', () => {
    it('should not return expired items in search results', async () => {
      // Fast forward time to expire short TTL item
      mockTime.advanceTime(61 * 60 * 1000); // 61 minutes

      // Try to find the expired short TTL item
      const result = await memoryStore.find({
        query: 'item-short-ttl',
        types: ['observation'],
        limit: 5,
      });

      // Should not find the expired item
      expect(result.success).toBe(true);
      const expiredItem = result.items.find(item => item.id === 'item-short-ttl');
      expect(expiredItem).toBeUndefined();

      // Should still find non-expired items
      const nonExpiredItem = result.items.find(item => item.id === 'item-no-ttl');
      expect(nonExpiredItem).toBeDefined();
    });

    it('should perform automatic cleanup of expired items', async () => {
      // Start cleanup service
      await cleanupService.start();

      // Fast forward time to expire session TTL item
      mockTime.advanceTime(31 * 60 * 1000); // 31 minutes

      // Wait for cleanup cycle (plus small buffer)
      await new Promise(resolve => setTimeout(resolve, 1500));

      // Verify expired item is cleaned up
      const result = await memoryStore.find({
        query: 'item-session-ttl',
        types: ['todo'],
        limit: 5,
      });

      expect(result.success).toBe(true);
      expect(result.items).toHaveLength(0);

      // Verify cleanup metrics
      const cleanupMetrics = cleanupService.getMetrics();
      expect(cleanupMetrics.itemsCleaned).toBeGreaterThan(0);
      expect(cleanupMetrics.lastCleanupTime).toBeGreaterThan(0);
    });

    it('should handle bulk cleanup of multiple expired items', async () => {
      // Start cleanup service
      await cleanupService.start();

      // Fast forward time to expire multiple items
      mockTime.advanceTime(2 * 60 * 60 * 1000 + 1000); // Just over 2 hours

      // Wait for cleanup cycle
      await new Promise(resolve => setTimeout(resolve, 1500));

      // Check which items should be cleaned up
      const remainingItems = await memoryStore.find({
        query: 'item-',
        types: ['observation', 'entity', 'todo', 'decision'],
        limit: 10,
      });

      // Should have cleaned up: item-short-ttl, item-session-ttl, item-custom-ttl
      // Should still have: item-default-ttl, item-long-ttl, item-no-ttl
      const expectedRemainingIds = [
        'item-default-ttl',
        'item-long-ttl',
        'item-no-ttl',
      ];

      expect(remainingItems.success).toBe(true);
      expect(remainingItems.items).toHaveLength(expectedRemainingIds.length);

      remainingItems.items.forEach(item => {
        expect(expectedRemainingIds).toContain(item.id);
      });

      // Verify cleanup metrics
      const cleanupMetrics = cleanupService.getMetrics();
      expect(cleanupMetrics.itemsCleaned).toBeGreaterThanOrEqual(3);
    });
  });

  describe('TTL Policy Enforcement', () => {
    it('should enforce TTL policies across different item types', async () => {
      // Create items of different types with specific TTL policies
      const multiTypeItems = [
        {
          id: 'entity-short',
          content: 'Entity with short TTL',
          kind: 'entity' as const,
          ttl_config: { policy: 'short' as const, expires_at: new Date(mockTime.currentTime + 60 * 60 * 1000) },
        },
        {
          id: 'relation-session',
          content: 'Relation with session TTL',
          kind: 'relation' as const,
          ttl_config: { policy: 'session' as const, expires_at: new Date(mockTime.currentTime + 30 * 60 * 1000) },
        },
        {
          id: 'runbook-long',
          content: 'Runbook with long TTL',
          kind: 'runbook' as const,
          ttl_config: { policy: 'long' as const, expires_at: new Date(mockTime.currentTime + 7 * 24 * 60 * 60 * 1000) },
        },
      ];

      await memoryStore.store(multiTypeItems);

      // Fast forward time to expire short and session items
      mockTime.advanceTime(31 * 60 * 1000); // 31 minutes

      // Check each type
      for (const item of multiTypeItems) {
        const result = await memoryStore.find({
          query: item.id,
          types: [item.kind],
          limit: 1,
        });

        if (item.ttl_config.policy === 'long') {
          // Long TTL item should still exist
          expect(result.success).toBe(true);
          expect(result.items).toHaveLength(1);
          expect(result.items[0].id).toBe(item.id);
        } else {
          // Short and session TTL items should be expired
          expect(result.success).toBe(true);
          expect(result.items).toHaveLength(0);
        }
      }
    });

    it('should handle TTL policy updates and extensions', async () => {
      const item = testItems.find(i => i.id === 'item-default-ttl')!;

      // Initially item should exist
      let result = await memoryStore.find({
        query: item.id,
        types: [item.kind],
        limit: 1,
      });
      expect(result.success).toBe(true);
      expect(result.items).toHaveLength(1);

      // Update the item with extended TTL
      const updatedItem = {
        ...result.items[0],
        metadata: {
          ...result.items[0].metadata,
          ttl_policy: 'long',
          expires_at: new Date(mockTime.currentTime + 7 * 24 * 60 * 60 * 1000),
        },
      };

      await memoryStore.update([updatedItem]);

      // Fast forward past original default TTL but within extended TTL
      mockTime.advanceTime(25 * 60 * 60 * 1000); // 25 hours

      // Item should still exist due to extended TTL
      result = await memoryStore.find({
        query: item.id,
        types: [item.kind],
        limit: 1,
      });
      expect(result.success).toBe(true);
      expect(result.items).toHaveLength(1);
      expect(result.items[0].metadata?.ttl_policy).toBe('long');
    });

    it('should respect manual TTL overrides', async () => {
      // Create item with manual TTL override
      const manualOverrideItem = {
        id: 'manual-override',
        content: 'Item with manual TTL override',
        kind: 'observation' as const,
        ttl_config: {
          policy: 'default' as const,
          expires_at: new Date(mockTime.currentTime + 5 * 60 * 1000), // 5 minutes
          auto_extend: false, // Manual override - no auto extension
        },
      };

      await memoryStore.store([manualOverrideItem]);

      // Verify item exists initially
      let result = await memoryStore.find({
        query: manualOverrideItem.id,
        types: ['observation'],
        limit: 1,
      });
      expect(result.success).toBe(true);
      expect(result.items).toHaveLength(1);

      // Fast forward past TTL
      mockTime.advanceTime(6 * 60 * 1000); // 6 minutes

      // Item should be expired and not returned
      result = await memoryStore.find({
        query: manualOverrideItem.id,
        types: ['observation'],
        limit: 1,
      });
      expect(result.success).toBe(true);
      expect(result.items).toHaveLength(0);
    });
  });

  describe('Cleanup Job Execution', () => {
    it('should execute cleanup jobs at configured intervals', async () => {
      const cleanupSpy = vi.spyOn(cleanupService, 'performCleanup');

      await cleanupService.start();

      // Wait for multiple cleanup cycles
      await new Promise(resolve => setTimeout(resolve, 3500)); // ~3.5 seconds for ~3 cycles

      expect(cleanupSpy).toHaveBeenCalledTimes(3); // Should have run ~3 times

      const metrics = cleanupService.getMetrics();
      expect(metrics.cleanupCount).toBeGreaterThanOrEqual(3);
      expect(metrics.lastCleanupTime).toBeGreaterThan(0);
    });

    it('should handle cleanup errors gracefully', async () => {
      // Mock a cleanup error
      const originalCleanup = cleanupService.performCleanup.bind(cleanupService);
      vi.spyOn(cleanupService, 'performCleanup').mockImplementation(async () => {
        // First call succeeds, second fails
        if (cleanupService.getMetrics().cleanupCount === 0) {
          return await originalCleanup();
        } else {
          throw new Error('Simulated cleanup error');
        }
      });

      await cleanupService.start();

      // Wait for cleanup cycles
      await new Promise(resolve => setTimeout(resolve, 2500));

      const metrics = cleanupService.getMetrics();
      expect(metrics.errorCount).toBeGreaterThan(0);
      expect(metrics.lastError).toBeDefined();

      // Service should still be running despite errors
      expect(cleanupService.isRunning()).toBe(true);
    });

    it('should provide detailed cleanup metrics', async () => {
      await cleanupService.start();

      // Fast forward time to ensure some items are expired
      mockTime.advanceTime(2 * 60 * 60 * 1000); // 2 hours

      // Wait for cleanup
      await new Promise(resolve => setTimeout(resolve, 1500));

      const metrics = cleanupService.getMetrics();

      expect(metrics).toMatchObject({
        cleanupCount: expect.any(Number),
        itemsCleaned: expect.any(Number),
        errorCount: expect.any(Number),
        lastCleanupTime: expect.any(Number),
        averageCleanupTime: expect.any(Number),
        totalItemsProcessed: expect.any(Number),
      });

      expect(metrics.cleanupCount).toBeGreaterThan(0);
      expect(metrics.lastCleanupTime).toBeGreaterThan(0);
      expect(metrics.averageCleanupTime).toBeGreaterThan(0);
    });

    it('should handle dry run mode correctly', async () => {
      const dryRunCleanupService = new CleanupWorkerService(memoryStore, {
        enabled: true,
        interval: 1000,
        dryRun: true, // Dry run mode
        batchSize: 10,
      });

      await dryRunCleanupService.start();

      // Fast forward time to expire items
      mockTime.advanceTime(31 * 60 * 1000); // 31 minutes

      // Wait for cleanup
      await new Promise(resolve => setTimeout(resolve, 1500));

      const metrics = dryRunCleanupService.getMetrics();

      // In dry run mode, items should be identified but not actually cleaned up
      expect(metrics.itemsIdentifiedForCleanup).toBeGreaterThan(0);
      expect(metrics.itemsCleaned).toBe(0); // No actual cleanup in dry run

      // Items should still exist in dry run mode
      const result = await memoryStore.find({
        query: 'item-session-ttl',
        types: ['todo'],
        limit: 5,
      });

      expect(result.success).toBe(true);
      expect(result.items.length).toBeGreaterThan(0);

      await dryRunCleanupService.stop();
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle large numbers of expired items efficiently', async () => {
      // Create many items with short TTL
      const largeBatch = Array.from({ length: 100 }, (_, i) => ({
        id: `bulk-item-${i}`,
        content: `Bulk item ${i} with short TTL`,
        kind: 'observation' as const,
        ttl_config: {
          policy: 'short' as const,
          expires_at: new Date(mockTime.currentTime + 60 * 1000), // 1 minute
        },
      }));

      await memoryStore.store(largeBatch);

      // Verify all items were stored
      const beforeCleanup = await memoryStore.find({
        query: 'bulk-item-',
        types: ['observation'],
        limit: 200,
      });
      expect(beforeCleanup.items).toHaveLength(100);

      // Start cleanup and fast forward time
      await cleanupService.start();
      mockTime.advanceTime(2 * 60 * 1000); // 2 minutes

      // Wait for cleanup
      await new Promise(resolve => setTimeout(resolve, 1500));

      // Verify cleanup was efficient
      const afterCleanup = await memoryStore.find({
        query: 'bulk-item-',
        types: ['observation'],
        limit: 200,
      });
      expect(afterCleanup.items).toHaveLength(0);

      const metrics = cleanupService.getMetrics();
      expect(metrics.itemsCleaned).toBeGreaterThanOrEqual(100);
      expect(metrics.averageCleanupTime).toBeLessThan(5000); // Should complete in under 5 seconds
    });

    it('should maintain performance during concurrent cleanup operations', async () => {
      await cleanupService.start();

      // Perform concurrent searches while cleanup runs
      const searchPromises = Array.from({ length: 20 }, (_, i) =>
        memoryStore.find({
          query: `search query ${i}`,
          types: ['observation'],
          limit: 5,
        })
      );

      // Fast forward time to trigger cleanup
      mockTime.advanceTime(31 * 60 * 1000);

      const searchResults = await Promise.all(searchPromises);

      // All searches should succeed despite cleanup running
      searchResults.forEach(result => {
        expect(result.success).toBe(true);
      });

      const metrics = cleanupService.getMetrics();
      expect(metrics.cleanupCount).toBeGreaterThan(0);
    });
  });
});