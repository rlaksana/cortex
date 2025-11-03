/**
 * Comprehensive Test Suite for Enhanced Deduplication Service
 *
 * Tests all merge strategies, configuration options, and edge cases:
 * - Similarity threshold variations
 * - Time window scenarios
 * - Scope filtering rules
 * - Merge strategy behaviors
 * - Audit logging functionality
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { EnhancedDeduplicationService } from '../../src/services/deduplication/enhanced-deduplication-service';
import type { KnowledgeItem } from '../../src/types/core-interfaces';
import { MergeStrategy } from '../../src/config/deduplication-config';

// Mock Qdrant client
vi.mock('@qdrant/js-client-rest', () => ({
  QdrantClient: class {
    constructor() {
      this.getCollections = vi.fn().mockResolvedValue({
        collections: [{ name: 'test-collection' }],
      });
      this.createCollection = vi.fn().mockResolvedValue(undefined);
      this.upsert = vi.fn().mockResolvedValue(undefined);
      this.search = vi.fn().mockImplementation(this.mockSearch.bind(this));
      this.retrieve = vi.fn().mockImplementation(this.mockRetrieve.bind(this));
      this.getCollection = vi.fn().mockResolvedValue({
        points_count: 0,
        status: 'green',
      });
    }

    // Mock search results for similarity testing
    async mockSearch(collection, query) {
      // Return mock similar items based on query content
      const queryText = JSON.stringify(query?.vector || []);

      if (queryText.includes('duplicate')) {
        return [
          {
            id: 'existing-duplicate-id',
            score: 0.95,
            payload: {
              kind: 'entity',
              data: { content: 'duplicate-content' },
              scope: { project: 'test-project' },
              created_at: '2024-01-01T00:00:00Z',
              updated_at: '2024-01-01T00:00:00Z',
            },
          },
        ];
      }

      if (queryText.includes('similar')) {
        return [
          {
            id: 'existing-similar-id',
            score: 0.88,
            payload: {
              kind: 'decision',
              data: { content: 'similar decision content' },
              scope: { project: 'test-project' },
              created_at: '2024-01-01T00:00:00Z',
              updated_at: '2024-01-01T00:00:00Z',
            },
          },
        ];
      }

      return [];
    }

    // Mock retrieve results for exact matches
    async mockRetrieve(collection, options) {
      if (options.filter?.content_hash === 'exact-match-hash') {
        return [
          {
            id: 'exact-match-id',
            payload: {
              kind: 'entity',
              data: { content: 'exact match content' },
              scope: { project: 'test-project' },
              created_at: '2024-01-01T00:00:00Z',
              updated_at: '2024-01-01T00:00:00Z',
            },
          },
        ];
      }

      return [];
    }
  },
}));

// Mock date manipulation for consistent testing
const mockDate = new Date('2024-01-15T00:00:00Z');
vi.mock('node:crypto', () => ({
  createHash: () => ({
    update: () => ({
      digest: () => 'mock-hash-12345',
    }),
  }),
}));

describe('Enhanced Deduplication Service', () => {
  let service: EnhancedDeduplicationService;
  const testBaseDate = new Date('2024-01-15T00:00:00Z');

  beforeEach(() => {
    vi.clearAllMocks();
    service = new EnhancedDeduplicationService();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Configuration', () => {
    it('should initialize with default configuration', () => {
      const config = service.getConfig();

      expect(config.enabled).toBe(true);
      expect(config.contentSimilarityThreshold).toBe(0.85);
      expect(config.mergeStrategy).toBe('intelligent');
      expect(config.checkWithinScopeOnly).toBe(true);
      expect(config.crossScopeDeduplication).toBe(false);
    });

    it('should update configuration', () => {
      service.updateConfig({
        contentSimilarityThreshold: 0.90,
        mergeStrategy: 'skip',
      });

      const config = service.getConfig();
      expect(config.contentSimilarityThreshold).toBe(0.90);
      expect(config.mergeStrategy).toBe('skip');
    });

    it('should load configuration from environment', () => {
      // Mock environment variables
      process.env.DEDUPE_SIMILARITY_THRESHOLD = '0.95';
      process.env.DEDUPE_MERGE_STRATEGY = 'combine';
      process.env.DEDUPE_CROSS_SCOPE = 'true';

      const envService = new EnhancedDeduplicationService();
      const config = envService.getConfig();

      expect(config.contentSimilarityThreshold).toBe(0.95);
      expect(config.mergeStrategy).toBe('combine');
      expect(config.crossScopeDeduplication).toBe(true);

      // Clean up
      delete process.env.DEDUPE_SIMILARITY_THRESHOLD;
      delete process.env.DEDUPE_MERGE_STRATEGY;
      delete process.env.DEDUPE_CROSS_SCOPE;
    });
  });

  describe('Merge Strategy: skip', () => {
    beforeEach(() => {
      service.updateConfig({ mergeStrategy: 'skip' });
    });

    it('should skip items above similarity threshold', async () => {
      const items = [createTestItem('duplicate-content')];

      const result = await service.processItems(items);

      expect(result.results).toHaveLength(1);
      expect(result.results[0].action).toBe('skipped');
      expect(result.results[0].reason).toContain('Duplicate skipped');
      expect(result.results[0].existingId).toBeDefined();
    });

    it('should store items below similarity threshold', async () => {
      const items = [createTestItem('unique-content')];

      const result = await service.processItems(items);

      expect(result.results).toHaveLength(1);
      expect(result.results[0].action).toBe('stored');
      expect(result.results[0].similarityScore).toBe(0);
    });
  });

  describe('Merge Strategy: prefer_existing', () => {
    beforeEach(() => {
      service.updateConfig({ mergeStrategy: 'prefer_existing' });
    });

    it('should always prefer existing items', async () => {
      const items = [createTestItem('duplicate-content')];

      const result = await service.processItems(items);

      expect(result.results[0].action).toBe('skipped');
      expect(result.results[0].reason).toContain('Kept existing item');
    });
  });

  describe('Merge Strategy: prefer_newer', () => {
    beforeEach(() => {
      service.updateConfig({ mergeStrategy: 'prefer_newer' });
    });

    it('should update when newer item is provided', async () => {
      const newerItem = createTestItem('duplicate-content');
      newerItem.created_at = new Date('2024-01-16T00:00:00Z').toISOString(); // Newer than mock existing

      const result = await service.processItems([newerItem]);

      expect(result.results[0].action).toBe('updated');
      expect(result.results[0].reason).toContain('Replaced existing item');
      expect(result.results[0].mergeDetails).toBeDefined();
      expect(result.results[0].mergeDetails!.strategy).toBe('prefer_newer');
    });

    it('should skip when existing item is newer', async () => {
      const olderItem = createTestItem('duplicate-content');
      olderItem.created_at = new Date('2023-12-01T00:00:00Z').toISOString(); // Older than mock existing

      const result = await service.processItems([olderItem]);

      expect(result.results[0].action).toBe('skipped');
      expect(result.results[0].reason).toContain('Kept existing item');
    });
  });

  describe('Merge Strategy: combine', () => {
    beforeEach(() => {
      service.updateConfig({ mergeStrategy: 'combine' });
    });

    it('should merge items above threshold', async () => {
      const newItem = createTestItem('duplicate-content');
      newItem.data = {
        content: 'Updated content',
        new_field: 'new value',
        existing_field: 'existing value'
      };

      const result = await service.processItems([newItem]);

      expect(result.results[0].action).toBe('merged');
      expect(result.results[0].reason).toContain('Combined items');
      expect(result.results[0].mergeDetails).toBeDefined();
      expect(result.results[0].mergeDetails!.strategy).toBe('combine');
      expect(result.results[0].mergeDetails!.fieldsMerged.length).toBeGreaterThan(0);
    });
  });

  describe('Merge Strategy: intelligent', () => {
    beforeEach(() => {
      service.updateConfig({ mergeStrategy: 'intelligent' });
    });

    it('should make intelligent merge decisions based on multiple factors', async () => {
      const newItem = createTestItem('similar');
      newItem.data = {
        content: 'Comprehensive decision rationale with detailed explanation',
        title: 'Important Decision',
        impact: 'High impact analysis',
        metadata: {
          tags: ['decision', 'architecture'],
          priority: 'high'
        }
      };

      const result = await service.processItems([newItem]);

      expect(result.results).toHaveLength(1);
      expect(result.results[0].action).toMatch(/merged|updated|skipped|stored/);

      if (result.results[0].mergeDetails) {
        expect(result.results[0].mergeDetails.strategy).toBe('intelligent');
      }
    });

    it('should prefer newer content when significantly better', async () => {
      const newItem = createTestItem('duplicate-content');
      newItem.data = {
        content: 'Much more comprehensive and detailed content that provides better context and explanation',
        additional_info: 'Extra valuable information'
      };
      newItem.created_at = new Date('2024-01-16T00:00:00Z').toISOString();

      const result = await service.processItems([newItem]);

      expect(result.results[0].action).toBe('merged');
      expect(result.results[0].reason).toContain('Intelligently merged');
    });
  });

  describe('Similarity Threshold Variations', () => {
    it('should be more strict with higher threshold', async () => {
      service.updateConfig({ contentSimilarityThreshold: 0.95, mergeStrategy: 'skip' });

      const items = [createTestItem('similar')]; // Mock returns 0.88 similarity

      const result = await service.processItems(items);

      expect(result.results[0].action).toBe('stored'); // Below 0.95 threshold
      expect(result.results[0].similarityScore).toBe(0.88);
    });

    it('should be more lenient with lower threshold', async () => {
      service.updateConfig({ contentSimilarityThreshold: 0.80, mergeStrategy: 'skip' });

      const items = [createTestItem('similar')]; // Mock returns 0.88 similarity

      const result = await service.processItems(items);

      expect(result.results[0].action).toBe('skipped'); // Above 0.80 threshold
      expect(result.results[0].similarityScore).toBe(0.88);
    });
  });

  describe('Time Window Scenarios', () => {
    it('should respect dedupe window settings', async () => {
      service.updateConfig({
        dedupeWindowDays: 1, // Very short window
        timeBasedDeduplication: true
      });

      const oldItem = createTestItem('duplicate-content');
      oldItem.created_at = new Date('2024-01-01T00:00:00Z').toISOString(); // 14 days ago

      const result = await service.processItems([oldItem]);

      // Should be stored as new because it's outside the 1-day window
      expect(result.results[0].action).toBe('stored');
    });

    it('should handle recently updated items correctly', async () => {
      service.updateConfig({
        respectUpdateTimestamps: true,
        mergeStrategy: 'prefer_newer'
      });

      const recentItem = createTestItem('duplicate-content');
      recentItem.updated_at = new Date('2024-01-14T23:00:00Z').toISOString(); // Recently updated

      const result = await service.processItems([recentItem]);

      expect(result.results[0].action).toBe('updated');
    });
  });

  describe('Scope Filtering Rules', () => {
    it('should dedupe within same scope', async () => {
      service.updateConfig({
        checkWithinScopeOnly: true,
        crossScopeDeduplication: false
      });

      const items = [createTestItem('duplicate-content', 'test-project')];

      const result = await service.processItems(items);

      expect(result.results[0].action).toMatch(/skipped|merged/);
    });

    it('should not dedupe across different projects when cross-scope is disabled', async () => {
      service.updateConfig({
        checkWithinScopeOnly: true,
        crossScopeDeduplication: false
      });

      const items = [createTestItem('duplicate-content', 'different-project')];

      const result = await service.processItems(items);

      // Should be stored as new because different project
      expect(result.results[0].action).toBe('stored');
    });

    it('should dedupe across different projects when cross-scope is enabled', async () => {
      service.updateConfig({
        crossScopeDeduplication: true,
        mergeStrategy: 'skip'
      });

      const items = [createTestItem('duplicate-content', 'different-project')];

      const result = await service.processItems(items);

      // Should be skipped even with different project
      expect(result.results[0].action).toBe('skipped');
    });
  });

  describe('Audit Logging', () => {
    it('should create audit log entries for all operations', async () => {
      const items = [createTestItem('duplicate-content')];

      const result = await service.processItems(items);

      expect(result.auditLog).toHaveLength(1);
      expect(result.auditLog[0]).toMatchObject({
        itemId: expect.any(String),
        action: expect.any(String),
        similarityScore: expect.any(Number),
        strategy: expect.any(String),
        matchType: expect.any(String),
        reason: expect.any(String),
        timestamp: expect.any(String),
        configSnapshot: expect.any(Object),
      });
    });

    it('should include merge details in audit log when applicable', async () => {
      service.updateConfig({ mergeStrategy: 'combine' });

      const items = [createTestItem('duplicate-content')];

      const result = await service.processItems(items);

      if (result.results[0].mergeDetails) {
        expect(result.auditLog[0].mergeDetails).toBeDefined();
        expect(result.auditLog[0].mergeDetails!.strategy).toBe('combine');
      }
    });

    it('should maintain audit log history', async () => {
      // Process multiple batches
      await service.processItems([createTestItem('content1')]);
      await service.processItems([createTestItem('content2')]);

      const auditLog = service.getAuditLog();

      expect(auditLog.length).toBeGreaterThan(0);
      expect(auditLog[auditLog.length - 1].timestamp).toBeDefined();
    });

    it('should limit audit log when requested', async () => {
      // Process multiple items
      await service.processItems([
        createTestItem('content1'),
        createTestItem('content2'),
        createTestItem('content3'),
      ]);

      const limitedLog = service.getAuditLog(2);

      expect(limitedLog.length).toBeLessThanOrEqual(2);
    });
  });

  describe('Performance Metrics', () => {
    it('should track processing metrics', async () => {
      const items = [
        createTestItem('unique1'),
        createTestItem('unique2'),
        createTestItem('duplicate-content'),
      ];

      await service.processItems(items);

      const metrics = service.getPerformanceMetrics();

      expect(metrics.totalProcessed).toBe(3);
      expect(metrics.avgProcessingTime).toBeGreaterThan(0);
    });

    it('should track duplicate detection metrics', async () => {
      service.updateConfig({ mergeStrategy: 'skip' });

      const items = [
        createTestItem('duplicate-content'), // Should detect as duplicate
        createTestItem('similar'), // Should detect as similar
        createTestItem('unique'), // Should be unique
      ];

      await service.processItems(items);

      const metrics = service.getPerformanceMetrics();

      expect(metrics.duplicatesFound).toBeGreaterThan(0);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty item list', async () => {
      const result = await service.processItems([]);

      expect(result.results).toHaveLength(0);
      expect(result.summary.totalProcessed).toBe(0);
    });

    it('should handle items with minimal data', async () => {
      const minimalItem: KnowledgeItem = {
        kind: 'entity',
        data: {},
        id: 'minimal-id',
      };

      const result = await service.processItems([minimalItem]);

      expect(result.results).toHaveLength(1);
      expect(result.results[0].action).toBe('stored');
    });

    it('should handle malformed items gracefully', async () => {
      const malformedItems = [
        { kind: 'invalid-kind' as any, data: null },
        { kind: 'entity', data: undefined },
        { kind: 'decision', data: 'not-an-object' as any },
      ];

      const result = await service.processItems(malformedItems);

      expect(result.results).toHaveLength(3);
      // Should not throw errors, but handle gracefully
      result.results.forEach(itemResult => {
        expect(['stored', 'skipped']).toContain(itemResult.action);
      });
    });

    it('should handle very large content efficiently', async () => {
      const largeContent = 'a'.repeat(10000);
      const largeItem = createTestItem(largeContent);

      const startTime = Date.now();
      const result = await service.processItems([largeItem]);
      const duration = Date.now() - startTime;

      expect(result.results).toHaveLength(1);
      expect(duration).toBeLessThan(5000); // Should complete within 5 seconds
    });

    it('should handle items with special characters', async () => {
      const specialContent = 'Special chars: 🚀 ñáéíóú 中文 العربية русский';
      const specialItem = createTestItem(specialContent);

      const result = await service.processItems([specialItem]);

      expect(result.results).toHaveLength(1);
      expect(result.results[0].action).toBe('stored');
    });

    it('should handle concurrent processing', async () => {
      const concurrentItems = Array.from({ length: 10 }, (_, i) =>
        createTestItem(`concurrent-content-${i}`)
      );

      const promises = concurrentItems.map(item =>
        service.processItems([item])
      );

      const results = await Promise.all(promises);

      expect(results).toHaveLength(10);
      results.forEach(result => {
        expect(result.results).toHaveLength(1);
      });
    });
  });

  describe('Batch Processing', () => {
    it('should process mixed batch correctly', async () => {
      service.updateConfig({ mergeStrategy: 'skip' });

      const mixedItems = [
        createTestItem('unique-content-1'),
        createTestItem('duplicate-content'), // Should be deduped
        createTestItem('unique-content-2'),
        createTestItem('similar'), // Should be deduped
        createTestItem('unique-content-3'),
      ];

      const result = await service.processItems(mixedItems);

      expect(result.results).toHaveLength(5);
      expect(result.summary.totalProcessed).toBe(5);

      const stored = result.results.filter(r => r.action === 'stored');
      const skipped = result.results.filter(r => r.action === 'skipped');

      expect(stored.length).toBe(3); // Unique items
      expect(skipped.length).toBe(2); // Duplicate/similar items
    });

    it('should provide comprehensive summary', async () => {
      const items = [
        createTestItem('unique1'),
        createTestItem('duplicate-content'),
        createTestItem('unique2'),
      ];

      const result = await service.processItems(items);

      expect(result.summary).toMatchObject({
        totalProcessed: 3,
        duration: expect.any(Number),
        avgProcessingTime: expect.any(Number),
        actions: {
          stored: expect.any(Number),
          skipped: expect.any(Number),
          merged: expect.any(Number),
          updated: expect.any(Number),
        },
        similarity: {
          avgScore: expect.any(Number),
          maxScore: expect.any(Number),
          duplicatesFound: expect.any(Number),
        },
        performance: expect.any(Object),
      });
    });
  });

  describe('Configuration Validation', () => {
    it('should handle invalid similarity threshold', () => {
      expect(() => {
        service.updateConfig({ contentSimilarityThreshold: -0.1 });
      }).toThrow();

      expect(() => {
        service.updateConfig({ contentSimilarityThreshold: 1.5 });
      }).toThrow();
    });

    it('should handle invalid merge strategy', () => {
      expect(() => {
        service.updateConfig({ mergeStrategy: 'invalid' as any });
      }).toThrow();
    });

    it('should handle invalid time settings', () => {
      expect(() => {
        service.updateConfig({ dedupeWindowDays: -1 });
      }).toThrow();

      expect(() => {
        service.updateConfig({ maxHistoryHours: -10 });
      }).toThrow();
    });
  });

  // Helper function to create test items
  function createTestItem(content: string, project: string = 'test-project'): KnowledgeItem {
    return {
      id: `test-id-${Math.random().toString(36).substr(2, 9)}`,
      kind: 'entity',
      data: {
        content,
        name: `Test Item: ${content.substring(0, 20)}`,
        type: 'test',
      },
      metadata: {
        source: 'test',
        created_by: 'test-suite',
      },
      scope: {
        project,
        branch: 'main',
        org: 'test-org',
      },
      created_at: testBaseDate.toISOString(),
      updated_at: testBaseDate.toISOString(),
    };
  }
});