// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck


/**
 * Comprehensive test suite for enhanced deduplication service
 * Tests all 5 merge strategies and scope window configuration
 */

import { beforeEach, describe, expect, it, jest } from '@jest/globals';

import type { DeduplicationConfig } from '../../../config/deduplication-config.js';
import type { KnowledgeItem } from '../../../types/core-interfaces.js';
import { EnhancedDeduplicationService } from '../enhanced-deduplication-service.js';

// Mock logger to avoid console output during tests
jest.mock('../../../utils/logger.js', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

// Mock qdrant client
jest.mock('../../../db/qdrant-client.js', () => ({
  qdrant: {
    client: {
      scroll: jest.fn(),
      search: jest.fn(),
    },
  },
}));

describe('Enhanced Deduplication Service', () => {
  let service: EnhancedDeduplicationService;
  let mockItems: KnowledgeItem[];

  beforeEach(() => {
    // Reset mocks
    jest.clearAllMocks();

    // Create service with test configuration
    const testConfig: Partial<DeduplicationConfig> = {
      enabled: true,
      contentSimilarityThreshold: 0.85,
      mergeStrategy: 'intelligent',
      checkWithinScopeOnly: true,
      crossScopeDeduplication: false,
      prioritizeSameScope: true,
      timeBasedDeduplication: true,
      dedupeWindowDays: 7,
      respectUpdateTimestamps: true,
      enableAuditLogging: true,
      preserveMergeHistory: true,
      maxItemsToCheck: 10,
    };

    service = new EnhancedDeduplicationService(testConfig);

    // Create test items
    mockItems = [
      {
        id: 'item-1',
        kind: 'decision',
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test Decision 1',
          rationale: 'This is a test decision rationale',
          content: 'Decision content for testing purposes',
        },
        created_at: '2025-01-01T00:00:00Z',
        updated_at: '2025-01-01T00:00:00Z',
      },
      {
        id: 'item-2',
        kind: 'decision',
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test Decision 2',
          rationale: 'This is a different test decision rationale',
          content: 'Different decision content for testing',
        },
        created_at: '2025-01-02T00:00:00Z',
        updated_at: '2025-01-02T00:00:00Z',
      },
      {
        id: 'item-3',
        kind: 'incident',
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test Incident',
          severity: 'medium',
          description: 'This is a test incident description',
        },
        created_at: '2025-01-03T00:00:00Z',
        updated_at: '2025-01-03T00:00:00Z',
      },
    ];
  });

  describe('Merge Strategy: skip', () => {
    beforeEach(() => {
      service.updateConfig({ mergeStrategy: 'skip' });
    });

    it('should skip duplicate items', async () => {
      // Mock exact match
      const mockExistingItem = {
        ...mockItems[0],
        id: 'existing-item-1',
      };

      jest.spyOn(service as unknown, 'findExactMatch').mockResolvedValue(mockExistingItem);
      jest.spyOn(service as unknown, 'findContentMatches').mockResolvedValue([]);

      const results = await service.processItems([mockItems[0]]);

      expect(results.results).toHaveLength(1);
      expect(results.results[0].action).toBe('skipped');
      expect(results.results[0].reason).toContain('skip');
    });

    it('should store non-duplicate items', async () => {
      // Mock no matches
      jest.spyOn(service as unknown, 'findExactMatch').mockResolvedValue(null);
      jest.spyOn(service as unknown, 'findContentMatches').mockResolvedValue([]);

      const results = await service.processItems([mockItems[0]]);

      expect(results.results).toHaveLength(1);
      expect(results.results[0].action).toBe('stored');
    });
  });

  describe('Merge Strategy: prefer_existing', () => {
    beforeEach(() => {
      service.updateConfig({ mergeStrategy: 'prefer_existing' });
    });

    it('should prefer existing items over new ones', async () => {
      const mockExistingItem = {
        ...mockItems[0],
        id: 'existing-item-1',
      };

      jest.spyOn(service as unknown, 'findExactMatch').mockResolvedValue(mockExistingItem);
      jest.spyOn(service as unknown, 'findContentMatches').mockResolvedValue([]);

      const results = await service.processItems([mockItems[0]]);

      expect(results.results).toHaveLength(1);
      expect(results.results[0].action).toBe('skipped');
      expect(results.results[0].reason).toContain('prefer_existing');
      expect(results.results[0].existingId).toBe('existing-item-1');
    });
  });

  describe('Merge Strategy: prefer_newer', () => {
    beforeEach(() => {
      service.updateConfig({ mergeStrategy: 'prefer_newer' });
    });

    it('should update when new item is newer', async () => {
      const oldExistingItem = {
        ...mockItems[0],
        id: 'existing-item-1',
        created_at: '2024-12-01T00:00:00Z', // Older than new item
        updated_at: '2024-12-01T00:00:00Z',
      };

      const newItem = {
        ...mockItems[0],
        created_at: '2025-01-01T00:00:00Z', // Newer
        updated_at: '2025-01-01T00:00:00Z',
      };

      jest.spyOn(service as unknown, 'findExactMatch').mockResolvedValue(oldExistingItem);
      jest.spyOn(service as unknown, 'findContentMatches').mockResolvedValue([]);

      const results = await service.processItems([newItem]);

      expect(results.results).toHaveLength(1);
      expect(results.results[0].action).toBe('updated');
      expect(results.results[0].reason).toContain('Replaced existing item with newer version');
    });

    it('should skip when new item is older', async () => {
      const existingItem = {
        ...mockItems[0],
        id: 'existing-item-1',
        created_at: '2025-01-02T00:00:00Z', // Newer than new item
        updated_at: '2025-01-02T00:00:00Z',
      };

      const oldNewItem = {
        ...mockItems[0],
        created_at: '2024-12-01T00:00:00Z', // Older
        updated_at: '2024-12-01T00:00:00Z',
      };

      jest.spyOn(service as unknown, 'findExactMatch').mockResolvedValue(existingItem);
      jest.spyOn(service as unknown, 'findContentMatches').mockResolvedValue([]);

      const results = await service.processItems([oldNewItem]);

      expect(results.results).toHaveLength(1);
      expect(results.results[0].action).toBe('skipped');
      expect(results.results[0].reason).toContain('Kept existing item (newer)');
    });
  });

  describe('Merge Strategy: combine', () => {
    beforeEach(() => {
      service.updateConfig({ mergeStrategy: 'combine' });
    });

    it('should merge items with combine strategy', async () => {
      const existingItem = {
        ...mockItems[0],
        id: 'existing-item-1',
        data: {
          title: 'Existing Title',
          rationale: 'Existing rationale',
          existingField: 'existing value',
        },
      };

      const newItem = {
        ...mockItems[0],
        data: {
          title: 'New Title',
          rationale: 'New rationale',
          newField: 'new value',
        },
      };

      jest.spyOn(service as unknown, 'findExactMatch').mockResolvedValue(existingItem);
      jest.spyOn(service as unknown, 'findContentMatches').mockResolvedValue([]);

      const results = await service.processItems([newItem]);

      expect(results.results).toHaveLength(1);
      expect(results.results[0].action).toBe('merged');
      expect(results.results[0].reason).toContain('Combined items');
      expect(results.results[0].mergeDetails?.strategy).toBe('combine');
    });
  });

  describe('Merge Strategy: intelligent', () => {
    beforeEach(() => {
      service.updateConfig({ mergeStrategy: 'intelligent' });
    });

    it('should intelligently decide to update newer items', async () => {
      const oldExistingItem = {
        ...mockItems[0],
        id: 'existing-item-1',
        created_at: '2024-12-01T00:00:00Z',
        data: {
          title: 'Short title',
          content: 'Brief content',
        },
      };

      const betterNewItem = {
        ...mockItems[0],
        created_at: '2025-01-01T00:00:00Z',
        data: {
          title: 'Much better and more descriptive title',
          content: 'Comprehensive and detailed content with much more information',
        },
      };

      jest.spyOn(service as unknown, 'findExactMatch').mockResolvedValue(oldExistingItem);
      jest.spyOn(service as unknown, 'findContentMatches').mockResolvedValue([]);

      const results = await service.processItems([betterNewItem]);

      expect(results.results).toHaveLength(1);
      expect(results.results[0].action).toBe('merged');
      expect(results.results[0].reason).toContain('Intelligently merged');
      expect(results.results[0].mergeDetails?.strategy).toBe('intelligent');
    });

    it("should prefer existing when it's better", async () => {
      const goodExistingItem = {
        ...mockItems[0],
        id: 'existing-item-1',
        created_at: '2024-12-01T00:00:00Z',
        data: {
          title: 'Comprehensive and detailed title',
          content: 'Extensive content with lots of details',
        },
      };

      const poorNewItem = {
        ...mockItems[0],
        created_at: '2025-01-01T00:00:00Z',
        data: {
          title: 'Short',
          content: 'Brief',
        },
      };

      jest.spyOn(service as unknown, 'findExactMatch').mockResolvedValue(goodExistingItem);
      jest.spyOn(service as unknown, 'findContentMatches').mockResolvedValue([]);

      const results = await service.processItems([poorNewItem]);

      expect(results.results).toHaveLength(1);
      expect(results.results[0].action).toBe('skipped');
      expect(results.results[0].reason).toContain('Existing item preferred');
    });
  });

  describe('Scope Window Configuration', () => {
    it('should respect scope matching', async () => {
      service.updateConfig({ checkWithinScopeOnly: true, prioritizeSameScope: true });

      const existingItem = {
        ...mockItems[0],
        id: 'existing-item-1',
        scope: { project: 'test-project', branch: 'main' }, // Same scope
      };

      const newItem = {
        ...mockItems[0],
        scope: { project: 'test-project', branch: 'main' }, // Same scope
      };

      jest.spyOn(service as unknown, 'findExactMatch').mockResolvedValue(existingItem);
      jest.spyOn(service as unknown, 'findContentMatches').mockResolvedValue([]);

      const results = await service.processItems([newItem]);

      expect(results.results).toHaveLength(1);
      // Should find the match due to same scope
      expect(results.results[0].existingId).toBe('existing-item-1');
    });

    it('should handle cross-scope deduplication', async () => {
      service.updateConfig({
        checkWithinScopeOnly: false,
        crossScopeDeduplication: true,
      });

      const existingItem = {
        ...mockItems[0],
        id: 'existing-item-1',
        scope: { project: 'different-project', branch: 'feature' }, // Different scope
      };

      const newItem = {
        ...mockItems[0],
        scope: { project: 'test-project', branch: 'main' }, // Different scope
      };

      jest.spyOn(service as unknown, 'findExactMatch').mockResolvedValue(existingItem);
      jest.spyOn(service as unknown, 'findContentMatches').mockResolvedValue([]);

      const results = await service.processItems([newItem]);

      expect(results.results).toHaveLength(1);
      // Should still find the match due to cross-scope deduplication
      expect(results.results[0].existingId).toBe('existing-item-1');
    });
  });

  describe('Time-based Deduplication', () => {
    it('should respect deduplication window', async () => {
      service.updateConfig({
        timeBasedDeduplication: true,
        dedupeWindowDays: 7,
      });

      const oldExistingItem = {
        ...mockItems[0],
        id: 'existing-item-1',
        created_at: '2024-12-01T00:00:00Z', // More than 7 days ago
        updated_at: '2024-12-01T00:00:00Z',
      };

      const newItem = {
        ...mockItems[0],
        created_at: '2025-01-08T00:00:00Z', // More than 7 days after existing
        updated_at: '2025-01-08T00:00:00Z',
      };

      jest.spyOn(service as unknown, 'findExactMatch').mockResolvedValue(oldExistingItem);
      jest.spyOn(service as unknown, 'findContentMatches').mockResolvedValue([]);

      const results = await service.processItems([newItem]);

      expect(results.results).toHaveLength(1);
      // Should not be considered duplicate due to being outside deduplication window
      expect(results.results[0].action).toBe('stored');
    });

    it('should allow deduplication within window', async () => {
      service.updateConfig({
        timeBasedDeduplication: true,
        dedupeWindowDays: 7,
      });

      const recentExistingItem = {
        ...mockItems[0],
        id: 'existing-item-1',
        created_at: '2025-01-05T00:00:00Z', // Within 7 days
        updated_at: '2025-01-05T00:00:00Z',
      };

      const newItem = {
        ...mockItems[0],
        created_at: '2025-01-08T00:00:00Z', // Within 7 days of existing
        updated_at: '2025-01-08T00:00:00Z',
      };

      jest.spyOn(service as unknown, 'findExactMatch').mockResolvedValue(recentExistingItem);
      jest.spyOn(service as unknown, 'findContentMatches').mockResolvedValue([]);

      const results = await service.processItems([newItem]);

      expect(results.results).toHaveLength(1);
      // Should be considered duplicate due to being within deduplication window
      expect(results.results[0].existingId).toBe('existing-item-1');
    });
  });

  describe('Content Similarity Threshold', () => {
    it('should not deduplicate below similarity threshold', async () => {
      service.updateConfig({ contentSimilarityThreshold: 0.9 });

      const dissimilarItem = {
        ...mockItems[0],
        id: 'existing-item-1',
        data: {
          title: 'Completely Different Title',
          content: 'Totally different content that should not match',
        },
      };

      jest.spyOn(service as unknown, 'findExactMatch').mockResolvedValue(null);
      jest.spyOn(service as unknown, 'findContentMatches').mockResolvedValue([
        {
          item: dissimilarItem,
          similarity: 0.8, // Below threshold
          matchType: 'content' as const,
        },
      ]);

      const results = await service.processItems([mockItems[0]]);

      expect(results.results).toHaveLength(1);
      expect(results.results[0].action).toBe('stored'); // Should store as new
    });

    it('should deduplicate above similarity threshold', async () => {
      service.updateConfig({ contentSimilarityThreshold: 0.7 });

      const similarItem = {
        ...mockItems[0],
        id: 'existing-item-1',
        data: {
          title: 'Test Decision 1',
          content: 'Decision content for testing purposes',
        },
      };

      jest.spyOn(service as unknown, 'findExactMatch').mockResolvedValue(null);
      jest.spyOn(service as unknown, 'findContentMatches').mockResolvedValue([
        {
          item: similarItem,
          similarity: 0.8, // Above threshold
          matchType: 'content' as const,
        },
      ]);

      const results = await service.processItems([mockItems[0]]);

      expect(results.results).toHaveLength(1);
      expect(results.results[0].existingId).toBe('existing-item-1');
    });
  });

  describe('Audit Logging', () => {
    it('should log audit entries when enabled', async () => {
      service.updateConfig({ enableAuditLogging: true });

      jest.spyOn(service as unknown, 'findExactMatch').mockResolvedValue(null);
      jest.spyOn(service as unknown, 'findContentMatches').mockResolvedValue([]);

      const results = await service.processItems([mockItems[0]]);

      expect(results.auditLog).toHaveLength(1);
      expect(results.auditLog[0]).toHaveProperty('timestamp');
      expect(results.auditLog[0]).toHaveProperty('itemId');
      expect(results.auditLog[0]).toHaveProperty('action');
      expect(results.auditLog[0]).toHaveProperty('similarityScore');
      expect(results.auditLog[0]).toHaveProperty('strategy');
    });

    it('should not log audit entries when disabled', async () => {
      service.updateConfig({ enableAuditLogging: false });

      jest.spyOn(service as unknown, 'findExactMatch').mockResolvedValue(null);
      jest.spyOn(service as unknown, 'findContentMatches').mockResolvedValue([]);

      const results = await service.processItems([mockItems[0]]);

      expect(results.auditLog).toHaveLength(0);
    });
  });

  describe('Configuration Management', () => {
    it('should update configuration', () => {
      const newConfig = {
        mergeStrategy: 'skip' as const,
        contentSimilarityThreshold: 0.9,
        enableAuditLogging: false,
      };

      service.updateConfig(newConfig);
      const updatedConfig = service.getConfig();

      expect(updatedConfig.mergeStrategy).toBe('skip');
      expect(updatedConfig.contentSimilarityThreshold).toBe(0.9);
      expect(updatedConfig.enableAuditLogging).toBe(false);
    });

    it('should get current configuration', () => {
      const config = service.getConfig();

      expect(config).toHaveProperty('enabled');
      expect(config).toHaveProperty('mergeStrategy');
      expect(config).toHaveProperty('contentSimilarityThreshold');
      expect(config).toHaveProperty('scopeFilters');
    });
  });

  describe('Performance Metrics', () => {
    it('should track performance metrics', async () => {
      jest.spyOn(service as unknown, 'findExactMatch').mockResolvedValue(null);
      jest.spyOn(service as unknown, 'findContentMatches').mockResolvedValue([]);

      await service.processItems(mockItems);

      const metrics = service.getPerformanceMetrics();

      expect(metrics.totalProcessed).toBe(mockItems.length);
      expect(metrics).toHaveProperty('duplicatesFound');
      expect(metrics).toHaveProperty('mergesPerformed');
      expect(metrics).toHaveProperty('avgProcessingTime');
    });
  });

  describe('Error Handling', () => {
    it('should handle errors gracefully', async () => {
      const error = new Error('Database error');
      jest.spyOn(service as unknown, 'findExactMatch').mockRejectedValue(error);

      const results = await service.processItems([mockItems[0]]);

      expect(results.results).toHaveLength(1);
      expect(results.results[0].action).toBe('skipped');
      expect(results.results[0].reason).toContain('Error processing item');
    });

    it('should continue processing batch when individual items fail', async () => {
      jest
        .spyOn(service as unknown, 'findExactMatch')
        .mockRejectedValueOnce(new Error('First item error'))
        .mockResolvedValueOnce(null);

      const results = await service.processItems(mockItems);

      expect(results.results).toHaveLength(mockItems.length);
      expect(results.results[0].action).toBe('skipped'); // Failed item
      expect(results.results[1].action).toBe('stored'); // Successful item
    });
  });

  describe('Merge History', () => {
    it('should preserve merge history when enabled', async () => {
      service.updateConfig({
        mergeStrategy: 'combine',
        preserveMergeHistory: true,
        maxMergeHistoryEntries: 5,
      });

      const existingItem = {
        ...mockItems[0],
        id: 'existing-item-1',
        metadata: {
          merge_history: [
            {
              timestamp: '2025-01-01T00:00:00Z',
              similarity: 0.9,
              merged_from: 'item-abc',
              strategy: 'combine',
            },
          ],
        },
      };

      jest.spyOn(service as unknown, 'findExactMatch').mockResolvedValue(existingItem);
      jest.spyOn(service as unknown, 'findContentMatches').mockResolvedValue([]);

      const results = await service.processItems([mockItems[0]]);

      expect(results.results).toHaveLength(1);
      expect(results.results[0].action).toBe('merged');
    });
  });
});
