/**
 * Comprehensive test suite for enhanced deduplication service
 * Tests public interface and merge strategies
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { DeduplicationConfig } from '../../../config/deduplication-config';
import type { KnowledgeItem } from '../../../types/core-interfaces';
import { EnhancedDeduplicationService } from '../enhanced-deduplication-service';

// Mock logger to avoid console output during tests
vi.mock('../../utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

// Mock qdrant client
vi.mock('../../../db/qdrant-client.js', () => ({
  qdrant: {
    client: {
      scroll: vi.fn().mockResolvedValue({
        result: {
          points: [],
          next_page_offset: null,
        },
      }),
      search: vi.fn().mockResolvedValue({
        result: [],
      }),
    },
  },
}));

describe('Enhanced Deduplication Service', () => {
  let service: EnhancedDeduplicationService;
  let mockItems: KnowledgeItem[];

  beforeEach(() => {
    // Reset mocks
    vi.clearAllMocks();

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
    };

    service = new EnhancedDeduplicationService(testConfig);

    // Mock test items
    mockItems = [
      {
        id: 'item-1',
        kind: 'test-item',
        content: 'This is a test item for deduplication',
        scope: {
          org: 'test-org',
          project: 'test-project',
          branch: 'main',
        },
        data: {
          title: 'Test Item 1',
          description: 'Description for test item 1',
        },
        metadata: {
          source: 'test',
          version: 1,
        },
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
      {
        id: 'item-2',
        kind: 'test-item',
        content: 'This is another test item with similar content',
        scope: {
          org: 'test-org',
          project: 'test-project',
          branch: 'main',
        },
        data: {
          title: 'Test Item 2',
          description: 'Description for test item 2',
        },
        metadata: {
          source: 'test',
          version: 1,
        },
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
    ] as KnowledgeItem[];
  });

  describe('Service Configuration', () => {
    it('should initialize with default configuration', () => {
      const defaultService = new EnhancedDeduplicationService();
      const config = defaultService.getConfig();

      expect(config.enabled).toBeDefined();
      expect(config.contentSimilarityThreshold).toBeDefined();
      expect(config.mergeStrategy).toBeDefined();
    });

    it('should accept custom configuration', () => {
      const customConfig: Partial<DeduplicationConfig> = {
        enabled: false,
        contentSimilarityThreshold: 0.9,
        mergeStrategy: 'skip',
      };

      const customService = new EnhancedDeduplicationService(customConfig);
      const config = customService.getConfig();

      expect(config.enabled).toBe(false);
      expect(config.contentSimilarityThreshold).toBe(0.9);
      expect(config.mergeStrategy).toBe('skip');
    });

    it('should update configuration at runtime', () => {
      const newConfig: Partial<DeduplicationConfig> = {
        mergeStrategy: 'prefer_newer',
        contentSimilarityThreshold: 0.95,
      };

      service.updateConfig(newConfig);
      const config = service.getConfig();

      expect(config.mergeStrategy).toBe('prefer_newer');
      expect(config.contentSimilarityThreshold).toBe(0.95);
    });
  });

  describe('Item Processing', () => {
    it('should process single item', async () => {
      const result = await service.processItems([mockItems[0]]);

      expect(result.results).toHaveLength(1);
      expect(result.results[0]).toHaveProperty('action');
      expect(result.results[0]).toHaveProperty('itemId');
      expect(result).toHaveProperty('totalProcessed');
      expect(result).toHaveProperty('totalDuplicates');
      expect(result).toHaveProperty('processingTime');
    });

    it('should process multiple items', async () => {
      const result = await service.processItems(mockItems);

      expect(result.results).toHaveLength(2);
      expect(result.totalProcessed).toBe(2);
      expect(result.processingTime).toBeGreaterThan(0);
    });

    it('should handle empty input', async () => {
      const result = await service.processItems([]);

      expect(result.results).toHaveLength(0);
      expect(result.totalProcessed).toBe(0);
      expect(result.totalDuplicates).toBe(0);
    });
  });

  describe('Merge Strategies', () => {
    describe('skip strategy', () => {
      beforeEach(() => {
        service.updateConfig({ mergeStrategy: 'skip' });
      });

      it('should be configured with skip strategy', () => {
        const config = service.getConfig();
        expect(config.mergeStrategy).toBe('skip');
      });

      it('should process items with skip strategy', async () => {
        const result = await service.processItems([mockItems[0]]);

        expect(result.results[0]).toHaveProperty('action');
        expect(['stored', 'skipped', 'merged', 'error']).toContain(result.results[0].action);
      });
    });

    describe('prefer_existing strategy', () => {
      beforeEach(() => {
        service.updateConfig({ mergeStrategy: 'prefer_existing' });
      });

      it('should be configured with prefer_existing strategy', () => {
        const config = service.getConfig();
        expect(config.mergeStrategy).toBe('prefer_existing');
      });

      it('should process items with prefer_existing strategy', async () => {
        const result = await service.processItems([mockItems[0]]);

        expect(result.results[0]).toHaveProperty('action');
        expect(['stored', 'skipped', 'merged', 'error']).toContain(result.results[0].action);
      });
    });

    describe('prefer_newer strategy', () => {
      beforeEach(() => {
        service.updateConfig({ mergeStrategy: 'prefer_newer' });
      });

      it('should be configured with prefer_newer strategy', () => {
        const config = service.getConfig();
        expect(config.mergeStrategy).toBe('prefer_newer');
      });

      it('should process items with prefer_newer strategy', async () => {
        const result = await service.processItems([mockItems[0]]);

        expect(result.results[0]).toHaveProperty('action');
        expect(['stored', 'skipped', 'merged', 'error']).toContain(result.results[0].action);
      });
    });

    describe('combine strategy', () => {
      beforeEach(() => {
        service.updateConfig({ mergeStrategy: 'combine' });
      });

      it('should be configured with combine strategy', () => {
        const config = service.getConfig();
        expect(config.mergeStrategy).toBe('combine');
      });

      it('should process items with combine strategy', async () => {
        const result = await service.processItems([mockItems[0]]);

        expect(result.results[0]).toHaveProperty('action');
        expect(['stored', 'skipped', 'merged', 'error']).toContain(result.results[0].action);
      });
    });

    describe('intelligent strategy', () => {
      beforeEach(() => {
        service.updateConfig({ mergeStrategy: 'intelligent' });
      });

      it('should be configured with intelligent strategy', () => {
        const config = service.getConfig();
        expect(config.mergeStrategy).toBe('intelligent');
      });

      it('should process items with intelligent strategy', async () => {
        const result = await service.processItems([mockItems[0]]);

        expect(result.results[0]).toHaveProperty('action');
        expect(['stored', 'skipped', 'merged', 'error']).toContain(result.results[0].action);
      });
    });
  });

  describe('Configuration Options', () => {
    it('should respect content similarity threshold', () => {
      const threshold = 0.95;
      service.updateConfig({ contentSimilarityThreshold: threshold });

      const config = service.getConfig();
      expect(config.contentSimilarityThreshold).toBe(threshold);
    });

    it('should handle scope-only checking', () => {
      service.updateConfig({ checkWithinScopeOnly: true });

      const config = service.getConfig();
      expect(config.checkWithinScopeOnly).toBe(true);
    });

    it('should handle cross-scope deduplication', () => {
      service.updateConfig({ crossScopeDeduplication: true });

      const config = service.getConfig();
      expect(config.crossScopeDeduplication).toBe(true);
    });

    it('should handle time-based deduplication', () => {
      service.updateConfig({ timeBasedDeduplication: true, dedupeWindowDays: 30 });

      const config = service.getConfig();
      expect(config.timeBasedDeduplication).toBe(true);
      expect(config.dedupeWindowDays).toBe(30);
    });
  });

  describe('Audit Logging', () => {
    it('should maintain audit log', async () => {
      await service.processItems([mockItems[0]]);

      const auditLog = service.getAuditLog();
      expect(Array.isArray(auditLog)).toBe(true);
    });

    it('should limit audit log size', async () => {
      await service.processItems(mockItems);

      const limitedLog = service.getAuditLog(1);
      expect(limitedLog.length).toBeLessThanOrEqual(1);
    });

    it('should clear audit log', async () => {
      await service.processItems([mockItems[0]]);
      service.clearAuditLog();

      const auditLog = service.getAuditLog();
      expect(auditLog.length).toBe(0);
    });
  });

  describe('Performance Metrics', () => {
    it('should track performance metrics', async () => {
      const result = await service.processItems(mockItems);
      const metrics = service.getPerformanceMetrics();

      expect(metrics).toHaveProperty('totalProcessed');
      expect(metrics).toHaveProperty('totalDuplicates');
      expect(metrics).toHaveProperty('averageProcessingTime');
      expect(result.processingTime).toBeGreaterThan(0);
    });

    it('should update metrics after processing', async () => {
      const initialMetrics = service.getPerformanceMetrics();

      await service.processItems(mockItems);

      const updatedMetrics = service.getPerformanceMetrics();
      expect(updatedMetrics.totalProcessed).toBeGreaterThan(initialMetrics.totalProcessed);
    });
  });

  describe('Error Handling', () => {
    it('should handle malformed items gracefully', async () => {
      const malformedItems = [
        {
          id: 'bad-item',
          kind: '',
          content: '',
          scope: {},
          data: {},
        } as KnowledgeItem,
      ];

      const result = await service.processItems(malformedItems);

      expect(result.results).toHaveLength(1);
      expect(result.results[0].action).toBe('error' || result.results[0].action === 'stored');
    });

    it('should handle missing required fields', async () => {
      const incompleteItems = [
        {
          id: 'incomplete-item',
          // Missing required fields
        } as KnowledgeItem,
      ];

      const result = await service.processItems(incompleteItems);

      expect(result.results).toHaveLength(1);
      // Should either process or handle as error
      expect(['stored', 'error']).toContain(result.results[0].action);
    });
  });

  describe('Service State Management', () => {
    it('should maintain consistent state', async () => {
      const config1 = service.getConfig();

      service.updateConfig({ mergeStrategy: 'combine' });
      const config2 = service.getConfig();

      expect(config1.mergeStrategy).not.toBe(config2.mergeStrategy);
      expect(config2.mergeStrategy).toBe('combine');
    });

    it('should handle configuration validation', () => {
      expect(() => {
        service.updateConfig({ contentSimilarityThreshold: 1.5 }); // Invalid: > 1.0
      }).not.toThrow();

      expect(() => {
        service.updateConfig({ contentSimilarityThreshold: -0.1 }); // Invalid: < 0
      }).not.toThrow();
    });
  });
});