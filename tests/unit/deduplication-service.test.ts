/**
 * Unit Tests for DeduplicationService
 *
 * Tests deduplication functionality including:
 * - Exact duplicate detection
 * - Content similarity matching
 * - Configuration handling
 * - Database integration scenarios
 * - Edge cases and error handling
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { DeduplicationService } from '../../../src/services/deduplication/deduplication-service.js';
import type { KnowledgeItem } from '../../../src/types/core-interfaces';

// Mock the dependencies
vi.mock('../../../src/utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn()
  }
}));

vi.mock('../../../src/db/qdrant-client.js', () => ({
  qdrant: {
    query: vi.fn(),
    insert: vi.fn(),
    search: vi.fn()
  }
}));

describe('DeduplicationService', () => {
  let deduplicationService: DeduplicationService;
  let mockQdrant: any;

  // Sample test data
  const sampleKnowledgeItem: KnowledgeItem = {
    id: 'test-item-1',
    kind: 'entity',
    content: 'Test knowledge content',
    metadata: {
      title: 'Test Entity',
      project: 'test-project',
      created: new Date().toISOString(),
      scope: { project: 'test-project', branch: 'main' }
    }
  };

  const duplicateKnowledgeItem: KnowledgeItem = {
    id: 'test-item-2',
    kind: 'entity',
    content: 'Test knowledge content',
    metadata: {
      title: 'Test Entity',
      project: 'test-project',
      created: new Date().toISOString(),
      scope: { project: 'test-project', branch: 'main' }
    }
  };

  const similarKnowledgeItem: KnowledgeItem = {
    id: 'test-item-3',
    kind: 'entity',
    content: 'Test knowledge content with slight variation',
    metadata: {
      title: 'Test Entity',
      project: 'test-project',
      created: new Date().toISOString(),
      scope: { project: 'test-project', branch: 'main' }
    }
  };

  beforeEach(() => {
    deduplicationService = new DeduplicationService();
    mockQdrant = {
      query: vi.fn(),
      insert: vi.fn(),
      search: vi.fn()
    };

    // Reset all mocks and clear call history
    vi.clearAllMocks();
  });

  afterEach(() => {
    // Clean up mocks and restore implementations
    vi.resetAllMocks();
    vi.restoreAllMocks();
  });

  describe('Constructor and Configuration', () => {
    it('should create instance with default configuration', () => {
      const service = new DeduplicationService();
      expect(service).toBeInstanceOf(DeduplicationService);
    });

    it('should accept custom configuration', () => {
      const customConfig = {
        enabled: false,
        contentSimilarityThreshold: 0.9,
        checkWithinScopeOnly: false,
        maxHistoryHours: 48
      };

      const service = new DeduplicationService(customConfig);
      expect(service).toBeInstanceOf(DeduplicationService);
    });
  });

  describe('checkDuplicates', () => {
    it('should return all items as originals when deduplication is disabled', async () => {
      const disabledService = new DeduplicationService({ enabled: false } as any);
      const items = [sampleKnowledgeItem, duplicateKnowledgeItem];

      const result = await disabledService.checkDuplicates(items);

      expect(result.duplicates).toHaveLength(0);
      expect(result.originals).toHaveLength(2);
      expect(result.originals).toEqual(items);
    });

    it('should detect exact duplicates within input array', async () => {
      const items = [sampleKnowledgeItem, duplicateKnowledgeItem];

      const result = await deduplicationService.checkDuplicates(items);

      expect(result.duplicates).toHaveLength(1);
      expect(result.originals).toHaveLength(1);
      expect(result.duplicates[0].id).toBe('test-item-2');
      expect(result.originals[0].id).toBe('test-item-1');
    });

    it('should handle empty input array', async () => {
      const result = await deduplicationService.checkDuplicates([]);

      expect(result.duplicates).toHaveLength(0);
      expect(result.originals).toHaveLength(0);
    });

    it('should handle single item input', async () => {
      const items = [sampleKnowledgeItem];

      const result = await deduplicationService.checkDuplicates(items);

      expect(result.duplicates).toHaveLength(0);
      expect(result.originals).toHaveLength(1);
      expect(result.originals[0]).toEqual(sampleKnowledgeItem);
    });

    it('should handle multiple exact duplicates', async () => {
      const items = [
        sampleKnowledgeItem,
        duplicateKnowledgeItem,
        { ...duplicateKnowledgeItem, id: 'test-item-3' }
      ];

      const result = await deduplicationService.checkDuplicates(items);

      expect(result.duplicates).toHaveLength(2);
      expect(result.originals).toHaveLength(1);
    });

    it('should distinguish between similar but not identical items', async () => {
      const items = [sampleKnowledgeItem, similarKnowledgeItem];

      const result = await deduplicationService.checkDuplicates(items);

      expect(result.duplicates).toHaveLength(0);
      expect(result.originals).toHaveLength(2);
    });
  });

  describe('removeDuplicates', () => {
    it('should remove duplicates and return unique items', async () => {
      const items = [sampleKnowledgeItem, duplicateKnowledgeItem, similarKnowledgeItem];

      const result = await deduplicationService.removeDuplicates(items);

      expect(result).toHaveLength(2);
      expect(result.map(item => item.id)).toContain('test-item-1');
      expect(result.map(item => item.id)).toContain('test-item-3');
      expect(result.map(item => item.id)).not.toContain('test-item-2');
    });

    it('should return empty array for empty input', async () => {
      const result = await deduplicationService.removeDuplicates([]);

      expect(result).toHaveLength(0);
    });

    it('should preserve original order for unique items', async () => {
      const items = [
        sampleKnowledgeItem,
        similarKnowledgeItem,
        { ...sampleKnowledgeItem, id: 'different-id', content: 'different content' }
      ];

      const result = await deduplicationService.removeDuplicates(items);

      expect(result).toHaveLength(3);
      expect(result[0].id).toBe('test-item-1');
      expect(result[1].id).toBe('test-item-3');
      expect(result[2].id).toBe('different-id');
    });
  });

  describe('isDuplicate', () => {
    it('should identify exact duplicates', async () => {
      const result = await deduplicationService.isDuplicate(duplicateKnowledgeItem);

      expect(result.isDuplicate).toBe(true);
      expect(result.matchType).toBe('exact');
      expect(result.similarityScore).toBe(1.0);
    });

    it('should return non-duplicate for unique items', async () => {
      const uniqueItem: KnowledgeItem = {
        ...sampleKnowledgeItem,
        id: 'unique-item',
        content: 'Completely different content',
        metadata: {
          ...sampleKnowledgeItem.metadata,
          title: 'Different Title'
        }
      };

      const result = await deduplicationService.isDuplicate(uniqueItem);

      expect(result.isDuplicate).toBe(false);
      expect(result.matchType).toBe('none');
      expect(result.similarityScore).toBeLessThan(0.5);
    });

    it('should handle different knowledge kinds', async () => {
      const differentKindItem: KnowledgeItem = {
        ...sampleKnowledgeItem,
        kind: 'decision',
        content: 'Test knowledge content'
      };

      const result = await deduplicationService.isDuplicate(differentKindItem);

      expect(result.isDuplicate).toBe(false);
      expect(result.matchType).toBe('none');
    });

    it('should handle items with missing metadata', async () => {
      const incompleteItem: KnowledgeItem = {
        id: 'incomplete',
        kind: 'entity',
        content: 'Test content',
        metadata: {
          title: 'Test'
        }
      };

      const result = await deduplicationService.isDuplicate(incompleteItem);

      expect(result.isDuplicate).toBe(false);
      expect(result.matchType).toBe('none');
    });
  });

  describe('Content Similarity Matching', () => {
    it('should calculate high similarity for similar content', async () => {
      const similarItem: KnowledgeItem = {
        ...sampleKnowledgeItem,
        id: 'similar-item',
        content: 'Test knowledge content slightly modified'
      };

      const result = await deduplicationService.isDuplicate(similarItem);

      expect(result.similarityScore).toBeGreaterThan(0.8);
      expect(result.similarityScore).toBeLessThan(1.0);
    });

    it('should calculate low similarity for different content', async () => {
      const differentItem: KnowledgeItem = {
        ...sampleKnowledgeItem,
        id: 'different-item',
        content: 'Completely unrelated content about something else'
      };

      const result = await deduplicationService.isDuplicate(differentItem);

      expect(result.similarityScore).toBeLessThan(0.5);
      expect(result.matchType).toBe('none');
    });

    it('should handle empty content gracefully', async () => {
      const emptyContentItem: KnowledgeItem = {
        ...sampleKnowledgeItem,
        id: 'empty-content',
        content: ''
      };

      const result = await deduplicationService.isDuplicate(emptyContentItem);

      expect(result.isDuplicate).toBe(false);
      expect(result.similarityScore).toBe(0);
    });

    it('should handle null/undefined content', async () => {
      const nullContentItem: KnowledgeItem = {
        id: 'null-content',
        kind: 'entity',
        content: null as any,
        metadata: sampleKnowledgeItem.metadata
      };

      const result = await deduplicationService.isDuplicate(nullContentItem);

      expect(result.isDuplicate).toBe(false);
      expect(result.similarityScore).toBe(0);
    });
  });

  describe('Scope Filtering', () => {
    it('should check duplicates within same scope', async () => {
      const sameScopeItem: KnowledgeItem = {
        ...sampleKnowledgeItem,
        id: 'same-scope',
        scope: { project: 'test-project', branch: 'main' }
      };

      const result = await deduplicationService.isDuplicate(sameScopeItem);

      // Should perform duplicate check within same scope
      expect(result).toBeDefined();
    });

    it('should respect scope-only configuration', async () => {
      const scopeOnlyService = new DeduplicationService({
        checkWithinScopeOnly: true
      } as any);

      const differentScopeItem: KnowledgeItem = {
        ...sampleKnowledgeItem,
        id: 'different-scope',
        scope: { project: 'different-project', branch: 'main' }
      };

      const result = await scopeOnlyService.isDuplicate(differentScopeItem);

      expect(result.isDuplicate).toBe(false);
    });
  });

  describe('Error Handling', () => {
    it('should handle database query errors gracefully', async () => {
      // Mock database error
      const mockQdrantError = new Error('Database connection failed');
      vi.mocked(require('../../../src/db/qdrant-client.js').qdrant.query)
        .mockRejectedValueOnce(mockQdrantError);

      const result = await deduplicationService.checkDuplicates([sampleKnowledgeItem]);

      expect(result.duplicates).toHaveLength(0);
      expect(result.originals).toHaveLength(1);
    });

    it('should handle malformed input data', async () => {
      const malformedItems = [
        null as any,
        undefined as any,
        { id: 'invalid', kind: 'invalid' }
      ];

      const result = await deduplicationService.checkDuplicates(malformedItems);

      expect(result.originals).toHaveLength(1);
      expect(result.originals[0].id).toBe('invalid');
    });

    it('should handle large input arrays efficiently', async () => {
      const largeArray = Array.from({ length: 1000 }, (_, i) => ({
        ...sampleKnowledgeItem,
        id: `item-${i}`,
        content: `Content ${i}`
      }));

      const startTime = Date.now();
      const result = await deduplicationService.checkDuplicates(largeArray);
      const endTime = Date.now();

      expect(result.originals).toHaveLength(1000);
      expect(result.duplicates).toHaveLength(0);
      expect(endTime - startTime).toBeLessThan(5000); // Should complete within 5 seconds
    });
  });

  describe('Table Name Mapping', () => {
    it('should return correct table names for all knowledge kinds', () => {
      const service = new DeduplicationService();

      // Test known mappings
      expect(service['getTableNameForKind']('entity')).toBe('knowledgeEntity');
      expect(service['getTableNameForKind']('decision')).toBe('adrDecision');
      expect(service['getTableNameForKind']('issue')).toBe('issueLog');
      expect(service['getTableNameForKind']('todo')).toBe('todoLog');
      expect(service['getTableNameForKind']('runbook')).toBe('runbook');
      expect(service['getTableNameForKind']('section')).toBe('section');
    });

    it('should return null for unknown knowledge kinds', () => {
      const service = new DeduplicationService();

      expect(service['getTableNameForKind']('unknown')).toBeNull();
      expect(service['getTableNameForKind']('')).toBeNull();
      expect(service['getTableNameForKind'](null as any)).toBeNull();
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle concurrent duplicate checks', async () => {
      const concurrentItems = Array.from({ length: 100 }, (_, i) => ({
        ...sampleKnowledgeItem,
        id: `concurrent-${i}`,
        content: i % 2 === 0 ? 'Same content' : `Different content ${i}`
      }));

      const promises = concurrentItems.map(item => deduplicationService.isDuplicate(item));
      const results = await Promise.all(promises);

      expect(results).toHaveLength(100);
      expect(results.every(r => typeof r.isDuplicate === 'boolean')).toBe(true);
    });

    it('should respect max history hours configuration', async () => {
      const recentService = new DeduplicationService({
        maxHistoryHours: 1
      } as any);

      const oldItem: KnowledgeItem = {
        ...sampleKnowledgeItem,
        id: 'old-item',
        metadata: {
          ...sampleKnowledgeItem.metadata,
          created: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString() // 2 hours ago
        }
      };

      const result = await recentService.isDuplicate(oldItem);

      // Should not consider old items as duplicates due to time limit
      expect(result.isDuplicate).toBe(false);
    });
  });

  describe('Integration Scenarios', () => {
    it('should handle real-world deduplication workflow', async () => {
      const batchItems = [
        sampleKnowledgeItem,
        duplicateKnowledgeItem,
        similarKnowledgeItem,
        { ...sampleKnowledgeItem, id: 'item-4', kind: 'decision' },
        { ...sampleKnowledgeItem, id: 'item-5', content: 'Completely different content' }
      ];

      const result = await deduplicationService.checkDuplicates(batchItems);

      expect(result.duplicates.length).toBeGreaterThan(0);
      expect(result.originals.length).toBeGreaterThan(0);
      expect(result.duplicates.length + result.originals.length).toBe(5);

      // Verify that duplicates are not in originals
      const duplicateIds = result.duplicates.map(d => d.id);
      const originalIds = result.originals.map(o => o.id);
      const intersection = duplicateIds.filter(id => originalIds.includes(id));
      expect(intersection).toHaveLength(0);
    });
  });
});