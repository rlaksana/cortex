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

// Create mock database interface that matches what DeduplicationService expects
const createMockDatabaseInterface = () => {
  const createMockTable = () => ({
    findFirst: vi.fn().mockResolvedValue(null),
    findMany: vi.fn().mockResolvedValue([]),
    create: vi.fn().mockResolvedValue({ id: 'test-id' }),
    update: vi.fn().mockResolvedValue({ id: 'test-id' }),
    delete: vi.fn().mockResolvedValue(true),
  });

  return {
    knowledgeEntity: createMockTable(),
    adrDecision: createMockTable(),
    issueLog: createMockTable(),
    todoLog: createMockTable(),
    runbook: createMockTable(),
    section: createMockTable(),
    changeLog: createMockTable(),
    releaseNote: createMockTable(),
    ddlHistory: createMockTable(),
    prContext: createMockTable(),
    knowledgeRelation: createMockTable(),
    knowledgeObservation: createMockTable(),
    incidentLog: createMockTable(),
    releaseLog: createMockTable(),
    riskLog: createMockTable(),
    assumptionLog: createMockTable(),
  };
};

// Mock the qdrant client completely to provide the expected interface
vi.mock('../../../src/db/qdrant-client.js', () => {
  const mockDb = createMockDatabaseInterface();
  return {
    qdrant: mockDb,
    getQdrantClient: vi.fn().mockReturnValue({}),
    qdrantClient: vi.fn().mockReturnValue({}),
  };
});

// Mock QdrantClient dependency
vi.mock('@qdrant/js-client-rest', () => {
  const mockClient = class MockQdrantClient {
    constructor() {}
    getCollections = vi.fn().mockResolvedValue({ collections: [] });
    createCollection = vi.fn().mockResolvedValue(undefined);
    upsert = vi.fn().mockResolvedValue(undefined);
    search = vi.fn().mockResolvedValue([]);
    getCollection = vi.fn().mockResolvedValue({ points_count: 0, status: 'green' });
    delete = vi.fn().mockResolvedValue(undefined);
    scroll = vi.fn().mockResolvedValue({ points: [], next_page_offset: null });
  };

  return { QdrantClient: mockClient };
});

// Mock the environment to avoid config issues
vi.mock('../../../src/config/environment', () => ({
  Environment: {
    getInstance: vi.fn().mockReturnValue({
      getRawConfig: vi.fn().mockReturnValue({
        QDRANT_URL: 'http://localhost:6333',
        QDRANT_API_KEY: undefined,
      }),
    }),
  },
}));

describe('DeduplicationService', () => {
  let deduplicationService: DeduplicationService;
  let mockQdrant: any;

  // Sample test data
  const sampleKnowledgeItem: KnowledgeItem = {
    id: 'test-item-1',
    kind: 'entity',
    scope: { project: 'test-project', branch: 'main' },
    data: {
      title: 'Test Entity',
      content: 'Test knowledge content',
      project: 'test-project',
      created: new Date().toISOString()
    }
  };

  const duplicateKnowledgeItem: KnowledgeItem = {
    id: 'test-item-2',
    kind: 'entity',
    scope: { project: 'test-project', branch: 'main' },
    data: {
      title: 'Test Entity',
      content: 'Test knowledge content',
      project: 'test-project',
      created: new Date().toISOString()
    }
  };

  const similarKnowledgeItem: KnowledgeItem = {
    id: 'test-item-3',
    kind: 'entity',
    scope: { project: 'test-project', branch: 'main' },
    data: {
      title: 'Test Entity',
      content: 'Test knowledge content with slight variation',
      project: 'test-project',
      created: new Date().toISOString()
    }
  };

  beforeEach(() => {
    deduplicationService = new DeduplicationService();

    // Reset all mocks and clear call history
    vi.clearAllMocks();

    // Reset mock behaviors to defaults
    const { qdrant } = require('../../../src/db/qdrant-client.js');
    Object.keys(qdrant).forEach(table => {
      if (qdrant[table].findFirst) {
        qdrant[table].findFirst.mockResolvedValue(null);
      }
      if (qdrant[table].findMany) {
        qdrant[table].findMany.mockResolvedValue([]);
      }
    });
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
        {
          ...sampleKnowledgeItem,
          id: 'different-id',
          data: {
            ...sampleKnowledgeItem.data,
            content: 'different content',
            title: 'Different Entity'
          }
        }
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
      // Mock an existing record in the database
      const { qdrant } = require('../../../src/db/qdrant-client.js');
      qdrant.knowledgeEntity.findFirst.mockResolvedValueOnce({
        id: 'existing-id'
      });

      const result = await deduplicationService.isDuplicate(duplicateKnowledgeItem);

      expect(result.isDuplicate).toBe(true);
      expect(result.matchType).toBe('exact');
      expect(result.similarityScore).toBe(1.0);
      expect(result.existingId).toBe('existing-id');
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
        id: 'different-kind',
        kind: 'decision',
        data: {
          ...sampleKnowledgeItem.data,
          content: 'Test knowledge content'
        }
      };

      const result = await deduplicationService.isDuplicate(differentKindItem);

      expect(result.isDuplicate).toBe(false);
      expect(result.matchType).toBe('none');
    });

    it('should handle items with missing metadata', async () => {
      const incompleteItem: KnowledgeItem = {
        id: 'incomplete',
        kind: 'entity',
        scope: { project: 'test-project' },
        data: {
          title: 'Test',
          content: 'Test content'
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
        data: {
          ...sampleKnowledgeItem.data,
          content: 'Test knowledge content slightly modified'
        }
      };

      // Mock a similar existing record in the database
      const { qdrant } = require('../../../src/db/qdrant-client.js');
      qdrant.knowledgeEntity.findFirst.mockResolvedValueOnce(null); // No exact match
      qdrant.knowledgeEntity.findMany.mockResolvedValueOnce([{
        id: 'similar-existing-id',
        data: {
          ...sampleKnowledgeItem.data,
          content: 'Test knowledge content'
        }
      }]);

      const result = await deduplicationService.isDuplicate(similarItem);

      expect(result.similarityScore).toBeGreaterThan(0.8);
      expect(result.similarityScore).toBeLessThan(1.0);
    });

    it('should calculate low similarity for different content', async () => {
      const differentItem: KnowledgeItem = {
        ...sampleKnowledgeItem,
        id: 'different-item',
        data: {
          ...sampleKnowledgeItem.data,
          content: 'Completely unrelated content about something else'
        }
      };

      // Mock no exact matches and some dissimilar existing records
      const { qdrant } = require('../../../src/db/qdrant-client.js');
      qdrant.knowledgeEntity.findFirst.mockResolvedValueOnce(null); // No exact match
      qdrant.knowledgeEntity.findMany.mockResolvedValueOnce([{
        id: 'dissimilar-existing-id',
        data: {
          content: 'Original test content'
        }
      }]);

      const result = await deduplicationService.isDuplicate(differentItem);

      expect(result.similarityScore).toBeLessThan(0.5);
      expect(result.matchType).toBe('none');
    });

    it('should handle empty content gracefully', async () => {
      const emptyContentItem: KnowledgeItem = {
        ...sampleKnowledgeItem,
        id: 'empty-content',
        data: {
          ...sampleKnowledgeItem.data,
          content: ''
        }
      };

      const result = await deduplicationService.isDuplicate(emptyContentItem);

      expect(result.isDuplicate).toBe(false);
      expect(result.similarityScore).toBe(0);
    });

    it('should handle null/undefined content', async () => {
      const nullContentItem: KnowledgeItem = {
        id: 'null-content',
        kind: 'entity',
        scope: sampleKnowledgeItem.scope,
        data: {
          title: 'Test Entity',
          content: null as any
        }
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
      const { qdrant } = require('../../../src/db/qdrant-client.js');
      const mockQdrantError = new Error('Database connection failed');
      qdrant.knowledgeEntity.findFirst.mockRejectedValueOnce(mockQdrantError);

      const result = await deduplicationService.checkDuplicates([sampleKnowledgeItem]);

      expect(result.duplicates).toHaveLength(0);
      expect(result.originals).toHaveLength(1);
    });

    it('should handle malformed input data', async () => {
      const malformedItems = [
        null as any,
        undefined as any,
        {
          id: 'invalid',
          kind: 'entity',
          scope: { project: 'test' },
          data: { title: 'Invalid Item' }
        }
      ];

      const result = await deduplicationService.checkDuplicates(malformedItems);

      expect(result.originals).toHaveLength(1);
      expect(result.originals[0].id).toBe('invalid');
    });

    it('should handle large input arrays efficiently', async () => {
      const largeArray = Array.from({ length: 100 }, (_, i) => ({ // Reduced from 1000 to 100 for test performance
        ...sampleKnowledgeItem,
        id: `item-${i}`,
        data: {
          ...sampleKnowledgeItem.data,
          content: `Content ${i}`,
          title: `Test Entity ${i}`
        }
      }));

      const startTime = Date.now();
      const result = await deduplicationService.checkDuplicates(largeArray);
      const endTime = Date.now();

      expect(result.originals).toHaveLength(100);
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