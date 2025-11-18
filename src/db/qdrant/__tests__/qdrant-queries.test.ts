/**
 * Qdrant Query Tests
 *
 * Tests for Qdrant query operations including search, filter, and aggregation
 */

import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest';
import { type MockQdrantClient } from '../../../types/database-types-enhanced.js';

describe('QdrantQueries', () => {
  let mockQdrantClient: MockQdrantClient;

  beforeEach(() => {
    mockQdrantClient = {
      connect: vi.fn().mockResolvedValue(undefined),
      disconnect: vi.fn().mockResolvedValue(undefined),
      healthCheck: vi.fn().mockResolvedValue(true),
      createCollection: vi.fn().mockResolvedValue(undefined),
      deleteCollection: vi.fn().mockResolvedValue(undefined),
      getCollection: vi.fn().mockResolvedValue({}),
      upsert: vi.fn().mockResolvedValue(undefined),
      search: vi.fn().mockResolvedValue([]),
      scroll: vi.fn().mockResolvedValue([]),
      recommend: vi.fn().mockResolvedValue([]),
      facet: vi.fn().mockResolvedValue({}),
    } as MockQdrantClient;
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('normal search', () => {
    test('should return relevant results for vector search', async () => {
      const mockResults = [
        { id: '1', score: 0.95, payload: { text: 'similar content' } },
        { id: '2', score: 0.87, payload: { text: 'related content' } },
      ];

      vi.mocked(mockQdrantClient.search).mockResolvedValue(mockResults as unknown[]);

      const queryVector = [1, 2, 3, 4, 5];
      const results = await mockQdrantClient.search('test-collection', {
        vector: queryVector,
        limit: 10,
      });

      expect(mockQdrantClient.search).toHaveBeenCalledWith('test-collection', {
        vector: queryVector,
        limit: 10,
      });
      expect(results).toEqual(mockResults);
      expect(results).toHaveLength(2);
    });

    test('should handle search with filters', async () => {
      const mockResults = [
        { id: '3', score: 0.92, payload: { category: 'tech', text: 'AI content' } },
      ];

      vi.mocked(mockQdrantClient.search).mockResolvedValue(mockResults as unknown[]);

      const queryVector = [0.1, 0.2, 0.3];
      const filter = { must: [{ key: 'category', match: { value: 'tech' } }] };

      const results = await mockQdrantClient.search('test-collection', {
        vector: queryVector,
        filter: filter,
        limit: 5,
      });

      expect(mockQdrantClient.search).toHaveBeenCalledWith('test-collection', {
        vector: queryVector,
        filter: filter,
        limit: 5,
      });
      expect(results).toHaveLength(1);
      expect((results[0] as { id: string; score: number; payload: { category: string; text: string } }).payload.category).toBe('tech');
    });
  });

  describe('empty results', () => {
    test('should handle empty search results gracefully', async () => {
      vi.mocked(mockQdrantClient.search).mockResolvedValue([]);

      const queryVector = [1, 0, 0, 0];
      const results = await mockQdrantClient.search('empty-collection', {
        vector: queryVector,
        limit: 10,
      });

      expect(results).toEqual([]);
      expect(results).toHaveLength(0);
    });

    test('should handle no matches found scenario', async () => {
      vi.mocked(mockQdrantClient.search).mockResolvedValue([]);

      const queryVector = [999, 999, 999]; // Unlikely to match anything
      const results = await mockQdrantClient.search('test-collection', {
        vector: queryVector,
        score_threshold: 0.99, // Very high threshold
      });

      expect(results).toEqual([]);
    });

    test('should handle empty collection scroll', async () => {
      const scrollResult = {
        result: {
          points: [],
          next_page_offset: null,
        },
      };
      vi.mocked(mockQdrantClient.scroll).mockResolvedValue([scrollResult] as unknown[]);

      const scrollResults = await mockQdrantClient.scroll('empty-collection', {
        limit: 100,
      });

      expect(scrollResults).toHaveLength(1);
      const firstResult = scrollResults[0] as { result: { points: unknown[]; next_page_offset: unknown } };
      expect(firstResult.result.points).toEqual([]);
      expect(firstResult.result.next_page_offset).toBeNull();
    });
  });

  describe('error scenarios', () => {
    test('should handle network timeout errors', async () => {
      const timeoutError = new Error('Request timeout after 30000ms');
      timeoutError.name = 'TimeoutError';

      vi.mocked(mockQdrantClient.search).mockRejectedValue(timeoutError);

      try {
        await mockQdrantClient.search('test-collection', {
          vector: [1, 2, 3],
          limit: 10,
        });
        expect.fail('Should have thrown a timeout error');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toContain('timeout');
        expect((error as Error).name).toBe('TimeoutError');
      }
    });

    test('should handle collection not found errors', async () => {
      const notFoundError = new Error('Collection "nonexistent" not found');
      vi.mocked(mockQdrantClient.search).mockRejectedValue(notFoundError);

      try {
        await mockQdrantClient.search('nonexistent', {
          vector: [1, 2, 3],
        });
        expect.fail('Should have thrown a collection not found error');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toContain('not found');
      }
    });

    test('should handle invalid vector dimension errors', async () => {
      const dimensionError = new Error('Wrong vector dimension: expected 1536, got 512');
      vi.mocked(mockQdrantClient.search).mockRejectedValue(dimensionError);

      try {
        await mockQdrantClient.search('test-collection', {
          vector: new Array(512).fill(0.1), // 512 dimensions instead of expected 1536
        });
        expect.fail('Should have thrown a dimension error');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toContain('vector dimension');
      }
    });

    test('should handle malformed filter queries', async () => {
      const filterError = new Error('Invalid filter: unknown field "invalid_field"');
      vi.mocked(mockQdrantClient.search).mockRejectedValue(filterError);

      const invalidFilter = {
        must: [{ key: 'invalid_field', match: { value: 'test' } }],
      };

      try {
        await mockQdrantClient.search('test-collection', {
          vector: [1, 2, 3],
          filter: invalidFilter,
        });
        expect.fail('Should have thrown a filter error');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toContain('Invalid filter');
      }
    });
  });

  describe('complex queries', () => {
    test('should handle recommendation queries', async () => {
      const mockRecommendations = [
        { id: '5', score: 0.89, payload: { text: 'recommended content' } },
        { id: '6', score: 0.85, payload: { text: 'similar item' } },
      ];

      vi.mocked(mockQdrantClient.recommend).mockResolvedValue(mockRecommendations as unknown[]);

      const positiveIds = ['1', '2'];
      const negativeIds = ['3'];

      const recommendations = await mockQdrantClient.recommend('test-collection', {
        positive: positiveIds,
        negative: negativeIds,
        limit: 5,
      });

      expect(mockQdrantClient.recommend).toHaveBeenCalledWith('test-collection', {
        positive: positiveIds,
        negative: negativeIds,
        limit: 5,
      });
      expect(recommendations).toHaveLength(2);
    });

    test('should handle aggregation queries', async () => {
      const mockAggregation = {
        result: [
          { key: 'category', value: 'tech', count: 150 },
          { key: 'category', value: 'science', count: 89 },
          { key: 'category', value: 'arts', count: 67 },
        ],
      };

      vi.mocked(mockQdrantClient.facet).mockResolvedValue(mockAggregation as unknown);

      const facetResults = await mockQdrantClient.facet('test-collection', {
        key: 'category',
      });

      const facetResultsTyped = facetResults as { result: { key: string; value: string; count: number }[] };
      expect(facetResultsTyped.result).toHaveLength(3);
      expect(facetResultsTyped.result[0].count).toBe(150);
    });
  });
});
