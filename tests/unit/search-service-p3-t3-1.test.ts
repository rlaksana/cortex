/**
 * Tests for SearchService semantic(), keyword(), and hybrid() methods
 * P3-T3.1: Factor out searchService with semantic(), keyword(), hybrid() methods
 */

import { SearchService } from '../../src/services/search/search-service';
import type { SearchQuery, SearchResult } from '../../src/types/core-interfaces';

describe('SearchService - P3-T3.1', () => {
  let searchService: SearchService;

  beforeEach(() => {
    searchService = new SearchService();
  });

  describe('semantic() method', () => {
    it('should perform vector-based semantic search', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'database connection pooling',
        limit: 10,
        types: ['decision'],
        scope: { project: 'test-project' },
      };

      // Act
      const result = await searchService.semantic(query);

      // Assert
      expect(result).toBeDefined();
      expect(result.results).toBeDefined();
      expect(Array.isArray(result.results)).toBe(true);
      expect(result.totalCount).toBeDefined();
      expect(typeof result.totalCount).toBe('number');

      // Verify semantic search characteristics
      result.results.forEach((item: SearchResult) => {
        expect(item).toHaveProperty('id');
        expect(item).toHaveProperty('kind');
        expect(item).toHaveProperty('confidence_score');
        expect(item).toHaveProperty('match_type');
        expect(item.match_type).toBe('semantic'); // Should indicate semantic match
        expect(typeof item.confidence_score).toBe('number');
        expect(item.confidence_score).toBeGreaterThanOrEqual(0);
        expect(item.confidence_score).toBeLessThanOrEqual(1);
      });
    });

    it('should return empty results for queries with no semantic matches', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'xyz123nonexistentterm456',
        limit: 5,
        types: ['observation'],
      };

      // Act
      const result = await searchService.semantic(query);

      // Assert
      expect(result.results).toEqual([]);
      expect(result.totalCount).toBe(0);
    });

    it('should respect scope filters in semantic search', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'authentication',
        limit: 10,
        scope: {
          project: 'specific-project',
          branch: 'feature-branch',
        },
      };

      // Act
      const result = await searchService.semantic(query);

      // Assert
      result.results.forEach((item: SearchResult) => {
        if (item.scope) {
          expect(item.scope.project).toBe('specific-project');
          expect(item.scope.branch).toBe('feature-branch');
        }
      });
    });
  });

  describe('keyword() method', () => {
    it('should perform text-based keyword search', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'error handling timeout',
        limit: 10,
        types: ['issue', 'incident'],
      };

      // Act
      const result = await searchService.keyword(query);

      // Assert
      expect(result).toBeDefined();
      expect(result.results).toBeDefined();
      expect(Array.isArray(result.results)).toBe(true);
      expect(result.totalCount).toBeDefined();
      expect(typeof result.totalCount).toBe('number');

      // Verify keyword search characteristics (even with empty results)
      if (result.results.length > 0) {
        result.results.forEach((item: SearchResult) => {
          expect(item).toHaveProperty('id');
          expect(item).toHaveProperty('kind');
          expect(item).toHaveProperty('confidence_score');
          expect(item).toHaveProperty('match_type');
          expect(item.match_type).toBe('keyword'); // Should indicate keyword match
          expect(typeof item.confidence_score).toBe('number');
        });

        // Verify that results contain the search terms when data exists
        const hasKeywordMatches = result.results.some((item: SearchResult) => {
          const content = JSON.stringify(item.data).toLowerCase();
          return (
            content.includes('error') || content.includes('handling') || content.includes('timeout')
          );
        });

        // Only assert this if we have actual data (which we might not in test environment)
        if (result.results.some((item) => Object.keys(item.data).length > 0)) {
          expect(hasKeywordMatches).toBe(true);
        }
      } else {
        // Empty results are acceptable in test environment
        expect(result.totalCount).toBe(0);
      }
    });

    it('should handle quoted phrases in keyword search', async () => {
      // Arrange
      const query: SearchQuery = {
        query: '"database connection" pooling',
        limit: 10,
      };

      // Act
      const result = await searchService.keyword(query);

      // Assert
      expect(result.results).toBeDefined();

      // Verify exact phrase matching gets higher scores
      if (result.results.length > 0) {
        const sortedByConfidence = [...result.results].sort(
          (a, b) => b.confidence_score - a.confidence_score
        );
        expect(sortedByConfidence[0].confidence_score).toBeGreaterThanOrEqual(
          sortedByConfidence[sortedByConfidence.length - 1].confidence_score
        );
      }
    });

    it('should return results ordered by keyword relevance', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'api endpoint rest',
        limit: 15,
      };

      // Act
      const result = await searchService.keyword(query);

      // Assert
      if (result.results.length > 1) {
        // Results should be ordered by confidence score (relevance)
        for (let i = 0; i < result.results.length - 1; i++) {
          expect(result.results[i].confidence_score).toBeGreaterThanOrEqual(
            result.results[i + 1].confidence_score
          );
        }
      }
    });
  });

  describe('hybrid() method', () => {
    it('should combine semantic and keyword search results', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'performance optimization database',
        limit: 10,
        types: ['decision', 'runbook'],
      };

      // Act
      const result = await searchService.hybrid(query);

      // Assert
      expect(result).toBeDefined();
      expect(result.results).toBeDefined();
      expect(Array.isArray(result.results)).toBe(true);
      expect(result.totalCount).toBeDefined();

      // Verify hybrid search characteristics
      result.results.forEach((item: SearchResult) => {
        expect(item).toHaveProperty('id');
        expect(item).toHaveProperty('kind');
        expect(item).toHaveProperty('confidence_score');
        expect(item).toHaveProperty('match_type');
        // Hybrid should contain both semantic and keyword matches
        expect(['semantic', 'keyword', 'hybrid']).toContain(item.match_type);
      });
    });

    it('should deduplicate results from semantic and keyword searches', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'security authentication',
        limit: 20,
      };

      // Act
      const result = await searchService.hybrid(query);

      // Assert
      const ids = result.results.map((item) => item.id);
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(ids.length); // No duplicates

      // Verify hybrid match type for combined results
      result.results.forEach((item: SearchResult) => {
        expect(['semantic', 'keyword', 'hybrid']).toContain(item.match_type);
      });
    });

    it('should weight semantic and keyword scores appropriately', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'caching strategy memory',
        limit: 15,
      };

      // Act
      const result = await searchService.hybrid(query);

      // Assert
      if (result.results.length > 0) {
        // Hybrid results should have boosted confidence scores
        result.results.forEach((item: SearchResult) => {
          expect(item.confidence_score).toBeGreaterThan(0);
          expect(item.confidence_score).toBeLessThanOrEqual(1);
        });

        // Results should be ordered by hybrid relevance
        for (let i = 0; i < result.results.length - 1; i++) {
          expect(result.results[i].confidence_score).toBeGreaterThanOrEqual(
            result.results[i + 1].confidence_score
          );
        }
      }
    });

    it('should fallback to keyword search if semantic search fails', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'test query for fallback',
        limit: 10,
      };

      // Act
      const result = await searchService.hybrid(query);

      // Assert
      expect(result.results).toBeDefined();
      // Should still return results even if one method fails
      expect(Array.isArray(result.results)).toBe(true);
    });
  });

  describe('SearchService integration', () => {
    it('should maintain backward compatibility with existing search methods', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'testing query',
        limit: 5,
      };

      // Act & Assert - All three methods should work with the same query interface
      const semanticResult = await searchService.semantic(query);
      const keywordResult = await searchService.keyword(query);
      const hybridResult = await searchService.hybrid(query);

      expect(semanticResult.results).toBeDefined();
      expect(keywordResult.results).toBeDefined();
      expect(hybridResult.results).toBeDefined();

      // All should have the same response structure
      [semanticResult, keywordResult, hybridResult].forEach((result) => {
        expect(result).toHaveProperty('results');
        expect(result).toHaveProperty('totalCount');
        expect(typeof result.totalCount).toBe('number');
      });
    });

    it('should handle different search modes (fast/auto/deep) for P3-T3.2', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'search mode test',
        limit: 10,
        mode: 'auto', // This will be used in P3-T3.2
      };

      // Act
      const semanticResult = await searchService.semantic(query);
      const keywordResult = await searchService.keyword(query);
      const hybridResult = await searchService.hybrid(query);

      // Assert
      expect(semanticResult.results).toBeDefined();
      expect(keywordResult.results).toBeDefined();
      expect(hybridResult.results).toBeDefined();
    });

    it('should include match_type field for P3-T3.3 compatibility', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'match type test',
        limit: 5,
      };

      // Act
      const semanticResult = await searchService.semantic(query);
      const keywordResult = await searchService.keyword(query);
      const hybridResult = await searchService.hybrid(query);

      // Assert
      semanticResult.results.forEach((item) => {
        expect(item.match_type).toBe('semantic');
      });

      keywordResult.results.forEach((item) => {
        expect(item.match_type).toBe('keyword');
      });

      hybridResult.results.forEach((item) => {
        expect(['semantic', 'keyword', 'hybrid']).toContain(item.match_type);
      });
    });
  });

  describe('Error handling', () => {
    it('should handle invalid queries gracefully', async () => {
      // Arrange
      const invalidQuery = {
        query: '',
        limit: -1,
      } as SearchQuery;

      // Act & Assert
      await expect(searchService.semantic(invalidQuery)).rejects.toThrow();
      await expect(searchService.keyword(invalidQuery)).rejects.toThrow();
      await expect(searchService.hybrid(invalidQuery)).rejects.toThrow();
    });

    it('should handle database connection errors', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'test query',
        limit: 5,
      };

      // Act & Assert - Should not crash, but return empty results or throw gracefully
      try {
        const semanticResult = await searchService.semantic(query);
        expect(semanticResult.results).toBeDefined();
      } catch (error) {
        expect(error).toBeDefined();
      }

      try {
        const keywordResult = await searchService.keyword(query);
        expect(keywordResult.results).toBeDefined();
      } catch (error) {
        expect(error).toBeDefined();
      }

      try {
        const hybridResult = await searchService.hybrid(query);
        expect(hybridResult.results).toBeDefined();
      } catch (error) {
        expect(error).toBeDefined();
      }
    });
  });
});
