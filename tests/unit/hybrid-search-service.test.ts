/**
 * Tests for Hybrid Search Service
 * Tests the production-ready retrieval improvements
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { SearchQuery, SearchResult } from '../../src/types/core-interfaces.js';

// Mock the dependencies before importing the service
vi.mock('../../src/db/qdrant.js', () => ({
  getQdrantClient: vi.fn(() => ({
    search: vi.fn(),
    scroll: vi.fn()
  }))
}));

vi.mock('../../src/services/search/query-parser.js', () => ({
  queryParser: {
    parse: vi.fn()
  }
}));

vi.mock('../../src/services/search/graph-expansion-service.js', () => ({
  graphExpansionService: {
    expandGraph: vi.fn()
  }
}));

vi.mock('../../src/utils/lru-cache.js', () => ({
  CacheFactory: {
    createSearchCache: vi.fn(() => ({
      get: vi.fn(),
      set: vi.fn()
    }))
  }
}));

// Import after mocking
import { HybridSearchService } from '../../src/services/search/hybrid-search-service.js';

describe('HybridSearchService', () => {
  let hybridSearchService: HybridSearchService;

  beforeEach(() => {
    vi.clearAllMocks();
    hybridSearchService = new HybridSearchService();
  });

  describe('Hybrid Search Features', () => {
    it('should perform hybrid search combining semantic and sparse results', async () => {
      const query: SearchQuery = {
        query: 'architecture decisions',
        mode: 'auto',
        limit: 10
      };

      // Mock semantic results
      const mockSemanticResults: SearchResult[] = [
        {
          id: 'decision-1',
          kind: 'decision',
          scope: { org: 'test' },
          data: { title: 'Microservices Architecture Decision', content: '...' },
          created_at: new Date().toISOString(),
          confidence_score: 0.9,
          match_type: 'semantic'
        }
      ];

      // Mock sparse results
      const mockSparseResults: SearchResult[] = [
        {
          id: 'decision-2',
          kind: 'decision',
          scope: { org: 'test' },
          data: { title: 'Database Choice Decision', content: '...' },
          created_at: new Date().toISOString(),
          confidence_score: 0.7,
          match_type: 'keyword'
        }
      ];

      // Mock the search methods to return our test data
      vi.spyOn(hybridSearchService as any, 'performSemanticSearch')
        .mockResolvedValue(mockSemanticResults);
      vi.spyOn(hybridSearchService as any, 'performSparseSearch')
        .mockResolvedValue(mockSparseResults);

      const result = await hybridSearchService.searchByMode(query);

      expect(result.strategy).toBe('hybrid');
      expect(result.results).toHaveLength(2);
      expect(result.results[0].rankingFactors).toBeDefined();
      expect(result.results[0].rankingFactors.finalScore).toBeGreaterThan(0);
    });

    it('should apply type-aware boosting for critical knowledge types', async () => {
      const query: SearchQuery = {
        query: 'test query',
        mode: 'auto'
      };

      const mockResults: SearchResult[] = [
        {
          id: 'decision-1',
          kind: 'decision',
          scope: { org: 'test' },
          data: { content: '...' },
          confidence_score: 0.5,
          match_type: 'semantic'
        },
        {
          id: 'section-1',
          kind: 'section',
          scope: { org: 'test' },
          data: { content: '...' },
          confidence_score: 0.5,
          match_type: 'semantic'
        }
      ];

      vi.spyOn(hybridSearchService as any, 'performSemanticSearch')
        .mockResolvedValue(mockResults);
      vi.spyOn(hybridSearchService as any, 'performSparseSearch')
        .mockResolvedValue([]);

      const result = await hybridSearchService.searchByMode(query);

      // Decision should be boosted higher than section
      const decisionResult = result.results.find(r => r.kind === 'decision');
      const sectionResult = result.results.find(r => r.kind === 'section');

      expect(decisionResult?.rankingFactors.typeBoost).toBe(1.5);
      expect(sectionResult?.rankingFactors.typeBoost).toBe(1.0);
      expect(decisionResult?.rankingFactors.finalScore)
        .toBeGreaterThan(sectionResult?.rankingFactors.finalScore || 0);
    });

    it('should apply recency boost to recent items', async () => {
      const query: SearchQuery = {
        query: 'test query',
        mode: 'auto'
      };

      const now = new Date();
      const recentDate = new Date(now.getTime() - (1000 * 60 * 60 * 24 * 5)); // 5 days ago
      const oldDate = new Date(now.getTime() - (1000 * 60 * 60 * 24 * 60)); // 60 days ago

      const mockResults: SearchResult[] = [
        {
          id: 'recent-1',
          kind: 'section',
          scope: { org: 'test' },
          data: { content: '...' },
          created_at: recentDate.toISOString(),
          confidence_score: 0.5,
          match_type: 'semantic'
        },
        {
          id: 'old-1',
          kind: 'section',
          scope: { org: 'test' },
          data: { content: '...' },
          created_at: oldDate.toISOString(),
          confidence_score: 0.5,
          match_type: 'semantic'
        }
      ];

      vi.spyOn(hybridSearchService as any, 'performSemanticSearch')
        .mockResolvedValue(mockResults);
      vi.spyOn(hybridSearchService as any, 'performSparseSearch')
        .mockResolvedValue([]);

      const result = await hybridSearchService.searchByMode(query);

      const recentResult = result.results.find(r => r.id === 'recent-1');
      const oldResult = result.results.find(r => r.id === 'old-1');

      expect(recentResult?.rankingFactors.recencyBoost).toBeGreaterThan(1.0);
      expect(oldResult?.rankingFactors.recencyBoost).toBe(1.0);
    });

    it('should apply scope boost for matching scope', async () => {
      const query: SearchQuery = {
        query: 'test query',
        mode: 'auto',
        scope: { org: 'test-org', project: 'test-project' }
      };

      const mockResults: SearchResult[] = [
        {
          id: 'scoped-1',
          kind: 'section',
          scope: { org: 'test-org', project: 'test-project' },
          data: { content: '...' },
          confidence_score: 0.5,
          match_type: 'semantic'
        },
        {
          id: 'unscoped-1',
          kind: 'section',
          scope: { org: 'other-org' },
          data: { content: '...' },
          confidence_score: 0.5,
          match_type: 'semantic'
        }
      ];

      vi.spyOn(hybridSearchService as any, 'performSemanticSearch')
        .mockResolvedValue(mockResults);
      vi.spyOn(hybridSearchService as any, 'performSparseSearch')
        .mockResolvedValue([]);

      const result = await hybridSearchService.searchByMode(query);

      const scopedResult = result.results.find(r => r.id === 'scoped-1');
      const unscopedResult = result.results.find(r => r.id === 'unscoped-1');

      expect(scopedResult?.rankingFactors.scopeBoost).toBeGreaterThan(1.0);
      expect(unscopedResult?.rankingFactors.scopeBoost).toBe(1.0);
    });
  });

  describe('Deep Search Guardrails', () => {
    it('should enforce timeout guardrail for deep search', async () => {
      const query: SearchQuery = {
        query: 'complex query',
        mode: 'deep'
      };

      // Mock a slow deep search that exceeds timeout
      vi.spyOn(hybridSearchService as any, 'performBoundedDeepSearch')
        .mockImplementation(() => new Promise(resolve => setTimeout(resolve, 10000)));

      const result = await hybridSearchService.searchByMode(query);

      // Should fallback to hybrid search due to timeout
      expect(result.strategy).toBe('hybrid');
    });

    it('should enforce node limit for deep search', async () => {
      const query: SearchQuery = {
        query: 'complex query',
        mode: 'deep'
      };

      // Mock deep search that returns too many nodes
      const mockDeepResults = Array.from({ length: 150 }, (_, i) => ({
        id: `node-${i}`,
        kind: 'entity',
        scope: { org: 'test' },
        data: { content: `Node ${i}` },
        confidence_score: 0.8,
        match_type: 'semantic'
      }));

      vi.spyOn(hybridSearchService as any, 'performBoundedDeepSearch')
        .mockResolvedValue(mockDeepResults.slice(0, 100)); // Should be limited to 100

      const result = await hybridSearchService.searchByMode(query);

      expect(result.results.length).toBeLessThanOrEqual(100);
      expect(result.strategy).toBe('deep-guarded');
      expect(result.partial).toBe(true);
    });
  });

  describe('Expand by Parent', () => {
    it('should expand results by parent chunks when requested', async () => {
      const query: SearchQuery = {
        query: 'test query',
        mode: 'auto',
        expand: 'parents'
      };

      const mockResults: SearchResult[] = [
        {
          id: 'chunk-1',
          kind: 'section',
          scope: { org: 'test' },
          data: {
            content: 'Chunk 1 content',
            is_chunk: true,
            parent_id: 'parent-1',
            chunk_index: 1,
            total_chunks: 3
          },
          confidence_score: 0.9,
          match_type: 'semantic'
        }
      ];

      const mockSiblings: SearchResult[] = [
        {
          id: 'chunk-2',
          kind: 'section',
          scope: { org: 'test' },
          data: {
            content: 'Chunk 2 content',
            is_chunk: true,
            parent_id: 'parent-1',
            chunk_index: 2,
            total_chunks: 3
          },
          confidence_score: 0.8,
          match_type: 'semantic'
        },
        {
          id: 'chunk-3',
          kind: 'section',
          scope: { org: 'test' },
          data: {
            content: 'Chunk 3 content',
            is_chunk: true,
            parent_id: 'parent-1',
            chunk_index: 3,
            total_chunks: 3
          },
          confidence_score: 0.7,
          match_type: 'semantic'
        }
      ];

      vi.spyOn(hybridSearchService as any, 'performSemanticSearch')
        .mockResolvedValue(mockResults);
      vi.spyOn(hybridSearchService as any, 'performSparseSearch')
        .mockResolvedValue([]);
      vi.spyOn(hybridSearchService as any, 'findParentSiblings')
        .mockResolvedValue(mockSiblings);

      const result = await hybridSearchService.searchByMode(query);

      // Should include original chunk + expanded siblings
      expect(result.results.length).toBeGreaterThan(1);
      expect(result.results.some(r => r.id === 'chunk-1')).toBe(true);
      expect(result.results.some(r => r.id === 'chunk-2')).toBe(true);
      expect(result.results.some(r => r.id === 'chunk-3')).toBe(true);

      // Expanded results should have slightly lower confidence scores
      const expandedChunk = result.results.find(r => r.id === 'chunk-2');
      expect(expandedChunk?.confidence_score).toBe(0.8 * 0.8); // 0.8 * 0.8 expansion penalty
    });
  });

  describe('Caching', () => {
    it('should cache and reuse results for identical queries', async () => {
      const query: SearchQuery = {
        query: 'cached query',
        mode: 'auto',
        limit: 10
      };

      const mockResults: SearchResult[] = [
        {
          id: 'cached-1',
          kind: 'section',
          scope: { org: 'test' },
          data: { content: 'Cached content' },
          confidence_score: 0.8,
          match_type: 'semantic'
        }
      ];

      const semanticSpy = vi.spyOn(hybridSearchService as any, 'performSemanticSearch')
        .mockResolvedValue(mockResults);
      const sparseSpy = vi.spyOn(hybridSearchService as any, 'performSparseSearch')
        .mockResolvedValue([]);

      // Mock cache to return undefined first time, then cached results
      let cacheCallCount = 0;
      vi.spyOn(hybridSearchService as any, 'searchCache', 'get')
        .mockImplementation(() => {
          cacheCallCount++;
          return cacheCallCount === 1 ? undefined : mockResults;
        });

      vi.spyOn(hybridSearchService as any, 'searchCache', 'set')
        .mockImplementation(() => {});

      // First call
      const result1 = await hybridSearchService.searchByMode(query);
      expect(semanticSpy).toHaveBeenCalledTimes(1);
      expect(sparseSpy).toHaveBeenCalledTimes(1);
      expect(result1.strategy).toBe('hybrid');

      // Second call with same query
      const result2 = await hybridSearchService.searchByMode(query);
      expect(semanticSpy).toHaveBeenCalledTimes(1); // Should not be called again
      expect(sparseSpy).toHaveBeenCalledTimes(1); // Should not be called again
      expect(result2.strategy).toBe('hybrid-cached');
      expect(result2.results).toEqual(result1.results);
    });
  });

  describe('Error Handling', () => {
    it('should fallback to semantic search when hybrid search fails', async () => {
      const query: SearchQuery = {
        query: 'test query',
        mode: 'auto'
      };

      vi.spyOn(hybridSearchService as any, 'performSemanticSearch')
        .mockRejectedValue(new Error('Semantic search failed'));
      vi.spyOn(hybridSearchService as any, 'performSparseSearch')
        .mockRejectedValue(new Error('Sparse search failed'));

      // Mock fallbackToSemantic to return error strategy
      vi.spyOn(hybridSearchService as any, 'fallbackToSemantic')
        .mockResolvedValue({
          results: [],
          totalCount: 0,
          strategy: 'semantic-fallback',
          executionTime: 100
        });

      const result = await hybridSearchService.searchByMode(query);

      expect(result.strategy).toBe('semantic-fallback');
      expect(result.results).toEqual([]);
    });

    it('should handle complete search failure gracefully', async () => {
      const query: SearchQuery = {
        query: 'test query',
        mode: 'auto'
      };

      vi.spyOn(hybridSearchService as any, 'performSemanticSearch')
        .mockRejectedValue(new Error('All search failed'));
      vi.spyOn(hybridSearchService as any, 'performSparseSearch')
        .mockRejectedValue(new Error('All search failed'));
      vi.spyOn(hybridSearchService as any, 'fallbackToSemantic')
        .mockResolvedValue({
          results: [],
          totalCount: 0,
          strategy: 'error',
          executionTime: 100
        });

      const result = await hybridSearchService.searchByMode(query);

      expect(result.strategy).toBe('error');
      expect(result.results).toEqual([]);
      expect(result.executionTime).toBeGreaterThan(0);
    });
  });

  describe('Score Calculation', () => {
    it('should correctly calculate hybrid scores', () => {
      // Test the private method through public interface
      const semanticScore = 0.8;
      const sparseScore = 0.6;

      const result: SearchResult = {
        id: 'test-1',
        kind: 'decision', // Should get type boost
        scope: { org: 'test' },
        data: { content: 'test' },
        created_at: new Date().toISOString(), // Should get recency boost
        confidence_score: 0.7,
        match_type: 'semantic'
      };

      const query: SearchQuery = {
        query: 'test',
        scope: { org: 'test' } // Should get scope boost
      };

      const finalScore = (hybridSearchService as any).calculateHybridScore(
        semanticScore,
        sparseScore,
        result,
        query
      );

      // Score should be boosted by all factors
      expect(finalScore).toBeGreaterThan(0.7); // Base score
      expect(finalScore).toBeLessThanOrEqual(1.0); // Max score
    });

    it('should handle missing metadata gracefully', () => {
      const semanticScore = 0.5;
      const sparseScore = 0.4;

      const result: SearchResult = {
        id: 'test-1',
        kind: 'unknown-type',
        scope: {},
        data: { content: 'test' },
        // No created_at
        confidence_score: 0.5,
        match_type: 'semantic'
      };

      const query: SearchQuery = {
        query: 'test'
        // No scope
      };

      const finalScore = (hybridSearchService as any).calculateHybridScore(
        semanticScore,
        sparseScore,
        result,
        query
      );

      // Should not throw and should return valid score
      expect(finalScore).toBeGreaterThanOrEqual(0);
      expect(finalScore).toBeLessThanOrEqual(1);
    });
  });
});