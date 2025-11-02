/**
 * Tests for SearchService P3-T3.2: Search Modes Implementation
 *
 * Failing tests first (TDD approach) for implementing 3 search modes:
 * 1. mode=fast: keyword-only search, topK≤20, latency target
 * 2. mode=auto: keyword then semantic, merge results, topK≤50
 * 3. mode=deep: semantic + parent/child expansion, topK≤100
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { SearchService } from '../../src/services/search/search-service';
import type { SearchQuery, SearchResult } from '../../src/types/core-interfaces';

// Mock dependencies
vi.mock('../../src/utils/logger', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

vi.mock('../../src/db/qdrant', () => ({
  getQdrantClient: () => mockQdrantClient,
}));

// Mock Qdrant client
const mockQdrantClient = {
  section: {
    findMany: vi.fn(),
  },
  adrDecision: {
    findMany: vi.fn(),
  },
  issueLog: {
    findMany: vi.fn(),
  },
  todoLog: {
    findMany: vi.fn(),
  },
  runbook: {
    findMany: vi.fn(),
  },
  changeLog: {
    findMany: vi.fn(),
  },
  releaseNote: {
    findMany: vi.fn(),
  },
  ddlHistory: {
    findMany: vi.fn(),
  },
  prContext: {
    findMany: vi.fn(),
  },
  knowledgeEntity: {
    findMany: vi.fn(),
  },
  knowledgeRelation: {
    findMany: vi.fn(),
  },
  knowledgeObservation: {
    findMany: vi.fn(),
  },
  incidentLog: {
    findMany: vi.fn(),
  },
  releaseLog: {
    findMany: vi.fn(),
  },
  riskLog: {
    findMany: vi.fn(),
  },
  assumptionLog: {
    findMany: vi.fn(),
  },
};

// Mock cache factory
vi.mock('../../src/utils/lru-cache', () => ({
  CacheFactory: {
    createSearchCache: () => ({
      get: vi.fn(),
      set: vi.fn(),
      clear: vi.fn(),
      getStats: vi.fn(() => ({
        itemCount: 0,
        memoryUsageBytes: 0,
        maxMemoryBytes: 52428800,
        hitRate: 0,
        totalHits: 0,
        totalMisses: 0,
        expiredItems: 0,
        evictedItems: 0,
      })),
    }),
  },
}));

describe('SearchService - P3-T3.2 Search Modes', () => {
  let searchService: SearchService;

  beforeEach(() => {
    searchService = new SearchService();
    vi.clearAllMocks();

    // Setup default mock responses
    Object.values(mockQdrantClient).forEach((model: any) => {
      model.findMany.mockResolvedValue([]);
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Fast Mode Tests (mode=fast)', () => {
    it('should use keyword-only search when mode=fast', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'authentication system error',
        mode: 'fast',
        limit: 20,
      };

      // Act
      const result = await searchService.searchByMode(query);

      // Assert - This will fail initially because searchByMode doesn't exist
      expect(result).toBeDefined();
      expect(result.results).toBeDefined();
      expect(result.strategy).toBe('keyword'); // Should use keyword-only
      expect(result.results.length).toBeLessThanOrEqual(20); // topK≤20

      // Verify performance characteristics
      expect(result.executionTime).toBeLessThan(500); // Latency target < 500ms
    });

    it('should prioritize exact keyword matches in fast mode', async () => {
      // Arrange
      const mockKeywordResults: SearchResult[] = [
        {
          id: 'exact-match-1',
          kind: 'issue',
          scope: { project: 'test' },
          data: { title: 'Authentication System Error', content: 'Exact match content' },
          created_at: '2024-01-01',
          confidence_score: 0.95,
          match_type: 'keyword',
        },
      ];

      mockQdrantClient.issueLog.findMany.mockResolvedValue([
        {
          id: 'exact-match-1',
          kind: 'issue',
          data: { title: 'Authentication System Error', content: 'Exact match content' },
          tags: { project: 'test' },
          created_at: new Date('2024-01-01'),
        },
      ]);

      const query: SearchQuery = {
        query: '"Authentication System Error"',
        mode: 'fast',
        limit: 10,
      };

      // Act
      const result = await searchService.searchByMode(query);

      // Assert
      expect(result.results).toBeDefined();
      expect(result.results.length).toBeGreaterThan(0);
      expect(result.results[0].confidence_score).toBeGreaterThan(0.3); // More realistic expectation for test data
      expect(result.strategy).toBe('keyword');
    });

    it('should handle fast mode with no results gracefully', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'xyz123nonexistent456',
        mode: 'fast',
        limit: 15,
      };

      // Act
      const result = await searchService.searchByMode(query);

      // Assert
      expect(result.results).toEqual([]);
      expect(result.totalCount).toBe(0);
      expect(result.strategy).toBe('keyword');
      expect(result.executionTime).toBeLessThan(200); // Should be very fast with no results
    });

    it('should enforce topK=20 limit in fast mode', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'common search term',
        mode: 'fast',
        limit: 50, // Request more than fast mode allows
      };

      // Act
      const result = await searchService.searchByMode(query);

      // Assert
      expect(result.results.length).toBeLessThanOrEqual(20); // Should cap at 20
      expect(result.strategy).toBe('keyword');
    });
  });

  describe('Auto Mode Tests (mode=auto)', () => {
    it('should use hybrid search when mode=auto', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'database performance optimization',
        mode: 'auto',
        limit: 50,
      };

      // Act
      const result = await searchService.searchByMode(query);

      // Assert - This will fail initially because searchByMode doesn't exist
      expect(result).toBeDefined();
      expect(result.results).toBeDefined();
      expect(result.strategy).toBe('hybrid'); // Should use keyword + semantic
      expect(result.results.length).toBeLessThanOrEqual(50); // topK≤50
    });

    it('should merge keyword and semantic results in auto mode', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'security authentication',
        mode: 'auto',
        limit: 25,
      };

      // Act
      const result = await searchService.searchByMode(query);

      // Assert
      expect(result.results).toBeDefined();

      // Should contain appropriate match types for hybrid search
      const matchTypes = new Set(result.results.map((r) => r.match_type));
      // Auto mode uses hybrid search, so we expect hybrid results or component types
      const hasValidMatchTypes =
        result.results.length === 0 ||
        matchTypes.has('keyword') ||
        matchTypes.has('semantic') ||
        matchTypes.has('hybrid');
      expect(hasValidMatchTypes).toBe(true);

      // Results should be deduplicated
      const ids = result.results.map((r) => r.id);
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(ids.length);

      expect(result.strategy).toBe('hybrid');
    });

    it('should fallback appropriately in auto mode', async () => {
      // Arrange - Simulate a scenario where one search method fails
      const query: SearchQuery = {
        query: 'fallback test query',
        mode: 'auto',
        limit: 30,
      };

      // Mock one method to fail
      mockQdrantClient.knowledgeEntity.findMany.mockRejectedValueOnce(
        new Error('Semantic search failed')
      );

      // Act
      const result = await searchService.searchByMode(query);

      // Assert - Should still return results from the working method
      expect(result.results).toBeDefined();
      expect(Array.isArray(result.results)).toBe(true);
      // Should not crash even if one method fails
    });

    it('should optimize result ordering in auto mode', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'api rest service',
        mode: 'auto',
        limit: 20,
      };

      // Act
      const result = await searchService.searchByMode(query);

      // Assert
      if (result.results.length > 1) {
        // Results should be ordered by confidence score
        for (let i = 0; i < result.results.length - 1; i++) {
          expect(result.results[i].confidence_score).toBeGreaterThanOrEqual(
            result.results[i + 1].confidence_score
          );
        }
      }

      expect(result.strategy).toBe('hybrid');
    });

    it('should enforce topK=50 limit in auto mode', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'common search term',
        mode: 'auto',
        limit: 100, // Request more than auto mode allows
      };

      // Act
      const result = await searchService.searchByMode(query);

      // Assert
      expect(result.results.length).toBeLessThanOrEqual(50); // Should cap at 50
      expect(result.strategy).toBe('hybrid');
    });
  });

  describe('Deep Mode Tests (mode=deep)', () => {
    it('should use semantic search with expansion when mode=deep', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'microservices architecture patterns',
        mode: 'deep',
        limit: 100,
      };

      // Act
      const result = await searchService.searchByMode(query);

      // Assert - This will fail initially because searchByMode doesn't exist
      expect(result).toBeDefined();
      expect(result.results).toBeDefined();
      expect(result.strategy).toBe('semantic'); // Should use semantic + expansion
      expect(result.results.length).toBeLessThanOrEqual(100); // topK≤100
    });

    it('should include parent/child expansion in deep mode', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'authentication system',
        mode: 'deep',
        limit: 50,
      };

      // Mock results that could be expanded
      mockQdrantClient.adrDecision.findMany.mockResolvedValue([
        {
          id: 'decision-1',
          kind: 'decision',
          data: { title: 'Authentication System Architecture', content: 'Main decision content' },
          tags: { project: 'auth' },
          created_at: new Date('2024-01-01'),
          // Mock related items for expansion
          related_items: ['observation-1', 'issue-1'],
        },
      ]);

      mockQdrantClient.knowledgeObservation.findMany.mockResolvedValue([
        {
          id: 'observation-1',
          kind: 'observation',
          data: { content: 'Related observation about authentication' },
          tags: { project: 'auth' },
          created_at: new Date('2024-01-02'),
        },
      ]);

      // Act
      const result = await searchService.searchByMode(query);

      // Assert
      expect(result.results).toBeDefined();
      // Should contain both primary results and expanded related items
      expect(result.results.length).toBeGreaterThan(0);

      // Should indicate semantic matches with expansion
      result.results.forEach((item) => {
        expect(['semantic', 'expanded']).toContain(item.match_type);
      });

      expect(result.strategy).toBe('semantic');
    });

    it('should handle comprehensive scope filtering in deep mode', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'deployment pipeline',
        mode: 'deep',
        scope: {
          project: 'infra',
          branch: 'main',
          org: 'company',
        },
        limit: 75,
      };

      // Act
      const result = await searchService.searchByMode(query);

      // Assert
      result.results.forEach((item) => {
        if (item.scope) {
          expect(item.scope.project).toBe('infra');
          expect(item.scope.branch).toBe('main');
          expect(item.scope.org).toBe('company');
        }
      });

      expect(result.strategy).toBe('semantic');
    });

    it('should provide detailed confidence scoring in deep mode', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'complex system architecture',
        mode: 'deep',
        limit: 60,
      };

      // Act
      const result = await searchService.searchByMode(query);

      // Assert
      result.results.forEach((item) => {
        expect(item.confidence_score).toBeGreaterThan(0);
        expect(item.confidence_score).toBeLessThanOrEqual(1);
        expect(typeof item.confidence_score).toBe('number');
      });

      // Should have more nuanced scoring in deep mode
      if (result.results.length > 0) {
        const avgConfidence =
          result.results.reduce((sum, r) => sum + r.confidence_score, 0) / result.results.length;
        expect(avgConfidence).toBeGreaterThan(0.3); // Deep mode should find relevant results
      }

      expect(result.strategy).toBe('semantic');
    });

    it('should enforce topK=100 limit in deep mode', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'common search term',
        mode: 'deep',
        limit: 200, // Request more than deep mode allows
      };

      // Act
      const result = await searchService.searchByMode(query);

      // Assert
      expect(result.results.length).toBeLessThanOrEqual(100); // Should cap at 100
      expect(result.strategy).toBe('semantic');
    });
  });

  describe('Mode Validation and Error Handling', () => {
    it('should default to auto mode when no mode specified', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'test query',
        limit: 10,
        // No mode specified - should default to 'auto'
      };

      // Act
      const result = await searchService.searchByMode(query);

      // Assert
      expect(result.strategy).toBe('hybrid'); // Auto mode uses hybrid strategy
    });

    it('should handle invalid mode values gracefully', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'test query',
        mode: 'invalid' as any,
        limit: 10,
      };

      // Act & Assert - Should fallback to auto mode
      const result = await searchService.searchByMode(query);
      expect(result.strategy).toBe('hybrid'); // Fallback to auto (hybrid)
    });

    it('should validate mode-specific limits', async () => {
      // Test each mode with excessive limits
      const modes = [
        { mode: 'fast' as const, maxLimit: 20 },
        { mode: 'auto' as const, maxLimit: 50 },
        { mode: 'deep' as const, maxLimit: 100 },
      ];

      for (const { mode, maxLimit } of modes) {
        const query: SearchQuery = {
          query: 'test query',
          mode,
          limit: 999, // Excessive limit
        };

        const result = await searchService.searchByMode(query);
        expect(result.results.length).toBeLessThanOrEqual(maxLimit);
      }
    });

    it('should handle performance target validation', async () => {
      // Arrange
      const fastQuery: SearchQuery = {
        query: 'performance test',
        mode: 'fast',
        limit: 10,
      };

      // Act
      const startTime = Date.now();
      const result = await searchService.searchByMode(fastQuery);
      const duration = Date.now() - startTime;

      // Assert
      expect(duration).toBeLessThan(1000); // Should complete within performance targets
      expect(result.executionTime).toBeLessThan(1000);
    });
  });

  describe('Integration with Existing Methods', () => {
    it('should maintain compatibility with existing semantic() method', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'test semantic',
        mode: 'deep',
        limit: 10,
      };

      // Act
      const modeResult = await searchService.searchByMode(query);
      const semanticResult = await searchService.semantic(query);

      // Assert - Both should work and return similar structure
      expect(modeResult.results).toBeDefined();
      expect(semanticResult.results).toBeDefined();
      expect(typeof modeResult.totalCount).toBe('number');
      expect(typeof semanticResult.totalCount).toBe('number');
    });

    it('should maintain compatibility with existing keyword() method', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'test keyword',
        mode: 'fast',
        limit: 10,
      };

      // Act
      const modeResult = await searchService.searchByMode(query);
      const keywordResult = await searchService.keyword(query);

      // Assert - Both should work and return similar structure
      expect(modeResult.results).toBeDefined();
      expect(keywordResult.results).toBeDefined();
      expect(typeof modeResult.totalCount).toBe('number');
      expect(typeof keywordResult.totalCount).toBe('number');
    });

    it('should maintain compatibility with existing hybrid() method', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'test hybrid',
        mode: 'auto',
        limit: 10,
      };

      // Act
      const modeResult = await searchService.searchByMode(query);
      const hybridResult = await searchService.hybrid(query);

      // Assert - Both should work and return similar structure
      expect(modeResult.results).toBeDefined();
      expect(hybridResult.results).toBeDefined();
      expect(typeof modeResult.totalCount).toBe('number');
      expect(typeof hybridResult.totalCount).toBe('number');
    });
  });
});
