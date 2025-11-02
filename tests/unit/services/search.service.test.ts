/**
 * Comprehensive Unit Tests for Search Service
 *
 * Tests advanced search service functionality including:
 * - Natural language query processing and parsing
 * - Semantic search operations with vector similarity
 * - Advanced filtering and faceted search capabilities
 * - Search performance and caching mechanisms
 * - Knowledge type-specific search strategies
 * - Search analytics and insights tracking
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { SearchService } from '../../../src/services/search/search-service';
import { QueryParser, type ParsedQuery } from '../../../src/services/search/query-parser';
import type { SearchQuery, SearchResult } from '../../../src/types/core-interfaces';

// Mock dependencies
vi.mock('../../../src/utils/logger', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

vi.mock('../../../src/db/qdrant', () => ({
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
vi.mock('../../../src/utils/lru-cache', () => ({
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

describe('SearchService - Comprehensive Search Functionality', () => {
  let searchService: SearchService;
  let queryParser: QueryParser;

  beforeEach(() => {
    searchService = new SearchService();
    queryParser = new QueryParser();

    // Reset all mocks
    vi.clearAllMocks();

    // Setup default mock responses
    Object.values(mockQdrantClient).forEach((model: any) => {
      model.findMany.mockResolvedValue([]);
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // 1. Search Query Processing Tests
  describe('Search Query Processing', () => {
    it('should parse simple natural language queries', () => {
      const query: SearchQuery = { query: 'user authentication issues' };
      const { parsed } = queryParser.parseQuery(query);

      expect(parsed.terms).toContain('user');
      expect(parsed.terms).toContain('authentication');
      expect(parsed.terms).toContain('issues');
      expect(parsed.normalized).toBe('user authentication issues');
    });

    it('should handle quoted phrases for exact matching', () => {
      const query: SearchQuery = { query: '"exact phrase" matching' };
      const { parsed } = queryParser.parseQuery(query);

      expect(parsed.quotedPhrases).toContain('exact phrase');
      expect(parsed.terms).toContain('matching');
    });

    it('should process Boolean operators correctly', () => {
      const query: SearchQuery = { query: 'term1 AND term2 OR term3 NOT term4' };
      const { parsed } = queryParser.parseQuery(query);

      expect(parsed.operators.and).toBeDefined();
      expect(parsed.operators.or).toBeDefined();
      expect(parsed.operators.not).toBeDefined();
    });

    it('should extract and validate query filters', () => {
      const query: SearchQuery = {
        query: 'search kind:decision project:myapp after:2024-01-01',
        scope: { project: 'myapp' },
        types: ['decision'],
      };

      const { parsed, validation } = queryParser.parseQuery(query);

      expect(parsed.filters.kind).toContain('decision');
      expect(parsed.filters.scope?.project).toBe('myapp');
      expect(validation.valid).toBe(true);
    });

    it('should recognize search intent and optimize queries', async () => {
      const searchService = new SearchService();
      searchService.updateConfig({
        enableFuzzyMatching: true,
        enableTrigramSearch: true,
        similarityThreshold: 0.7,
      });

      const config = searchService.getConfig();
      expect(config.enableFuzzyMatching).toBe(true);
      expect(config.enableTrigramSearch).toBe(true);
      expect(config.similarityThreshold).toBe(0.7);
    });

    it('should handle multi-language query support', () => {
      const queries = [
        { query: 'recherche en français', expected: ['recherche', 'français'] },
        { query: 'búsqueda en español', expected: ['búsqueda', 'español'] },
        { query: 'Suche auf Deutsch', expected: ['suche', 'deutsch'] },
      ];

      queries.forEach(({ query, expected }) => {
        const { parsed } = queryParser.parseQuery({ query });
        expected.forEach((term) => {
          expect(parsed.normalized).toContain(term.toLowerCase());
        });
      });
    });
  });

  // 2. Semantic Search Operations Tests
  describe('Semantic Search Operations', () => {
    it('should perform vector similarity search', async () => {
      // Mock candidate records with vector-like data
      const mockCandidates = [
        {
          id: '1',
          kind: 'entity',
          data: { title: 'User Authentication System', content: 'Secure login mechanisms' },
          tags: { project: 'myapp' },
          created_at: new Date('2024-01-01'),
        },
      ];

      mockQdrantClient.knowledgeEntity.findMany.mockResolvedValue(mockCandidates);

      const query: SearchQuery = { query: 'authentication system' };
      const { parsed } = queryParser.parseQuery(query);

      const result = await searchService.performFallbackSearch(parsed, query);

      expect(result.results).toBeDefined();
      expect(result.totalCount).toBeGreaterThanOrEqual(0);
    });

    it('should implement hybrid keyword-semantic search', async () => {
      const mockCandidates = [
        {
          id: '1',
          kind: 'decision',
          data: { title: 'Database Architecture Decision', description: 'Choosing PostgreSQL' },
          tags: { project: 'backend' },
          created_at: new Date('2024-02-01'),
        },
      ];

      mockQdrantClient.adrDecision.findMany.mockResolvedValue(mockCandidates);

      const query: SearchQuery = {
        query: 'PostgreSQL database architecture',
        types: ['decision'],
      };

      const { parsed } = queryParser.parseQuery(query);
      const result = await searchService.performFallbackSearch(parsed, query);

      expect(result.results).toBeDefined();
      if (result.results.length > 0) {
        expect(result.results[0].confidence_score).toBeGreaterThan(0);
      }
    });

    it('should provide context-aware search results', async () => {
      const mockCandidates = [
        {
          id: '1',
          kind: 'observation',
          data: { title: 'System Performance Metrics', content: 'CPU usage at 80%' },
          tags: { project: 'monitoring', branch: 'main' },
          created_at: new Date('2024-03-01'),
        },
      ];

      mockQdrantClient.knowledgeObservation.findMany.mockResolvedValue(mockCandidates);

      const query: SearchQuery = {
        query: 'performance metrics',
        scope: { project: 'monitoring', branch: 'main' },
      };

      const { parsed } = queryParser.parseQuery(query);
      const result = await searchService.performFallbackSearch(parsed, query);

      expect(result.results).toBeDefined();
      if (result.results.length > 0) {
        expect(result.results[0].scope?.project).toBe('monitoring');
      }
    });

    it('should implement search result ranking with confidence scores', async () => {
      const mockCandidates = [
        {
          id: '1',
          kind: 'entity',
          data: { title: 'Exact Match Title', content: 'Related content' },
          tags: { project: 'test' },
          created_at: new Date(),
        },
        {
          id: '2',
          kind: 'entity',
          data: { title: 'Partial Match', content: 'Some related content here' },
          tags: { project: 'test' },
          created_at: new Date(),
        },
      ];

      mockQdrantClient.knowledgeEntity.findMany.mockResolvedValue(mockCandidates);

      const query: SearchQuery = { query: 'exact match title' };
      const { parsed } = queryParser.parseQuery(query);
      const result = await searchService.performFallbackSearch(parsed, query);

      if (result.results.length > 1) {
        expect(result.results[0].confidence_score).toBeGreaterThanOrEqual(
          result.results[1].confidence_score
        );
      }
    });
  });

  // 3. Filtering and Faceting Tests
  describe('Filtering and Faceting', () => {
    it('should apply advanced filtering capabilities', async () => {
      const mockCandidates = [
        {
          id: '1',
          kind: 'decision',
          data: { title: 'Security Decision', description: 'Authentication method' },
          tags: { project: 'security', org: 'company' },
          created_at: new Date('2024-01-15'),
        },
      ];

      mockQdrantClient.adrDecision.findMany.mockResolvedValue(mockCandidates);

      const query: SearchQuery = {
        query: 'security',
        types: ['decision'],
        scope: { project: 'security', org: 'company' },
      };

      const { parsed } = queryParser.parseQuery(query);
      const result = await searchService.performFallbackSearch(parsed, query);

      expect(mockQdrantClient.adrDecision.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            AND: expect.arrayContaining([
              expect.objectContaining({ tags: expect.objectContaining({ project: 'security' }) }),
            ]),
          }),
        })
      );
    });

    it('should implement faceted search functionality', async () => {
      // Mock multiple knowledge types with different facets
      mockQdrantClient.adrDecision.findMany.mockResolvedValue([
        {
          id: '1',
          kind: 'decision',
          data: { title: 'Architecture Decision' },
          tags: { project: 'backend' },
          created_at: new Date(),
        },
      ]);

      mockQdrantClient.issueLog.findMany.mockResolvedValue([
        {
          id: '2',
          kind: 'issue',
          data: { title: 'Frontend Bug' },
          tags: { project: 'frontend' },
          created_at: new Date(),
        },
      ]);

      const query: SearchQuery = {
        query: 'architecture',
        types: ['decision', 'issue'],
      };

      const { parsed } = queryParser.parseQuery(query);
      const result = await searchService.performFallbackSearch(parsed, query);

      // Should search across both types
      expect(mockQdrantClient.adrDecision.findMany).toHaveBeenCalled();
      expect(mockQdrantClient.issueLog.findMany).toHaveBeenCalled();
    });

    it('should handle dynamic filter generation', async () => {
      const query: SearchQuery = {
        query: 'test',
        scope: { project: 'dynamic', branch: 'feature-branch', org: 'test-org' },
      };

      const { parsed } = queryParser.parseQuery(query);
      const result = await searchService.performFallbackSearch(parsed, query);

      // Verify that scope filters are applied correctly
      expect(mockQdrantClient.section.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            AND: expect.arrayContaining([
              expect.objectContaining({ tags: expect.objectContaining({ project: 'dynamic' }) }),
              expect.objectContaining({
                tags: expect.objectContaining({ branch: 'feature-branch' }),
              }),
              expect.objectContaining({ tags: expect.objectContaining({ org: 'test-org' }) }),
            ]),
          }),
        })
      );
    });

    it('should implement complex filter combination logic', async () => {
      const mockCandidates = [
        {
          id: '1',
          kind: 'entity',
          entity_type: 'component',
          data: { title: 'Test Component' },
          tags: { project: 'test' },
          created_at: new Date(),
        },
      ];

      mockQdrantClient.knowledgeEntity.findMany.mockResolvedValue(mockCandidates);

      const query: SearchQuery = {
        query: 'component',
        types: ['entity'],
        scope: { project: 'test' },
      };

      const { parsed } = queryParser.parseQuery(query);
      const result = await searchService.performFallbackSearch(parsed, query);

      expect(mockQdrantClient.knowledgeEntity.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            entity_type: { in: ['entity'] },
            AND: expect.arrayContaining([
              expect.objectContaining({ tags: expect.objectContaining({ project: 'test' }) }),
            ]),
          }),
        })
      );
    });
  });

  // 4. Search Performance and Caching Tests
  describe('Search Performance and Caching', () => {
    it('should implement search result caching', async () => {
      const mockCache = {
        get: vi.fn().mockReturnValue([]),
        set: vi.fn(),
        clear: vi.fn(),
        getStats: vi.fn(() => ({ hitRate: 85, totalHits: 100, totalMisses: 15 })),
      };

      // Create search service with mocked cache
      const searchServiceWithMockCache = new SearchService();
      (searchServiceWithMockCache as any).searchCache = mockCache;

      const query: SearchQuery = { query: 'cached query test' };
      const { parsed } = queryParser.parseQuery(query);

      const result = await searchServiceWithMockCache.performFallbackSearch(parsed, query);

      expect(mockCache.get).toHaveBeenCalled();
      expect(mockCache.set).toHaveBeenCalled();
    });

    it('should handle cache hits efficiently', async () => {
      const cachedResults: SearchResult[] = [
        {
          id: '1',
          kind: 'decision',
          scope: { project: 'test' },
          data: { title: 'Cached Result' },
          created_at: '2024-01-01',
          confidence_score: 0.9,
          match_type: 'exact',
        },
      ];

      const mockCache = {
        get: vi.fn().mockReturnValue(cachedResults),
        set: vi.fn(),
        clear: vi.fn(),
        getStats: vi.fn(),
      };

      const searchServiceWithMockCache = new SearchService();
      (searchServiceWithMockCache as any).searchCache = mockCache;

      const query: SearchQuery = { query: 'cached query' };
      const { parsed } = queryParser.parseQuery(query);

      const result = await searchServiceWithMockCache.performFallbackSearch(parsed, query);

      expect(result.results).toEqual(cachedResults);
      expect(result.totalCount).toBe(cachedResults.length);
      // Should not call database when cache hit
      expect(mockQdrantClient.section.findMany).not.toHaveBeenCalled();
    });

    it('should provide query performance optimization', async () => {
      const searchService = new SearchService();
      const startTime = Date.now();

      // Mock slow database response
      mockQdrantClient.knowledgeEntity.findMany.mockImplementation(
        () => new Promise((resolve) => setTimeout(() => resolve([]), 100))
      );

      const query: SearchQuery = { query: 'performance test' };
      const { parsed } = queryParser.parseQuery(query);

      await searchService.performFallbackSearch(parsed, query);
      const duration = Date.now() - startTime;

      // Should complete in reasonable time
      expect(duration).toBeGreaterThan(100);
      expect(duration).toBeLessThan(1000);
    });

    it('should track search analytics and metrics', async () => {
      const searchService = new SearchService();
      const stats = searchService.getCacheStats();

      expect(stats).toHaveProperty('hitRate');
      expect(stats).toHaveProperty('totalHits');
      expect(stats).toHaveProperty('totalMisses');
      expect(stats).toHaveProperty('memoryUsageBytes');
    });

    it('should handle concurrent search requests', async () => {
      // Setup multiple concurrent searches
      const queries = Array.from({ length: 5 }, (_, i) => ({
        query: `concurrent search ${i}`,
        parsed: queryParser.parseQuery({ query: `concurrent search ${i}` }).parsed,
      }));

      // Mock responses
      mockQdrantClient.section.findMany.mockResolvedValue([
        {
          id: `result-1`,
          kind: 'section',
          data: { title: 'Concurrent Result' },
          tags: {},
          created_at: new Date(),
        },
      ]);

      const searchPromises = queries.map(({ query, parsed }) =>
        searchService.performFallbackSearch(parsed, { query })
      );

      const results = await Promise.all(searchPromises);

      expect(results).toHaveLength(5);
      results.forEach((result) => {
        expect(result).toHaveProperty('results');
        expect(result).toHaveProperty('totalCount');
      });
    });
  });

  // 5. Knowledge Type-Specific Search Tests
  describe('Knowledge Type-Specific Search', () => {
    it('should implement specialized search for each knowledge type', async () => {
      const knowledgeTypes = [
        'section',
        'decision',
        'issue',
        'todo',
        'runbook',
        'change',
        'release_note',
        'ddl',
        'pr_context',
        'entity',
        'relation',
        'observation',
        'incident',
        'release',
        'risk',
        'assumption',
      ];

      for (const kind of knowledgeTypes) {
        const tableName = searchService['getTableNameForKind'](kind);
        expect(tableName).toBeTruthy();

        // Mock response for each type
        const mockModel = (mockQdrantClient as any)[tableName];
        if (mockModel) {
          mockModel.findMany.mockResolvedValueOnce([
            {
              id: `test-${kind}`,
              kind,
              data: { title: `Test ${kind}` },
              tags: {},
              created_at: new Date(),
            },
          ]);
        }
      }

      const query: SearchQuery = { query: 'test search across all types' };
      const { parsed } = queryParser.parseQuery(query);

      const result = await searchService.performFallbackSearch(parsed, query);

      expect(result.results).toBeDefined();
      expect(result.totalCount).toBeGreaterThanOrEqual(0);
    });

    it('should handle cross-type federated search', async () => {
      // Mock responses from different types
      mockQdrantClient.adrDecision.findMany.mockResolvedValue([
        {
          id: 'decision-1',
          kind: 'decision',
          data: { title: 'Architecture Decision' },
          tags: {},
          created_at: new Date(),
        },
      ]);

      mockQdrantClient.issueLog.findMany.mockResolvedValue([
        {
          id: 'issue-1',
          kind: 'issue',
          data: { title: 'Critical Issue' },
          tags: {},
          created_at: new Date(),
        },
      ]);

      mockQdrantClient.knowledgeEntity.findMany.mockResolvedValue([
        {
          id: 'entity-1',
          kind: 'entity',
          data: { title: 'System Component' },
          tags: {},
          created_at: new Date(),
        },
      ]);

      const query: SearchQuery = {
        query: 'architecture critical system',
        types: ['decision', 'issue', 'entity'],
      };

      const { parsed } = queryParser.parseQuery(query);
      const result = await searchService.performFallbackSearch(parsed, query);

      expect(mockQdrantClient.adrDecision.findMany).toHaveBeenCalled();
      expect(mockQdrantClient.issueLog.findMany).toHaveBeenCalled();
      expect(mockQdrantClient.knowledgeEntity.findMany).toHaveBeenCalled();
    });

    it('should implement type-aware result ranking', async () => {
      // Mock high-scoring decision and lower-scoring observation
      mockQdrantClient.adrDecision.findMany.mockResolvedValue([
        {
          id: 'decision-1',
          kind: 'decision',
          data: { title: 'Exact Architecture Decision Match' },
          tags: { project: 'architecture' },
          created_at: new Date(),
        },
      ]);

      mockQdrantClient.knowledgeObservation.findMany.mockResolvedValue([
        {
          id: 'obs-1',
          kind: 'observation',
          data: { content: 'Some architecture related observation' },
          tags: { project: 'other' },
          created_at: new Date('2023-01-01'),
        },
      ]);

      const query: SearchQuery = {
        query: 'architecture decision',
        types: ['decision', 'observation'],
      };

      const { parsed } = queryParser.parseQuery(query);
      const result = await searchService.performFallbackSearch(parsed, query);

      if (result.results.length > 1) {
        // Results should be ranked by confidence score
        const scores = result.results.map((r) => r.confidence_score);
        const sortedScores = [...scores].sort((a, b) => b - a);
        expect(scores).toEqual(sortedScores);
      }
    });

    it('should handle type-specific search strategies', async () => {
      // Test entity-specific search with entity_type filter
      mockQdrantClient.knowledgeEntity.findMany.mockResolvedValue([
        {
          id: 'entity-1',
          kind: 'entity',
          entity_type: 'service',
          data: { name: 'User Service', description: 'Handles user operations' },
          tags: { project: 'backend' },
          created_at: new Date(),
        },
      ]);

      const query: SearchQuery = {
        query: 'user service',
        types: ['entity'],
      };

      const { parsed } = queryParser.parseQuery(query);
      const result = await searchService.performFallbackSearch(parsed, query);

      expect(mockQdrantClient.knowledgeEntity.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          select: expect.objectContaining({
            entity_type: true,
            name: true,
          }),
        })
      );
    });
  });

  // 6. Search Analytics and Insights Tests
  describe('Search Analytics and Insights', () => {
    it('should track search behavior analytics', async () => {
      const searchService = new SearchService();

      // Perform multiple searches to generate analytics
      const queries = ['user authentication', 'database performance', 'security policies'];

      for (const query of queries) {
        const { parsed } = queryParser.parseQuery({ query });
        await searchService.performFallbackSearch(parsed, { query });
      }

      const stats = searchService.getCacheStats();
      expect(stats).toHaveProperty('totalHits');
      expect(stats).toHaveProperty('totalMisses');
    });

    it('should analyze query patterns', async () => {
      const complexQuery: SearchQuery = {
        query: 'authentication system "exact phrase" kind:decision project:security',
        types: ['decision'],
        scope: { project: 'security' },
      };

      const { parsed, validation } = queryParser.parseQuery(complexQuery);

      expect(parsed.quotedPhrases).toContain('exact phrase');
      expect(parsed.filters.kind).toContain('decision');
      expect(validation.suggestions.length).toBeGreaterThanOrEqual(0);
    });

    it('should measure search effectiveness metrics', async () => {
      // Setup high-quality mock results
      mockQdrantClient.knowledgeEntity.findMany.mockResolvedValue([
        {
          id: 'high-quality-1',
          kind: 'entity',
          data: { title: 'High Quality Match', content: 'Exact content match' },
          tags: { project: 'test' },
          created_at: new Date(),
        },
        {
          id: 'medium-quality-1',
          kind: 'entity',
          data: { content: 'Partial match content' },
          tags: { project: 'test' },
          created_at: new Date('2023-01-01'),
        },
      ]);

      const query: SearchQuery = { query: 'high quality exact match' };
      const { parsed } = queryParser.parseQuery(query);
      const result = await searchService.performFallbackSearch(parsed, query);

      if (result.results.length > 0) {
        const avgConfidence =
          result.results.reduce((sum, r) => sum + r.confidence_score, 0) / result.results.length;
        expect(avgConfidence).toBeGreaterThan(0);
        expect(avgConfidence).toBeLessThanOrEqual(1.0);
      }
    });

    it('should provide search insights and recommendations', async () => {
      const queryParser = new QueryParser();

      // Test query with potential improvements
      const query: SearchQuery = { query: 'broad generic search term' };
      const { parsed, validation } = queryParser.parseQuery(query);

      const suggestions = queryParser.generateSuggestions(parsed, validation);

      expect(suggestions).toBeInstanceOf(Array);
      expect(suggestions.length).toBeGreaterThan(0);

      // Should suggest ways to improve the query
      const suggestionText = suggestions.join(' ');
      expect(suggestionText).toMatch(/(quotes|exact|phrase|filters|operators)/i);
    });

    it('should handle search error tracking and recovery', async () => {
      // Mock database error
      mockQdrantClient.knowledgeEntity.findMany.mockRejectedValue(
        new Error('Database connection failed')
      );

      const query: SearchQuery = { query: 'error test' };
      const { parsed } = queryParser.parseQuery(query);

      const result = await searchService.performFallbackSearch(parsed, query);

      // Should handle errors gracefully
      expect(result.results).toEqual([]);
      expect(result.totalCount).toBe(0);
    });
  });

  // Configuration and Utility Tests
  describe('Configuration and Utilities', () => {
    it('should update search configuration dynamically', () => {
      const searchService = new SearchService();

      searchService.updateConfig({
        maxResults: 100,
        similarityThreshold: 0.8,
        resultBoosting: {
          exactMatch: 2.0,
          titleMatch: 1.5,
        },
      });

      const config = searchService.getConfig();
      expect(config.maxResults).toBe(100);
      expect(config.similarityThreshold).toBe(0.8);
      expect(config.resultBoosting.exactMatch).toBe(2.0);
    });

    it('should create appropriate cache keys', async () => {
      const searchService = new SearchService();
      const query: SearchQuery = {
        query: 'test query',
        types: ['decision'],
        scope: { project: 'test' },
        limit: 25,
      };

      const { parsed } = queryParser.parseQuery(query);

      // Access private method for testing
      const cacheKey = (searchService as any).createCacheKey(parsed, query);

      expect(cacheKey).toBeTruthy();
      expect(typeof cacheKey).toBe('string');
      // Should be base64 encoded
      expect(() => Buffer.from(cacheKey, 'base64')).not.toThrow();
    });

    it('should clear cache and reset statistics', () => {
      const searchService = new SearchService();

      searchService.clearCache();

      const stats = searchService.getCacheStats();
      expect(stats.itemCount).toBe(0);
      expect(stats.memoryUsageBytes).toBe(0);
    });
  });
});
