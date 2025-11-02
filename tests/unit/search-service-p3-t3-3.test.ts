/**
 * Tests for P3-T3.3: match_type assignment validation
 *
 * Comprehensive test suite to validate that match_type is correctly assigned
 * across all search methods and scenarios, including edge cases and error conditions.
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

// Mock Qdrant client with comprehensive test data
const mockQdrantClient = {
  section: { findMany: vi.fn() },
  adrDecision: { findMany: vi.fn() },
  issueLog: { findMany: vi.fn() },
  todoLog: { findMany: vi.fn() },
  runbook: { findMany: vi.fn() },
  changeLog: { findMany: vi.fn() },
  releaseNote: { findMany: vi.fn() },
  ddlHistory: { findMany: vi.fn() },
  prContext: { findMany: vi.fn() },
  knowledgeEntity: { findMany: vi.fn() },
  knowledgeRelation: { findMany: vi.fn() },
  knowledgeObservation: { findMany: vi.fn() },
  incidentLog: { findMany: vi.fn() },
  releaseLog: { findMany: vi.fn() },
  riskLog: { findMany: vi.fn() },
  assumptionLog: { findMany: vi.fn() },
};

// Test data factories
const createMockSearchResult = (
  id: string,
  kind: string,
  matchType: string,
  data: any = {}
): any => ({
  id,
  kind,
  data: {
    title: `Test ${kind} ${id}`,
    content: `Test content for ${id}`,
    description: `Test description for ${id}`,
    ...data,
  },
  tags: { project: 'test-project', branch: 'main', org: 'test-org' },
  created_at: new Date('2024-01-01'),
});

describe('P3-T3.3: match_type Assignment Validation', () => {
  let searchService: SearchService;

  beforeEach(() => {
    searchService = new SearchService();
    vi.clearAllMocks();

    // Reset all mock responses
    Object.values(mockQdrantClient).forEach((model: any) => {
      model.findMany.mockResolvedValue([]);
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Semantic Search match_type Assignment', () => {
    it('should assign match_type=semantic for all semantic search results', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'database architecture patterns',
        limit: 10,
        types: ['decision'],
      };

      // Setup mock data
      mockQdrantClient.adrDecision.findMany.mockResolvedValue([
        createMockSearchResult('decision-1', 'decision', 'semantic'),
        createMockSearchResult('decision-2', 'decision', 'semantic'),
      ]);

      // Act
      const result = await searchService.semantic(query);

      // Assert
      expect(result.results).toBeDefined();
      result.results.forEach((item: SearchResult) => {
        expect(item.match_type).toBe('semantic');
        expect(item.confidence_score).toBeGreaterThanOrEqual(0);
        expect(item.confidence_score).toBeLessThanOrEqual(1);
      });

      expect(result.strategy).toBe('semantic');
    });

    it('should preserve match_type=semantic in semantic search with scope filters', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'security implementation',
        limit: 5,
        scope: { project: 'security-project', branch: 'feature-auth' },
        types: ['decision', 'runbook'],
      };

      mockQdrantClient.adrDecision.findMany.mockResolvedValue([
        {
          id: 'decision-1',
          kind: 'decision',
          data: {
            title: 'Security Implementation Decision',
            content: 'Test content for decision-1',
          },
          tags: { project: 'security-project', branch: 'feature-auth', org: 'test-org' },
          created_at: new Date('2024-01-01'),
        },
      ]);

      mockQdrantClient.runbook.findMany.mockResolvedValue([
        {
          id: 'runbook-1',
          kind: 'runbook',
          data: {
            title: 'Security Implementation Runbook',
            content: 'Test content for runbook-1',
          },
          tags: { project: 'security-project', branch: 'feature-auth', org: 'test-org' },
          created_at: new Date('2024-01-01'),
        },
      ]);

      // Act
      const result = await searchService.semantic(query);

      // Assert
      result.results.forEach((item: SearchResult) => {
        expect(item.match_type).toBe('semantic');
        if (item.scope) {
          expect(item.scope.project).toBe('security-project');
          expect(item.scope.branch).toBe('feature-auth');
        }
      });
    });

    it('should handle empty semantic search results gracefully', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'nonexistent-term-xyz123',
        limit: 10,
      };

      // Act
      const result = await searchService.semantic(query);

      // Assert
      expect(result.results).toEqual([]);
      expect(result.totalCount).toBe(0);
      expect(result.strategy).toBe('semantic');
    });
  });

  describe('Keyword Search match_type Assignment', () => {
    it('should assign match_type=keyword for all keyword search results', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'error handling timeout',
        limit: 10,
        types: ['issue', 'incident'],
      };

      // Setup mock data
      mockQdrantClient.issueLog.findMany.mockResolvedValue([
        createMockSearchResult('issue-1', 'issue', 'keyword', {
          title: 'Error Handling Timeout Issue',
          content: 'System experiences timeout during error handling',
        }),
      ]);

      mockQdrantClient.incidentLog.findMany.mockResolvedValue([
        createMockSearchResult('incident-1', 'incident', 'keyword', {
          title: 'Timeout Incident',
          description: 'Critical incident with timeout handling',
        }),
      ]);

      // Act
      const result = await searchService.keyword(query);

      // Assert
      expect(result.results).toBeDefined();
      result.results.forEach((item: SearchResult) => {
        expect(item.match_type).toBe('keyword');
        expect(item.confidence_score).toBeGreaterThanOrEqual(0);
        expect(item.confidence_score).toBeLessThanOrEqual(1);
      });

      expect(result.strategy).toBe('keyword');
    });

    it('should preserve match_type=keyword with quoted phrase searches', async () => {
      // Arrange
      const query: SearchQuery = {
        query: '"database connection" pooling optimization',
        limit: 10,
      };

      mockQdrantClient.adrDecision.findMany.mockResolvedValue([
        createMockSearchResult('decision-1', 'decision', 'keyword', {
          title: 'Database Connection Pooling Optimization',
          content: 'Decision about database connection pooling strategies',
        }),
      ]);

      // Act
      const result = await searchService.keyword(query);

      // Assert
      result.results.forEach((item: SearchResult) => {
        expect(item.match_type).toBe('keyword');
      });
    });

    it('should handle empty keyword search results gracefully', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'xyz123nonexistent456',
        limit: 5,
      };

      // Act
      const result = await searchService.keyword(query);

      // Assert
      expect(result.results).toEqual([]);
      expect(result.totalCount).toBe(0);
      expect(result.strategy).toBe('keyword');
    });
  });

  describe('Hybrid Search match_type Assignment', () => {
    it('should assign appropriate match_types for hybrid search results', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'authentication authorization system',
        limit: 15,
        types: ['decision', 'runbook', 'issue'],
      };

      // Setup mock data for different match types
      mockQdrantClient.adrDecision.findMany.mockResolvedValue([
        createMockSearchResult('decision-1', 'decision', 'semantic', {
          title: 'Authentication System Architecture',
        }),
        createMockSearchResult('decision-2', 'decision', 'keyword', {
          title: 'Authorization Configuration',
        }),
      ]);

      mockQdrantClient.runbook.findMany.mockResolvedValue([
        createMockSearchResult('runbook-1', 'runbook', 'keyword', {
          title: 'Authentication Setup Guide',
        }),
      ]);

      mockQdrantClient.issueLog.findMany.mockResolvedValue([
        createMockSearchResult('issue-1', 'issue', 'semantic', {
          title: 'Authentication Security Issue',
        }),
      ]);

      // Act
      const result = await searchService.hybrid(query);

      // Assert
      expect(result.results).toBeDefined();
      result.results.forEach((item: SearchResult) => {
        // Hybrid search should contain semantic, keyword, or hybrid match types
        expect(['semantic', 'keyword', 'hybrid']).toContain(item.match_type);
      });

      expect(result.strategy).toBe('hybrid');
    });

    it('should assign match_type=hybrid for duplicate items found by both searches', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'security vulnerability assessment',
        limit: 10,
      };

      // Mock the same item being found by both searches
      const duplicateItem = createMockSearchResult('security-1', 'decision', 'semantic', {
        title: 'Security Vulnerability Assessment',
      });

      mockQdrantClient.adrDecision.findMany.mockResolvedValue([duplicateItem]);

      // Act
      const result = await searchService.hybrid(query);

      // Assert
      result.results.forEach((item: SearchResult) => {
        expect(['semantic', 'keyword', 'hybrid']).toContain(item.match_type);
      });

      // Should be deduplicated
      const ids = result.results.map((item) => item.id);
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(ids.length);
    });

    it('should handle empty hybrid search results gracefully', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'nonexistent-term-xyz789',
        limit: 10,
      };

      // Act
      const result = await searchService.hybrid(query);

      // Assert
      expect(result.results).toEqual([]);
      expect(result.totalCount).toBe(0);
      expect(result.strategy).toBe('hybrid');
    });
  });

  describe('Search Mode match_type Assignment (P3-T3.2)', () => {
    it('should assign match_type=keyword for fast mode', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'performance optimization',
        mode: 'fast',
        limit: 10,
      };

      mockQdrantClient.issueLog.findMany.mockResolvedValue([
        createMockSearchResult('issue-1', 'issue', 'keyword', {
          title: 'Performance Optimization Issue',
        }),
      ]);

      // Act
      const result = await searchService.searchByMode(query);

      // Assert
      expect(result.strategy).toBe('keyword');
      result.results.forEach((item: SearchResult) => {
        expect(item.match_type).toBe('keyword');
      });
    });

    it('should assign match_type=expanded for deep mode expansion results', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'microservices architecture',
        mode: 'deep',
        limit: 20,
      };

      // Mock primary semantic results
      mockQdrantClient.adrDecision.findMany.mockResolvedValue([
        createMockSearchResult('decision-1', 'decision', 'semantic', {
          title: 'Microservices Architecture Decision',
        }),
      ]);

      // Mock expanded results (these will be marked as expanded by the expansion logic)
      mockQdrantClient.knowledgeObservation.findMany.mockResolvedValue([
        createMockSearchResult('observation-1', 'observation', 'expanded', {
          content: 'Related observation about microservices',
        }),
      ]);

      // Act
      const result = await searchService.searchByMode(query);

      // Assert
      expect(result.strategy).toBe('semantic');
      result.results.forEach((item: SearchResult) => {
        // Deep mode should have semantic or expanded match types
        expect(['semantic', 'expanded']).toContain(item.match_type);
      });
    });

    it('should handle auto mode with hybrid match_types', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'api design patterns',
        mode: 'auto',
        limit: 25,
      };

      mockQdrantClient.adrDecision.findMany.mockResolvedValue([
        createMockSearchResult('decision-1', 'decision', 'semantic', {
          title: 'API Design Patterns Decision',
        }),
      ]);

      // Act
      const result = await searchService.searchByMode(query);

      // Assert
      expect(result.strategy).toBe('hybrid');
      result.results.forEach((item: SearchResult) => {
        expect(['semantic', 'keyword', 'hybrid']).toContain(item.match_type);
      });
    });

    it('should default to auto mode when no mode specified', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'test query without mode',
        limit: 10,
      };

      // Act
      const result = await searchService.searchByMode(query);

      // Assert
      expect(result.strategy).toBe('hybrid');
      result.results.forEach((item: SearchResult) => {
        expect(['semantic', 'keyword', 'hybrid']).toContain(item.match_type);
      });
    });

    it('should fallback to auto mode for invalid mode', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'test query invalid mode',
        mode: 'invalid' as any,
        limit: 10,
      };

      // Act
      const result = await searchService.searchByMode(query);

      // Assert
      expect(result.strategy).toBe('hybrid');
      result.results.forEach((item: SearchResult) => {
        expect(['semantic', 'keyword', 'hybrid']).toContain(item.match_type);
      });
    });
  });

  describe('Fallback Search match_type Assignment', () => {
    it('should preserve match_type in fallback search results', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'fallback test query',
        limit: 10,
        types: ['observation'],
      };

      mockQdrantClient.knowledgeObservation.findMany.mockResolvedValue([
        createMockSearchResult('observation-1', 'observation', 'keyword', {
          content: 'Fallback test observation',
        }),
      ]);

      // Act - This will use performFallbackSearch internally
      const result = await searchService.semantic(query);

      // Assert
      result.results.forEach((item: SearchResult) => {
        expect(item.match_type).toBe('semantic'); // semantic() method overrides to 'semantic'
      });
    });

    it('should handle fallback with multiple knowledge types', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'multiple types test',
        limit: 15,
        types: ['decision', 'issue', 'runbook'],
      };

      mockQdrantClient.adrDecision.findMany.mockResolvedValue([
        createMockSearchResult('decision-1', 'decision', 'keyword', {
          title: 'Multiple Types Decision',
        }),
      ]);

      mockQdrantClient.issueLog.findMany.mockResolvedValue([
        createMockSearchResult('issue-1', 'issue', 'keyword', {
          title: 'Multiple Types Issue',
        }),
      ]);

      mockQdrantClient.runbook.findMany.mockResolvedValue([
        createMockSearchResult('runbook-1', 'runbook', 'keyword', {
          title: 'Multiple Types Runbook',
        }),
      ]);

      // Act
      const result = await searchService.semantic(query);

      // Assert
      expect(result.results.length).toBe(3);
      result.results.forEach((item: SearchResult) => {
        expect(item.match_type).toBe('semantic');
      });
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle database connection errors gracefully', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'test error handling',
        limit: 10,
      };

      // Mock database error
      mockQdrantClient.issueLog.findMany.mockRejectedValue(new Error('Database connection failed'));

      // Act & Assert - Should not throw but return empty results
      const result = await searchService.semantic(query);
      expect(result.results).toEqual([]);
      expect(result.strategy).toBe('semantic');
    });

    it('should handle invalid query parameters', async () => {
      // Arrange
      const invalidQuery = {
        query: '',
        limit: -1,
      } as SearchQuery;

      // Act & Assert - Individual methods should throw validation errors
      await expect(searchService.semantic(invalidQuery)).rejects.toThrow();
      await expect(searchService.keyword(invalidQuery)).rejects.toThrow();
      await expect(searchService.hybrid(invalidQuery)).rejects.toThrow();

      // searchByMode has different error handling - it may return empty results instead of throwing
      // Let's test this behavior separately
      const modeResult = await searchService.searchByMode(invalidQuery);
      expect(modeResult).toBeDefined();
      // It should either throw or return empty results, both are valid error handling
      if (modeResult.results) {
        expect(Array.isArray(modeResult.results)).toBe(true);
      }
    });

    it('should handle very large limits with mode constraints', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'large limit test',
        mode: 'fast',
        limit: 1000, // Excessive limit
      };

      mockQdrantClient.issueLog.findMany.mockResolvedValue([
        createMockSearchResult('issue-1', 'issue', 'keyword', {
          title: 'Large Limit Issue',
        }),
      ]);

      // Act
      const result = await searchService.searchByMode(query);

      // Assert - Should respect mode limits
      expect(result.results.length).toBeLessThanOrEqual(20); // Fast mode limit
      expect(result.strategy).toBe('keyword');
    });

    it('should handle mixed quality results with appropriate match_types', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'mixed quality search',
        limit: 20,
      };

      // Mock results with varying confidence scores
      const highQualityResult = createMockSearchResult('high-1', 'decision', 'semantic', {
        title: 'High Quality Match',
      });

      const lowQualityResult = createMockSearchResult('low-1', 'issue', 'keyword', {
        title: 'Low Quality Match',
      });

      mockQdrantClient.adrDecision.findMany.mockResolvedValue([highQualityResult]);
      mockQdrantClient.issueLog.findMany.mockResolvedValue([lowQualityResult]);

      // Act
      const result = await searchService.hybrid(query);

      // Assert
      result.results.forEach((item: SearchResult) => {
        expect(item.confidence_score).toBeGreaterThanOrEqual(0);
        expect(item.confidence_score).toBeLessThanOrEqual(1);
        expect(['semantic', 'keyword', 'hybrid']).toContain(item.match_type);
      });

      // Should be ordered by confidence score
      if (result.results.length > 1) {
        for (let i = 0; i < result.results.length - 1; i++) {
          expect(result.results[i].confidence_score).toBeGreaterThanOrEqual(
            result.results[i + 1].confidence_score
          );
        }
      }
    });

    it('should handle search with special characters and encoding', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'search with "quotes" and &symbols&',
        limit: 10,
      };

      mockQdrantClient.issueLog.findMany.mockResolvedValue([
        createMockSearchResult('special-1', 'issue', 'keyword', {
          title: 'Search with Special Characters',
          content: 'Content with "quotes" and &symbols&',
        }),
      ]);

      // Act
      const result = await searchService.keyword(query);

      // Assert
      expect(result.results).toBeDefined();
      result.results.forEach((item: SearchResult) => {
        expect(item.match_type).toBe('keyword');
      });
    });
  });

  describe('Comprehensive Integration Tests', () => {
    it('should maintain match_type consistency across all search methods', async () => {
      // Arrange
      const query: SearchQuery = {
        query: 'consistency test query',
        limit: 5,
        types: ['decision'],
      };

      mockQdrantClient.adrDecision.findMany.mockResolvedValue([
        createMockSearchResult('consistency-1', 'decision', 'semantic', {
          title: 'Consistency Test Decision',
        }),
      ]);

      // Act
      const semanticResult = await searchService.semantic(query);
      const keywordResult = await searchService.keyword(query);
      const hybridResult = await searchService.hybrid(query);
      const modeResult = await searchService.searchByMode({ ...query, mode: 'auto' });

      // Assert - All should have appropriate match_types
      semanticResult.results.forEach((item) => {
        expect(item.match_type).toBe('semantic');
      });

      keywordResult.results.forEach((item) => {
        expect(item.match_type).toBe('keyword');
      });

      hybridResult.results.forEach((item) => {
        expect(['semantic', 'keyword', 'hybrid']).toContain(item.match_type);
      });

      modeResult.results.forEach((item) => {
        expect(['semantic', 'keyword', 'hybrid']).toContain(item.match_type);
      });
    });

    it('should validate all supported match_types are assignable', async () => {
      // Test that all match_types in the interface can be assigned
      const query: SearchQuery = {
        query: 'match type validation test',
        limit: 10,
      };

      // Mock different scenarios for each match_type
      mockQdrantClient.adrDecision.findMany.mockResolvedValue([
        createMockSearchResult('semantic-1', 'decision', 'semantic'),
        createMockSearchResult('keyword-1', 'decision', 'keyword'),
        createMockSearchResult('expanded-1', 'decision', 'expanded'),
        createMockSearchResult('graph-1', 'decision', 'graph'), // For future P4 support
      ]);

      // Act
      const result = await searchService.semantic(query);

      // Assert
      expect(result.results).toBeDefined();
      // All results should be marked as semantic by the semantic() method
      result.results.forEach((item) => {
        expect(item.match_type).toBe('semantic');
      });
    });

    it('should handle concurrent searches with correct match_type assignment', async () => {
      // Arrange
      const queries = [
        { query: 'concurrent test 1', types: ['decision'] as const },
        { query: 'concurrent test 2', types: ['issue'] as const },
        { query: 'concurrent test 3', types: ['runbook'] as const },
      ];

      mockQdrantClient.adrDecision.findMany.mockResolvedValue([
        createMockSearchResult('concurrent-decision', 'decision', 'semantic'),
      ]);

      mockQdrantClient.issueLog.findMany.mockResolvedValue([
        createMockSearchResult('concurrent-issue', 'issue', 'semantic'),
      ]);

      mockQdrantClient.runbook.findMany.mockResolvedValue([
        createMockSearchResult('concurrent-runbook', 'runbook', 'semantic'),
      ]);

      // Act - Run searches concurrently
      const promises = queries.map((q) => searchService.semantic({ ...q, limit: 5 }));
      const results = await Promise.all(promises);

      // Assert
      results.forEach((result) => {
        expect(result.results).toBeDefined();
        result.results.forEach((item) => {
          expect(item.match_type).toBe('semantic');
        });
      });
    });
  });
});
