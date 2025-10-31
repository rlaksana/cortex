/**
 * Search Service Integration Tests
 * P4-T4.2: Test integration of graph expansion with search service
 *
 * Test Coverage:
 * - Integration of graph expansion with search modes (fast, auto, deep)
 * - End-to-end search with expand parameter
 * - Performance with graph expansion enabled
 * - Error handling in integration scenarios
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { searchService } from '../../../src/services/search/search-service';
import type { SearchQuery } from '../../../src/types/core-interfaces';

// Mock the graph expansion service
vi.mock('../../../src/services/search/graph-expansion-service', () => ({
  graphExpansionService: {
    expandResults: vi.fn(),
  },
}));

// Mock other dependencies
vi.mock('../../../src/services/search/query-parser', () => ({
  queryParser: {
    parseQuery: vi.fn().mockReturnValue({
      parsed: {
        terms: ['test'],
        quotedPhrases: [],
        excludedTerms: [],
      }
    }),
  },
}));

vi.mock('../../../src/db/qdrant', () => ({
  getQdrantClient: vi.fn().mockReturnValue({
    knowledgeRelation: {
      findMany: vi.fn().mockResolvedValue([]),
    },
    section: {
      findMany: vi.fn().mockResolvedValue([]),
    },
    adrDecision: {
      findMany: vi.fn().mockResolvedValue([]),
    },
    issueLog: {
      findMany: vi.fn().mockResolvedValue([]),
    },
    todoLog: {
      findMany: vi.fn().mockResolvedValue([]),
    },
    runbook: {
      findMany: vi.fn().mockResolvedValue([]),
    },
    changeLog: {
      findMany: vi.fn().mockResolvedValue([]),
    },
    releaseNote: {
      findMany: vi.fn().mockResolvedValue([]),
    },
    ddlHistory: {
      findMany: vi.fn().mockResolvedValue([]),
    },
    prContext: {
      findMany: vi.fn().mockResolvedValue([]),
    },
    knowledgeEntity: {
      findMany: vi.fn().mockResolvedValue([]),
    },
    knowledgeObservation: {
      findMany: vi.fn().mockResolvedValue([]),
    },
    incidentLog: {
      findMany: vi.fn().mockResolvedValue([]),
    },
    releaseLog: {
      findMany: vi.fn().mockResolvedValue([]),
    },
    riskLog: {
      findMany: vi.fn().mockResolvedValue([]),
    },
    assumptionLog: {
      findMany: vi.fn().mockResolvedValue([]),
    },
  }),
}));

describe('SearchService Graph Expansion Integration', () => {
  let mockGraphExpansionService: any;

  beforeEach(() => {
    jest.clearAllMocks();

    // Get the mocked graph expansion service
    const { graphExpansionService } = require('../../../src/services/search/graph-expansion-service');
    mockGraphExpansionService = graphExpansionService;
  });

  describe('Integration with Search Modes', () => {
    it('should apply graph expansion in fast mode', async () => {
      // Arrange
      const mockSearchResults = [
        {
          id: 'test-id-1',
          kind: 'decision',
          scope: { project: 'test', branch: 'main' },
          data: { title: 'Test Decision' },
          created_at: '2024-01-01T00:00:00Z',
          confidence_score: 0.9,
          match_type: 'keyword'
        }
      ];

      const mockExpandedResults = [
        ...mockSearchResults,
        {
          id: 'expanded-id-1',
          kind: 'issue',
          scope: { project: 'test', branch: 'main' },
          data: { title: 'Related Issue' },
          created_at: '2024-01-02T00:00:00Z',
          confidence_score: 0.72, // 0.9 * 0.8
          match_type: 'graph'
        }
      ];

      // Mock the graph expansion service
      mockGraphExpansionService.expandResults.mockResolvedValue({
        expandedResults: mockExpandedResults,
        expansionMetadata: {
          totalExpansions: 1,
          expansionType: 'relations',
          neighborsFound: 1,
          neighborsLimited: false,
          executionTime: 50
        }
      });

      const query: SearchQuery = {
        query: 'test query',
        mode: 'fast',
        expand: 'relations',
        limit: 10
      };

      // Act
      const result = await searchService.searchByMode(query);

      // Assert
      expect(mockGraphExpansionService.expandResults).toHaveBeenCalledWith(
        expect.any(Array),
        expect.objectContaining({
          query: 'test query',
          expand: 'relations',
          mode: 'fast'
        })
      );

      expect(result.results).toHaveLength(2);
      expect(result.strategy).toBe('keyword'); // Fast mode uses keyword strategy
      expect(result.executionTime).toBeGreaterThan(50); // Should include expansion time

      // Verify that expanded results are included
      const graphResults = result.results.filter(r => r.match_type === 'graph');
      expect(graphResults).toHaveLength(1);
      expect(graphResults[0].id).toBe('expanded-id-1');
    });

    it('should apply graph expansion in auto mode', async () => {
      // Arrange
      const mockSearchResults = [
        {
          id: 'test-id-1',
          kind: 'decision',
          scope: { project: 'test', branch: 'main' },
          data: { title: 'Test Decision' },
          created_at: '2024-01-01T00:00:00Z',
          confidence_score: 0.9,
          match_type: 'hybrid'
        }
      ];

      mockGraphExpansionService.expandResults.mockResolvedValue({
        expandedResults: mockSearchResults, // No expansion in this test
        expansionMetadata: {
          totalExpansions: 0,
          expansionType: 'relations',
          neighborsFound: 0,
          neighborsLimited: false,
          executionTime: 30
        }
      });

      const query: SearchQuery = {
        query: 'test query',
        mode: 'auto',
        expand: 'relations'
      };

      // Act
      const result = await searchService.searchByMode(query);

      // Assert
      expect(mockGraphExpansionService.expandResults).toHaveBeenCalled();
      expect(result.strategy).toBe('hybrid'); // Auto mode uses hybrid strategy
      expect(result.results).toHaveLength(1);
    });

    it('should apply graph expansion in deep mode', async () => {
      // Arrange
      const mockSearchResults = [
        {
          id: 'test-id-1',
          kind: 'decision',
          scope: { project: 'test', branch: 'main' },
          data: { title: 'Test Decision' },
          created_at: '2024-01-01T00:00:00Z',
          confidence_score: 0.9,
          match_type: 'semantic'
        }
      ];

      mockGraphExpansionService.expandResults.mockResolvedValue({
        expandedResults: mockSearchResults,
        expansionMetadata: {
          totalExpansions: 0,
          expansionType: 'none',
          neighborsFound: 0,
          neighborsLimited: false,
          executionTime: 20
        }
      });

      const query: SearchQuery = {
        query: 'test query',
        mode: 'deep',
        expand: 'none' // No expansion
      };

      // Act
      const result = await searchService.searchByMode(query);

      // Assert
      expect(result.strategy).toBe('semantic'); // Deep mode uses semantic strategy
      expect(mockGraphExpansionService.expandResults).not.toHaveBeenCalled(); // Should not be called when expand=none
    });
  });

  describe('Expand Parameter Validation', () => {
    it('should handle all valid expand values', async () => {
      const validExpandValues = ['relations', 'parents', 'children', 'none'];
      const mockResults = [
        {
          id: 'test-id-1',
          kind: 'decision',
          scope: { project: 'test', branch: 'main' },
          data: { title: 'Test Decision' },
          created_at: '2024-01-01T00:00:00Z',
          confidence_score: 0.9,
          match_type: 'keyword'
        }
      ];

      for (const expandValue of validExpandValues) {
        // Arrange
        mockGraphExpansionService.expandResults.mockResolvedValue({
          expandedResults: mockResults,
          expansionMetadata: {
            totalExpansions: expandValue === 'none' ? 0 : 1,
            expansionType: expandValue,
            neighborsFound: expandValue === 'none' ? 0 : 1,
            neighborsLimited: false,
            executionTime: 25
          }
        });

        const query: SearchQuery = {
          query: 'test query',
          mode: 'auto',
          expand: expandValue as any
        };

        // Act
        const result = await searchService.searchByMode(query);

        // Assert
        expect(result.results).toBeDefined();
        expect(mockGraphExpansionService.expandResults).toHaveBeenCalledWith(
          expect.any(Array),
          expect.objectContaining({ expand: expandValue })
        );

        // Reset mock for next iteration
        mockGraphExpansionService.expandResults.mockClear();
      }
    });

    it('should default expand to none when not specified', async () => {
      // Arrange
      const mockResults = [
        {
          id: 'test-id-1',
          kind: 'decision',
          scope: { project: 'test', branch: 'main' },
          data: { title: 'Test Decision' },
          created_at: '2024-01-01T00:00:00Z',
          confidence_score: 0.9,
          match_type: 'keyword'
        }
      ];

      mockGraphExpansionService.expandResults.mockResolvedValue({
        expandedResults: mockResults,
        expansionMetadata: {
          totalExpansions: 0,
          expansionType: 'none',
          neighborsFound: 0,
          neighborsLimited: false,
          executionTime: 10
        }
      });

      const query: SearchQuery = {
        query: 'test query',
        mode: 'auto'
        // No expand parameter specified
      };

      // Act
      const result = await searchService.searchByMode(query);

      // Assert
      expect(mockGraphExpansionService.expandResults).toHaveBeenCalledWith(
        expect.any(Array),
        expect.objectContaining({ expand: 'none' })
      );
    });
  });

  describe('Performance and Timing', () => {
    it('should include expansion time in total execution time', async () => {
      // Arrange
      const mockResults = [
        {
          id: 'test-id-1',
          kind: 'decision',
          scope: { project: 'test', branch: 'main' },
          data: { title: 'Test Decision' },
          created_at: '2024-01-01T00:00:00Z',
          confidence_score: 0.9,
          match_type: 'keyword'
        }
      ];

      const expansionTime = 150; // 150ms for expansion
      mockGraphExpansionService.expandResults.mockResolvedValue({
        expandedResults: mockResults,
        expansionMetadata: {
          totalExpansions: 1,
          expansionType: 'relations',
          neighborsFound: 1,
          neighborsLimited: false,
          executionTime: expansionTime
        }
      });

      const query: SearchQuery = {
        query: 'test query',
        mode: 'fast',
        expand: 'relations'
      };

      // Act
      const result = await searchService.searchByMode(query);

      // Assert
      expect(result.executionTime).toBeGreaterThanOrEqual(expansionTime);
    });
  });

  describe('Error Handling in Integration', () => {
    it('should handle graph expansion service errors gracefully', async () => {
      // Arrange
      const mockResults = [
        {
          id: 'test-id-1',
          kind: 'decision',
          scope: { project: 'test', branch: 'main' },
          data: { title: 'Test Decision' },
          created_at: '2024-01-01T00:00:00Z',
          confidence_score: 0.9,
          match_type: 'keyword'
        }
      ];

      // Mock expansion service to throw error
      mockGraphExpansionService.expandResults.mockRejectedValue(
        new Error('Graph expansion service error')
      );

      const query: SearchQuery = {
        query: 'test query',
        mode: 'auto',
        expand: 'relations'
      };

      // Act
      const result = await searchService.searchByMode(query);

      // Assert
      expect(result.results).toEqual([]); // Should return empty results on error
      expect(result.strategy).toBe('hybrid');
      expect(result.executionTime).toBeGreaterThan(0);
    });
  });

  describe('Mode-specific Behavior with Expansion', () => {
    it('should respect fast mode limits even with expansion', async () => {
      // Arrange
      const mockResults = Array.from({ length: 20 }, (_, i) => ({
        id: `test-id-${i}`,
        kind: 'decision' as const,
        scope: { project: 'test', branch: 'main' },
        data: { title: `Test Decision ${i}` },
        created_at: '2024-01-01T00:00:00Z',
        confidence_score: 0.9 - (i * 0.01),
        match_type: 'keyword' as const
      }));

      mockGraphExpansionService.expandResults.mockResolvedValue({
        expandedResults: mockResults,
        expansionMetadata: {
          totalExpansions: 5,
          expansionType: 'relations',
          neighborsFound: 5,
          neighborsLimited: false,
          executionTime: 50
        }
      });

      const query: SearchQuery = {
        query: 'test query',
        mode: 'fast',
        expand: 'relations',
        limit: 100 // Large limit, but fast mode should cap it
      };

      // Act
      const result = await searchService.searchByMode(query);

      // Assert
      expect(result.results.length).toBeLessThanOrEqual(20); // Fast mode limit
      expect(result.strategy).toBe('keyword');
    });

    it('should respect auto mode limits with expansion', async () => {
      // Arrange
      const mockResults = Array.from({ length: 60 }, (_, i) => ({
        id: `test-id-${i}`,
        kind: 'decision' as const,
        scope: { project: 'test', branch: 'main' },
        data: { title: `Test Decision ${i}` },
        created_at: '2024-01-01T00:00:00Z',
        confidence_score: 0.9 - (i * 0.01),
        match_type: 'hybrid' as const
      }));

      mockGraphExpansionService.expandResults.mockResolvedValue({
        expandedResults: mockResults,
        expansionMetadata: {
          totalExpansions: 10,
          expansionType: 'relations',
          neighborsFound: 10,
          neighborsLimited: false,
          executionTime: 75
        }
      });

      const query: SearchQuery = {
        query: 'test query',
        mode: 'auto',
        expand: 'relations',
        limit: 100
      };

      // Act
      const result = await searchService.searchByMode(query);

      // Assert
      expect(result.results.length).toBeLessThanOrEqual(50); // Auto mode limit
      expect(result.strategy).toBe('hybrid');
    });

    it('should respect deep mode limits with expansion', async () => {
      // Arrange
      const mockResults = Array.from({ length: 120 }, (_, i) => ({
        id: `test-id-${i}`,
        kind: 'decision' as const,
        scope: { project: 'test', branch: 'main' },
        data: { title: `Test Decision ${i}` },
        created_at: '2024-01-01T00:00:00Z',
        confidence_score: 0.9 - (i * 0.01),
        match_type: 'semantic' as const
      }));

      mockGraphExpansionService.expandResults.mockResolvedValue({
        expandedResults: mockResults,
        expansionMetadata: {
          totalExpansions: 20,
          expansionType: 'relations',
          neighborsFound: 20,
          neighborsLimited: false,
          executionTime: 100
        }
      });

      const query: SearchQuery = {
        query: 'test query',
        mode: 'deep',
        expand: 'relations',
        limit: 150
      };

      // Act
      const result = await searchService.searchByMode(query);

      // Assert
      expect(result.results.length).toBeLessThanOrEqual(100); // Deep mode limit
      expect(result.strategy).toBe('semantic');
    });
  });
});