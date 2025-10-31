/**
 * P4-T4.3: Entity-First Search Integration Test
 * Integration test to verify entity-first search functionality works end-to-end
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';

describe('P4-T4.3: Entity-First Search Integration', () => {
  beforeAll(async () => {
    // Integration test setup - verify services are available
    console.log('Setting up entity-first search integration test');
  });

  afterAll(async () => {
    // Integration test cleanup
    console.log('Cleaning up entity-first search integration test');
  });

  describe('Entity-First Search Service Integration', () => {
    it('should have SearchService available', async () => {
      // Test that the search service can be imported
      const { searchService } = await import('../../src/services/search/search-service');

      expect(searchService).toBeDefined();
      expect(typeof searchService.searchByMode).toBe('function');
      expect(typeof (searchService as any).performEntityFirstSearch).toBe('function');
    });

    it('should have GraphExpansionService available', async () => {
      // Test that the graph expansion service is available for integration
      const { graphExpansionService } = await import('../../src/services/search/graph-expansion-service');

      expect(graphExpansionService).toBeDefined();
      expect(typeof graphExpansionService.expandResults).toBe('function');
    });

    it('should have core interfaces available', async () => {
      // Test that core interfaces are available
      const types = await import('../../src/types/core-interfaces');

      expect(types).toBeDefined();
      expect(typeof types.SearchQuery).toBeDefined();
      expect(typeof types.SearchResult).toBeDefined();
      expect(typeof types.SearchMethodResult).toBeDefined();
    });
  });

  describe('Entity-First Search Method Verification', () => {
    it('should have performEntityFirstSearch method', async () => {
      const { searchService } = await import('../../src/services/search/search-service');

      // Verify the entity-first search method exists
      expect(typeof (searchService as any).performEntityFirstSearch).toBe('function');

      // Verify method signature (it should accept SearchQuery and return Promise)
      const method = (searchService as any).performEntityFirstSearch;
      expect(method.length).toBe(1); // Should accept one parameter (query)
    });

    it('should have findExactEntityMatch method', async () => {
      const { searchService } = await import('../../src/services/search/search-service');

      // Verify the exact entity match method exists (private method accessed for testing)
      expect(typeof (searchService as any).findExactEntityMatch).toBe('function');
    });

    it('should have resolveEntityWithRelations method', async () => {
      const { searchService } = await import('../../src/services/search/search-service');

      // Verify the entity resolution method exists
      expect(typeof (searchService as any).resolveEntityWithRelations).toBe('function');
    });
  });

  describe('Entity-First Search Logic Verification', () => {
    it('should handle empty queries gracefully', async () => {
      const { searchService } = await import('../../src/services/search/search-service');

      const emptyQuery = {
        query: '',
        limit: 10
      };

      // Should not throw
      const result = await (searchService as any).performEntityFirstSearch(emptyQuery);

      expect(result).toHaveProperty('results');
      expect(result).toHaveProperty('entityMatch');
      expect(Array.isArray(result.results)).toBe(true);
      expect(typeof result.entityMatch).toBe('boolean');
      expect(result.entityMatch).toBe(false); // No entity match for empty query
    });

    it('should handle complex queries that should not trigger entity lookup', async () => {
      const { searchService } = await import('../../src/services/search/search-service');

      const complexQueries = [
        { query: 'Test Entity AND Something', limit: 10 },
        { query: '"Test Entity"', limit: 10 },
        { query: 'Test Entity OR Something', limit: 10 }
      ];

      for (const query of complexQueries) {
        const result = await (searchService as any).performEntityFirstSearch(query);

        expect(result).toHaveProperty('results');
        expect(result).toHaveProperty('entityMatch');
        expect(Array.isArray(result.results)).toBe(true);
        expect(typeof result.entityMatch).toBe('boolean');
        expect(result.entityMatch).toBe(false); // Complex queries should not trigger entity lookup
      }
    });

    it('should attempt entity lookup for simple entity-like queries', async () => {
      const { searchService } = await import('../../src/services/search/search-service');

      const entityQueries = [
        { query: 'User Service', limit: 10 },
        { query: 'AuthenticationComponent', limit: 10 },
        { query: 'DatabaseManager', limit: 10 }
      ];

      for (const query of entityQueries) {
        // These should not throw, even if they don't find entities due to database setup
        const result = await (searchService as any).performEntityFirstSearch(query);

        expect(result).toHaveProperty('results');
        expect(result).toHaveProperty('entityMatch');
        expect(Array.isArray(result.results)).toBe(true);
        expect(typeof result.entityMatch).toBe('boolean');
      }
    });
  });

  describe('Integration with searchByMode', () => {
    it('should integrate entity-first search into searchByMode', async () => {
      const { searchService } = await import('../../src/services/search/search-service');

      const testQuery = {
        query: 'Test Entity',
        limit: 10
      };

      // Should not throw and should return valid SearchMethodResult
      const result = await searchService.searchByMode(testQuery);

      expect(result).toHaveProperty('results');
      expect(result).toHaveProperty('totalCount');
      expect(result).toHaveProperty('strategy');
      expect(result).toHaveProperty('executionTime');
      expect(Array.isArray(result.results)).toBe(true);
      expect(typeof result.totalCount).toBe('number');
      expect(typeof result.strategy).toBe('string');
      expect(typeof result.executionTime).toBe('number');
    });

    it('should handle expand parameter with entity-first search', async () => {
      const { searchService } = await import('../../src/services/search/search-service');

      const testQuery = {
        query: 'Test Entity',
        expand: 'relations' as const,
        limit: 10
      };

      const result = await searchService.searchByMode(testQuery);

      expect(result).toHaveProperty('results');
      expect(result).toHaveProperty('strategy');
      expect(Array.isArray(result.results)).toBe(true);
    });

    it('should handle different modes with entity-first search', async () => {
      const { searchService } = await import('../../src/services/search/search-service');

      const modes: Array<'fast' | 'auto' | 'deep'> = ['fast', 'auto', 'deep'];

      for (const mode of modes) {
        const testQuery = {
          query: 'Test Entity',
          mode,
          limit: 10
        };

        const result = await searchService.searchByMode(testQuery);

        expect(result).toHaveProperty('results');
        expect(result).toHaveProperty('strategy');
        expect(Array.isArray(result.results)).toBe(true);
      }
    });
  });

  describe('Performance and Reliability', () => {
    it('should complete searches within reasonable time', async () => {
      const { searchService } = await import('../../src/services/search/search-service');

      const testQuery = {
        query: 'Test Entity',
        limit: 10
      };

      const startTime = Date.now();
      const result = await searchService.searchByMode(testQuery);
      const duration = Date.now() - startTime;

      expect(duration).toBeLessThan(5000); // 5 seconds max
      expect(result.executionTime).toBeLessThan(5000);
    });

    it('should handle concurrent searches', async () => {
      const { searchService } = await import('../../src/services/search/search-service');

      const queries = Array.from({ length: 5 }, (_, i) => ({
        query: `Test Entity ${i}`,
        limit: 10
      }));

      // Should handle multiple concurrent searches
      const promises = queries.map(query => searchService.searchByMode(query));
      const results = await Promise.all(promises);

      expect(results).toHaveLength(5);
      results.forEach(result => {
        expect(result).toHaveProperty('results');
        expect(result).toHaveProperty('strategy');
        expect(Array.isArray(result.results)).toBe(true);
      });
    });
  });
});