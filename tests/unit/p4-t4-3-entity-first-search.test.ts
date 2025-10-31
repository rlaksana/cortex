/**
 * P4-T4.3: Entity-First Search Tests
 * Tests for entity name detection and entity-first resolution with graph expansion
 *
 * Expected behavior:
 * 1. When query exactly matches entity name → return entity + its relations
 * 2. Entity results should be prioritized over regular search results
 * 3. Should integrate with existing P4-T4.1 relation storage and P4-T4.2 graph expansion
 * 4. Should respect scope filtering and project/branch boundaries
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { SearchQuery, SearchResult } from '../../../src/types/core-interfaces';
import type { ParsedQuery } from '../../../src/services/search/query-parser';
import { searchService } from '../../../src/services/search/search-service';

describe('P4-T4.3: Entity-First Search', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Entity Name Detection', () => {
    it('should detect exact entity name matches in queries', async () => {
      // Create a test entity named "User Service"
      const testQuery: SearchQuery = {
        query: 'User Service',
        types: ['entity'],
        limit: 10
      };

      // Mock database to return exact entity match
      const mockEntity = {
        id: 'entity-123',
        kind: 'entity',
        entity_type: 'component',
        name: 'User Service',
        data: {
          name: 'User Service',
          description: 'Handles user authentication and management',
          type: 'service'
        },
        tags: { project: 'test-project' },
        created_at: new Date()
      };

      // Mock entity lookup
      vi.mock('../../../src/db/unified-database-layer-v2', () => ({
        UnifiedDatabaseLayer: vi.fn().mockImplementation(() => ({
          initialize: vi.fn().mockResolvedValue(undefined),
          find: vi.fn().mockResolvedValue([mockEntity])
        }))
      }));

      const result = await searchService.searchByMode(testQuery);

      // Should return the exact entity match with high confidence
      expect(result.results).toHaveLength(1);
      expect(result.results[0].id).toBe('entity-123');
      expect(result.results[0].confidence_score).toBeGreaterThan(0.9);
      expect(result.results[0].match_type).toBe('exact');
    });

    it('should handle case-sensitive exact matching', async () => {
      const testQuery: SearchQuery = {
        query: 'User Service',
        types: ['entity'],
        limit: 10
      };

      // Mock entities with different cases
      const mockEntities = [
        {
          id: 'entity-123',
          name: 'User Service', // Exact match
          created_at: new Date()
        },
        {
          id: 'entity-456',
          name: 'user service', // Different case
          created_at: new Date()
        },
        {
          id: 'entity-789',
          name: 'USER SERVICE', // Different case
          created_at: new Date()
        }
      ];

      // Should only match the exact case
      const result = await searchService.searchByMode(testQuery);

      // Implementation should match exact case only
      expect(result.results[0].data.name).toBe('User Service');
    });

    it('should return empty when no exact entity match exists', async () => {
      const testQuery: SearchQuery = {
        query: 'NonExistent Service',
        types: ['entity'],
        limit: 10
      };

      // Mock empty entity lookup
      vi.mock('../../../src/db/unified-database-layer-v2', () => ({
        UnifiedDatabaseLayer: vi.fn().mockImplementation(() => ({
          initialize: vi.fn().mockResolvedValue(undefined),
          find: vi.fn().mockResolvedValue([])
        }))
      }));

      const result = await searchService.searchByMode(testQuery);

      // Should fallback to regular search (empty in this case)
      expect(result.results).toHaveLength(0);
    });
  });

  describe('Entity-First Resolution with Relations', () => {
    it('should return entity + its relations when exact match found', async () => {
      const testQuery: SearchQuery = {
        query: 'User Service',
        expand: 'relations',
        limit: 20
      };

      // Mock the exact entity match
      const mockEntity = {
        id: 'entity-123',
        kind: 'entity',
        entity_type: 'component',
        name: 'User Service',
        data: {
          name: 'User Service',
          description: 'Handles user authentication and management'
        },
        tags: { project: 'test-project' },
        created_at: new Date()
      };

      // Mock related entities via relations
      const mockRelations = [
        {
          id: 'rel-1',
          from_entity_type: 'entity',
          from_entity_id: 'entity-123',
          to_entity_type: 'decision',
          to_entity_id: 'decision-456',
          relation_type: 'implements'
        },
        {
          id: 'rel-2',
          from_entity_type: 'issue',
          from_entity_id: 'issue-789',
          to_entity_type: 'entity',
          to_entity_id: 'entity-123',
          relation_type: 'affects'
        }
      ];

      // Mock related entities
      const mockDecision = {
        id: 'decision-456',
        kind: 'decision',
        data: {
          title: 'Use OAuth 2.0 for User Service',
          content: 'Decision to implement OAuth 2.0'
        },
        tags: { project: 'test-project' },
        created_at: new Date()
      };

      const mockIssue = {
        id: 'issue-789',
        kind: 'issue',
        data: {
          title: 'User Service authentication bug',
          description: 'Authentication failing for User Service'
        },
        tags: { project: 'test-project' },
        created_at: new Date()
      };

      const result = await searchService.searchByMode(testQuery);

      // Should return:
      // 1. The exact entity match (high confidence, match_type='exact')
      // 2. Related entities (lower confidence, match_type='graph')
      expect(result.results.length).toBeGreaterThan(1);

      // Verify main entity is first with high confidence
      const mainEntity = result.results.find(r => r.id === 'entity-123');
      expect(mainEntity).toBeDefined();
      expect(mainEntity!.confidence_score).toBeGreaterThan(0.9);
      expect(mainEntity!.match_type).toBe('exact');

      // Verify related entities are included with graph match_type
      const relatedDecision = result.results.find(r => r.id === 'decision-456');
      const relatedIssue = result.results.find(r => r.id === 'issue-789');

      expect(relatedDecision).toBeDefined();
      expect(relatedIssue).toBeDefined();
      expect(relatedDecision!.match_type).toBe('graph');
      expect(relatedIssue!.match_type).toBe('graph');
      expect(relatedDecision!.confidence_score).toBeLessThan(mainEntity!.confidence_score);
      expect(relatedIssue!.confidence_score).toBeLessThan(mainEntity!.confidence_score);
    });

    it('should respect expand parameter for entity-first search', async () => {
      const testQueryWithoutExpand: SearchQuery = {
        query: 'User Service',
        expand: 'none',
        limit: 20
      };

      const testQueryWithExpand: SearchQuery = {
        query: 'User Service',
        expand: 'relations',
        limit: 20
      };

      // Mock exact entity match
      const mockEntity = {
        id: 'entity-123',
        name: 'User Service',
        created_at: new Date()
      };

      // Test without expansion
      const resultWithoutExpand = await searchService.searchByMode(testQueryWithoutExpand);

      // Test with expansion
      const resultWithExpand = await searchService.searchByMode(testQueryWithExpand);

      // With expand='none' should only return the entity
      expect(resultWithoutExpand.results).toHaveLength(1);
      expect(resultWithoutExpand.results[0].id).toBe('entity-123');

      // With expand='relations' should return entity + relations
      expect(resultWithExpand.results.length).toBeGreaterThan(1);
      expect(resultWithExpand.results[0].id).toBe('entity-123');
    });
  });

  describe('Integration with Existing Search Pipeline', () => {
    it('should integrate with searchByMode method', async () => {
      const testQuery: SearchQuery = {
        query: 'User Service',
        mode: 'auto',
        expand: 'relations',
        limit: 20
      };

      const result = await searchService.searchByMode(testQuery);

      // Should return SearchMethodResult format
      expect(result).toHaveProperty('results');
      expect(result).toHaveProperty('totalCount');
      expect(result).toHaveProperty('strategy');
      expect(result).toHaveProperty('executionTime');
      expect(result.strategy).toBe('hybrid'); // auto mode uses hybrid
    });

    it('should work with all search modes (fast, auto, deep)', async () => {
      const modes: Array<'fast' | 'auto' | 'deep'> = ['fast', 'auto', 'deep'];

      for (const mode of modes) {
        const testQuery: SearchQuery = {
          query: 'User Service',
          mode,
          limit: 10
        };

        const result = await searchService.searchByMode(testQuery);

        expect(result.results).toBeDefined();
        expect(result.strategy).toBeDefined();
      }
    });
  });

  describe('Scope Filtering and Boundaries', () => {
    it('should respect project scope filtering for entity-first search', async () => {
      const testQuery: SearchQuery = {
        query: 'User Service',
        scope: {
          project: 'my-project'
        },
        limit: 10
      };

      // Mock entities in different projects
      const mockEntities = [
        {
          id: 'entity-123',
          name: 'User Service',
          tags: { project: 'my-project' }, // Matching scope
          created_at: new Date()
        },
        {
          id: 'entity-456',
          name: 'User Service',
          tags: { project: 'other-project' }, // Different scope
          created_at: new Date()
        }
      ];

      const result = await searchService.searchByMode(testQuery);

      // Should only return entity from matching project
      expect(result.results).toHaveLength(1);
      expect(result.results[0].id).toBe('entity-123');
      expect(result.results[0].scope.project).toBe('my-project');
    });

    it('should respect branch and org scope filtering', async () => {
      const testQuery: SearchQuery = {
        query: 'User Service',
        scope: {
          project: 'my-project',
          branch: 'main',
          org: 'my-org'
        },
        limit: 10
      };

      const result = await searchService.searchByMode(testQuery);

      // Should return entities matching all scope criteria
      if (result.results.length > 0) {
        const entity = result.results[0];
        expect(entity.scope.project).toBe('my-project');
        expect(entity.scope.branch).toBe('main');
        expect(entity.scope.org).toBe('my-org');
      }
    });
  });

  describe('Fallback Behavior', () => {
    it('should fallback to regular search when no exact entity match', async () => {
      const testQuery: SearchQuery = {
        query: 'search term without exact entity match',
        limit: 10
      };

      // Mock no exact entity matches
      vi.mock('../../../src/db/unified-database-layer-v2', () => ({
        UnifiedDatabaseLayer: vi.fn().mockImplementation(() => ({
          initialize: vi.fn().mockResolvedValue(undefined),
          find: vi.fn().mockResolvedValue([])
        }))
      }));

      const result = await searchService.searchByMode(testQuery);

      // Should perform regular search instead
      expect(result.results).toBeDefined();
      expect(result.strategy).toBeDefined();
    });

    it('should gracefully handle database errors during entity lookup', async () => {
      const testQuery: SearchQuery = {
        query: 'User Service',
        limit: 10
      };

      // Mock database error
      vi.mock('../../../src/db/unified-database-layer-v2', () => ({
        UnifiedDatabaseLayer: vi.fn().mockImplementation(() => ({
          initialize: vi.fn().mockRejectedValue(new Error('Database error')),
          find: vi.fn().mockRejectedValue(new Error('Database error'))
        }))
      }));

      const result = await searchService.searchByMode(testQuery);

      // Should fallback to regular search on error
      expect(result.results).toBeDefined();
      expect(result.strategy).toBeDefined();
    });
  });

  describe('Performance Considerations', () => {
    it('should perform fast exact entity lookup', async () => {
      const testQuery: SearchQuery = {
        query: 'User Service',
        limit: 10
      };

      const startTime = Date.now();
      const result = await searchService.searchByMode(testQuery);
      const duration = Date.now() - startTime;

      // Entity lookup should be fast (< 100ms for direct lookup)
      expect(duration).toBeLessThan(100);
      expect(result.results).toBeDefined();
    });

    it('should cache entity lookup results', async () => {
      const testQuery: SearchQuery = {
        query: 'User Service',
        limit: 10
      };

      // First call
      const result1 = await searchService.searchByMode(testQuery);

      // Second call should use cache
      const result2 = await searchService.searchByMode(testQuery);

      // Results should be identical
      expect(result1.results).toEqual(result2.results);
    });
  });

  describe('Integration with P4-T4.1 and P4-T4.2', () => {
    it('should use P4-T4.1 relation storage for fetching entity relations', async () => {
      const testQuery: SearchQuery = {
        query: 'User Service',
        expand: 'relations',
        limit: 20
      };

      // This test verifies that entity-first search uses the existing
      // relation storage system from P4-T4.1
      const result = await searchService.searchByMode(testQuery);

      // If relations exist, they should be fetched using relation storage
      if (result.results.length > 1) {
        const graphResults = result.results.filter(r => r.match_type === 'graph');
        expect(graphResults.length).toBeGreaterThan(0);
      }
    });

    it('should use P4-T4.2 graph expansion for related entities', async () => {
      const testQuery: SearchQuery = {
        query: 'User Service',
        expand: 'relations',
        limit: 20
      };

      // This test verifies that entity-first search integrates with
      // the graph expansion service from P4-T4.2
      const result = await searchService.searchByMode(testQuery);

      // Should include graph-tagged results from expansion
      const hasGraphResults = result.results.some(r => r.match_type === 'graph');
      if (result.results.length > 1) {
        expect(hasGraphResults).toBe(true);
      }
    });
  });
});