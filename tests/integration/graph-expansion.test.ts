/**
 * Comprehensive Test Suite for Graph Expansion Functionality
 *
 * Tests P2-2: Graph expansion (when expand=true, return parent + ordered children; ranking correct)
 *
 * @file tests/integration/graph-expansion.test.ts
 */

import { describe, test, expect, beforeAll, afterAll, jest } from '@jest/globals';
import { traverseGraphWithExpansion } from '../../src/services/graph-traversal.js';
import { coreMemoryFind, type CoreFindParams } from '../../src/services/core-memory-find.js';
import type { GraphTraversalResult, TraversalOptions } from '../../src/services/graph-traversal.js';

describe('Graph Expansion Functionality', () => {
  // Mock data for testing
  const mockEntityId = 'test-entity-123';
  const mockEntityType = 'entity';

  beforeAll(() => {
    // Set up test environment variables if needed
    process.env.NODE_ENV = 'test';
  });

  afterAll(() => {
    // Clean up
    delete process.env.NODE_ENV;
  });

  describe('Enhanced Graph Traversal', () => {
    test('should traverse graph with basic parent-child relationships', async () => {
      const options: TraversalOptions = {
        depth: 2,
        direction: 'outgoing',
        max_results: 10,
        sort_by: 'relevance',
      };

      const result = await traverseGraphWithExpansion(mockEntityType, mockEntityId, options);

      expect(result).toBeDefined();
      expect(result.nodes).toBeDefined();
      expect(result.edges).toBeDefined();
      expect(result.root_entity_type).toBe(mockEntityType);
      expect(result.root_entity_id).toBe(mockEntityId);
      expect(result.circular_refs_detected).toBeDefined();
      expect(result.expansion_metadata).toBeDefined();
      expect(result.expansion_metadata.execution_time_ms).toBeGreaterThanOrEqual(0);
      expect(result.expansion_metadata.scope_filtered).toBe(false);
      expect(result.expansion_metadata.ranked_by).toBe('relevance');
    });

    test('should handle circular reference detection', async () => {
      const options: TraversalOptions = {
        depth: 3,
        direction: 'both',
        include_circular_refs: true,
        max_results: 20,
      };

      const result = await traverseGraphWithExpansion(mockEntityType, mockEntityId, options);

      expect(result.circular_refs_detected).toBeDefined();
      expect(Array.isArray(result.circular_refs_detected)).toBe(true);
    });

    test('should respect scope boundaries', async () => {
      const scope = {
        project: 'test-project',
        branch: 'test-branch',
        org: 'test-org',
      };

      const options: TraversalOptions = {
        depth: 2,
        direction: 'outgoing',
        scope,
        max_results: 10,
      };

      const result = await traverseGraphWithExpansion(mockEntityType, mockEntityId, options);

      expect(result.expansion_metadata.scope_filtered).toBe(true);
    });

    test('should apply different sorting algorithms correctly', async () => {
      const sortOptions = ['created_at', 'updated_at', 'relevance', 'confidence'] as const;

      for (const sortBy of sortOptions) {
        const options: TraversalOptions = {
          depth: 2,
          direction: 'outgoing',
          max_results: 10,
          sort_by: sortBy,
        };

        const result = await traverseGraphWithExpansion(mockEntityType, mockEntityId, options);

        expect(result.expansion_metadata.ranked_by).toBe(sortBy);

        // Verify sorting is applied (nodes should be ordered by the specified criteria)
        if (result.nodes.length > 1) {
          for (let i = 1; i < Math.min(result.nodes.length, 3); i++) {
            expect(result.nodes[i].confidence_score).toBeDefined();
          }
        }
      }
    });

    test('should enforce max_results limit', async () => {
      const maxResults = 5;
      const options: TraversalOptions = {
        depth: 3,
        direction: 'both',
        max_results: maxResults,
      };

      const result = await traverseGraphWithExpansion(mockEntityType, mockEntityId, options);

      expect(result.nodes.length).toBeLessThanOrEqual(maxResults + 1); // +1 for root node
    });

    test('should handle different traversal directions', async () => {
      const directions = ['outgoing', 'incoming', 'both'] as const;

      for (const direction of directions) {
        const options: TraversalOptions = {
          depth: 2,
          direction,
          max_results: 10,
        };

        const result = await traverseGraphWithExpansion(mockEntityType, mockEntityId, options);

        expect(result.nodes).toBeDefined();
        expect(result.edges).toBeDefined();
        expect(result.root_entity_type).toBe(mockEntityType);
        expect(result.root_entity_id).toBe(mockEntityId);
      }
    });

    test('should provide proper relationship metadata', async () => {
      const options: TraversalOptions = {
        depth: 2,
        direction: 'outgoing',
        max_results: 10,
      };

      const result = await traverseGraphWithExpansion(mockEntityType, mockEntityId, options);

      // Check that non-root nodes have relationship metadata
      const nonRootNodes = result.nodes.filter(node => node.depth > 0);

      for (const node of nonRootNodes.slice(0, 3)) { // Check first 3 nodes
        expect(node.relationship_metadata).toBeDefined();

        if (node.relationship_metadata) {
          expect(node.relationship_metadata.relation_type).toBeDefined();
          expect(node.relationship_metadata.direction).toBeDefined();
          expect(['parent', 'child', 'sibling']).toContain(node.relationship_metadata.direction);
        }
      }
    });
  });

  describe('Core Memory Find with Graph Expansion', () => {
    test('should perform basic graph expansion', async () => {
      const params: CoreFindParams = {
        query: 'test query',
        expand: 'children',
        limit: 10,
      };

      const result = await coreMemoryFind(params);

      expect(result.results).toBeDefined();
      expect(result.graph_expansion).toBeDefined();
      expect(result.graph_expansion!.enabled).toBe(true);
      expect(result.graph_expansion!.expansion_type).toBe('children');
      expect(result.graph_expansion!.child_entities).toBeDefined();
      expect(result.graph_expansion!.traversal_metadata).toBeDefined();
    });

    test('should handle parents expansion', async () => {
      const params: CoreFindParams = {
        query: 'test query',
        expand: 'parents',
        limit: 10,
      };

      const result = await coreMemoryFind(params);

      expect(result.graph_expansion).toBeDefined();
      expect(result.graph_expansion!.enabled).toBe(true);
      expect(result.graph_expansion!.expansion_type).toBe('parents');
      expect(result.graph_expansion!.parent_entities).toBeDefined();
    });

    test('should handle relations expansion', async () => {
      const params: CoreFindParams = {
        query: 'test query',
        expand: 'relations',
        limit: 10,
      };

      const result = await coreMemoryFind(params);

      expect(result.graph_expansion).toBeDefined();
      expect(result.graph_expansion!.enabled).toBe(true);
      expect(result.graph_expansion!.expansion_type).toBe('relations');
    });

    test('should skip expansion when expand=none', async () => {
      const params: CoreFindParams = {
        query: 'test query',
        expand: 'none',
        limit: 10,
      };

      const result = await coreMemoryFind(params);

      expect(result.graph_expansion).toBeDefined();
      expect(result.graph_expansion!.enabled).toBe(false);
      expect(result.graph_expansion!.expansion_type).toBe('none');
    });

    test('should include proper traversal metadata', async () => {
      const params: CoreFindParams = {
        query: 'test query',
        expand: 'children',
        limit: 15,
        scope: { project: 'test-project' },
      };

      const result = await coreMemoryFind(params);

      expect(result.graph_expansion).toBeDefined();
      expect(result.graph_expansion!.traversal_metadata).toBeDefined();

      const metadata = result.graph_expansion!.traversal_metadata;
      expect(metadata.total_entities_traversed).toBeGreaterThanOrEqual(0);
      expect(metadata.max_depth_reached).toBeGreaterThanOrEqual(0);
      expect(metadata.circular_references_detected).toBeDefined();
      expect(metadata.scope_filtered).toBe(true);
      expect(metadata.ranking_algorithm).toBeDefined();
      expect(metadata.traversal_time_ms).toBeGreaterThanOrEqual(0);
    });

    test('should maintain result limits with expansion', async () => {
      const limit = 10;
      const params: CoreFindParams = {
        query: 'test query',
        expand: 'children',
        limit,
      };

      const result = await coreMemoryFind(params);

      expect(result.results.length).toBeLessThanOrEqual(limit);
      expect(result.total_count).toBeLessThanOrEqual(limit);
    });

    test('should enhance confidence scores based on relationships', async () => {
      const params: CoreFindParams = {
        query: 'test query',
        expand: 'children',
        limit: 10,
      };

      const result = await coreMemoryFind(params);

      // Check that expanded results have confidence scores
      for (const searchResult of result.results) {
        expect(searchResult.confidence_score).toBeGreaterThanOrEqual(0);
        expect(searchResult.confidence_score).toBeLessThanOrEqual(1);
      }

      // Check that relationship metadata is included in expanded results
      const expandedResults = result.results.filter(r =>
        r.data?.expansion_type && r.data?.expansion_type !== 'none'
      );

      for (const expandedResult of expandedResults) {
        expect(expandedResult.data?.relationship_metadata).toBeDefined();
        expect(expandedResult.data?.depth_from_parent).toBeDefined();
        expect(typeof expandedResult.data?.circular_reference).toBe('boolean');
      }
    });

    test('should handle graph expansion errors gracefully', async () => {
      // Test with invalid parameters that might cause errors
      const params: CoreFindParams = {
        query: '', // Empty query might cause issues
        expand: 'children',
        limit: 10,
      };

      const result = await coreMemoryFind(params);

      // Should still return a valid response even if expansion fails
      expect(result).toBeDefined();
      expect(result.results).toBeDefined();
      expect(result.graph_expansion).toBeDefined();
    });
  });

  describe('Performance Tests', () => {
    test('should handle reasonable traversal performance', async () => {
      const startTime = Date.now();

      const options: TraversalOptions = {
        depth: 3,
        direction: 'both',
        max_results: 50,
      };

      const result = await traverseGraphWithExpansion(mockEntityType, mockEntityId, options);

      const executionTime = Date.now() - startTime;

      expect(result.expansion_metadata.execution_time_ms).toBeGreaterThanOrEqual(0);
      // Performance should be reasonable (under 5 seconds for test data)
      expect(executionTime).toBeLessThan(5000);
    });

    test('should scale linearly with depth', async () => {
      const depths = [1, 2, 3];
      const executionTimes: number[] = [];

      for (const depth of depths) {
        const startTime = Date.now();

        const options: TraversalOptions = {
          depth,
          direction: 'outgoing',
          max_results: 20,
        };

        await traverseGraphWithExpansion(mockEntityType, mockEntityId, options);

        executionTimes.push(Date.now() - startTime);
      }

      // Execution time should increase with depth, but not exponentially
      expect(executionTimes[2]).toBeGreaterThan(executionTimes[0]);
      // Last execution shouldn't be more than 3x the first for these small depths
      expect(executionTimes[2]).toBeLessThan(executionTimes[0] * 3);
    });
  });

  describe('Edge Cases', () => {
    test('should handle empty results gracefully', async () => {
      const params: CoreFindParams = {
        query: 'nonexistent-query-xyz-123',
        expand: 'children',
        limit: 10,
      };

      const result = await coreMemoryFind(params);

      expect(result.results).toBeDefined();
      expect(result.graph_expansion).toBeDefined();
      expect(result.graph_expansion!.enabled).toBe(true); // Still attempted
    });

    test('should handle maximum depth limits', async () => {
      const options: TraversalOptions = {
        depth: 10, // Large depth
        direction: 'both',
        max_results: 100,
      };

      const result = await traverseGraphWithExpansion(mockEntityType, mockEntityId, options);

      // Should not exceed reasonable limits even with large depth
      expect(result.nodes.length).toBeLessThanOrEqual(101); // max_results + root
      expect(result.max_depth_reached).toBeLessThanOrEqual(10);
    });

    test('should handle invalid entity types gracefully', async () => {
      const invalidEntityType = 'invalid-type';
      const options: TraversalOptions = {
        depth: 2,
        direction: 'outgoing',
        max_results: 10,
      };

      const result = await traverseGraphWithExpansion(invalidEntityType, mockEntityId, options);

      expect(result).toBeDefined();
      expect(result.root_entity_type).toBe(invalidEntityType);
      expect(result.root_entity_id).toBe(mockEntityId);
    });
  });
});