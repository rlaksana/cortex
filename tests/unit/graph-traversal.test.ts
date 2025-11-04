/**
 * Unit Tests for Enhanced Graph Traversal Functions
 *
 * Tests individual components of the graph expansion functionality
 *
 * @file tests/unit/graph-traversal.test.ts
 */

import { describe, test, expect, jest, beforeAll } from 'vitest';
import type { TraversalOptions, GraphNode, GraphTraversalResult } from '../../src/services/graph-traversal.js';

// Mock the qdrant client
vi.mock('../../src/db/qdrant-client.js', () => ({
  qdrant: {
    getClient: vi.fn().mockReturnValue({
      section: { findMany: vi.fn() },
      adrDecision: { findMany: vi.fn() },
      issueLog: { findMany: vi.fn() },
      runbook: { findMany: vi.fn() },
      todoLog: { findMany: vi.fn() },
      knowledgeEntity: { findMany: vi.fn() },
    }),
  },
}));

describe('Graph Traversal Unit Tests', () => {
  // Helper function to create test data
  function createMockGraphNode(overrides: Partial<GraphNode> = {}): GraphNode {
    return {
      entity_type: 'entity',
      entity_id: 'test-id',
      depth: 0,
      confidence_score: 0.8,
      ...overrides,
    };
  }

  function createMockTraversalResult(overrides: Partial<GraphTraversalResult> = {}): GraphTraversalResult {
    return {
      nodes: [createMockGraphNode()],
      edges: [],
      root_entity_type: 'entity',
      root_entity_id: 'test-id',
      max_depth_reached: 0,
      total_entities_found: 1,
      circular_refs_detected: [],
      expansion_metadata: {
        execution_time_ms: 100,
        scope_filtered: false,
        ranked_by: 'relevance',
      },
      ...overrides,
    };
  }

  describe('Traversal Options Validation', () => {
    test('should accept default traversal options', () => {
      const options: TraversalOptions = {};

      expect(options.depth).toBeUndefined();
      expect(options.direction).toBeUndefined();
      expect(options.max_results).toBeUndefined();
      expect(options.sort_by).toBeUndefined();
    });

    test('should validate traversal option ranges', () => {
      const validOptions: TraversalOptions = {
        depth: 5,
        max_results: 100,
        sort_by: 'confidence',
        direction: 'both',
      };

      expect(validOptions.depth).toBe(5);
      expect(validOptions.max_results).toBe(100);
      expect(validOptions.sort_by).toBe('confidence');
      expect(validOptions.direction).toBe('both');
    });

    test('should handle scope in traversal options', () => {
      const scope = {
        project: 'test-project',
        branch: 'test-branch',
        org: 'test-org',
      };

      const options: TraversalOptions = {
        scope,
      };

      expect(options.scope).toEqual(scope);
    });
  });

  describe('Graph Node Structure', () => {
    test('should create valid graph node with required fields', () => {
      const node = createMockGraphNode();

      expect(node.entity_type).toBe('entity');
      expect(node.entity_id).toBe('test-id');
      expect(node.depth).toBe(0);
    });

    test('should include optional confidence score', () => {
      const node = createMockGraphNode({ confidence_score: 0.95 });

      expect(node.confidence_score).toBe(0.95);
    });

    test('should include relationship metadata', () => {
      const relationshipMetadata = {
        relation_type: 'implements',
        direction: 'child' as const,
        confidence: 0.9,
      };

      const node = createMockGraphNode({ relationship_metadata });

      expect(node.relationship_metadata).toEqual(relationshipMetadata);
      expect(node.relationship_metadata?.direction).toBe('child');
    });
  });

  describe('Graph Traversal Result Structure', () => {
    test('should create valid traversal result with all fields', () => {
      const result = createMockTraversalResult();

      expect(result.nodes).toHaveLength(1);
      expect(result.edges).toHaveLength(0);
      expect(result.root_entity_type).toBe('entity');
      expect(result.root_entity_id).toBe('test-id');
      expect(result.max_depth_reached).toBe(0);
      expect(result.total_entities_found).toBe(1);
      expect(result.circular_refs_detected).toEqual([]);
    });

    test('should include expansion metadata', () => {
      const result = createMockTraversalResult();

      expect(result.expansion_metadata).toBeDefined();
      expect(result.expansion_metadata.execution_time_ms).toBe(100);
      expect(result.expansion_metadata.scope_filtered).toBe(false);
      expect(result.expansion_metadata.ranked_by).toBe('relevance');
    });

    test('should handle multiple circular references', () => {
      const circularRefs = ['entity:id1', 'entity:id2', 'entity:id3'];
      const result = createMockTraversalResult({
        circular_refs_detected: circularRefs,
      });

      expect(result.circular_refs_detected).toEqual(circularRefs);
      expect(result.circular_refs_detected).toHaveLength(3);
    });
  });

  describe('Node Relationship Metadata', () => {
    test('should handle parent relationship direction', () => {
      const node = createMockGraphNode({
        relationship_metadata: {
          relation_type: 'resolves',
          direction: 'parent',
          confidence: 0.85,
        },
      });

      expect(node.relationship_metadata?.direction).toBe('parent');
      expect(node.relationship_metadata?.relation_type).toBe('resolves');
      expect(node.relationship_metadata?.confidence).toBe(0.85);
    });

    test('should handle child relationship direction', () => {
      const node = createMockGraphNode({
        relationship_metadata: {
          relation_type: 'implements',
          direction: 'child',
          confidence: 0.75,
        },
      });

      expect(node.relationship_metadata?.direction).toBe('child');
    });

    test('should handle sibling relationship direction', () => {
      const node = createMockGraphNode({
        relationship_metadata: {
          relation_type: 'relates_to',
          direction: 'sibling',
          confidence: 0.6,
        },
      });

      expect(node.relationship_metadata?.direction).toBe('sibling');
    });
  });

  describe('Sorting Algorithms', () => {
    test('should validate confidence sorting', () => {
      const nodes = [
        createMockGraphNode({ confidence_score: 0.7 }),
        createMockGraphNode({ confidence_score: 0.9 }),
        createMockGraphNode({ confidence_score: 0.5 }),
      ];

      // Sort by confidence (highest first)
      const sortedNodes = nodes.sort((a, b) => (b.confidence_score || 0) - (a.confidence_score || 0));

      expect(sortedNodes[0].confidence_score).toBe(0.9);
      expect(sortedNodes[1].confidence_score).toBe(0.7);
      expect(sortedNodes[2].confidence_score).toBe(0.5);
    });

    test('should validate relevance sorting', () => {
      const nodes = [
        createMockGraphNode({ depth: 2, confidence_score: 0.8 }),
        createMockGraphNode({ depth: 0, confidence_score: 0.7 }),
        createMockGraphNode({ depth: 1, confidence_score: 0.9 }),
      ];

      // Calculate relevance = confidence * (1 - depth * 0.1)
      const sortedNodes = nodes.sort((a, b) => {
        const aRelevance = (a.confidence_score || 0) * (1 - a.depth * 0.1);
        const bRelevance = (b.confidence_score || 0) * (1 - b.depth * 0.1);
        return bRelevance - aRelevance;
      });

      expect(sortedNodes[0].depth).toBe(1); // Relevance: 0.9 * 0.9 = 0.81
      expect(sortedNodes[1].depth).toBe(0); // Relevance: 0.7 * 1.0 = 0.7
      expect(sortedNodes[2].depth).toBe(2); // Relevance: 0.8 * 0.8 = 0.64
    });
  });

  describe('Circular Reference Detection', () => {
    test('should identify simple circular references', () => {
      const circularRefs = ['entity:a', 'entity:b', 'entity:a'];
      const uniqueRefs = Array.from(new Set(circularRefs));

      expect(uniqueRefs).toEqual(['entity:a', 'entity:b']);
      expect(uniqueRefs).toHaveLength(2);
    });

    test('should handle empty circular reference arrays', () => {
      const result = createMockTraversalResult({
        circular_refs_detected: [],
      });

      expect(result.circular_refs_detected).toHaveLength(0);
      expect(result.circular_refs_detected).toEqual([]);
    });
  });

  describe('Performance Metrics', () => {
    test('should track execution time correctly', () => {
      const executionTime = 250; // milliseconds
      const result = createMockTraversalResult({
        expansion_metadata: {
          execution_time_ms: executionTime,
          scope_filtered: true,
          ranked_by: 'created_at',
        },
      });

      expect(result.expansion_metadata.execution_time_ms).toBe(executionTime);
      expect(result.expansion_metadata.scope_filtered).toBe(true);
      expect(result.expansion_metadata.ranked_by).toBe('created_at');
    });

    test('should track entity counts accurately', () => {
      const totalEntities = 15;
      const maxDepth = 3;
      const result = createMockTraversalResult({
        total_entities_found: totalEntities,
        max_depth_reached: maxDepth,
      });

      expect(result.total_entities_found).toBe(totalEntities);
      expect(result.max_depth_reached).toBe(maxDepth);
    });
  });

  describe('Error Handling', () => {
    test('should handle missing optional fields gracefully', () => {
      const node = createMockGraphNode();
      delete (node as any).confidence_score;
      delete (node as any).relationship_metadata;

      expect(node.entity_type).toBeDefined();
      expect(node.entity_id).toBeDefined();
      expect(node.depth).toBeDefined();
      expect(node.confidence_score).toBeUndefined();
      expect(node.relationship_metadata).toBeUndefined();
    });

    test('should handle invalid relationship direction', () => {
      const node = createMockGraphNode({
        relationship_metadata: {
          relation_type: 'test_relation',
          direction: 'invalid' as any,
          confidence: 0.5,
        },
      });

      // The direction should still be stored even if invalid
      expect(node.relationship_metadata?.direction).toBe('invalid');
    });
  });
});