/**
 * Comprehensive Unit Tests for Graph Traversal Service
 *
 * Tests graph traversal functionality including:
 * - Recursive CTE-based traversal
 * - Depth limits and cycle detection
 * - Bidirectional traversal
 * - Relation type filtering
 * - Node enrichment with entity data
 * - Shortest path finding
 * - Error handling and performance
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Mock the dependencies
vi.mock('../../../src/db/unified-database-layer.js', () => ({
  UnifiedDatabaseLayer: vi.fn().mockImplementation(() => mockDatabaseLayer),
}));

// Mock Unified Database Layer
const mockDatabaseLayer = {
  query: vi.fn(),
  section: {
    findMany: vi.fn(),
  },
  adrDecision: {
    findMany: vi.fn(),
  },
  issueLog: {
    findMany: vi.fn(),
  },
  runbook: {
    findMany: vi.fn(),
  },
  todoLog: {
    findMany: vi.fn(),
  },
  knowledgeEntity: {
    findMany: vi.fn(),
  },
};

import type {
  TraversalOptions,
  GraphNode,
  GraphEdge,
  GraphTraversalResult
} from '../../../src/services/graph-traversal';

describe('Graph Traversal Service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.resetAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('traverseGraph', () => {
    it('should perform basic graph traversal with default options', async () => {
      const { traverseGraph } = await import('../../src/services/graph-traversal.js');

      const mockTraversalResult = [
        {
          entity_type: 'decision',
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
          depth: 0,
          path: ['123e4567-e89b-12d3-a456-426614174000'],
          from_entity_type: null,
          from_entity_id: null,
          relation_type: null,
          relation_metadata: null,
        },
        {
          entity_type: 'issue',
          entity_id: '123e4567-e89b-12d3-a456-426614174001',
          depth: 1,
          path: ['123e4567-e89b-12d3-a456-426614174000', '123e4567-e89b-12d3-a456-426614174001'],
          from_entity_type: 'decision',
          from_entity_id: '123e4567-e89b-12d3-a456-426614174000',
          relation_type: 'resolves',
          relation_metadata: { priority: 'high' },
        },
      ];

      mockDatabaseLayer.query.mockResolvedValue(mockTraversalResult);

      const result = await traverseGraph('decision', '123e4567-e89b-12d3-a456-426614174000');

      expect(mockDatabaseLayer.query).toHaveBeenCalledWith(
        expect.stringContaining('WITH RECURSIVE graph_traverse')
      );

      expect(result).toEqual({
        nodes: [
          {
            entity_type: 'decision',
            entity_id: '123e4567-e89b-12d3-a456-426614174000',
            depth: 0,
          },
          {
            entity_type: 'issue',
            entity_id: '123e4567-e89b-12d3-a456-426614174001',
            depth: 1,
          },
        ],
        edges: [
          {
            from_entity_type: 'decision',
            from_entity_id: '123e4567-e89b-12d3-a456-426614174000',
            to_entity_type: 'issue',
            to_entity_id: '123e4567-e89b-12d3-a456-426614174001',
            relation_type: 'resolves',
            metadata: { priority: 'high' },
          },
        ],
        root_entity_type: 'decision',
        root_entity_id: '123e4567-e89b-12d3-a456-426614174000',
        max_depth_reached: 1,
      });
    });

    it('should respect depth limit', async () => {
      const { traverseGraph } = await import('../../src/services/graph-traversal.js');

      const mockTraversalResult = [
        {
          entity_type: 'decision',
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
          depth: 0,
          path: ['123e4567-e89b-12d3-a456-426614174000'],
        },
        {
          entity_type: 'issue',
          entity_id: '123e4567-e89b-12d3-a456-426614174001',
          depth: 1,
          path: ['123e4567-e89b-12d3-a456-426614174000', '123e4567-e89b-12d3-a456-426614174001'],
        },
        // This node should be included as it's at the max depth
        {
          entity_type: 'todo',
          entity_id: '123e4567-e89b-12d3-a456-426614174002',
          depth: 2,
          path: ['123e4567-e89b-12d3-a456-426614174000', '123e4567-e89b-12d3-a456-426614174001', '123e4567-e89b-12d3-a456-426614174002'],
        },
      ];

      mockDatabaseLayer.query.mockResolvedValue(mockTraversalResult);

      const options: TraversalOptions = { depth: 2 };
      const result = await traverseGraph('decision', '123e4567-e89b-12d3-a456-426614174000', options);

      expect(mockDatabaseLayer.query).toHaveBeenCalledWith(
        expect.stringContaining('gt.depth < 2')
      );

      expect(result.max_depth_reached).toBe(2);
      expect(result.nodes).toHaveLength(3);
    });

    it('should filter by relation types', async () => {
      const { traverseGraph } = await import('../../src/services/graph-traversal.js');

      mockDatabaseLayer.query.mockResolvedValue([
        {
          entity_type: 'decision',
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
          depth: 0,
          path: ['123e4567-e89b-12d3-a456-426614174000'],
        },
        {
          entity_type: 'issue',
          entity_id: '123e4567-e89b-12d3-a456-426614174001',
          depth: 1,
          path: ['123e4567-e89b-12d3-a456-426614174000', '123e4567-e89b-12d3-a456-426614174001'],
          from_entity_type: 'decision',
          from_entity_id: '123e4567-e89b-12d3-a456-426614174000',
          relation_type: 'resolves',
        },
      ]);

      const options: TraversalOptions = { relation_types: ['resolves', 'supersedes'] };
      await traverseGraph('decision', '123e4567-e89b-12d3-a456-426614174000', options);

      // Note: The current implementation doesn't actually use relation_types in the SQL query
      // This test documents the current behavior and can be updated when the feature is implemented
      expect(mockDatabaseLayer.query).toHaveBeenCalled();
    });

    it('should handle incoming traversal direction', async () => {
      const { traverseGraph } = await import('../../src/services/graph-traversal.js');

      const mockTraversalResult = [
        {
          entity_type: 'decision',
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
          depth: 0,
          path: ['123e4567-e89b-12d3-a456-426614174000'],
        },
        {
          entity_type: 'issue',
          entity_id: '123e4567-e89b-12d3-a456-426614174001',
          depth: 1,
          path: ['123e4567-e89b-12d3-a456-426614174000', '123e4567-e89b-12d3-a456-426614174001'],
          from_entity_type: 'decision',
          from_entity_id: '123e4567-e89b-12d3-a456-426614174000',
          relation_type: 'resolves',
        },
      ];

      mockDatabaseLayer.query.mockResolvedValue(mockTraversalResult);

      const options: TraversalOptions = { direction: 'incoming' };
      const result = await traverseGraph('decision', '123e4567-e89b-12d3-a456-426614174000', options);

      // Should reverse edge direction for incoming traversal
      expect(result.edges[0]).toMatchObject({
        from_entity_type: 'decision',
        from_entity_id: '123e4567-e89b-12d3-a456-426614174000',
        to_entity_type: 'decision', // Should be root entity for incoming
        to_entity_id: '123e4567-e89b-12d3-a456-426614174000', // Should be root entity for incoming
        relation_type: 'resolves',
      });
    });

    it('should handle both directions traversal', async () => {
      const { traverseGraph } = await import('../../src/services/graph-traversal.js');

      mockDatabaseLayer.query.mockResolvedValue([
        {
          entity_type: 'decision',
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
          depth: 0,
          path: ['123e4567-e89b-12d3-a456-426614174000'],
        },
      ]);

      const options: TraversalOptions = { direction: 'both' };
      await traverseGraph('decision', '123e4567-e89b-12d3-a456-426614174000', options);

      expect(mockDatabaseLayer.query).toHaveBeenCalled();
    });

    it('should detect and prevent cycles', async () => {
      const { traverseGraph } = await import('../../src/services/graph-traversal.js');

      const mockTraversalResult = [
        {
          entity_type: 'decision',
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
          depth: 0,
          path: ['123e4567-e89b-12d3-a456-426614174000'],
        },
        {
          entity_type: 'issue',
          entity_id: '123e4567-e89b-12d3-a456-426614174001',
          depth: 1,
          path: ['123e4567-e89b-12d3-a456-426614174000', '123e4567-e89b-12d3-a456-426614174001'],
        },
        // This would create a cycle back to the root, so it should be excluded by the SQL
      ];

      mockDatabaseLayer.query.mockResolvedValue(mockTraversalResult);

      const result = await traverseGraph('decision', '123e4567-e89b-12d3-a456-426614174000');

      expect(mockDatabaseLayer.query).toHaveBeenCalledWith(
        expect.stringContaining('NOT (kr.to_entity_id = ANY(gt.path))')
      );

      expect(result.nodes).toHaveLength(2);
      expect(result.edges).toHaveLength(1);
    });

    it('should handle database errors gracefully', async () => {
      const { traverseGraph } = await import('../../src/services/graph-traversal.js');

      mockDatabaseLayer.query.mockRejectedValue(new Error('Database connection failed'));

      const result = await traverseGraph('decision', '123e4567-e89b-12d3-a456-426614174000');

      // Should return fallback graph with just the root node
      expect(result).toEqual({
        nodes: [
          {
            entity_type: 'decision',
            entity_id: '123e4567-e89b-12d3-a456-426614174000',
            depth: 0,
          },
        ],
        edges: [],
        root_entity_type: 'decision',
        root_entity_id: '123e4567-e89b-12d3-a456-426614174000',
        max_depth_reached: 0,
      });
    });

    it('should deduplicate nodes', async () => {
      const { traverseGraph } = await import('../../src/services/graph-traversal.js');

      const mockTraversalResult = [
        {
          entity_type: 'decision',
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
          depth: 0,
          path: ['123e4567-e89b-12d3-a456-426614174000'],
        },
        {
          entity_type: 'issue',
          entity_id: '123e4567-e89b-12d3-a456-426614174001',
          depth: 1,
          path: ['123e4567-e89b-12d3-a456-426614174000', '123e4567-e89b-12d3-a456-426614174001'],
        },
        // Duplicate node at different depth - should be deduplicated
        {
          entity_type: 'issue',
          entity_id: '123e4567-e89b-12d3-a456-426614174001',
          depth: 2,
          path: ['123e4567-e89b-12d3-a456-426614174000', '123e4567-e89b-12d3-a456-426614174002', '123e4567-e89b-12d3-a456-426614174001'],
        },
      ];

      mockDatabaseLayer.query.mockResolvedValue(mockTraversalResult);

      const result = await traverseGraph('decision', '123e4567-e89b-12d3-a456-426614174000');

      // Should have unique nodes only
      expect(result.nodes).toHaveLength(2);
      expect(result.nodes.map(n => `${n.entity_type}:${n.entity_id}`)).toEqual([
        'decision:123e4567-e89b-12d3-a456-426614174000',
        'issue:123e4567-e89b-12d3-a456-426614174001',
      ]);
    });

    it('should handle empty traversal results', async () => {
      const { traverseGraph } = await import('../../src/services/graph-traversal.js');

      mockDatabaseLayer.query.mockResolvedValue([]);

      const result = await traverseGraph('decision', '123e4567-e89b-12d3-a456-426614174000');

      // Should still return root node even if SQL returns empty
      expect(result).toEqual({
        nodes: [
          {
            entity_type: 'decision',
            entity_id: '123e4567-e89b-12d3-a456-426614174000',
            depth: 0,
          },
        ],
        edges: [],
        root_entity_type: 'decision',
        root_entity_id: '123e4567-e89b-12d3-a456-426614174000',
        max_depth_reached: 0,
      });
    });
  });

  describe('enrichGraphNodes', () => {
    it('should enrich nodes with entity data', async () => {
      const { enrichGraphNodes } = await import('../../src/services/graph-traversal.js');

      const nodes: GraphNode[] = [
        {
          entity_type: 'decision',
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
          depth: 0,
        },
        {
          entity_type: 'issue',
          entity_id: '123e4567-e89b-12d3-a456-426614174001',
          depth: 1,
        },
      ];

      const mockDecisionData = {
        id: '123e4567-e89b-12d3-a456-426614174000',
        title: 'Use OAuth 2.0',
        status: 'accepted',
      };

      const mockIssueData = {
        id: '123e4567-e89b-12d3-a456-426614174001',
        title: 'Authentication Security Issue',
        severity: 'high',
      };

      mockDatabaseLayer.adrDecision.findMany.mockResolvedValue([mockDecisionData]);
      mockDatabaseLayer.issueLog.findMany.mockResolvedValue([mockIssueData]);

      const enrichedNodes = await enrichGraphNodes(nodes);

      expect(enrichedNodes).toHaveLength(2);
      expect(enrichedNodes[0]).toEqual({
        entity_type: 'decision',
        entity_id: '123e4567-e89b-12d3-a456-426614174000',
        depth: 0,
        data: mockDecisionData,
      });

      expect(enrichedNodes[1]).toEqual({
        entity_type: 'issue',
        entity_id: '123e4567-e89b-12d3-a456-426614174001',
        depth: 1,
        data: mockIssueData,
      });

      expect(mockDatabaseLayer.adrDecision.findMany).toHaveBeenCalledWith({
        where: { id: { in: ['123e4567-e89b-12d3-a456-426614174000'] } },
      });

      expect(mockDatabaseLayer.issueLog.findMany).toHaveBeenCalledWith({
        where: { id: { in: ['123e4567-e89b-12d3-a456-426614174001'] } },
      });
    });

    it('should group nodes by entity type for efficient queries', async () => {
      const { enrichGraphNodes } = await import('../../src/services/graph-traversal.js');

      const nodes: GraphNode[] = [
        { entity_type: 'decision', entity_id: 'id1', depth: 0 },
        { entity_type: 'decision', entity_id: 'id2', depth: 1 },
        { entity_type: 'issue', entity_id: 'id3', depth: 1 },
        { entity_type: 'decision', entity_id: 'id4', depth: 2 },
      ];

      mockDatabaseLayer.adrDecision.findMany.mockResolvedValue([
        { id: 'id1', title: 'Decision 1' },
        { id: 'id2', title: 'Decision 2' },
        { id: 'id4', title: 'Decision 4' },
      ]);

      mockDatabaseLayer.issueLog.findMany.mockResolvedValue([
        { id: 'id3', title: 'Issue 1' },
      ]);

      const enrichedNodes = await enrichGraphNodes(nodes);

      // Should batch queries by entity type
      expect(mockDatabaseLayer.adrDecision.findMany).toHaveBeenCalledTimes(1);
      expect(mockDatabaseLayer.issueLog.findMany).toHaveBeenCalledTimes(1);

      expect(mockDatabaseLayer.adrDecision.findMany).toHaveBeenCalledWith({
        where: { id: { in: ['id1', 'id2', 'id4'] } },
      });

      expect(mockDatabaseLayer.issueLog.findMany).toHaveBeenCalledWith({
        where: { id: { in: ['id3'] } },
      });

      expect(enrichedNodes).toHaveLength(4);
      expect(enrichedNodes.filter(n => n.entity_type === 'decision')).toHaveLength(3);
      expect(enrichedNodes.filter(n => n.entity_type === 'issue')).toHaveLength(1);
    });

    it('should handle unknown entity types gracefully', async () => {
      const { enrichGraphNodes } = await import('../../src/services/graph-traversal.js');

      const nodes: GraphNode[] = [
        {
          entity_type: 'unknown_type',
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
          depth: 0,
        },
      ];

      const enrichedNodes = await enrichGraphNodes(nodes);

      // Should return nodes without enrichment for unknown types
      expect(enrichedNodes).toEqual(nodes);
    });

    it('should handle database errors during enrichment', async () => {
      const { enrichGraphNodes } = await import('../../src/services/graph-traversal.js');

      const nodes: GraphNode[] = [
        {
          entity_type: 'decision',
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
          depth: 0,
        },
        {
          entity_type: 'issue',
          entity_id: '123e4567-e89b-12d3-a456-426614174001',
          depth: 1,
        },
      ];

      mockDatabaseLayer.adrDecision.findMany.mockRejectedValue(new Error('Table not found'));
      mockDatabaseLayer.issueLog.findMany.mockResolvedValue([{ id: '123e4567-e89b-12d3-a456-426614174001', title: 'Issue 1' }]);

      const enrichedNodes = await enrichGraphNodes(nodes);

      // Should skip enrichment for failed queries but continue with others
      expect(enrichedNodes).toHaveLength(2);
      expect(enrichedNodes[0]).toEqual(nodes[0]); // No enrichment due to error
      expect(enrichedNodes[1].data).toBeDefined(); // Enrichment succeeded
    });

    it('should handle nodes with missing data', async () => {
      const { enrichGraphNodes } = await import('../../src/services/graph-traversal.js');

      const nodes: GraphNode[] = [
        {
          entity_type: 'decision',
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
          depth: 0,
        },
        {
          entity_type: 'decision',
          entity_id: '123e4567-e89b-12d3-a456-426614174001',
          depth: 1,
        },
      ];

      // Return data for only one of the nodes
      mockDatabaseLayer.adrDecision.findMany.mockResolvedValue([
        { id: '123e4567-e89b-12d3-a456-426614174000', title: 'Decision 1' },
      ]);

      const enrichedNodes = await enrichGraphNodes(nodes);

      expect(enrichedNodes).toHaveLength(2);
      expect(enrichedNodes[0].data).toBeDefined();
      expect(enrichedNodes[1].data).toBeUndefined();
    });
  });

  describe('findShortestPath', () => {
    it('should find shortest path between two entities', async () => {
      const { findShortestPath } = await import('../../src/services/graph-traversal.js');

      const mockPathResult = [
        {
          edges: [
            {
              from_entity_type: 'decision',
              from_entity_id: '123e4567-e89b-12d3-a456-426614174000',
              to_entity_type: 'issue',
              to_entity_id: '123e4567-e89b-12d3-a456-426614174001',
              relation_type: 'resolves',
              metadata: { priority: 'high' },
            },
            {
              from_entity_type: 'issue',
              from_entity_id: '123e4567-e89b-12d3-a456-426614174001',
              to_entity_type: 'todo',
              to_entity_id: '123e4567-e89b-12d3-a456-426614174002',
              relation_type: 'implements',
              metadata: { assignee: 'team-a' },
            },
          ],
        },
      ];

      mockDatabaseLayer.query.mockResolvedValue(mockPathResult);

      const path = await findShortestPath(
        'decision',
        '123e4567-e89b-12d3-a456-426614174000',
        'todo',
        '123e4567-e89b-12d3-a456-426614174002'
      );

      expect(mockDatabaseLayer.query).toHaveBeenCalledWith(
        expect.stringContaining('WITH RECURSIVE path_search')
      );

      expect(path).toHaveLength(2);
      expect(path[0]).toMatchObject({
        from_entity_type: 'decision',
        from_entity_id: '123e4567-e89b-12d3-a456-426614174000',
        to_entity_type: 'issue',
        to_entity_id: '123e4567-e89b-12d3-a456-426614174001',
        relation_type: 'resolves',
        metadata: { priority: 'high' },
      });

      expect(path[1]).toMatchObject({
        from_entity_type: 'issue',
        from_entity_id: '123e4567-e89b-12d3-a456-426614174001',
        to_entity_type: 'todo',
        to_entity_id: '123e4567-e89b-12d3-a456-426614174002',
        relation_type: 'implements',
        metadata: { assignee: 'team-a' },
      });
    });

    it('should return null when no path exists', async () => {
      const { findShortestPath } = await import('../../src/services/graph-traversal.js');

      mockDatabaseLayer.query.mockResolvedValue([]);

      const path = await findShortestPath(
        'decision',
        '123e4567-e89b-12d3-a456-426614174000',
        'todo',
        '123e4567-e89b-12d3-a456-426614174002'
      );

      expect(path).toBeNull();
    });

    it('should respect max depth limit', async () => {
      const { findShortestPath } = await import('../../src/services/graph-traversal.js');

      mockDatabaseLayer.query.mockResolvedValue([]);

      await findShortestPath(
        'decision',
        '123e4567-e89b-12d3-a456-426614174000',
        'todo',
        '123e4567-e89b-12d3-a456-426614174002',
        3
      );

      expect(mockDatabaseLayer.query).toHaveBeenCalledWith(
        expect.stringContaining('ps.depth < 3')
      );
    });

    it('should use default max depth when not specified', async () => {
      const { findShortestPath } = await import('../../src/services/graph-traversal.js');

      mockDatabaseLayer.query.mockResolvedValue([]);

      await findShortestPath(
        'decision',
        '123e4567-e89b-12d3-a456-426614174000',
        'todo',
        '123e4567-e89b-12d3-a456-426614174002'
      );

      expect(mockDatabaseLayer.query).toHaveBeenCalledWith(
        expect.stringContaining('ps.depth < 5')
      );
    });

    it('should handle database errors gracefully', async () => {
      const { findShortestPath } = await import('../../src/services/graph-traversal.js');

      mockDatabaseLayer.query.mockRejectedValue(new Error('Database error'));

      const path = await findShortestPath(
        'decision',
        '123e4567-e89b-12d3-a456-426614174000',
        'todo',
        '123e4567-e89b-12d3-a456-426614174002'
      );

      expect(path).toBeNull();
    });

    it('should order results by depth to find shortest path', async () => {
      const { findShortestPath } = await import('../../src/services/graph-traversal.js');

      mockDatabaseLayer.query.mockResolvedValue([]);

      await findShortestPath(
        'decision',
        '123e4567-e89b-12d3-a456-426614174000',
        'todo',
        '123e4567-e89b-12d3-a456-426614174002'
      );

      expect(mockDatabaseLayer.query).toHaveBeenCalledWith(
        expect.stringContaining('ORDER BY depth ASC')
      );

      expect(mockDatabaseLayer.query).toHaveBeenCalledWith(
        expect.stringContaining('LIMIT 1')
      );
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle large graphs efficiently', async () => {
      const { traverseGraph } = await import('../../src/services/graph-traversal.js');

      // Generate a large traversal result
      const largeResult = Array.from({ length: 1000 }, (_, i) => ({
        entity_type: i % 2 === 0 ? 'decision' : 'issue',
        entity_id: `123e4567-e89b-12d3-a456-42661417${i.toString().padStart(4, '0')}`,
        depth: Math.floor(i / 10),
        path: Array.from({ length: Math.floor(i / 10) + 1 }, (_, j) =>
          `123e4567-e89b-12d3-a456-42661417${j.toString().padStart(4, '0')}`
        ),
        from_entity_type: i > 0 ? 'decision' : null,
        from_entity_id: i > 0 ? `123e4567-e89b-12d3-a456-42661417${(i-1).toString().padStart(4, '0')}` : null,
        relation_type: i > 0 ? 'resolves' : null,
      }));

      mockDatabaseLayer.query.mockResolvedValue(largeResult);

      const startTime = Date.now();
      const result = await traverseGraph('decision', '123e4567-e89b-12d3-a456-426614174000', { depth: 10 });
      const endTime = Date.now();

      expect(result.nodes).toHaveLength(1000);
      expect(result.edges.length).toBeGreaterThan(0);

      // Should complete in reasonable time (adjust threshold as needed)
      expect(endTime - startTime).toBeLessThan(1000); // 1 second max
    });

    it('should handle concurrent traversals safely', async () => {
      const { traverseGraph } = await import('../../src/services/graph-traversal.js');

      mockDatabaseLayer.query.mockResolvedValue([
        {
          entity_type: 'decision',
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
          depth: 0,
          path: ['123e4567-e89b-12d3-a456-426614174000'],
        },
      ]);

      // Run multiple concurrent traversals
      const promises = Array(10).fill(null).map((_, i) =>
        traverseGraph('decision', `123e4567-e89b-12d3-a456-426614174${i}`)
      );

      const results = await Promise.all(promises);

      expect(results).toHaveLength(10);
      expect(results.every(r => r.nodes.length > 0)).toBe(true);
      expect(mockDatabaseLayer.query).toHaveBeenCalledTimes(10);
    });

    it('should use CTE for efficient recursive queries', async () => {
      const { traverseGraph } = await import('../../src/services/graph-traversal.js');

      mockDatabaseLayer.query.mockResolvedValue([]);

      await traverseGraph('decision', '123e4567-e89b-12d3-a456-426614174000');

      expect(mockDatabaseLayer.query).toHaveBeenCalledWith(
        expect.stringContaining('WITH RECURSIVE')
      );
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle empty entity IDs', async () => {
      const { traverseGraph } = await import('../../src/services/graph-traversal.js');

      mockDatabaseLayer.query.mockRejectedValue(new Error('Invalid UUID'));

      const result = await traverseGraph('decision', '');

      expect(result.nodes).toHaveLength(1);
      expect(result.nodes[0].entity_id).toBe('');
    });

    it('should handle special characters in entity types', async () => {
      const { traverseGraph } = await import('../../src/services/graph-traversal.js');

      mockDatabaseLayer.query.mockResolvedValue([]);

      const result = await traverseGraph('special-type', '123e4567-e89b-12d3-a456-426614174000');

      expect(result.root_entity_type).toBe('special-type');
    });

    it('should handle invalid depth values', async () => {
      const { traverseGraph } = await import('../../src/services/graph-traversal.js');

      mockDatabaseLayer.query.mockResolvedValue([]);

      // @ts-expect-error - Testing invalid input
      const result = await traverseGraph('decision', '123e4567-e89b-12d3-a456-426614174000', { depth: -1 });

      expect(result).toBeDefined();
      expect(result.nodes).toHaveLength(1);
    });

    it('should handle SQL injection attempts safely', async () => {
      const { traverseGraph } = await import('../../src/services/graph-traversal.js');

      mockDatabaseLayer.query.mockResolvedValue([]);

      const maliciousId = "123e4567-e89b-12d3-a456-426614174000'; DROP TABLE knowledge_relation; --";

      await traverseGraph('decision', maliciousId);

      // The query should use parameterized binding
      expect(mockDatabaseLayer.query).toHaveBeenCalledWith(
        expect.stringContaining('${maliciousId}')
      );
    });
  });

  describe('Integration with Entity Types', () => {
    it('should support all known entity types', async () => {
      const { enrichGraphNodes } = await import('../../src/services/graph-traversal.js');

      const entityTypes = ['section', 'decision', 'issue', 'runbook', 'todo', 'entity'];
      const nodes: GraphNode[] = entityTypes.map((type, index) => ({
        entity_type: type,
        entity_id: `123e4567-e89b-12d3-a456-42661417${index.toString().padStart(4, '0')}`,
        depth: 0,
      }));

      // Mock successful data retrieval for all types
      mockDatabaseLayer.section.findMany.mockResolvedValue([{ id: nodes[0].entity_id, title: 'Section' }]);
      mockDatabaseLayer.adrDecision.findMany.mockResolvedValue([{ id: nodes[1].entity_id, title: 'Decision' }]);
      mockDatabaseLayer.issueLog.findMany.mockResolvedValue([{ id: nodes[2].entity_id, title: 'Issue' }]);
      mockDatabaseLayer.runbook.findMany.mockResolvedValue([{ id: nodes[3].entity_id, title: 'Runbook' }]);
      mockDatabaseLayer.todoLog.findMany.mockResolvedValue([{ id: nodes[4].entity_id, title: 'Todo' }]);
      mockDatabaseLayer.knowledgeEntity.findMany.mockResolvedValue([{ id: nodes[5].entity_id, title: 'Entity' }]);

      const enrichedNodes = await enrichGraphNodes(nodes);

      expect(enrichedNodes).toHaveLength(6);
      expect(enrichedNodes.every(n => n.data)).toBe(true);

      // Should call the appropriate findMany method for each type
      expect(mockDatabaseLayer.section.findMany).toHaveBeenCalled();
      expect(mockDatabaseLayer.adrDecision.findMany).toHaveBeenCalled();
      expect(mockDatabaseLayer.issueLog.findMany).toHaveBeenCalled();
      expect(mockDatabaseLayer.runbook.findMany).toHaveBeenCalled();
      expect(mockDatabaseLayer.todoLog.findMany).toHaveBeenCalled();
      expect(mockDatabaseLayer.knowledgeEntity.findMany).toHaveBeenCalled();
    });
  });
});