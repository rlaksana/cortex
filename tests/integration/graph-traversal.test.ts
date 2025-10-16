/**
 * Integration tests for graph traversal
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { memoryStore } from '../../src/services/memory-store.js';
import { memoryFind } from '../../src/services/memory-find.js';
import { dbPool } from '../../src/db/pool.js';
import { traverseGraph, findShortestPath } from '../../src/services/graph-traversal.js';

describe('Graph Traversal Integration Tests', () => {
  let nodeA: string;
  let nodeB: string;
  let nodeC: string;
  let nodeD: string;

  beforeAll(async () => {
    // Setup: Create a test graph
    // A → B → C
    // A → D
    // C → D (creates a diamond pattern)
    const pool = dbPool;
    await pool.query('SELECT 1');

    // Create nodes
    const results = await memoryStore([
      {
        kind: 'entity',
        scope: { project: 'test', branch: 'test' },
        data: {
          entity_type: 'node',
          name: 'node_a',
          data: { label: 'A' },
        },
        tags: { test: true, graph: 'traversal' },
      },
      {
        kind: 'entity',
        scope: { project: 'test', branch: 'test' },
        data: {
          entity_type: 'node',
          name: 'node_b',
          data: { label: 'B' },
        },
        tags: { test: true, graph: 'traversal' },
      },
      {
        kind: 'entity',
        scope: { project: 'test', branch: 'test' },
        data: {
          entity_type: 'node',
          name: 'node_c',
          data: { label: 'C' },
        },
        tags: { test: true, graph: 'traversal' },
      },
      {
        kind: 'entity',
        scope: { project: 'test', branch: 'test' },
        data: {
          entity_type: 'node',
          name: 'node_d',
          data: { label: 'D' },
        },
        tags: { test: true, graph: 'traversal' },
      },
    ]);

    [nodeA, nodeB, nodeC, nodeD] = results.stored.map((r) => r.id);

    // Create edges
    await memoryStore([
      {
        kind: 'relation',
        scope: { project: 'test', branch: 'test' },
        data: {
          from_entity_type: 'entity',
          from_entity_id: nodeA,
          to_entity_type: 'entity',
          to_entity_id: nodeB,
          relation_type: 'connects_to',
        },
        tags: { test: true, graph: 'traversal' },
      },
      {
        kind: 'relation',
        scope: { project: 'test', branch: 'test' },
        data: {
          from_entity_type: 'entity',
          from_entity_id: nodeB,
          to_entity_type: 'entity',
          to_entity_id: nodeC,
          relation_type: 'connects_to',
        },
        tags: { test: true, graph: 'traversal' },
      },
      {
        kind: 'relation',
        scope: { project: 'test', branch: 'test' },
        data: {
          from_entity_type: 'entity',
          from_entity_id: nodeA,
          to_entity_type: 'entity',
          to_entity_id: nodeD,
          relation_type: 'connects_to',
        },
        tags: { test: true, graph: 'traversal' },
      },
      {
        kind: 'relation',
        scope: { project: 'test', branch: 'test' },
        data: {
          from_entity_type: 'entity',
          from_entity_id: nodeC,
          to_entity_type: 'entity',
          to_entity_id: nodeD,
          relation_type: 'connects_to',
        },
        tags: { test: true, graph: 'traversal' },
      },
    ]);
  });

  afterAll(async () => {
    // Cleanup
    const pool = dbPool;
    await pool.query(
      'DELETE FROM knowledge_relation WHERE tags @> \'{"test": true, "graph": "traversal"}\'::jsonb'
    );
    await pool.query(
      'DELETE FROM knowledge_entity WHERE tags @> \'{"test": true, "graph": "traversal"}\'::jsonb'
    );
    // Don't close the shared pool in tests;
  });

  it('should traverse 1-hop outgoing relations', async () => {
    const pool = dbPool;
    const result = await traverseGraph(pool, 'entity', nodeA, { depth: 1, direction: 'outgoing' });

    // Should find: A (depth 0), B (depth 1), D (depth 1)
    expect(result.nodes.length).toBeGreaterThanOrEqual(3);
    expect(result.nodes.some((n) => n.entity_id === nodeA && n.depth === 0)).toBe(true);
    expect(result.nodes.some((n) => n.entity_id === nodeB && n.depth === 1)).toBe(true);
    expect(result.nodes.some((n) => n.entity_id === nodeD && n.depth === 1)).toBe(true);

    // Should have 2 edges: A→B, A→D
    expect(result.edges.length).toBe(2);
  });

  it('should traverse 2-hop outgoing relations', async () => {
    const pool = dbPool;
    const result = await traverseGraph(pool, 'entity', nodeA, { depth: 2, direction: 'outgoing' });

    // Should find: A (depth 0), B (depth 1), D (depth 1), C (depth 2)
    expect(result.nodes.length).toBeGreaterThanOrEqual(4);
    expect(result.nodes.some((n) => n.entity_id === nodeC && n.depth === 2)).toBe(true);

    // Should have 3 edges: A→B, A→D, B→C
    expect(result.edges.length).toBeGreaterThanOrEqual(3);
  });

  it('should detect and prevent cycles', async () => {
    const pool = dbPool;

    // Create a cycle: D → A (back to start)
    await memoryStore([
      {
        kind: 'relation',
        scope: { project: 'test', branch: 'test' },
        data: {
          from_entity_type: 'entity',
          from_entity_id: nodeD,
          to_entity_type: 'entity',
          to_entity_id: nodeA,
          relation_type: 'connects_to',
        },
        tags: { test: true, graph: 'traversal' },
      },
    ]);

    // Traverse with cycle present - should not infinite loop
    const result = await traverseGraph(pool, 'entity', nodeA, { depth: 5, direction: 'outgoing' });

    // Should complete without hanging
    expect(result.nodes.length).toBeGreaterThan(0);
    expect(result.max_depth_reached).toBeLessThanOrEqual(5);
  });

  it('should filter relations by relation_type', async () => {
    const pool = dbPool;

    // Create a relation with different type
    await memoryStore([
      {
        kind: 'relation',
        scope: { project: 'test', branch: 'test' },
        data: {
          from_entity_type: 'entity',
          from_entity_id: nodeA,
          to_entity_type: 'entity',
          to_entity_id: nodeD,
          relation_type: 'special_link',
        },
        tags: { test: true, graph: 'traversal' },
      },
    ]);

    // Traverse with relation type filter
    const result = await traverseGraph(pool, 'entity', nodeA, {
      depth: 2,
      direction: 'outgoing',
      relation_types: ['special_link'],
    });

    // Should only follow special_link edges
    expect(result.edges.every((e) => e.relation_type === 'special_link')).toBe(true);
  });

  it('should traverse incoming relations', async () => {
    const pool = dbPool;

    // Traverse from D backwards
    const result = await traverseGraph(pool, 'entity', nodeD, { depth: 2, direction: 'incoming' });

    // Should find nodes that point TO D: A, C
    expect(result.nodes.some((n) => n.entity_id === nodeA)).toBe(true);
    expect(result.nodes.some((n) => n.entity_id === nodeC)).toBe(true);
  });

  it('should traverse bidirectionally', async () => {
    const pool = dbPool;

    // Traverse from B in both directions
    const result = await traverseGraph(pool, 'entity', nodeB, { depth: 1, direction: 'both' });

    // Should find: A (incoming to B), C (outgoing from B), B itself
    expect(result.nodes.some((n) => n.entity_id === nodeA)).toBe(true);
    expect(result.nodes.some((n) => n.entity_id === nodeB)).toBe(true);
    expect(result.nodes.some((n) => n.entity_id === nodeC)).toBe(true);
  });

  it('should respect depth limits', async () => {
    const pool = dbPool;

    // Traverse with depth=0 (only start node)
    const result = await traverseGraph(pool, 'entity', nodeA, { depth: 0 });

    expect(result.nodes.length).toBe(1);
    expect(result.nodes[0].entity_id).toBe(nodeA);
    expect(result.edges.length).toBe(0);
  });

  it('should integrate with memory.find via traverse parameter', async () => {
    const result = await memoryFind({
      query: 'node_a',
      types: ['entity'],
      traverse: {
        depth: 2,
        relation_types: ['connects_to'],
        direction: 'outgoing',
        start_entity_type: 'entity',
        start_entity_id: nodeA,
      },
    });

    // Should return graph structure
    expect(result.graph).toBeDefined();
    expect(result.graph?.nodes.length).toBeGreaterThan(0);
    expect(result.graph?.edges.length).toBeGreaterThan(0);
  });

  it('should find shortest path between two nodes', async () => {
    const pool = dbPool;

    // Find path from A to C
    const path = await findShortestPath(pool, 'entity', nodeA, 'entity', nodeC);

    expect(path).not.toBeNull();
    expect(path?.length).toBe(2); // A→B→C (2 edges)

    if (path) {
      expect(path[0].from_entity_id).toBe(nodeA);
      expect(path[0].to_entity_id).toBe(nodeB);
      expect(path[1].from_entity_id).toBe(nodeB);
      expect(path[1].to_entity_id).toBe(nodeC);
    }
  });

  it('should return null when no path exists', async () => {
    const pool = dbPool;

    // Create isolated node
    const isolatedResult = await memoryStore([
      {
        kind: 'entity',
        scope: { project: 'test', branch: 'test' },
        data: {
          entity_type: 'node',
          name: 'isolated_node',
          data: { label: 'Isolated' },
        },
        tags: { test: true, graph: 'traversal' },
      },
    ]);
    const isolatedId = isolatedResult.stored[0].id;

    // Find path from A to isolated node (no path exists)
    const path = await findShortestPath(pool, 'entity', nodeA, 'entity', isolatedId);

    expect(path).toBeNull();
  });

  it('should handle large graphs efficiently', async () => {
    const pool = dbPool;
    const startTime = Date.now();

    // Traverse with reasonable depth
    const result = await traverseGraph(pool, 'entity', nodeA, { depth: 3 });

    const duration = Date.now() - startTime;

    // Should complete within performance SLO
    expect(duration).toBeLessThan(200); // Well under 300ms SLO
    expect(result.nodes.length).toBeGreaterThan(0);
  });
});
