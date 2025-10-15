/**
 * Graph traversal service
 *
 * Implements recursive graph traversal using PostgreSQL CTEs.
 * Supports depth limits, cycle detection, and relation type filtering.
 *
 * @module services/graph-traversal
 */

import type { Pool } from 'pg';

export interface TraversalOptions {
  depth?: number; // Max depth (default: 2)
  relation_types?: string[]; // Filter by relation types (e.g., ["resolves", "supersedes"])
  direction?: 'outgoing' | 'incoming' | 'both'; // Traversal direction (default: 'outgoing')
}

export interface GraphNode {
  entity_type: string;
  entity_id: string;
  depth: number;
  data?: Record<string, unknown>; // Optional: include entity data
}

export interface GraphEdge {
  from_entity_type: string;
  from_entity_id: string;
  to_entity_type: string;
  to_entity_id: string;
  relation_type: string;
  metadata?: Record<string, unknown>;
}

export interface GraphTraversalResult {
  nodes: GraphNode[];
  edges: GraphEdge[];
  root_entity_type: string;
  root_entity_id: string;
  max_depth_reached: number;
}

/**
 * Traverse knowledge graph starting from a given entity
 *
 * Uses recursive CTE for efficient graph traversal with:
 * - Depth limits (prevent infinite recursion)
 * - Cycle detection (track visited nodes)
 * - Relation type filtering
 * - Bidirectional traversal support
 *
 * @param pool - PostgreSQL connection pool
 * @param startEntityType - Starting entity type
 * @param startEntityId - Starting entity UUID
 * @param options - Traversal options
 * @returns Graph nodes and edges
 */
export async function traverseGraph(
  pool: Pool,
  startEntityType: string,
  startEntityId: string,
  options: TraversalOptions = {}
): Promise<GraphTraversalResult> {
  const maxDepth = options.depth ?? 2;
  const relationTypes = options.relation_types ?? [];
  const direction = options.direction ?? 'outgoing';

  // Build relation type filter
  const relationTypeFilter = relationTypes.length > 0 ? `AND relation_type = ANY($3::text[])` : '';

  let query: string;

  if (direction === 'outgoing') {
    // Traverse outgoing relations only (from → to)
    query = `
      WITH RECURSIVE graph_traverse AS (
        -- Base case: start node
        SELECT
          $1::text as entity_type,
          $2::uuid as entity_id,
          0 as depth,
          ARRAY[$2::uuid] as path,
          NULL::text as from_entity_type,
          NULL::uuid as from_entity_id,
          NULL::text as relation_type,
          NULL::jsonb as relation_metadata

        UNION ALL

        -- Recursive case: follow outgoing relations
        SELECT
          kr.to_entity_type,
          kr.to_entity_id,
          gt.depth + 1,
          gt.path || kr.to_entity_id,
          kr.from_entity_type,
          kr.from_entity_id,
          kr.relation_type,
          kr.metadata
        FROM graph_traverse gt
        JOIN knowledge_relation kr ON
          kr.from_entity_type = gt.entity_type AND
          kr.from_entity_id = gt.entity_id AND
          kr.deleted_at IS NULL
          ${relationTypeFilter}
        WHERE
          gt.depth < $${relationTypes.length > 0 ? '4' : '3'}
          AND NOT (kr.to_entity_id = ANY(gt.path)) -- Cycle detection
      )
      SELECT * FROM graph_traverse;
    `;
  } else if (direction === 'incoming') {
    // Traverse incoming relations only (to ← from)
    query = `
      WITH RECURSIVE graph_traverse AS (
        -- Base case: start node
        SELECT
          $1::text as entity_type,
          $2::uuid as entity_id,
          0 as depth,
          ARRAY[$2::uuid] as path,
          NULL::text as from_entity_type,
          NULL::uuid as from_entity_id,
          NULL::text as relation_type,
          NULL::jsonb as relation_metadata

        UNION ALL

        -- Recursive case: follow incoming relations
        SELECT
          kr.from_entity_type,
          kr.from_entity_id,
          gt.depth + 1,
          gt.path || kr.from_entity_id,
          kr.from_entity_type,
          kr.from_entity_id,
          kr.relation_type,
          kr.metadata
        FROM graph_traverse gt
        JOIN knowledge_relation kr ON
          kr.to_entity_type = gt.entity_type AND
          kr.to_entity_id = gt.entity_id AND
          kr.deleted_at IS NULL
          ${relationTypeFilter}
        WHERE
          gt.depth < $${relationTypes.length > 0 ? '4' : '3'}
          AND NOT (kr.from_entity_id = ANY(gt.path)) -- Cycle detection
      )
      SELECT * FROM graph_traverse;
    `;
  } else {
    // Traverse both directions (undirected graph)
    query = `
      WITH RECURSIVE graph_traverse AS (
        -- Base case: start node
        SELECT
          $1::text as entity_type,
          $2::uuid as entity_id,
          0 as depth,
          ARRAY[$2::uuid] as path,
          NULL::text as from_entity_type,
          NULL::uuid as from_entity_id,
          NULL::text as to_entity_type,
          NULL::uuid as to_entity_id,
          NULL::text as relation_type,
          NULL::jsonb as relation_metadata

        UNION ALL

        -- Recursive case: follow outgoing relations
        SELECT
          kr.to_entity_type,
          kr.to_entity_id,
          gt.depth + 1,
          gt.path || kr.to_entity_id,
          kr.from_entity_type,
          kr.from_entity_id,
          kr.to_entity_type,
          kr.to_entity_id,
          kr.relation_type,
          kr.metadata
        FROM graph_traverse gt
        JOIN knowledge_relation kr ON
          kr.from_entity_type = gt.entity_type AND
          kr.from_entity_id = gt.entity_id AND
          kr.deleted_at IS NULL
          ${relationTypeFilter}
        WHERE
          gt.depth < $${relationTypes.length > 0 ? '4' : '3'}
          AND NOT (kr.to_entity_id = ANY(gt.path))

        UNION ALL

        -- Recursive case: follow incoming relations
        SELECT
          kr.from_entity_type,
          kr.from_entity_id,
          gt.depth + 1,
          gt.path || kr.from_entity_id,
          kr.from_entity_type,
          kr.from_entity_id,
          kr.to_entity_type,
          kr.to_entity_id,
          kr.relation_type,
          kr.metadata
        FROM graph_traverse gt
        JOIN knowledge_relation kr ON
          kr.to_entity_type = gt.entity_type AND
          kr.to_entity_id = gt.entity_id AND
          kr.deleted_at IS NULL
          ${relationTypeFilter}
        WHERE
          gt.depth < $${relationTypes.length > 0 ? '4' : '3'}
          AND NOT (kr.from_entity_id = ANY(gt.path))
      )
      SELECT * FROM graph_traverse;
    `;
  }

  // Execute query
  const params =
    relationTypes.length > 0
      ? [startEntityType, startEntityId, maxDepth, relationTypes]
      : [startEntityType, startEntityId, maxDepth];

  const result = await pool.query(query, params);

  // Process results into nodes and edges
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const seenNodes = new Set<string>();
  let maxDepthReached = 0;

  for (const row of result.rows) {
    const nodeKey = `${row.entity_type}:${row.entity_id}`;

    // Add node if not seen
    if (!seenNodes.has(nodeKey)) {
      nodes.push({
        entity_type: row.entity_type,
        entity_id: row.entity_id,
        depth: row.depth,
      });
      seenNodes.add(nodeKey);
      maxDepthReached = Math.max(maxDepthReached, row.depth);
    }

    // Add edge if not root node
    if (row.depth > 0 && row.from_entity_type && row.from_entity_id) {
      edges.push({
        from_entity_type: row.from_entity_type,
        from_entity_id: row.from_entity_id,
        to_entity_type: direction === 'incoming' ? startEntityType : row.entity_type,
        to_entity_id: direction === 'incoming' ? startEntityId : row.entity_id,
        relation_type: row.relation_type,
        metadata: row.relation_metadata,
      });
    }
  }

  return {
    nodes,
    edges,
    root_entity_type: startEntityType,
    root_entity_id: startEntityId,
    max_depth_reached: maxDepthReached,
  };
}

/**
 * Enrich graph nodes with entity data
 *
 * Fetches entity data for all nodes in the graph from their respective tables.
 *
 * @param pool - PostgreSQL connection pool
 * @param nodes - Graph nodes to enrich
 * @returns Enriched nodes with data
 */
export async function enrichGraphNodes(pool: Pool, nodes: GraphNode[]): Promise<GraphNode[]> {
  // Group nodes by entity_type for efficient batched queries
  const nodesByType = new Map<string, GraphNode[]>();

  for (const node of nodes) {
    if (!nodesByType.has(node.entity_type)) {
      nodesByType.set(node.entity_type, []);
    }
    nodesByType.get(node.entity_type)!.push(node);
  }

  // Fetch data for each entity type
  const enrichedNodes: GraphNode[] = [];

  for (const [entityType, typeNodes] of nodesByType.entries()) {
    const ids = typeNodes.map((n) => n.entity_id);

    // Map entity_type to table name
    const tableName = getTableName(entityType);
    if (!tableName) {
      // Unknown entity type, skip enrichment
      enrichedNodes.push(...typeNodes);
      continue;
    }

    // Fetch entity data
    const query = `
      SELECT id, *
      FROM ${tableName}
      WHERE id = ANY($1::uuid[])
    `;

    try {
      const result = await pool.query(query, [ids]);
      const dataMap = new Map(result.rows.map((row) => [row.id, row]));

      // Enrich nodes with fetched data
      for (const node of typeNodes) {
        enrichedNodes.push({
          ...node,
          data: dataMap.get(node.entity_id) || undefined,
        });
      }
    } catch (err) {
      // If table doesn't exist or query fails, skip enrichment
      enrichedNodes.push(...typeNodes);
    }
  }

  return enrichedNodes;
}

/**
 * Map entity_type to table name
 *
 * @param entityType - Entity type
 * @returns Table name or null if unknown
 */
function getTableName(entityType: string): string | null {
  const tableMap: Record<string, string> = {
    section: 'section',
    runbook: 'runbook',
    change: 'change_log',
    issue: 'issue_log',
    decision: 'adr_decision',
    todo: 'todo_log',
    release_note: 'release_note',
    ddl: 'ddl_history',
    pr_context: 'pr_context',
    entity: 'knowledge_entity',
  };

  return tableMap[entityType] || null;
}

/**
 * Find shortest path between two entities
 *
 * Uses BFS (via recursive CTE with depth ordering) to find shortest path.
 *
 * @param pool - PostgreSQL connection pool
 * @param fromType - Source entity type
 * @param fromId - Source entity UUID
 * @param toType - Target entity type
 * @param toId - Target entity UUID
 * @param maxDepth - Maximum depth to search (default: 5)
 * @returns Path as array of edges, or null if no path found
 */
export async function findShortestPath(
  pool: Pool,
  fromType: string,
  fromId: string,
  toType: string,
  toId: string,
  maxDepth: number = 5
): Promise<GraphEdge[] | null> {
  const query = `
    WITH RECURSIVE path_search AS (
      -- Base case: start node
      SELECT
        $1::text as entity_type,
        $2::uuid as entity_id,
        0 as depth,
        ARRAY[$2::uuid] as path,
        ARRAY[]::jsonb[] as edges

      UNION ALL

      -- Recursive case: follow relations
      SELECT
        kr.to_entity_type,
        kr.to_entity_id,
        ps.depth + 1,
        ps.path || kr.to_entity_id,
        ps.edges || jsonb_build_object(
          'from_entity_type', kr.from_entity_type,
          'from_entity_id', kr.from_entity_id,
          'to_entity_type', kr.to_entity_type,
          'to_entity_id', kr.to_entity_id,
          'relation_type', kr.relation_type,
          'metadata', kr.metadata
        )::jsonb
      FROM path_search ps
      JOIN knowledge_relation kr ON
        kr.from_entity_type = ps.entity_type AND
        kr.from_entity_id = ps.entity_id AND
        kr.deleted_at IS NULL
      WHERE
        ps.depth < $5
        AND NOT (kr.to_entity_id = ANY(ps.path))
    )
    SELECT edges
    FROM path_search
    WHERE entity_type = $3 AND entity_id = $4
    ORDER BY depth ASC
    LIMIT 1;
  `;

  const result = await pool.query(query, [fromType, fromId, toType, toId, maxDepth]);

  if (result.rows.length === 0) {
    return null; // No path found
  }

  // Parse edges from JSONB array
  const edges: GraphEdge[] = result.rows[0].edges.map((edge: any) => ({
    from_entity_type: edge.from_entity_type,
    from_entity_id: edge.from_entity_id,
    to_entity_type: edge.to_entity_type,
    to_entity_id: edge.to_entity_id,
    relation_type: edge.relation_type,
    metadata: edge.metadata,
  }));

  return edges;
}
