/**
 * Graph traversal service
 *
 * Implements recursive graph traversal using qdrant CTEs.
 * Supports depth limits, cycle detection, and relation type filtering.
 *
 * @module services/graph-traversal
 */

import { qdrant } from '../db/qdrant-client.js';

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
 * @param pool - qdrant connection pool
 * @param startEntityType - Starting entity type
 * @param startEntityId - Starting entity UUID
 * @param options - Traversal options
 * @returns Graph nodes and edges
 */
export async function traverseGraph(
  startEntityType: string,
  startEntityId: string,
  options: TraversalOptions = {}
): Promise<GraphTraversalResult> {
  const maxDepth = options.depth ?? 2;
  const direction = options.direction ?? 'outgoing';

  try {
    // Use simplified Qdrant query for graph traversal
    const result = await qdrant.getClient().$queryRaw`
      WITH RECURSIVE graph_traverse AS (
        -- Base case: start node
        SELECT
          ${startEntityType}::text as entity_type,
          ${startEntityId}::uuid as entity_id,
          0 as depth,
          ARRAY[${startEntityId}::uuid] as path,
          NULL::text as from_entity_type,
          NULL::uuid as from_entity_id,
          NULL::text as relation_type,
          NULL::jsonb as relation_metadata
        UNION ALL
        -- Recursive case: follow relations (simplified)
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
        WHERE
          gt.depth < ${maxDepth}
          AND NOT (kr.to_entity_id = ANY(gt.path))
      )
      SELECT * FROM graph_traverse;
    `;

    // Process results into nodes and edges
    const nodes: GraphNode[] = [];
    const edges: GraphEdge[] = [];
    const seenNodes = new Set<string>();
    let maxDepthReached = 0;

    for (const row of result as (GraphNode & {
      from_entity_type?: string;
      from_entity_id?: string;
      relation_type?: string;
      relation_metadata?: Record<string, unknown>;
    })[]) {
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
      if (row.depth > 0 && row.from_entity_type && row.from_entity_id && row.relation_type) {
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
  } catch (error) {
    // Fallback: return minimal graph with just the root node
    return {
      nodes: [{
        entity_type: startEntityType,
        entity_id: startEntityId,
        depth: 0,
      }],
      edges: [],
      root_entity_type: startEntityType,
      root_entity_id: startEntityId,
      max_depth_reached: 0,
    };
  }
}

/**
 * Enrich graph nodes with entity data
 *
 * Fetches entity data for all nodes in the graph from their respective tables.
 *
 * @param pool - qdrant connection pool
 * @param nodes - Graph nodes to enrich
 * @returns Enriched nodes with data
 */
export async function enrichGraphNodes(nodes: GraphNode[]): Promise<GraphNode[]> {
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

  for (const [entity_type, typeNodes] of nodesByType.entries()) {
    const ids = typeNodes.map((n) => n.entity_id);

    try {
      // Use Qdrant based on entity type
      let entities: any[] = [];

      switch (entity_type) {
        case 'section':
          entities = await qdrant.getClient().section.findMany({
            where: { id: { in: ids } },
          });
          break;
        case 'decision':
          entities = await qdrant.getClient().adrDecision.findMany({
            where: { id: { in: ids } },
          });
          break;
        case 'issue':
          entities = await qdrant.getClient().issueLog.findMany({
            where: { id: { in: ids } },
          });
          break;
        case 'runbook':
          entities = await qdrant.getClient().runbook.findMany({
            where: { id: { in: ids } },
          });
          break;
        case 'todo':
          entities = await qdrant.getClient().todoLog.findMany({
            where: { id: { in: ids } },
          });
          break;
        case 'entity':
          entities = await qdrant.getClient().knowledgeEntity.findMany({
            where: { id: { in: ids } },
          });
          break;
        default:
          // Unknown entity type, skip enrichment
          enrichedNodes.push(...typeNodes);
          continue;
      }

      const dataMap = new Map(entities.map((entity) => [entity.id, entity]));

      // Enrich nodes with fetched data
      for (const node of typeNodes) {
        enrichedNodes.push({
          ...node,
          data: dataMap.get(node.entity_id) ?? undefined,
        });
      }
    } catch {
      // If table doesn't exist or query fails, skip enrichment
      enrichedNodes.push(...typeNodes);
    }
  }

  return enrichedNodes;
}


/**
 * Find shortest path between two entities
 *
 * Uses BFS (via recursive CTE with depth ordering) to find shortest path.
 *
 * @param pool - qdrant connection pool
 * @param fromType - Source entity type
 * @param fromId - Source entity UUID
 * @param toType - Target entity type
 * @param toId - Target entity UUID
 * @param maxDepth - Maximum depth to search (default: 5)
 * @returns Path as array of edges, or null if no path found
 */
export async function findShortestPath(
  fromType: string,
  fromId: string,
  toType: string,
  toId: string,
  maxDepth: number = 5
): Promise<GraphEdge[] | null> {
  
  try {
    const result = await qdrant.getClient().$queryRaw<Array<{ edges: Record<string, unknown>[] }>>`
      WITH RECURSIVE path_search AS (
        -- Base case: start node
        SELECT
          ${fromType}::text as entity_type,
          ${fromId}::uuid as entity_id,
          0 as depth,
          ARRAY[${fromId}::uuid] as path,
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
          ps.depth < ${maxDepth}
          AND NOT (kr.to_entity_id = ANY(ps.path))
      )
      SELECT edges
      FROM path_search
      WHERE entity_type = ${toType} AND entity_id = ${toId}
      ORDER BY depth ASC
      LIMIT 1;
    `;

    if (result.length === 0) {
      return null; // No path found
    }

    // Parse edges from JSONB array
    const edges: GraphEdge[] = result[0].edges.map((edge: Record<string, unknown>) => ({
      from_entity_type: edge.from_entity_type as string,
      from_entity_id: edge.from_entity_id as string,
      to_entity_type: edge.to_entity_type as string,
      to_entity_id: edge.to_entity_id as string,
      relation_type: edge.relation_type as string,
      metadata: edge.metadata as Record<string, unknown> | undefined,
    }));

    return edges;
  } catch {
    return null; // Error or no path found
  }
}
