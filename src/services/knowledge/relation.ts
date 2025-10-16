/**
 * Relation storage service (11th knowledge type - entity relationships)
 *
 * Handles storage of directed relationships between any knowledge items.
 * Supports polymorphic relationships: any entity type can link to any other.
 *
 * @module services/knowledge/relation
 */

import type { Pool } from 'pg';
import type { RelationItem } from '../../schemas/knowledge-types.js';

/**
 * Store a relation in knowledge_relation table
 *
 * Features:
 * - Polymorphic relationships (any entity type → any entity type)
 * - Unique constraint on (from_entity_type, from_entity_id, to_entity_type, to_entity_id, relation_type)
 * - Soft delete support
 * - Optional metadata (weight, confidence, timestamps)
 *
 * @param pool - PostgreSQL connection pool
 * @param data - Relation data (from, to, relation_type, metadata)
 * @param scope - Scope metadata (org, project, branch, etc.)
 * @returns UUID of stored relation
 */
export async function storeRelation(
  pool: Pool,
  data: RelationItem['data'],
  scope: Record<string, unknown>
): Promise<string> {
  // Check for existing relation with same (from, to, relation_type) - unique constraint
  const existing = await pool.query(
    `SELECT id FROM knowledge_relation
     WHERE from_entity_type = $1 AND from_entity_id = $2
       AND to_entity_type = $3 AND to_entity_id = $4
       AND relation_type = $5
       AND deleted_at IS NULL`,
    [
      data.from_entity_type,
      data.from_entity_id,
      data.to_entity_type,
      data.to_entity_id,
      data.relation_type,
    ]
  );

  if (existing.rows.length > 0) {
    // Relation already exists, return existing ID (idempotent)
    // Optionally update metadata if provided
    if (data.metadata) {
      await pool.query(
        `UPDATE knowledge_relation
         SET metadata = $1, tags = $2, updated_at = NOW()
         WHERE id = $3`,
        [data.metadata, JSON.stringify(scope), existing.rows[0].id]
      );
    }
    return existing.rows[0].id;
  }

  // Insert new relation
  const result = await pool.query(
    `INSERT INTO knowledge_relation (
       from_entity_type, from_entity_id,
       to_entity_type, to_entity_id,
       relation_type, metadata, tags
     ) VALUES ($1, $2, $3, $4, $5, $6, $7)
     RETURNING id`,
    [
      data.from_entity_type,
      data.from_entity_id,
      data.to_entity_type,
      data.to_entity_id,
      data.relation_type,
      data.metadata || null,
      JSON.stringify(scope),
    ]
  );

  return result.rows[0].id;
}

/**
 * Soft delete a relation by ID
 *
 * @param pool - PostgreSQL connection pool
 * @param relationId - UUID of relation to delete
 * @returns true if deleted, false if not found
 */
export async function softDeleteRelation(pool: Pool, relationId: string): Promise<boolean> {
  const result = await pool.query(
    `UPDATE knowledge_relation
     SET deleted_at = NOW()
     WHERE id = $1 AND deleted_at IS NULL
     RETURNING id`,
    [relationId]
  );

  return result.rows.length > 0;
}

/**
 * Get outgoing relations from an entity
 *
 * @param pool - PostgreSQL connection pool
 * @param entityType - Entity type (e.g., "decision", "entity")
 * @param entityId - Entity UUID
 * @param relationTypeFilter - Optional filter by relation type
 * @returns Array of relations
 */
export async function getOutgoingRelations(
  pool: Pool,
  entityType: string,
  entityId: string,
  relationTypeFilter?: string
): Promise<
  Array<{
    id: string;
    to_entity_type: string;
    to_entity_id: string;
    relation_type: string;
    metadata: Record<string, unknown> | null;
    created_at: Date;
  }>
> {
  let query = `
    SELECT id, to_entity_type, to_entity_id, relation_type, metadata, created_at
    FROM knowledge_relation
    WHERE from_entity_type = $1 AND from_entity_id = $2 AND deleted_at IS NULL
  `;
  const params: unknown[] = [entityType, entityId];

  if (relationTypeFilter) {
    query += ` AND relation_type = $3`;
    params.push(relationTypeFilter);
  }

  query += ` ORDER BY created_at DESC`;

  const result = await pool.query(query, params);
  return result.rows;
}

/**
 * Get incoming relations to an entity
 *
 * @param pool - PostgreSQL connection pool
 * @param entityType - Entity type (e.g., "issue", "entity")
 * @param entityId - Entity UUID
 * @param relationTypeFilter - Optional filter by relation type
 * @returns Array of relations
 */
export async function getIncomingRelations(
  pool: Pool,
  entityType: string,
  entityId: string,
  relationTypeFilter?: string
): Promise<
  Array<{
    id: string;
    from_entity_type: string;
    from_entity_id: string;
    relation_type: string;
    metadata: Record<string, unknown> | null;
    created_at: Date;
  }>
> {
  let query = `
    SELECT id, from_entity_type, from_entity_id, relation_type, metadata, created_at
    FROM knowledge_relation
    WHERE to_entity_type = $1 AND to_entity_id = $2 AND deleted_at IS NULL
  `;
  const params: unknown[] = [entityType, entityId];

  if (relationTypeFilter) {
    query += ` AND relation_type = $3`;
    params.push(relationTypeFilter);
  }

  query += ` ORDER BY created_at DESC`;

  const result = await pool.query(query, params);
  return result.rows;
}

/**
 * Get all relations for an entity (both incoming and outgoing)
 *
 * @param pool - PostgreSQL connection pool
 * @param entityType - Entity type
 * @param entityId - Entity UUID
 * @returns Object with outgoing and incoming relations
 */
export async function getAllRelations(
  pool: Pool,
  entityType: string,
  entityId: string
): Promise<{
  outgoing: Array<{
    id: string;
    to_entity_type: string;
    to_entity_id: string;
    relation_type: string;
    metadata: Record<string, unknown> | null;
    created_at: Date;
  }>;
  incoming: Array<{
    id: string;
    from_entity_type: string;
    from_entity_id: string;
    relation_type: string;
    metadata: Record<string, unknown> | null;
    created_at: Date;
  }>;
}> {
  const [outgoing, incoming] = await Promise.all([
    getOutgoingRelations(pool, entityType, entityId),
    getIncomingRelations(pool, entityType, entityId),
  ]);

  return { outgoing, incoming };
}

/**
 * Check if a relation exists between two entities
 *
 * @param pool - PostgreSQL connection pool
 * @param fromType - Source entity type
 * @param fromId - Source entity UUID
 * @param toType - Target entity type
 * @param toId - Target entity UUID
 * @param relationType - Relation type
 * @returns true if relation exists, false otherwise
 */
export async function relationExists(
  pool: Pool,
  fromType: string,
  fromId: string,
  toType: string,
  toId: string,
  relationType: string
): Promise<boolean> {
  const result = await pool.query(
    `SELECT 1 FROM knowledge_relation
     WHERE from_entity_type = $1 AND from_entity_id = $2
       AND to_entity_type = $3 AND to_entity_id = $4
       AND relation_type = $5
       AND deleted_at IS NULL
     LIMIT 1`,
    [fromType, fromId, toType, toId, relationType]
  );

  return result.rows.length > 0;
}
