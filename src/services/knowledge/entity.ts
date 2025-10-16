/**
 * Entity storage service (10th knowledge type - flexible entity storage)
 *
 * Handles storage of user-defined entities with dynamic schemas.
 * Unlike the 9 typed knowledge types, entities have no schema constraints.
 *
 * @module services/knowledge/entity
 */

import type { Pool } from 'pg';
import { computeContentHash } from '../../utils/hash.js';
import type { EntityItem } from '../../schemas/knowledge-types.js';

/**
 * Store a flexible entity in knowledge_entity table
 *
 * Features:
 * - Content-hash based deduplication
 * - Soft delete support
 * - Flexible JSONB schema (no validation)
 * - Unique constraint on (entity_type, name) for active entities
 *
 * @param pool - PostgreSQL connection pool
 * @param data - Entity data (entity_type, name, data)
 * @param scope - Scope metadata (org, project, branch, etc.)
 * @returns UUID of stored entity
 */
export async function storeEntity(
  pool: Pool,
  data: EntityItem['data'],
  scope: Record<string, unknown>
): Promise<string> {
  // Compute content hash for deduplication
  const contentData = JSON.stringify({
    entity_type: data.entity_type,
    name: data.name,
    data: data.data,
  });
  const hash = computeContentHash(contentData);

  // Check for existing entity with same content_hash (dedupe)
  const existing = await pool.query<{ id: string }>(
    'SELECT id FROM knowledge_entity WHERE content_hash = $1 AND deleted_at IS NULL',
    [hash]
  );

  if (existing.rows.length > 0) {
    // Entity already exists, return existing ID (idempotent)
    return existing.rows[0].id;
  }

  // Check for existing entity with same (entity_type, name) - update case
  const existingByName = await pool.query<{ id: string }>(
    'SELECT id FROM knowledge_entity WHERE entity_type = $1 AND name = $2 AND deleted_at IS NULL',
    [data.entity_type, data.name]
  );

  if (existingByName.rows.length > 0) {
    // Update existing entity
    const result = await pool.query<{ id: string }>(
      `UPDATE knowledge_entity
       SET data = $1, tags = $2, content_hash = $3, updated_at = NOW()
       WHERE id = $4
       RETURNING id`,
      [data.data, JSON.stringify(scope), hash, existingByName.rows[0].id]
    );
    return result.rows[0].id;
  }

  // Insert new entity
  const result = await pool.query<{ id: string }>(
    `INSERT INTO knowledge_entity (entity_type, name, data, tags, content_hash)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING id`,
    [data.entity_type, data.name, data.data, JSON.stringify(scope), hash]
  );

  return result.rows[0].id;
}

/**
 * Soft delete an entity by ID
 *
 * @param pool - PostgreSQL connection pool
 * @param entityId - UUID of entity to delete
 * @returns true if deleted, false if not found
 */
export async function softDeleteEntity(pool: Pool, entityId: string): Promise<boolean> {
  const result = await pool.query(
    `UPDATE knowledge_entity
     SET deleted_at = NOW()
     WHERE id = $1 AND deleted_at IS NULL
     RETURNING id`,
    [entityId]
  );

  return result.rows.length > 0;
}

/**
 * Retrieve entity by ID
 *
 * @param pool - PostgreSQL connection pool
 * @param entityId - UUID of entity
 * @returns Entity data or null if not found
 */
export async function getEntity(
  pool: Pool,
  entityId: string
): Promise<{
  id: string;
  entity_type: string;
  name: string;
  data: Record<string, unknown>;
  tags: Record<string, unknown>;
  created_at: Date;
  updated_at: Date;
} | null> {
  const result = await pool.query(
    `SELECT id, entity_type, name, data, tags, created_at, updated_at
     FROM knowledge_entity
     WHERE id = $1 AND deleted_at IS NULL`,
    [entityId]
  );

  if (result.rows.length === 0) {
    return null;
  }

  return result.rows[0] as {
    id: string;
    entity_type: string;
    name: string;
    data: Record<string, unknown>;
    tags: Record<string, unknown>;
    created_at: Date;
    updated_at: Date;
  };
}

/**
 * Search entities by entity_type and optional name filter
 *
 * @param pool - PostgreSQL connection pool
 * @param entityType - Entity type filter
 * @param namePattern - Optional name pattern (LIKE query)
 * @param limit - Result limit
 * @returns Array of matching entities
 */
export async function searchEntities(
  pool: Pool,
  entityType?: string,
  namePattern?: string,
  limit: number = 20
): Promise<
  Array<{
    id: string;
    entity_type: string;
    name: string;
    data: Record<string, unknown>;
    tags: Record<string, unknown>;
    created_at: Date;
    updated_at: Date;
  }>
> {
  let query =
    'SELECT id, entity_type, name, data, tags, created_at, updated_at FROM knowledge_entity WHERE deleted_at IS NULL';
  const params: unknown[] = [];
  let paramIndex = 1;

  if (entityType) {
    query += ` AND entity_type = $${paramIndex}`;
    params.push(entityType);
    paramIndex++;
  }

  if (namePattern) {
    query += ` AND name ILIKE $${paramIndex}`;
    params.push(`%${namePattern}%`);
    paramIndex++;
  }

  query += ` ORDER BY updated_at DESC LIMIT $${paramIndex}`;
  params.push(limit);

  const result = await pool.query<{
    id: string;
    entity_type: string;
    name: string;
    data: Record<string, unknown>;
    tags: Record<string, unknown>;
    created_at: Date;
    updated_at: Date;
  }>(query, params);
  return result.rows;
}
