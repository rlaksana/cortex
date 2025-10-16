/**
 * Observation storage service (12th knowledge type - fine-grained facts)
 *
 * Handles append-only storage of timestamped observations attached to entities.
 * Supports soft delete for observation lifecycle management.
 *
 * @module services/knowledge/observation
 */

import type { Pool } from 'pg';
import type { ObservationItem } from '../../schemas/knowledge-types.js';

/**
 * Add an observation to an entity
 *
 * Features:
 * - Append-only by default (multiple observations can be added)
 * - Soft delete support
 * - FTS indexing on observation text
 * - Optional categorization via observation_type
 *
 * @param pool - PostgreSQL connection pool
 * @param data - Observation data (entity_type, entity_id, observation, observation_type, metadata)
 * @param scope - Scope metadata (not used for observations, but kept for consistency)
 * @returns UUID of stored observation
 */
export async function addObservation(
  pool: Pool,
  data: ObservationItem['data'],
  _scope?: Record<string, unknown>
): Promise<string> {
  // Insert new observation (append-only)
  const result = await pool.query<{ id: string }>(
    `INSERT INTO knowledge_observation (
       entity_type, entity_id, observation, observation_type, metadata
     ) VALUES ($1, $2, $3, $4, $5)
     RETURNING id`,
    [
      data.entity_type,
      data.entity_id,
      data.observation,
      data.observation_type ?? null,
      data.metadata ?? null,
    ]
  );

  return result.rows[0].id;
}

/**
 * Soft delete an observation by ID
 *
 * @param pool - PostgreSQL connection pool
 * @param observationId - UUID of observation to delete
 * @returns true if deleted, false if not found
 */
export async function deleteObservation(pool: Pool, observationId: string): Promise<boolean> {
  const result = await pool.query<{ id: string }>(
    `UPDATE knowledge_observation
     SET deleted_at = NOW()
     WHERE id = $1 AND deleted_at IS NULL
     RETURNING id`,
    [observationId]
  );

  return result.rows.length > 0;
}

/**
 * Delete observations by exact observation text match
 *
 * Useful for removing specific facts without knowing observation IDs.
 *
 * @param pool - PostgreSQL connection pool
 * @param entityType - Entity type
 * @param entityId - Entity UUID
 * @param observationText - Exact observation text to delete
 * @returns Number of observations deleted
 */
export async function deleteObservationsByText(
  pool: Pool,
  entityType: string,
  entityId: string,
  observationText: string
): Promise<number> {
  const result = await pool.query<{ id: string }>(
    `UPDATE knowledge_observation
     SET deleted_at = NOW()
     WHERE entity_type = $1 AND entity_id = $2 AND observation = $3 AND deleted_at IS NULL
     RETURNING id`,
    [entityType, entityId, observationText]
  );

  return result.rows.length;
}

/**
 * Get all active observations for an entity
 *
 * @param pool - PostgreSQL connection pool
 * @param entityType - Entity type
 * @param entityId - Entity UUID
 * @param observationTypeFilter - Optional filter by observation_type
 * @returns Array of observations ordered by created_at DESC
 */
export async function getObservations(
  pool: Pool,
  entityType: string,
  entityId: string,
  observationTypeFilter?: string
): Promise<
  Array<{
    id: string;
    observation: string;
    observation_type: string | null;
    metadata: Record<string, unknown> | null;
    created_at: Date;
  }>
> {
  let query = `
    SELECT id, observation, observation_type, metadata, created_at
    FROM knowledge_observation
    WHERE entity_type = $1 AND entity_id = $2 AND deleted_at IS NULL
  `;
  const params: unknown[] = [entityType, entityId];

  if (observationTypeFilter) {
    query += ` AND observation_type = $3`;
    params.push(observationTypeFilter);
  }

  query += ` ORDER BY created_at DESC`;

  const result = await pool.query<{
    id: string;
    observation: string;
    observation_type: string | null;
    metadata: Record<string, unknown> | null;
    created_at: Date;
  }>(query, params);
  return result.rows;
}

/**
 * Search observations by text pattern (FTS)
 *
 * @param pool - PostgreSQL connection pool
 * @param searchQuery - Search query (FTS or LIKE pattern)
 * @param entityTypeFilter - Optional filter by entity_type
 * @param limit - Result limit
 * @returns Array of matching observations with entity context
 */
export async function searchObservations(
  pool: Pool,
  searchQuery: string,
  entityTypeFilter?: string,
  limit: number = 20
): Promise<
  Array<{
    id: string;
    entity_type: string;
    entity_id: string;
    observation: string;
    observation_type: string | null;
    metadata: Record<string, unknown> | null;
    created_at: Date;
  }>
> {
  // Use FTS if query looks like search terms, otherwise use LIKE
  const useFts = searchQuery.split(/\s+/).length > 1;

  let query: string;
  const params: unknown[] = [];
  let paramIndex = 1;

  if (useFts) {
    // Full-text search - escape special characters and format properly
    const tsQuery = searchQuery
      .split(/\s+/)
      .filter(w => w.trim().length > 0) // Remove empty words
      .map((w) => {
        // Escape special PostgreSQL tsquery characters
        const escaped = w.replace(/[&|!():*]/g, '\\$&');
        return `${escaped}:*`;
      })
      .join(' & ');
    query = `
      SELECT id, entity_type, entity_id, observation, observation_type, metadata, created_at
      FROM knowledge_observation
      WHERE to_tsvector('english', observation) @@ plainto_tsquery('english', $${paramIndex})
        AND deleted_at IS NULL
    `;
    params.push(tsQuery);
    paramIndex++;
  } else {
    // LIKE pattern search
    query = `
      SELECT id, entity_type, entity_id, observation, observation_type, metadata, created_at
      FROM knowledge_observation
      WHERE observation ILIKE $${paramIndex}
        AND deleted_at IS NULL
    `;
    params.push(`%${searchQuery}%`);
    paramIndex++;
  }

  if (entityTypeFilter) {
    query += ` AND entity_type = $${paramIndex}`;
    params.push(entityTypeFilter);
    paramIndex++;
  }

  query += ` ORDER BY created_at DESC LIMIT $${paramIndex}`;
  params.push(limit);

  const result = await pool.query<{
    id: string;
    entity_type: string;
    entity_id: string;
    observation: string;
    observation_type: string | null;
    metadata: Record<string, unknown> | null;
    created_at: Date;
  }>(query, params);
  return result.rows;
}

/**
 * Get observation count for an entity
 *
 * @param pool - PostgreSQL connection pool
 * @param entityType - Entity type
 * @param entityId - Entity UUID
 * @returns Number of active observations
 */
export async function getObservationCount(
  pool: Pool,
  entityType: string,
  entityId: string
): Promise<number> {
  const result = await pool.query<{ count: string }>(
    `SELECT COUNT(*) as count
     FROM knowledge_observation
     WHERE entity_type = $1 AND entity_id = $2 AND deleted_at IS NULL`,
    [entityType, entityId]
  );

  return parseInt(result.rows[0].count, 10);
}

/**
 * Get recent observations across all entities
 *
 * Useful for activity feeds or audit trails.
 *
 * @param pool - PostgreSQL connection pool
 * @param limit - Result limit
 * @param entityTypeFilter - Optional filter by entity_type
 * @returns Array of recent observations
 */
export async function getRecentObservations(
  pool: Pool,
  limit: number = 50,
  entityTypeFilter?: string
): Promise<
  Array<{
    id: string;
    entity_type: string;
    entity_id: string;
    observation: string;
    observation_type: string | null;
    metadata: Record<string, unknown> | null;
    created_at: Date;
  }>
> {
  let query = `
    SELECT id, entity_type, entity_id, observation, observation_type, metadata, created_at
    FROM knowledge_observation
    WHERE deleted_at IS NULL
  `;
  const params: unknown[] = [];

  if (entityTypeFilter) {
    query += ` AND entity_type = $1`;
    params.push(entityTypeFilter);
    query += ` ORDER BY created_at DESC LIMIT $2`;
    params.push(limit);
  } else {
    query += ` ORDER BY created_at DESC LIMIT $1`;
    params.push(limit);
  }

  const result = await pool.query<{
    id: string;
    entity_type: string;
    entity_id: string;
    observation: string;
    observation_type: string | null;
    metadata: Record<string, unknown> | null;
    created_at: Date;
  }>(query, params);
  return result.rows;
}
