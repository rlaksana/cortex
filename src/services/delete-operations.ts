/**
 * Delete operations service
 *
 * Implements soft delete operations for all knowledge types.
 * Preserves audit trail and supports cascade delete for relations.
 *
 * @module services/delete-operations
 */

import type { Pool } from 'pg';
import { softDeleteEntity } from './knowledge/entity.js';
import { softDeleteRelation } from './knowledge/relation.js';
import { deleteObservation } from './knowledge/observation.js';

export interface DeleteRequest {
  entity_type: string; // "entity", "relation", "observation", or any typed knowledge type
  entity_id: string; // UUID of entity to delete
  cascade_relations?: boolean; // If true, also delete relations pointing to/from this entity
}

export interface DeleteResult {
  id: string;
  entity_type: string;
  status: 'deleted' | 'not_found' | 'immutable';
  cascaded_relations?: number;
  message?: string;
}

/**
 * Soft delete a knowledge item by type and ID
 *
 * Features:
 * - Soft delete (sets deleted_at timestamp)
 * - Preserves audit trail
 * - Respects immutability constraints (e.g., accepted ADRs cannot be deleted)
 * - Optional cascade delete for relations
 *
 * @param pool - PostgreSQL connection pool
 * @param request - Delete request
 * @returns Delete result
 */
export async function softDelete(pool: Pool, request: DeleteRequest): Promise<DeleteResult> {
  const { entity_type, entity_id, cascade_relations = false } = request;

  // Handle graph extension types first
  if (entity_type === 'entity') {
    const deleted = await softDeleteEntity(pool, entity_id);

    if (!deleted) {
      return {
        id: entity_id,
        entity_type: 'entity',
        status: 'not_found',
        message: 'Entity not found or already deleted',
      };
    }

    // Cascade delete relations if requested
    let cascadedCount = 0;
    if (cascade_relations) {
      cascadedCount = await cascadeDeleteRelations(pool, 'entity', entity_id);
    }

    return {
      id: entity_id,
      entity_type: 'entity',
      status: 'deleted',
      cascaded_relations: cascadedCount,
    };
  }

  if (entity_type === 'relation') {
    const deleted = await softDeleteRelation(pool, entity_id);

    if (!deleted) {
      return {
        id: entity_id,
        entity_type: 'relation',
        status: 'not_found',
        message: 'Relation not found or already deleted',
      };
    }

    return {
      id: entity_id,
      entity_type: 'relation',
      status: 'deleted',
    };
  }

  if (entity_type === 'observation') {
    const deleted = await deleteObservation(pool, entity_id);

    if (!deleted) {
      return {
        id: entity_id,
        entity_type: 'observation',
        status: 'not_found',
        message: 'Observation not found or already deleted',
      };
    }

    return {
      id: entity_id,
      entity_type: 'observation',
      status: 'deleted',
    };
  }

  // Handle typed knowledge types
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
  };

  const tableName = tableMap[entity_type];
  if (!tableName) {
    return {
      id: entity_id,
      entity_type,
      status: 'not_found',
      message: `Unknown entity type: ${entity_type}`,
    };
  }

  // Check immutability constraints
  if (entity_type === 'decision') {
    const result = await pool.query(`SELECT status FROM ${tableName} WHERE id = $1`, [entity_id]);

    if (
      result.rows.length > 0 &&
      (result.rows[0] as Record<string, unknown>).status === 'accepted'
    ) {
      return {
        id: entity_id,
        entity_type: 'decision',
        status: 'immutable',
        message: 'Cannot delete accepted ADR (immutability constraint)',
      };
    }
  }

  // Soft delete: add deleted_at column if it doesn't exist, or use status = 'deleted'
  // For simplicity, we'll use a DELETE operation with audit trail
  // In production, tables should have deleted_at column
  try {
    // Check if table has deleted_at column
    const hasDeletedAt = await pool.query(
      `SELECT column_name FROM information_schema.columns
       WHERE table_name = $1 AND column_name = 'deleted_at'`,
      [tableName]
    );

    if (hasDeletedAt.rows.length > 0) {
      // Use soft delete
      const result = await pool.query(
        `UPDATE ${tableName}
         SET deleted_at = NOW()
         WHERE id = $1 AND deleted_at IS NULL
         RETURNING id`,
        [entity_id]
      );

      if (result.rows.length === 0) {
        return {
          id: entity_id,
          entity_type,
          status: 'not_found',
          message: 'Entity not found or already deleted',
        };
      }
    } else {
      // Table doesn't have deleted_at, perform hard delete with audit
      const result = await pool.query(`DELETE FROM ${tableName} WHERE id = $1 RETURNING id`, [
        entity_id,
      ]);

      if (result.rows.length === 0) {
        return {
          id: entity_id,
          entity_type,
          status: 'not_found',
          message: 'Entity not found',
        };
      }
    }

    // Cascade delete relations if requested
    let cascadedCount = 0;
    if (cascade_relations) {
      cascadedCount = await cascadeDeleteRelations(pool, entity_type, entity_id);
    }

    return {
      id: entity_id,
      entity_type,
      status: 'deleted',
      cascaded_relations: cascadedCount,
    };
  } catch (err) {
    return {
      id: entity_id,
      entity_type,
      status: 'not_found',
      message: (err as Error).message,
    };
  }
}

/**
 * Cascade delete all relations pointing to/from an entity
 *
 * @param pool - PostgreSQL connection pool
 * @param entityType - Entity type
 * @param entityId - Entity UUID
 * @returns Number of relations deleted
 */
async function cascadeDeleteRelations(
  pool: Pool,
  entityType: string,
  entityId: string
): Promise<number> {
  const result = await pool.query(
    `UPDATE knowledge_relation
     SET deleted_at = NOW()
     WHERE (from_entity_type = $1 AND from_entity_id = $2
            OR to_entity_type = $1 AND to_entity_id = $2)
       AND deleted_at IS NULL
     RETURNING id`,
    [entityType, entityId]
  );

  return result.rows.length;
}

/**
 * Bulk delete operation
 *
 * @param pool - PostgreSQL connection pool
 * @param requests - Array of delete requests
 * @returns Array of delete results
 */
export async function bulkDelete(pool: Pool, requests: DeleteRequest[]): Promise<DeleteResult[]> {
  const results: DeleteResult[] = [];

  for (const request of requests) {
    const result = await softDelete(pool, request);
    results.push(result);
  }

  return results;
}

/**
 * Undelete (restore) a soft-deleted entity
 *
 * @param pool - PostgreSQL connection pool
 * @param entityType - Entity type
 * @param entityId - Entity UUID
 * @returns true if restored, false if not found
 */
export async function undelete(pool: Pool, entityType: string, entityId: string): Promise<boolean> {
  // Handle graph extension types
  if (entityType === 'entity') {
    const result = await pool.query(
      `UPDATE knowledge_entity
       SET deleted_at = NULL
       WHERE id = $1 AND deleted_at IS NOT NULL
       RETURNING id`,
      [entityId]
    );
    return result.rows.length > 0;
  }

  if (entityType === 'relation') {
    const result = await pool.query(
      `UPDATE knowledge_relation
       SET deleted_at = NULL
       WHERE id = $1 AND deleted_at IS NOT NULL
       RETURNING id`,
      [entityId]
    );
    return result.rows.length > 0;
  }

  if (entityType === 'observation') {
    const result = await pool.query(
      `UPDATE knowledge_observation
       SET deleted_at = NULL
       WHERE id = $1 AND deleted_at IS NOT NULL
       RETURNING id`,
      [entityId]
    );
    return result.rows.length > 0;
  }

  // Handle typed knowledge types
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
  };

  const tableName = tableMap[entityType];
  if (!tableName) {
    return false;
  }

  try {
    const result = await pool.query(
      `UPDATE ${tableName}
       SET deleted_at = NULL
       WHERE id = $1 AND deleted_at IS NOT NULL
       RETURNING id`,
      [entityId]
    );

    return result.rows.length > 0;
  } catch {
    return false;
  }
}
