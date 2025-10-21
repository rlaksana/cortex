/**
 * Delete operations service
 *
 * Implements soft delete operations for all knowledge types.
 * Preserves audit trail and supports cascade delete for relations.
 *
 * @module services/delete-operations
 */

import { getPrismaClient } from '../db/prisma.js';
import { softDeleteEntity } from './knowledge/entity.js';
import { softDeleteRelation } from './knowledge/relation.js';
import { deleteObservation } from './knowledge/observation.js';
import { logger } from '../utils/logger.js';

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
export async function softDelete(request: DeleteRequest): Promise<DeleteResult> {
  const prisma = getPrismaClient();
  const { entity_type, entity_id, cascade_relations = false } = request;

  // Handle graph extension types first
  if (entity_type === 'entity') {
    const deleted = await softDeleteEntity(entity_id);

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
      cascadedCount = await cascadeDeleteRelations('entity', entity_id);
    }

    return {
      id: entity_id,
      entity_type: 'entity',
      status: 'deleted',
      cascaded_relations: cascadedCount,
    };
  }

  if (entity_type === 'relation') {
    const deleted = await softDeleteRelation(entity_id);

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
    const deleted = await deleteObservation(entity_id);

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

  const table_name = tableMap[entity_type];
  if (!table_name) {
    return {
      id: entity_id,
      entity_type,
      status: 'not_found',
      message: `Unknown entity type: ${entity_type}`,
    };
  }

  // Handle typed knowledge types with Prisma Client
  try {
    // Check immutability constraints for decisions
    if (entity_type === 'decision') {
      const decision = await prisma.adrDecision.findUnique({
        where: { id: entity_id },
        select: { status: true }
      });

      if (decision?.status === 'accepted') {
        return {
          id: entity_id,
          entity_type: 'decision',
          status: 'immutable',
          message: 'Cannot delete accepted ADR (immutability constraint)',
        };
      }
    }

    // Check if entity exists first
    const findOperations: Record<string, () => Promise<{ id: string } | null>> = {
      section: () => prisma.section.findUnique({ where: { id: entity_id }, select: { id: true } }),
      runbook: () => prisma.runbook.findUnique({ where: { id: entity_id }, select: { id: true } }),
      change: () => prisma.changeLog.findUnique({ where: { id: entity_id }, select: { id: true } }),
      issue: () => prisma.issueLog.findUnique({ where: { id: entity_id }, select: { id: true } }),
      decision: () => prisma.adrDecision.findUnique({ where: { id: entity_id }, select: { id: true } }),
      todo: () => prisma.todoLog.findUnique({ where: { id: entity_id }, select: { id: true } }),
      release_note: () => prisma.releaseNote.findUnique({ where: { id: entity_id }, select: { id: true } }),
      ddl: () => prisma.ddlHistory.findUnique({ where: { id: entity_id }, select: { id: true } }),
      pr_context: () => prisma.prContext.findUnique({ where: { id: entity_id }, select: { id: true } }),
      incident: () => prisma.incidentLog.findUnique({ where: { id: entity_id }, select: { id: true } }),
      release: () => prisma.releaseLog.findUnique({ where: { id: entity_id }, select: { id: true } }),
      risk: () => prisma.riskLog.findUnique({ where: { id: entity_id }, select: { id: true } }),
      assumption: () => prisma.assumptionLog.findUnique({ where: { id: entity_id }, select: { id: true } }),
    };

    // Use Prisma model map for type-safe delete operations
    const deleteOperations: Record<string, () => Promise<any>> = {
      section: () => prisma.section.delete({ where: { id: entity_id } }),
      runbook: () => prisma.runbook.delete({ where: { id: entity_id } }),
      change: () => prisma.changeLog.delete({ where: { id: entity_id } }),
      issue: () => prisma.issueLog.delete({ where: { id: entity_id } }),
      decision: () => prisma.adrDecision.delete({ where: { id: entity_id } }),
      todo: () => prisma.todoLog.delete({ where: { id: entity_id } }),
      release_note: () => prisma.releaseNote.delete({ where: { id: entity_id } }),
      ddl: () => prisma.ddlHistory.delete({ where: { id: entity_id } }),
      pr_context: () => prisma.prContext.delete({ where: { id: entity_id } }),
      incident: () => prisma.incidentLog.delete({ where: { id: entity_id } }),
      release: () => prisma.releaseLog.delete({ where: { id: entity_id } }),
      risk: () => prisma.riskLog.delete({ where: { id: entity_id } }),
      assumption: () => prisma.assumptionLog.delete({ where: { id: entity_id } }),
    };

    const findOperation = findOperations[entity_type];
    const deleteOperation = deleteOperations[entity_type];

    if (!findOperation || !deleteOperation) {
      return {
        id: entity_id,
        entity_type,
        status: 'not_found',
        message: `Unknown entity type: ${entity_type}`,
      };
    }

    // Check if entity exists first
    const existingEntity = await findOperation();
    if (!existingEntity) {
      return {
        id: entity_id,
        entity_type,
        status: 'not_found',
        message: 'Entity not found',
      };
    }

    // Perform the delete operation
    await deleteOperation();

    // Cascade delete relations if requested
    let cascadedCount = 0;
    if (cascade_relations) {
      cascadedCount = await cascadeDeleteRelations(entity_type, entity_id);
    }

    logger.debug(
      {
        id: entity_id,
        entity_type,
        cascaded_relations: cascadedCount
      },
      'Entity deleted successfully'
    );

    return {
      id: entity_id,
      entity_type,
      status: 'deleted',
      cascaded_relations: cascadedCount,
    };
  } catch (err) {
    logger.error(
      {
        error: err,
        id: entity_id,
        entity_type
      },
      'Failed to delete entity'
    );

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
 * @param entity_type - Entity type
 * @param entity_id - Entity UUID
 * @returns Number of relations deleted
 */
async function cascadeDeleteRelations(
  entity_type: string,
  entity_id: string
): Promise<number> {
  const prisma = getPrismaClient();

  try {
    const result = await prisma.knowledgeRelation.updateMany({
      where: {
        AND: [
          {
            OR: [
              {
                from_entity_type: entity_type,
                from_entity_id: entity_id,
              },
              {
                to_entity_type: entity_type,
                to_entity_id: entity_id,
              },
            ],
          },
          {
            deleted_at: null, // Only soft-delete non-deleted relations
          },
        ],
      },
      data: {
        deleted_at: new Date(),
      },
    });

    logger.debug(
      {
        entity_type,
        entity_id,
        cascadedCount: result.count
      },
      'Cascade deleted relations'
    );

    return result.count;
  } catch (error) {
    logger.error(
      {
        error,
        entity_type,
        entity_id
      },
      'Failed to cascade delete relations'
    );
    return 0;
  }
}

/**
 * Bulk delete operation
 *
 * @param pool - PostgreSQL connection pool
 * @param requests - Array of delete requests
 * @returns Array of delete results
 */
export async function bulkDelete(requests: DeleteRequest[]): Promise<DeleteResult[]> {
  const results: DeleteResult[] = [];

  for (const request of requests) {
    const result = await softDelete(request);
    results.push(result);
  }

  return results;
}

/**
 * Undelete (restore) a soft-deleted entity
 *
 * @param pool - PostgreSQL connection pool
 * @param entity_type - Entity type
 * @param entity_id - Entity UUID
 * @returns true if restored, false if not found
 */
export async function undelete(entity_type: string, entity_id: string): Promise<boolean> {
  const prisma = getPrismaClient();

  try {
    // Handle graph extension types with soft delete support
    if (entity_type === 'entity') {
      const result = await prisma.knowledgeEntity.updateMany({
        where: {
          id: entity_id,
          deleted_at: { not: null },
        },
        data: {
          deleted_at: null,
        },
      });
      return result.count > 0;
    }

    if (entity_type === 'relation') {
      const result = await prisma.knowledgeRelation.updateMany({
        where: {
          id: entity_id,
          deleted_at: { not: null },
        },
        data: {
          deleted_at: null,
        },
      });
      return result.count > 0;
    }

    if (entity_type === 'observation') {
      const result = await prisma.knowledgeObservation.updateMany({
        where: {
          id: entity_id,
          deleted_at: { not: null },
        },
        data: {
          deleted_at: null,
        },
      });
      return result.count > 0;
    }

    // Note: Typed knowledge types don't support undelete as they use hard delete
    // This maintains consistency with the schema where these tables don't have deleted_at columns
    logger.warn(
      {
        entity_type,
        entity_id
      },
      'Undelete not supported for entity type (hard delete only)'
    );

    return false;
  } catch (error) {
    logger.error(
      {
        error,
        entity_type,
        entity_id
      },
      'Failed to undelete entity'
    );
    return false;
  }
}
