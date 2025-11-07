// @ts-nocheck
/**
 * Relation storage service (11th knowledge type - entity relationships)
 *
 * Handles storage of directed relationships between any knowledge items.
 * Supports polymorphic relationships: unknown entity type can link to any other.
 *
 * @module services/knowledge/relation
 */

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
 * @param data - Relation data (from, to, relation_type, metadata)
 * @param scope - Scope metadata (org, project, branch, etc.)
 * @returns UUID of stored relation
 */
export async function storeRelation(
  data: RelationItem['data'],
  scope: Record<string, unknown>
): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();
  // Check for existing relation with same (from, to, relation_type) - unique constraint
  const existing = await db.find('knowledgeRelation', {
    where: {
      from_entity_type: data.from_entity_type,
      from_entity_id: data.from_entity_id,
      to_entity_type: data.to_entity_type,
      to_entity_id: data.to_entity_id,
      relation_type: data.relation_type,
      deleted_at: null,
    },
  });
  if (existing.length > 0) return existing[0];

  if (existing && existing.length > 0) {
    // Relation already exists, return existing ID (idempotent)
    const existingRelation = existing[0];
    // Optionally update metadata if provided
    if (data.metadata) {
      // Update using UnifiedDatabaseLayer store method
      const updatedRelation = {
        ...existingRelation,
        metadata: data.metadata as any,
        tags: scope as any,
        updated_at: new Date().toISOString(),
      };

      const knowledgeItem = {
        id: existingRelation.id,
        kind: 'relation',
        content: JSON.stringify(updatedRelation),
        data: updatedRelation,
        scope,
        created_at: existingRelation.created_at,
        updated_at: new Date().toISOString(),
      };

      await db.store([knowledgeItem]);
    }
    return existingRelation.id;
  }

  // Insert new relation using UnifiedDatabaseLayer
  const relationData = {
    from_entity_type: data.from_entity_type,
    from_entity_id: data.from_entity_id,
    to_entity_type: data.to_entity_type,
    to_entity_id: data.to_entity_id,
    relation_type: data.relation_type,
    metadata: data.metadata as any,
    tags: scope as any,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  const result = await db.create('knowledge_relation', relationData);
  return result.id;
}

/**
 * Soft delete a relation by ID
 *
 * @param relationId - UUID of relation to delete
 * @returns true if deleted, false if not found
 */
export async function softDeleteRelation(relationId: string): Promise<boolean> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();
  // Find existing relation first
  const existingArray = await db.find('knowledge_relation', { id: relationId, deleted_at: null });
  if (existingArray.length === 0) {
    return false;
  }

  const existing = existingArray[0];

  // Update using store method
  const updatedRelation = {
    ...existing,
    deleted_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  const knowledgeItem = {
    id: existing.id,
    kind: 'relation',
    content: JSON.stringify(updatedRelation),
    data: updatedRelation,
    scope: {},
    created_at: existing.created_at,
    updated_at: new Date().toISOString(),
  };

  await db.store([knowledgeItem]);
  return true;
}

/**
 * Get outgoing relations from an entity
 *
 * @param entity_type - Entity type (e.g., "decision", "entity")
 * @param entity_id - Entity UUID
 * @param relation_typeFilter - Optional filter by relation type
 * @returns Array of relations
 */
export async function getOutgoingRelations(
  entity_type: string,
  entity_id: string,
  relation_typeFilter?: string
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
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const whereClause: any = {
    from_entity_type: entity_type,
    from_entity_id: entity_id,
    deleted_at: null,
  };

  if (relation_typeFilter) {
    whereClause.relation_type = relation_typeFilter;
  }

  const result = await db.find('knowledgeRelation', {
    where: whereClause,
    orderBy: { created_at: 'desc' },
    select: {
      id: true,
      to_entity_type: true,
      to_entity_id: true,
      relation_type: true,
      metadata: true,
      created_at: true,
    },
  });

  return result.map((relation) => ({
    id: relation.id,
    to_entity_type: relation.to_entity_type,
    to_entity_id: relation.to_entity_id,
    relation_type: relation.relation_type,
    metadata: (relation.metadata as any) || null,
    created_at: relation.created_at,
  }));
}

/**
 * Get incoming relations to an entity
 *
 * @param pool - qdrant connection pool
 * @param entity_type - Entity type (e.g., "issue", "entity")
 * @param entity_id - Entity UUID
 * @param relation_typeFilter - Optional filter by relation type
 * @returns Array of relations
 */
export async function getIncomingRelations(
  entity_type: string,
  entity_id: string,
  relation_typeFilter?: string
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
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const whereClause: any = {
    to_entity_type: entity_type,
    to_entity_id: entity_id,
    deleted_at: null,
  };

  if (relation_typeFilter) {
    whereClause.relation_type = relation_typeFilter;
  }

  const result = await db.find('knowledgeRelation', {
    where: whereClause,
    orderBy: { created_at: 'desc' },
    select: {
      id: true,
      from_entity_type: true,
      from_entity_id: true,
      relation_type: true,
      metadata: true,
      created_at: true,
    },
  });

  return result.map((relation) => ({
    id: relation.id,
    from_entity_type: relation.from_entity_type,
    from_entity_id: relation.from_entity_id,
    relation_type: relation.relation_type,
    metadata: (relation.metadata as any) || null,
    created_at: relation.created_at,
  }));
}

/**
 * Get all relations for an entity (both incoming and outgoing)
 *
 * @param pool - qdrant connection pool
 * @param entity_type - Entity type
 * @param entity_id - Entity UUID
 * @returns Object with outgoing and incoming relations
 */
export async function getAllRelations(
  entity_type: string,
  entity_id: string
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
    getOutgoingRelations(entity_type, entity_id),
    getIncomingRelations(entity_type, entity_id),
  ]);

  return { outgoing, incoming };
}

/**
 * Check if a relation exists between two entities
 *
 * @param pool - qdrant connection pool
 * @param fromType - Source entity type
 * @param fromId - Source entity UUID
 * @param toType - Target entity type
 * @param toId - Target entity UUID
 * @param relation_type - Relation type
 * @returns true if relation exists, false otherwise
 */
export async function relationExists(
  fromType: string,
  fromId: string,
  toType: string,
  toId: string,
  relation_type: string
): Promise<boolean> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();
  const result = await db.find('knowledgeRelation', {
    where: {
      from_entity_type: fromType,
      from_entity_id: fromId,
      to_entity_type: toType,
      to_entity_id: toId,
      relation_type,
      deleted_at: null,
    },
    select: { id: true },
  });
  if (result.length > 0) return result[0];

  return result !== null;
}
