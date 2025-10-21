/**
 * Entity storage service (10th knowledge type - flexible entity storage)
 *
 * Handles storage of user-defined entities with dynamic schemas.
 * Unlike the 9 typed knowledge types, entities have no schema constraints.
 *
 * @module services/knowledge/entity
 */

import { getPrismaClient } from '../../db/prisma.js';
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
 * @param data - Entity data (entity_type, name, data)
 * @param scope - Scope metadata (org, project, branch, etc.)
 * @returns UUID of stored entity
 */
export async function storeEntity(
  data: EntityItem['data'],
  scope: Record<string, unknown>
): Promise<string> {
  const prisma = getPrismaClient();

  // FIXED: Use content_hash for proper deduplication
  const content_hash = generateContentHash(data);

  // Check for existing entity by content_hash first
  const existingByHash = await prisma.knowledgeEntity.findFirst({
    where: {
      content_hash: content_hash,
      deleted_at: null
    }
  });

  if (existingByHash) {
    return existingByHash.id;
  }

  // Check for existing entity with same (entity_type, name) - update case
  const existingByName = await prisma.knowledgeEntity.findFirst({
    where: {
      entity_type: data.entity_type,
      name: data.name,
      deleted_at: null
    }
  });

  if (existingByName) {
    // Update existing entity
    const result = await prisma.knowledgeEntity.update({
      where: { id: existingByName.id },
      data: {
        data: data.data as any,
        content_hash: content_hash,
        tags: scope as any
      }
    });
    return result.id;
  }

  // Insert new entity
  const result = await prisma.knowledgeEntity.create({
    data: {
      entity_type: data.entity_type,
      name: data.name,
      data: data.data as any,
      content_hash: content_hash,
      tags: scope as any
    }
  });

  return result.id;
}

/**
 * Generate content hash for entity deduplication
 */
function generateContentHash(data: EntityItem['data']): string {
  const crypto = require('crypto');
  const content = JSON.stringify({
    entity_type: data.entity_type,
    name: data.name,
    data: data.data
  });
  return crypto.createHash('sha256').update(content).digest('hex').substring(0, 128);
}

/**
 * Soft delete an entity by ID
 *
 * @param entity_id - UUID of entity to delete
 * @returns true if deleted, false if not found
 */
export async function softDeleteEntity(entity_id: string): Promise<boolean> {
  const prisma = getPrismaClient();
  const result = await prisma.knowledgeEntity.updateMany({
    where: {
      id: entity_id,
      deleted_at: null
    },
    data: {
      deleted_at: new Date()
    }
  });

  return result.count > 0;
}

/**
 * Retrieve entity by ID
 *
 * @param entity_id - UUID of entity
 * @returns Entity data or null if not found
 */
export async function getEntity(
  entity_id: string
): Promise<{
  id: string;
  entity_type: string;
  name: string;
  data: Record<string, unknown>;
  tags: Record<string, unknown>;
  created_at: Date;
  updated_at: Date;
} | null> {
  const prisma = getPrismaClient();
  const result = await prisma.knowledgeEntity.findFirst({
    where: {
      id: entity_id,
      deleted_at: null
    }
  });

  if (!result) {
    return null;
  }

  return {
    id: result.id,
    entity_type: result.entity_type,
    name: result.name,
    data: (result.data as any) || {},
    tags: (result.tags as any) || {},
    created_at: result.created_at,
    updated_at: result.updated_at
  };
}

/**
 * Search entities by entity_type and optional name filter
 *
 * @param entity_type - Entity type filter
 * @param namePattern - Optional name pattern (LIKE query)
 * @param limit - Result limit
 * @returns Array of matching entities
 */
export async function searchEntities(
  entity_type?: string,
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
  const prisma = getPrismaClient();

  const whereClause: any = {
    deleted_at: null
  };

  if (entity_type) {
    whereClause.entity_type = entity_type;
  }

  if (namePattern) {
    whereClause.name = {
      contains: namePattern,
      mode: 'insensitive'
    };
  }

  const result = await prisma.knowledgeEntity.findMany({
    where: whereClause,
    orderBy: { updated_at: 'desc' },
    take: limit
  });

  return result.map(entity => ({
    id: entity.id,
    entity_type: entity.entity_type,
    name: entity.name,
    data: (entity.data as any) || {},
    tags: (entity.tags as any) || {},
    created_at: entity.created_at,
    updated_at: entity.updated_at
  }));
}
