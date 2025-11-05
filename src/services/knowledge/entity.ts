/**
 * Entity storage service (10th knowledge type - flexible entity storage)
 *
 * Handles storage of user-defined entities with dynamic schemas.
 * Unlike the 9 typed knowledge types, entities have no schema constraints.
 *
 * @module services/knowledge/entity
 */

// Removed qdrant.js import - using UnifiedDatabaseLayer instead
import { createHash } from 'node:crypto';
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
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  // FIXED: Use content_hash for proper deduplication
  const content_hash = generateContentHash(data);

  try {
    // Check for existing entity by content_hash first using Qdrant
    const existingByHash = await db.find('knowledge_entity', {
      content_hash,
      deleted_at: null,
    });

    if (existingByHash.length > 0) {
      return existingByHash[0].id;
    }

    // Check for existing entity with same (entity_type, name) - update case
    const existingByName = await db.find('knowledge_entity', {
      entity_type: data.entity_type,
      name: data.name,
      deleted_at: null,
    });

    const entityData = {
      entity_type: data.entity_type,
      name: data.name,
      data: data.data,
      content_hash,
      scope,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    if (existingByName.length > 0) {
      // Update existing entity using store method
      const knowledgeItem: any = {
        id: existingByName[0].id,
        kind: 'entity',
        content: JSON.stringify(entityData),
        data: entityData,
        scope,
        created_at: existingByName[0].created_at,
        updated_at: new Date().toISOString(),
      };
      await db.store([knowledgeItem]);
      return existingByName[0].id;
    } else {
      // Create new entity
      const result = await db.create('knowledge_entity', entityData);
      return result.id;
    }
  } catch (error) {
    console.error('Failed to store entity:', error);
    throw new Error(`Entity storage failed: ${(error as Error).message}`);
  }
}

/**
 * Generate content hash for entity deduplication
 */
function generateContentHash(data: any): string {
  const content = JSON.stringify(data, Object.keys(data).sort());
  return createHash('sha256').update(content).digest('hex');
}

/**
 * Soft delete an entity by ID
 *
 * @param entity_id - UUID of entity to delete
 * @returns true if deleted, false if not found
 */
/**
 * Soft delete an entity by marking it as deleted
 *
 * @param id - Entity UUID
 * @returns True if entity was deleted, false if not found
 */
export async function softDeleteEntity(id: string): Promise<boolean> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  try {
    // Find the existing entity first
    const existing = await db.find('knowledge_entity', { id, deleted_at: null });
    if (existing.length === 0) {
      return false;
    }

    // Update using store method
    const knowledgeItem: any = {
      id: existing[0].id,
      kind: 'entity',
      content: JSON.stringify({ ...existing[0], deleted_at: new Date().toISOString() }),
      data: { ...existing[0], deleted_at: new Date().toISOString() },
      scope: existing[0].scope,
      created_at: existing[0].created_at,
      updated_at: new Date().toISOString(),
    };
    await db.store([knowledgeItem]);

    return true;
  } catch (error) {
    console.error('Failed to soft delete entity:', error);
    throw new Error(`Entity soft delete failed: ${(error as Error).message}`);
  }
}

/**
 * Retrieve entity by ID
 *
 * @param entity_id - UUID of entity
 * @returns Entity data or null if not found
 */
/**
 * Retrieve a flexible entity by ID with optional scope filtering
 *
 * @param id - Entity UUID
 * @param scope - Scope filter (org, project, branch, etc.)
 * @returns Entity data or null if not found
 */
export async function getEntity(
  id: string,
  scope?: Record<string, unknown>
): Promise<EntityItem | null> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  try {
    const whereConditions: any = { id, deleted_at: null };

    // Add scope filtering if provided
    if (scope) {
      Object.keys(scope).forEach((key) => {
        whereConditions[`scope->>${key}`] = scope[key];
      });
    }

    const results = await db.find('knowledge_entity', whereConditions);

    if (results.length === 0) {
      return null;
    }

    const entity = results[0];
    return {
      ...(entity.id && { id: entity.id }),
      kind: 'entity',
      data: {
        entity_type: entity.entity_type,
        name: entity.name,
        data: entity.data,
      },
      scope: entity.scope,
      source: {
        timestamp: entity.created_at,
        actor: 'system',
        tool: 'entity-service',
      },
    };
  } catch (error) {
    console.error('Failed to get entity:', error);
    throw new Error(`Entity retrieval failed: ${(error as Error).message}`);
  }
}

/**
 * Search entities by entity_type and optional name filter
 *
 * @param entity_type - Entity type filter
 * @param namePattern - Optional name pattern (LIKE query)
 * @param limit - Result limit
 * @returns Array of matching entities
 */
/**
 * Search for flexible entities using Qdrant full-text search
 *
 * @param query - Search query string
 * @param filters - Optional filters (entity_type, scope, etc.)
 * @param options - Search options (limit, offset, etc.)
 * @returns Array of matching entities
 */
export async function searchEntities(
  query: string,
  filters: {
    entity_type?: string;
    scope?: Record<string, unknown>;
    limit?: number;
    offset?: number;
  } = {}
): Promise<EntityItem[]> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  try {
    const whereConditions: any = { deleted_at: null };

    // Add entity_type filter if provided
    if (filters.entity_type) {
      whereConditions.entity_type = filters.entity_type;
    }

    // Add scope filtering if provided
    if (filters.scope) {
      Object.keys(filters.scope).forEach((key) => {
        whereConditions[`scope->>${key}`] = filters.scope![key];
      });
    }

    // Use Qdrant full-text search if query provided
    if (query.trim()) {
      const searchResults = await db.fullTextSearch('knowledge_entity', {
        query: query.trim(),
        config: 'english',
        weighting: { D: 0.1, C: 0.2, B: 0.4, A: 1.0 },
        highlight: true,
        snippet_size: 150,
        max_results: filters.limit || 50,
      });

      return searchResults.map((result) => ({
        id: result.id,
        kind: 'entity',
        data: {
          entity_type: result.entity_type,
          name: result.name,
          data: result.data,
        },
        scope: result.scope,
        created_at: result.created_at,
        updated_at: result.updated_at,
        rank: result.rank,
        score: result.score,
        highlight: result.highlight,
      }));
    } else {
      // Simple filter-based search
      const results = await db.find('knowledge_entity', whereConditions, {
        take: filters.limit || 50,
        orderBy: { updated_at: 'desc' },
      });

      return results.map((entity) => ({
        id: entity.id,
        kind: 'entity',
        data: {
          entity_type: entity.entity_type,
          name: entity.name,
          data: entity.data,
        },
        scope: entity.scope,
        created_at: entity.created_at,
        updated_at: entity.updated_at,
      }));
    }
  } catch (error) {
    console.error('Failed to search entities:', error);
    throw new Error(`Entity search failed: ${(error as Error).message}`);
  }
}
