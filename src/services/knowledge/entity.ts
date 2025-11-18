/**
 * Entity storage service (10th knowledge type - flexible entity storage)
 *
 * Handles storage of user-defined entities with dynamic schemas.
 * Unlike the 9 typed knowledge types, entities have no schema constraints.
 *
 * @module services/knowledge/entity
 */

// Removed qdrant.js import - using UnifiedDatabaseLayer instead
import { createHash } from 'crypto';

import { KnowledgeServiceAdapter } from '../../interfaces/service-adapter.js';
import {
  hasPropertySimple,
  isString,
  isObject,
  isUnknown
} from '../../utils/type-guards.js';
import type { KnowledgeItem, Scope } from '../../types/core-interfaces.js';
import type {
  EntityData,
  EntityFilters,
  IEntityService,
  ListOptions,
  SearchOptions,
  ServiceResponse,
} from '../../interfaces/service-interfaces.js';
import type { EntityResponse } from '../../types/database.js';

/**
 * Entity Service Class - Implements standardized IEntityService interface
 *
 * Handles storage of user-defined entities with dynamic schemas using the
 * standardized service interface framework.
 */
export class EntityService
  extends KnowledgeServiceAdapter<EntityData, EntityFilters>
  implements IEntityService
{
  constructor() {
    super('EntityService');
  }

  /**
   * Store a flexible entity in knowledge_entity table
   *
   * Features:
   * - Content-hash based deduplication
   * - Soft delete support
   * - Flexible JSONB schema (no validation)
   * - Unique constraint on (entity_type, name) for active entities
   */
  async store(data: EntityData, scope: Scope): Promise<ServiceResponse<{ id: string }>> {
    return this.storeOperation(data, scope as Record<string, unknown>, async (entityData: EntityData, entityScope: Scope) => {
      const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
      const db = new UnifiedDatabaseLayer();
      await db.initialize();

      // FIXED: Use content_hash for proper deduplication
      const content_hash = this.generateContentHash(entityData);

      try {
        // Check for existing entity by content_hash first using Qdrant
        const existingByHash = await db.find('knowledge_entity', {
          content_hash,
          deleted_at: null,
        });

        if (Array.isArray(existingByHash) && existingByHash.length > 0) {
          const firstResult = existingByHash[0];
          if (firstResult && hasPropertySimple(firstResult, 'id') && isString((firstResult as Record<string, unknown>).id)) {
            return { id: (firstResult as Record<string, unknown>).id as string };
          }
        }

        // Check for existing entity with same (entity_type, name) - update case
        const existingByName = await db.find('knowledge_entity', {
          entity_type: entityData.entity_type,
          name: entityData.name,
          deleted_at: null,
        });

        const entityRecord = {
          entity_type: entityData.entity_type,
          name: entityData.name,
          data: entityData.data,
          content_hash,
          scope: entityScope,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        };

        if (Array.isArray(existingByName) && existingByName.length > 0) {
          const firstExisting = existingByName[0];
          if (firstExisting && hasPropertySimple(firstExisting, 'id') && isString((firstExisting as Record<string, unknown>).id)) {
            const existingId = (firstExisting as Record<string, unknown>).id as string;
            // Update existing entity using store method
            const knowledgeItem: KnowledgeItem = {
              id: existingId,
              kind: 'entity',
              content: JSON.stringify(entityRecord),
              data: entityRecord,
              scope: entityScope,
              created_at: hasPropertySimple(firstExisting, 'created_at')
                ? (firstExisting as Record<string, unknown>).created_at as string
                : new Date().toISOString(),
              updated_at: new Date().toISOString(),
            };
            await db.store([knowledgeItem]);
            return { id: existingId };
          }
        }

        // Create new entity
        const result = await db.create('knowledge_entity', entityRecord);
        if (result && hasPropertySimple(result, 'id') && isString((result as Record<string, unknown>).id)) {
          return { id: (result as Record<string, unknown>).id as string };
        }
        throw new Error('Failed to create entity - invalid response from database');
      } catch (error) {
        console.error('Failed to store entity:', error);
        throw new Error(`Entity storage failed: ${(error as Error).message}`);
      }
    });
  }

  /**
   * Legacy function for backward compatibility - wraps the new service method
   * @deprecated Use EntityService.store() instead
   */
  static async storeEntity(data: EntityData, scope: Scope): Promise<string> {
    const service = new EntityService();
    const result = await service.store(data, scope);

    if (!result.success || !result.data) {
      throw new Error(result.error?.message || 'Failed to store entity');
    }

    return result.data.id;
  }

  /**
   * Retrieve an entity by ID
   */
  async get(id: string, scope?: Scope): Promise<ServiceResponse<KnowledgeItem>> {
    return this.getOperation(id, scope as Record<string, unknown> | undefined, async (entityId: string, entityScope?: Scope) => {
      const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
      const db = new UnifiedDatabaseLayer();
      await db.initialize();

      const whereConditions: unknown = { id: entityId, deleted_at: null };

      // Add scope filtering if provided
      if (entityScope) {
        Object.keys(entityScope).forEach((key) => {
          whereConditions[`scope->>${key}`] = entityScope[key];
        });
      }

      const results = await db.find('knowledge_entity', whereConditions as Record<string, unknown>);

      if (!Array.isArray(results) || results.length === 0) {
        throw new Error(`Entity with id ${entityId} not found`);
      }

      const entity = results[0];
      if (!entity || !hasPropertySimple(entity, 'id') || !isString((entity as Record<string, unknown>).id)) {
        throw new Error(`Invalid entity data received`);
      }

      const entityRecord = entity as Record<string, unknown>;
      return {
        id: entityRecord.id as string,
        kind: 'entity',
        data: {
          entity_type: hasPropertySimple(entity, 'entity_type') && isString(entityRecord.entity_type) ? entityRecord.entity_type : '',
          name: hasPropertySimple(entity, 'name') && isString(entityRecord.name) ? entityRecord.name : '',
          data: hasPropertySimple(entity, 'data') ? entityRecord.data : {},
        },
        scope: hasPropertySimple(entity, 'scope') && isObject(entityRecord.scope) ? entityRecord.scope : {},
        created_at: hasPropertySimple(entity, 'created_at') ? entityRecord.created_at : new Date().toISOString(),
        updated_at: hasPropertySimple(entity, 'updated_at') ? entityRecord.updated_at : new Date().toISOString(),
      } as KnowledgeItem;
    });
  }

  /**
   * Update an entity
   */
  async update(
    id: string,
    data: Partial<EntityData>,
    scope?: Scope
  ): Promise<ServiceResponse<{ id: string }>> {
    return this.updateOperation(
      id,
      data,
      scope as Record<string, unknown> | undefined,
      async (entityId: string, entityData: Partial<EntityData>, entityScope?: Scope) => {
        const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
        const db = new UnifiedDatabaseLayer();
        await db.initialize();

        // Get existing entity
        const existing = await db.find('knowledge_entity', { id: entityId, deleted_at: null });
        if (!Array.isArray(existing) || existing.length === 0) {
          throw new Error(`Entity with id ${entityId} not found`);
        }

        const firstExisting = existing[0];
        if (!firstExisting || !hasPropertySimple(firstExisting, 'id') || !isString(firstExisting.id)) {
          throw new Error(`Invalid entity data received`);
        }

        // Update entity data
        const updatedEntity = {
          ...firstExisting,
          ...entityData,
          scope: entityScope || (hasPropertySimple(firstExisting, 'scope') ? firstExisting.scope : {}),
          updated_at: new Date().toISOString(),
        };

        // Store updated entity
        const knowledgeItem: unknown = {
          id: entityId,
          kind: 'entity',
          content: JSON.stringify(updatedEntity),
          data: updatedEntity,
          scope: updatedEntity.scope,
          created_at: updatedEntity.created_at,
          updated_at: updatedEntity.updated_at,
        };

        await db.store([knowledgeItem]);
        return { id: entityId };
      }
    );
  }

  /**
   * Soft delete an entity
   */
  async delete(id: string, scope?: Scope): Promise<ServiceResponse<{ deleted: boolean }>> {
    return this.deleteOperation(id, scope, async (entityId: string) => {
      const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
      const db = new UnifiedDatabaseLayer();
      await db.initialize();

      // Find the existing entity first
      const existing = await db.find('knowledge_entity', { id: entityId, deleted_at: null });
      if (!Array.isArray(existing) || existing.length === 0) {
        return { deleted: false };
      }

      const firstExisting = existing[0];
      if (!firstExisting || !hasPropertySimple(firstExisting, 'id') || !isString(firstExisting.id)) {
        return { deleted: false };
      }

      // Update using store method
      const updatedEntity = {
        ...firstExisting,
        deleted_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };

      const knowledgeItem: unknown = {
        id: firstExisting.id,
        kind: 'entity',
        content: JSON.stringify(updatedEntity),
        data: updatedEntity,
        scope: hasPropertySimple(firstExisting, 'scope') ? firstExisting.scope : {},
        created_at: hasPropertySimple(firstExisting, 'created_at') ? firstExisting.created_at : new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };

      await db.store([knowledgeItem]);
      return { deleted: true };
    });
  }

  /**
   * Search entities
   */
  async search(
    query: string,
    filters?: EntityFilters,
    options?: SearchOptions
  ): Promise<ServiceResponse<unknown[]>> {
    return this.searchOperation(
      query,
      filters,
      options,
      async (searchQuery: string, searchFilters?: EntityFilters, searchOptions?: SearchOptions) => {
        const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
        const db = new UnifiedDatabaseLayer();
        await db.initialize();

        const whereConditions: unknown = { deleted_at: null };

        // Add entity_type filter if provided
        if (searchFilters?.entity_type) {
          whereConditions.entity_type = searchFilters.entity_type;
        }

        // Add name filter if provided
        if (searchFilters?.name) {
          whereConditions.name = { $like: `%${searchFilters.name}%` };
        }

        // Add scope filtering if provided
        if (searchFilters?.scope && isObject(searchFilters.scope)) {
          Object.keys(searchFilters.scope).forEach((key) => {
            whereConditions[`scope->>${key}`] = (searchFilters.scope as Record<string, unknown>)[key];
          });
        }

        // Use full-text search if query provided
        if (searchQuery.trim()) {
          const searchResults = await db.fullTextSearch('knowledge_entity', {
            query: searchQuery.trim(),
            config: 'english',
            weighting: { D: 0.1, C: 0.2, B: 0.4, A: 1.0 },
            highlight: true,
            snippet_size: 150,
            max_results: searchOptions?.limit || 50,
          });

          return searchResults.map((result) => {
        if (!hasPropertySimple(result, 'id') || !isString(result.id)) {
          return null;
        }
        return {
          id: result.id,
          kind: 'entity',
          data: {
            entity_type: hasPropertySimple(result, 'entity_type') && isString(result.entity_type) ? result.entity_type : '',
            name: hasPropertySimple(result, 'name') && isString(result.name) ? result.name : '',
            data: hasPropertySimple(result, 'data') ? result.data : {},
          },
          scope: hasPropertySimple(result, 'scope') && isObject(result.scope) ? result.scope : {},
          created_at: hasPropertySimple(result, 'created_at') ? result.created_at : new Date().toISOString(),
          updated_at: hasPropertySimple(result, 'updated_at') ? result.updated_at : new Date().toISOString(),
          rank: hasPropertySimple(result, 'rank') ? result.rank : undefined,
          score: hasPropertySimple(result, 'score') ? result.score : undefined,
          highlight: hasPropertySimple(result, 'highlight') ? result.highlight : undefined,
        };
      }).filter((result): result is NonNullable<typeof result> => result !== null);
        } else {
          // Simple filter-based search
          const results = await db.find('knowledge_entity', whereConditions, {
            take: searchOptions?.limit || 50,
            orderBy: { updated_at: 'desc' },
          });

          if (!Array.isArray(results)) {
            return [];
          }

          return results.map((entity) => {
            if (!hasPropertySimple(entity, 'id') || !isString(entity.id)) {
              return null;
            }
            return {
              id: entity.id,
              kind: 'entity',
              data: {
                entity_type: hasPropertySimple(entity, 'entity_type') && isString(entity.entity_type) ? entity.entity_type : '',
                name: hasPropertySimple(entity, 'name') && isString(entity.name) ? entity.name : '',
                data: hasPropertySimple(entity, 'data') ? entity.data : {},
              },
              scope: hasPropertySimple(entity, 'scope') && isObject(entity.scope) ? entity.scope : {},
              created_at: hasPropertySimple(entity, 'created_at') ? entity.created_at : new Date().toISOString(),
              updated_at: hasPropertySimple(entity, 'updated_at') ? entity.updated_at : new Date().toISOString(),
            };
          }).filter((result): result is NonNullable<typeof result> => result !== null);
        }
      }
    );
  }

  /**
   * List entities with optional filtering
   */
  async list(
    filters?: EntityFilters,
    options?: ListOptions
  ): Promise<ServiceResponse<KnowledgeItem<EntityData>[]>> {
    return this.executeOperation(
      async () => {
        const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
        const db = new UnifiedDatabaseLayer();
        await db.initialize();

        const whereConditions: unknown = { deleted_at: null };

        // Add filters
        if (filters?.entity_type) {
          whereConditions.entity_type = filters.entity_type;
        }

        if (filters?.name) {
          whereConditions.name = { $like: `%${filters.name}%` };
        }

        if (filters?.scope && isObject(filters.scope)) {
          Object.keys(filters.scope).forEach((key) => {
            whereConditions[`scope->>${key}`] = (filters.scope as Record<string, unknown>)[key];
          });
        }

        const results = await db.find('knowledge_entity', whereConditions, {
          take: options?.limit || 50,
          skip: options?.offset || 0,
          orderBy: options?.sortBy
            ? { [options.sortBy]: options.sortOrder || 'desc' }
            : { updated_at: 'desc' },
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
        })) as KnowledgeItem<EntityData>[];
      },
      'list',
      { filters, options }
    );
  }

  /**
   * Count entities matching filters
   */
  async count(filters?: EntityFilters): Promise<ServiceResponse<{ count: number }>> {
    return this.executeOperation(
      async () => {
        const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
        const db = new UnifiedDatabaseLayer();
        await db.initialize();

        const whereConditions: unknown = { deleted_at: null };

        // Add filters
        if (filters?.entity_type) {
          whereConditions.entity_type = filters.entity_type;
        }

        if (filters?.name) {
          whereConditions.name = { $like: `%${filters.name}%` };
        }

        if (filters?.scope) {
          Object.keys(filters.scope).forEach((key) => {
            whereConditions[`scope->>${key}`] = filters.scope![key];
          });
        }

        const count = await db.count('knowledge_entity', whereConditions);
        return { count };
      },
      'count',
      { filters }
    );
  }

  /**
   * Health check for the entity service
   */
  async healthCheck(): Promise<ServiceResponse<{ status: 'healthy' | 'unhealthy' }>> {
    return this.executeOperation(async () => {
      try {
        const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
        const db = new UnifiedDatabaseLayer();
        await db.initialize();

        // Simple test query
        await db.find('knowledge_entity', { deleted_at: null }, { take: 1 });
        return { status: 'healthy' };
      } catch (error) {
        throw new Error(`Entity service health check failed: ${(error as Error).message}`);
      }
    }, 'healthCheck');
  }

  /**
   * Generate content hash for entity deduplication
   */
  private generateContentHash(data: EntityData): string {
    const content = JSON.stringify(data, Object.keys(data as unknown).sort());
    return createHash('sha256').update(content).digest('hex');
  }
}

// Legacy wrapper functions for backward compatibility

/**
 * Legacy soft delete function - wraps the new service method
 * @deprecated Use EntityService.delete() instead
 */
export async function softDeleteEntity(id: string): Promise<boolean> {
  const service = new EntityService();
  const result = await service.delete(id);

  if (!result.success || !result.data) {
    throw new Error(result.error?.message || 'Failed to delete entity');
  }

  return result.data.deleted;
}

/**
 * Legacy get function - wraps the new service method
 * @deprecated Use EntityService.get() instead
 */
export async function getEntity(id: string, scope?: Scope): Promise<unknown> {
  const service = new EntityService();
  const result = await service.get(id, scope);

  if (!result.success || !result.data) {
    throw new Error(result.error?.message || 'Failed to get entity');
  }

  return {
    ...(result.data.id && { id: result.data.id }),
    kind: result.data.kind,
    data: result.data.data,
    scope: result.data.scope,
    source: {
      timestamp: result.data.created_at,
      actor: 'system',
      tool: 'entity-service',
    },
  };
}

/**
 * Legacy search function - wraps the new service method
 * @deprecated Use EntityService.search() instead
 */
export async function searchEntities(
  query: string,
  filters: EntityFilters = {}
): Promise<unknown[]> {
  const service = new EntityService();
  const result = await service.search(query, filters);

  if (!result.success || !result.data) {
    throw new Error(result.error?.message || 'Failed to search entities');
  }

  return result.data;
}

// Convenience export for backward compatibility
export const storeEntity = EntityService.storeEntity.bind(EntityService);

// Export singleton instance for direct use
export const entityService = new EntityService();
