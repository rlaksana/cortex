/**
 * Observation storage service (12th knowledge type - fine-grained facts)
 *
 * Handles append-only storage of timestamped observations attached to entities.
 * Supports soft delete for observation lifecycle management.
 *
 * @module services/knowledge/observation
 */

// Removed qdrant.js import - using UnifiedDatabaseLayer instead
import type { ObservationItem } from '../../schemas/knowledge-types';

/**
 * Add an observation to an entity
 *
 * Features:
 * - Append-only by default (multiple observations can be added)
 * - Soft delete support
 * - FTS indexing on observation text
 * - Optional categorization via observation_type
 *
 * @param data - Observation data (entity_type, entity_id, observation, observation_type, metadata)
 * @param scope - Scope metadata (not used for observations, but kept for consistency)
 * @returns UUID of stored observation
 */
export async function addObservation(
  data: ObservationItem['data'],
  _scope?: Record<string, unknown>
): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();
  // FIXED: Use direct field access for observation_type and store metadata properly
  const result = await qdrant.knowledgeObservation.create({
    data: {
      entity_type: data.entity_type,
      entity_id: data.entity_id,
      observation: data.observation,
      observation_type: data.observation_type || undefined,
      metadata: data.metadata || (undefined as any),
      tags: {},
    },
  });

  return result.id;
}

/**
 * Soft delete an observation by ID
 *
 * @param pool - qdrant connection pool
 * @param observationId - UUID of observation to delete
 * @returns true if deleted, false if not found
 */
export async function deleteObservation(observationId: string): Promise<boolean> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();
  const result = await qdrant.knowledgeObservation.updateMany({
    where: {
      id: observationId,
      deleted_at: null,
    },
    data: {
      deleted_at: new Date(),
    },
  });

  return result.count > 0;
}

/**
 * Delete observations by exact observation text match
 *
 * Useful for removing specific facts without knowing observation IDs.
 *
 * @param pool - qdrant connection pool
 * @param entity_type - Entity type
 * @param entity_id - Entity UUID
 * @param observationText - Exact observation text to delete
 * @returns Number of observations deleted
 */
export async function deleteObservationsByText(
  entity_type: string,
  entity_id: string,
  observationText: string
): Promise<number> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();
  const result = await qdrant.knowledgeObservation.updateMany({
    where: {
      entity_type,
      entity_id,
      observation: observationText,
      deleted_at: null,
    },
    data: {
      deleted_at: new Date(),
    },
  });

  return result.count;
}

/**
 * Get all active observations for an entity
 *
 * @param pool - qdrant connection pool
 * @param entity_type - Entity type
 * @param entity_id - Entity UUID
 * @param observationTypeFilter - Optional filter by observation_type
 * @returns Array of observations ordered by created_at DESC
 */
export async function getObservations(
  entity_type: string,
  entity_id: string,
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
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const whereClause: any = {
    entity_type,
    entity_id,
    deleted_at: null,
  };

  // FIXED: Use direct field access for observation_type filtering
  if (observationTypeFilter) {
    whereClause.observation_type = observationTypeFilter;
  }

  const result = await db.find('knowledgeObservation', {
    where: whereClause,
    orderBy: { created_at: 'desc' },
    select: {
      id: true,
      observation: true,
      observation_type: true,
      metadata: true,
      created_at: true,
    },
  });

  return result.map((observation) => ({
    id: observation.id,
    observation: observation.observation,
    observation_type: observation.observation_type,
    metadata: observation.metadata as Record<string, unknown> | null,
    created_at: observation.created_at,
  }));
}

/**
 * Search observations by text pattern (FTS)
 *
 * @param pool - qdrant connection pool
 * @param searchQuery - Search query (FTS or LIKE pattern)
 * @param entity_typeFilter - Optional filter by entity_type
 * @param limit - Result limit
 * @returns Array of matching observations with entity context
 */
export async function searchObservations(
  searchQuery: string,
  entity_typeFilter?: string,
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
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();
  // Use FTS if query looks like search terms, otherwise use LIKE
  const useFts = searchQuery.split(/\s+/).length > 1;

  if (useFts) {
    // Full-text search - escape special characters and format properly
    const tsQuery = searchQuery
      .split(/\s+/)
      .filter((w) => w.trim().length > 0) // Remove empty words
      .map((w) => {
        // Escape special qdrant tsquery characters
        const escaped = w.replace(/[&|!():*]/g, '\\$&');
        return `${escaped}:*`;
      })
      .join(' & ');

    if (entity_typeFilter) {
      const result = await qdrant.$queryRaw<
        Array<{
          id: string;
          entity_type: string;
          entity_id: string;
          observation: string;
          observation_type: string | null;
          metadata: Record<string, unknown> | null;
          created_at: Date;
        }>
      >`
        SELECT id, entity_type, entity_id, observation, observation_type, metadata, created_at
        FROM knowledge_observation
        WHERE to_tsvector('english', observation) @@ plainto_tsquery('english', ${tsQuery})
          AND deleted_at IS NULL AND entity_type = ${entity_typeFilter}
        ORDER BY created_at DESC LIMIT ${limit}
      `;
      return result.flat();
    } else {
      const result = await qdrant.$queryRaw<
        Array<{
          id: string;
          entity_type: string;
          entity_id: string;
          observation: string;
          observation_type: string | null;
          metadata: Record<string, unknown> | null;
          created_at: Date;
        }>
      >`
        SELECT id, entity_type, entity_id, observation, observation_type, metadata, created_at
        FROM knowledge_observation
        WHERE to_tsvector('english', observation) @@ plainto_tsquery('english', ${tsQuery})
          AND deleted_at IS NULL
        ORDER BY created_at DESC LIMIT ${limit}
      `;
      return result.flat();
    }
  } else {
    // LIKE pattern search
    if (entity_typeFilter) {
      const result = await qdrant.$queryRaw<
        Array<{
          id: string;
          entity_type: string;
          entity_id: string;
          observation: string;
          observation_type: string | null;
          metadata: Record<string, unknown> | null;
          created_at: Date;
        }>
      >`
        SELECT id, entity_type, entity_id, observation, observation_type, metadata, created_at
        FROM knowledge_observation
        WHERE observation ILIKE ${`%${searchQuery}%`}
          AND deleted_at IS NULL AND entity_type = ${entity_typeFilter}
        ORDER BY created_at DESC LIMIT ${limit}
      `;
      return result.flat();
    } else {
      const result = await qdrant.$queryRaw<
        Array<
          Array<{
            id: string;
            entity_type: string;
            entity_id: string;
            observation: string;
            observation_type: string | null;
            metadata: Record<string, unknown> | null;
            created_at: Date;
          }>
        >
      >`
        SELECT id, entity_type, entity_id, observation, observation_type, metadata, created_at
        FROM knowledge_observation
        WHERE observation ILIKE ${`%${searchQuery}%`}
          AND deleted_at IS NULL
        ORDER BY created_at DESC LIMIT ${limit}
      `;
      if (result.length > 0 && result[0].length > 0) {
        return result[0] as unknown as Array<{
          id: string;
          entity_type: string;
          entity_id: string;
          observation: string;
          observation_type: string | null;
          metadata: Record<string, unknown> | null;
          created_at: Date;
        }>;
      }
      return [];
    }
  }
}

/**
 * Get observation count for an entity
 *
 * @param pool - qdrant connection pool
 * @param entity_type - Entity type
 * @param entity_id - Entity UUID
 * @returns Number of active observations
 */
export async function getObservationCount(entity_type: string, entity_id: string): Promise<number> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();
  const result = await qdrant.$queryRaw`
    SELECT COUNT(*) as count
     FROM knowledge_observation
     WHERE entity_type = ${entity_type} AND entity_id = ${entity_id} AND deleted_at IS NULL
  `;

  const typedResult = result as Array<{ count: bigint }>;
  if (typedResult.length > 0) {
    return Number(typedResult[0].count);
  }
  return 0;
}

/**
 * Get recent observations across all entities
 *
 * Useful for activity feeds or audit trails.
 *
 * @param pool - qdrant connection pool
 * @param limit - Result limit
 * @param entity_typeFilter - Optional filter by entity_type
 * @returns Array of recent observations
 */
export async function getRecentObservations(
  limit: number = 50,
  entity_typeFilter?: string
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
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  if (entity_typeFilter) {
    const result = await qdrant.$queryRaw<
      Array<
        Array<{
          id: string;
          entity_type: string;
          entity_id: string;
          observation: string;
          observation_type: string | null;
          metadata: Record<string, unknown> | null;
          created_at: Date;
        }>
      >
    >`
      SELECT id, entity_type, entity_id, observation, observation_type, metadata, created_at
      FROM knowledge_observation
      WHERE deleted_at IS NULL AND entity_type = ${entity_typeFilter}
      ORDER BY created_at DESC LIMIT ${limit}
    `;
    return result.flat() as unknown as Array<{
      id: string;
      entity_type: string;
      entity_id: string;
      observation: string;
      observation_type: string | null;
      metadata: Record<string, unknown> | null;
      created_at: Date;
    }>;
  } else {
    const result = await qdrant.$queryRaw<
      Array<
        Array<{
          id: string;
          entity_type: string;
          entity_id: string;
          observation: string;
          observation_type: string | null;
          metadata: Record<string, unknown> | null;
          created_at: Date;
        }>
      >
    >`
      SELECT id, entity_type, entity_id, observation, observation_type, metadata, created_at
      FROM knowledge_observation
      WHERE deleted_at IS NULL
      ORDER BY created_at DESC LIMIT ${limit}
    `;
    return result.flat() as unknown as Array<{
      id: string;
      entity_type: string;
      entity_id: string;
      observation: string;
      observation_type: string | null;
      metadata: Record<string, unknown> | null;
      created_at: Date;
    }>;
  }
}
