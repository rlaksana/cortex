import { logger } from '@/utils/logger.js';

import { getQdrantClient } from '../../db/qdrant.js';
import { hasProperty, hasStringProperty, safeGetProperty,safeGetStringProperty } from '../../utils/type-fixes.js';

export interface AuditLogEntry {
  id: string;
  eventType: string;
  table_name: string;
  record_id: string;
  operation: string;
  changed_by: string | null;
  old_data: Record<string, unknown> | null;
  new_data: Record<string, unknown> | null;
  created_at: Date;
}

export interface AuditLogFilters {
  table_name?: string;
  record_id?: string;
  operation?: 'INSERT' | 'UPDATE' | 'DELETE';
  changed_by?: string;
  since?: Date;
  until?: Date;
  eventType?: string;
}

export interface AuditLogQueryResult {
  entries: AuditLogEntry[];
  total: number;
  page: number;
  page_size: number;
}

/**
 * Query audit log with flexible filtering and pagination
 *
 * Use cases:
 * - Track all changes to specific entity
 * - Find all actions by specific actor
 * - Audit trail for compliance reporting
 * - Temporal analysis of mutation patterns
 *
 * @param pool - Database connection pool
 * @param filters - Optional filter criteria
 * @param options - Pagination and sorting options
 * @returns Paginated audit log entries
 */
export async function queryAuditLog(
  filters: AuditLogFilters = {},
  options: {
    page?: number;
    page_size?: number;
    order_by?: 'created_at' | 'table_name' | 'eventType';
    order_dir?: 'ASC' | 'DESC';
  } = {}
): Promise<AuditLogQueryResult> {
  const qdrant = getQdrantClient();
  const { page = 1, page_size = 50, order_by = 'created_at', order_dir = 'DESC' } = options;

  try {
    // Build Qdrant where clause
    const whereClause: Record<string, unknown> = {};

    if (filters.table_name) {
      whereClause.table_name = filters.table_name;
    }

    if (filters.record_id) {
      whereClause.record_id = filters.record_id;
    }

    if (filters.operation) {
      whereClause.operation = filters.operation;
    }

    if (filters.changed_by) {
      whereClause.changed_by = filters.changed_by;
    }

    if (filters.eventType) {
      whereClause.eventType = filters.eventType;
    }

    // Handle date range filtering
    if (filters.since || filters.until) {
      const dateFilter: Record<string, unknown> = {};
      if (filters.since) dateFilter.gte = filters.since;
      if (filters.until) dateFilter.lte = filters.until;
      whereClause.created_at = dateFilter;
    }

    // Calculate pagination
    const offset = (page - 1) * page_size;

    // Execute count and data queries in parallel
    const [totalResult, entriesResult] = await Promise.all([
      // Use findMany with limit to simulate count - this is a temporary workaround
      qdrant.eventAudit.findMany({
        where: whereClause,
        select: { id: true },
        take: 10000, // Large number for counting
      }).then(results => results.length),
      qdrant.eventAudit.findMany({
        where: whereClause,
        orderBy: { [order_by]: order_dir.toLowerCase() as 'asc' | 'desc' },
        skip: offset,
        take: page_size,
        select: {
          id: true,
          event_type: true,
          table_name: true,
          record_id: true,
          operation: true,
          changed_by: true,
          old_data: true,
          new_data: true,
          created_at: true,
        },
      }),
    ]);

    logger.debug(
      {
        filters,
        total: totalResult,
        page,
        page_size,
        returned: entriesResult.length
      },
      'Audit log query executed'
    );

    // Map database field names to interface field names with type safety
    const entries = entriesResult.map((entry: unknown): AuditLogEntry => {
      if (!entry || typeof entry !== 'object') {
        throw new Error('Invalid audit entry returned from database');
      }

      const entryRecord = entry as Record<string, unknown>;

      return {
        id: safeGetStringProperty(entryRecord, 'id', ''),
        eventType: safeGetStringProperty(entryRecord, 'event_type', ''),
        table_name: safeGetStringProperty(entryRecord, 'table_name', ''),
        record_id: safeGetStringProperty(entryRecord, 'record_id', ''),
        operation: safeGetStringProperty(entryRecord, 'operation', ''),
        changed_by: safeGetStringProperty(entryRecord, 'changed_by', null) as string | null,
        old_data: safeGetProperty(entryRecord, 'old_data', null) as Record<string, unknown> | null,
        new_data: safeGetProperty(entryRecord, 'new_data', null) as Record<string, unknown> | null,
        created_at: new Date(safeGetStringProperty(entryRecord, 'created_at', new Date().toISOString())),
      };
    });

    return {
      entries,
      total: totalResult,
      page,
      page_size,
    };
  } catch (error) {
    logger.error(
      {
        error,
        filters,
        options
      },
      'Failed to query audit log'
    );
    throw error;
  }
}

/**
 * Get audit trail for specific entity
 *
 * Convenience wrapper for queryAuditLog focused on single entity history
 *
 * @param pool - Database connection pool
 * @param entity_type - Entity type (e.g., 'section', 'adr_decision')
 * @param entity_id - Entity UUID
 * @returns Chronological audit entries for entity
 */
export async function getEntityAuditTrail(
  table_name: string,
  record_id: string
): Promise<AuditLogEntry[]> {
  try {
    const result = await queryAuditLog(
      { table_name, record_id },
      { page_size: 100, order_dir: 'ASC' }
    );

    logger.debug(
      {
        table_name,
        record_id,
        count: result.entries.length
      },
      'Retrieved entity audit trail'
    );

    return result.entries;
  } catch (error) {
    logger.error(
      {
        error,
        table_name,
        record_id
      },
      'Failed to get entity audit trail'
    );
    throw error;
  }
}

/**
 * Get recent audit activity across all entities
 *
 * @param pool - Database connection pool
 * @param limit - Number of recent entries to return
 * @returns Recent audit log entries
 */
export async function getRecentAuditActivity(
  limit: number = 20
): Promise<AuditLogEntry[]> {
  const qdrant = getQdrantClient();

  try {
    const entries = await qdrant.eventAudit.findMany({
      orderBy: { created_at: 'desc' },
      take: limit,
      select: {
        id: true,
        event_type: true,
        table_name: true,
        record_id: true,
        operation: true,
        changed_by: true,
        old_data: true,
        new_data: true,
        created_at: true,
      },
    });

    logger.debug(
      {
        limit,
        count: entries.length
      },
      'Retrieved recent audit activity'
    );

    // Map database field names to interface field names with type safety
    return entries.map((entry: unknown): AuditLogEntry => {
      if (!entry || typeof entry !== 'object') {
        throw new Error('Invalid audit entry returned from database');
      }

      const entryRecord = entry as Record<string, unknown>;

      return {
        id: safeGetStringProperty(entryRecord, 'id', ''),
        eventType: safeGetStringProperty(entryRecord, 'event_type', ''),
        table_name: safeGetStringProperty(entryRecord, 'table_name', ''),
        record_id: safeGetStringProperty(entryRecord, 'record_id', ''),
        operation: safeGetStringProperty(entryRecord, 'operation', ''),
        changed_by: safeGetStringProperty(entryRecord, 'changed_by', null) as string | null,
        old_data: safeGetProperty(entryRecord, 'old_data', null) as Record<string, unknown> | null,
        new_data: safeGetProperty(entryRecord, 'new_data', null) as Record<string, unknown> | null,
        created_at: new Date(safeGetStringProperty(entryRecord, 'created_at', new Date().toISOString())),
      };
    });
  } catch (error) {
    logger.error(
      {
        error,
        limit
      },
      'Failed to get recent audit activity'
    );
    throw error;
  }
}

/**
 * Get audit statistics for reporting
 *
 * @param pool - Database connection pool
 * @param since - Start date for statistics window
 * @returns Aggregated audit statistics
 */
export async function getAuditStatistics(
  since?: Date
): Promise<{
  total_events: number;
  events_by_type: Record<string, number>;
  events_by_operation: Record<string, number>;
  unique_actors: number;
}> {
  const qdrant = getQdrantClient();

  try {
    // Build where clause for date filtering
    const whereClause = since ? { created_at: { gte: since } } : {};

    // Execute all queries in parallel for better performance
    const [
      totalResult,
      typeResult,
      operationResult,
      actorResult
    ] = await Promise.all([
      // Total events - use findMany as workaround for missing count
      qdrant.eventAudit.findMany({
        where: whereClause,
        select: { id: true },
        take: 10000,
      }).then(results => results.length),

      // Events by table name (entity type) - use findMany and aggregate
      qdrant.eventAudit.findMany({
        where: whereClause,
        select: { table_name: true },
        take: 10000,
      }).then(results => {
        const groups: Record<string, number> = {};
        results.forEach(item => {
          if (hasStringProperty(item, 'table_name')) {
            const key = item.table_name;
            groups[key] = (groups[key] || 0) + 1;
          }
        });
        return Object.entries(groups).map(([table_name, _count]) => ({ table_name, _count }));
      }),

      // Events by operation - use findMany and aggregate
      qdrant.eventAudit.findMany({
        where: whereClause,
        select: { operation: true },
        take: 10000,
      }).then(results => {
        const groups: Record<string, number> = {};
        results.forEach(item => {
          if (hasStringProperty(item, 'operation')) {
            const key = item.operation;
            groups[key] = (groups[key] || 0) + 1;
          }
        });
        return Object.entries(groups).map(([operation, _count]) => ({ operation, _count }));
      }),

      // Unique actors - use findMany and extract unique values
      qdrant.eventAudit.findMany({
        where: whereClause,
        select: { changed_by: true },
        take: 10000,
      }).then(results => {
        const uniqueActors = [...new Set(results.map(item =>
          hasStringProperty(item, 'changed_by') ? item.changed_by : null
        ).filter(Boolean))];
        return uniqueActors.map(changed_by => ({ changed_by }));
      }),
    ]);

    // Process results with type safety
    const events_by_type: Record<string, number> = {};
    typeResult.forEach((item: unknown) => {
      if (hasStringProperty(item, 'table_name') && hasProperty(item, '_count')) {
        events_by_type[item.table_name] = (item as any)._count;
      }
    });

    const events_by_operation: Record<string, number> = {};
    operationResult.forEach((item: unknown) => {
      if (hasStringProperty(item, 'operation') && hasProperty(item, '_count')) {
        events_by_operation[item.operation] = (item as any)._count;
      }
    });

    const unique_actors = actorResult.filter((item: unknown) =>
      hasProperty(item, 'changed_by') && (item as any).changed_by !== null
    ).length;

    const statistics = {
      total_events: totalResult,
      events_by_type,
      events_by_operation,
      unique_actors,
    };

    logger.debug(
      {
        since,
        statistics
      },
      'Retrieved audit statistics'
    );

    return statistics;
  } catch (error) {
    logger.error(
      {
        error,
        since
      },
      'Failed to get audit statistics'
    );
    throw error;
  }
}
