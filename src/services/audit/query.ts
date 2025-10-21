import { getPrismaClient } from '../../db/prisma.js';
import { logger } from '../../utils/logger.js';

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
  const prisma = getPrismaClient();
  const { page = 1, page_size = 50, order_by = 'created_at', order_dir = 'DESC' } = options;

  try {
    // Build Prisma where clause
    const whereClause: any = {};

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
      whereClause.created_at = {};
      if (filters.since) whereClause.created_at.gte = filters.since;
      if (filters.until) whereClause.created_at.lte = filters.until;
    }

    // Calculate pagination
    const offset = (page - 1) * page_size;

    // Execute count and data queries in parallel
    const [totalResult, entriesResult] = await Promise.all([
      prisma.eventAudit.count({ where: whereClause }),
      prisma.eventAudit.findMany({
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

    // Map database field names to interface field names
    const entries = entriesResult.map((entry: any) => ({
      ...entry,
      eventType: entry.event_type,
    })) as AuditLogEntry[];

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
  const prisma = getPrismaClient();

  try {
    const entries = await prisma.eventAudit.findMany({
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

    // Map database field names to interface field names
    return entries.map((entry: any) => ({
      ...entry,
      eventType: entry.event_type,
    })) as AuditLogEntry[];
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
  const prisma = getPrismaClient();

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
      // Total events
      prisma.eventAudit.count({ where: whereClause }),

      // Events by table name (entity type)
      prisma.eventAudit.groupBy({
        by: ['table_name'],
        where: whereClause,
        _count: true,
      }),

      // Events by operation
      prisma.eventAudit.groupBy({
        by: ['operation'],
        where: whereClause,
        _count: true,
      }),

      // Unique actors
      prisma.eventAudit.groupBy({
        by: ['changed_by'],
        where: whereClause,
      }),
    ]);

    // Process results
    const events_by_type: Record<string, number> = {};
    typeResult.forEach((item: any) => {
      if (item.table_name) {
        events_by_type[item.table_name] = item._count;
      }
    });

    const events_by_operation: Record<string, number> = {};
    operationResult.forEach((item: any) => {
      events_by_operation[item.operation] = item._count;
    });

    const unique_actors = actorResult.filter((item: any) => item.changed_by !== null).length;

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
