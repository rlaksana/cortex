import { Pool } from 'pg';

export interface AuditLogEntry {
  id: string;
  entity_type: string;
  entity_id: string;
  operation: string;
  actor: string | null;
  change_summary: Record<string, unknown> | null;
  created_at: Date;
}

export interface AuditLogFilters {
  entity_type?: string;
  entity_id?: string;
  operation?: 'INSERT' | 'UPDATE' | 'DELETE';
  actor?: string;
  since?: Date;
  until?: Date;
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
  pool: Pool,
  filters: AuditLogFilters = {},
  options: {
    page?: number;
    page_size?: number;
    order_by?: 'created_at' | 'entity_type';
    order_dir?: 'ASC' | 'DESC';
  } = {}
): Promise<AuditLogQueryResult> {
  const { page = 1, page_size = 50, order_by = 'created_at', order_dir = 'DESC' } = options;

  // Build WHERE clause dynamically
  const whereClauses: string[] = [];
  const params: unknown[] = [];
  let paramIndex = 1;

  if (filters.entity_type) {
    whereClauses.push(`entity_type = $${paramIndex++}`);
    params.push(filters.entity_type);
  }

  if (filters.entity_id) {
    whereClauses.push(`entity_id = $${paramIndex++}`);
    params.push(filters.entity_id);
  }

  if (filters.operation) {
    whereClauses.push(`operation = $${paramIndex++}`);
    params.push(filters.operation);
  }

  if (filters.actor) {
    whereClauses.push(`actor = $${paramIndex++}`);
    params.push(filters.actor);
  }

  if (filters.since) {
    whereClauses.push(`created_at >= $${paramIndex++}`);
    params.push(filters.since);
  }

  if (filters.until) {
    whereClauses.push(`created_at <= $${paramIndex++}`);
    params.push(filters.until);
  }

  const whereClause = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

  // Count total matching entries
  const countQuery = `SELECT COUNT(*) as total FROM event_audit ${whereClause}`;
  const countResult = await pool.query(countQuery, params);
  const total = parseInt(countResult.rows[0].total, 10);

  // Fetch paginated entries
  const offset = (page - 1) * page_size;
  const dataQuery = `
    SELECT
      id,
      entity_type,
      entity_id,
      operation,
      actor,
      change_summary,
      created_at
    FROM event_audit
    ${whereClause}
    ORDER BY ${order_by} ${order_dir}
    LIMIT $${paramIndex++} OFFSET $${paramIndex}
  `;

  const dataParams = [...params, page_size, offset];
  const dataResult = await pool.query<AuditLogEntry>(dataQuery, dataParams);

  return {
    entries: dataResult.rows,
    total,
    page,
    page_size,
  };
}

/**
 * Get audit trail for specific entity
 *
 * Convenience wrapper for queryAuditLog focused on single entity history
 *
 * @param pool - Database connection pool
 * @param entityType - Entity type (e.g., 'section', 'adr_decision')
 * @param entityId - Entity UUID
 * @returns Chronological audit entries for entity
 */
export async function getEntityAuditTrail(
  pool: Pool,
  entityType: string,
  entityId: string
): Promise<AuditLogEntry[]> {
  const result = await queryAuditLog(
    pool,
    { entity_type: entityType, entity_id: entityId },
    { page_size: 100, order_dir: 'ASC' }
  );

  return result.entries;
}

/**
 * Get recent audit activity across all entities
 *
 * @param pool - Database connection pool
 * @param limit - Number of recent entries to return
 * @returns Recent audit log entries
 */
export async function getRecentAuditActivity(
  pool: Pool,
  limit: number = 20
): Promise<AuditLogEntry[]> {
  const result = await pool.query<AuditLogEntry>(
    `SELECT
       id, entity_type, entity_id, operation, actor, change_summary, created_at
     FROM event_audit
     ORDER BY created_at DESC
     LIMIT $1`,
    [limit]
  );

  return result.rows;
}

/**
 * Get audit statistics for reporting
 *
 * @param pool - Database connection pool
 * @param since - Start date for statistics window
 * @returns Aggregated audit statistics
 */
export async function getAuditStatistics(
  pool: Pool,
  since?: Date
): Promise<{
  total_events: number;
  events_by_type: Record<string, number>;
  events_by_operation: Record<string, number>;
  unique_actors: number;
}> {
  const sinceClause = since ? 'WHERE created_at >= $1' : '';
  const params = since ? [since] : [];

  // Total events
  const totalResult = await pool.query(
    `SELECT COUNT(*) as total FROM event_audit ${sinceClause}`,
    params
  );
  const total_events = parseInt(totalResult.rows[0].total, 10);

  // Events by entity type
  const typeResult = await pool.query(
    `SELECT entity_type, COUNT(*) as count
     FROM event_audit ${sinceClause}
     GROUP BY entity_type`,
    params
  );
  const events_by_type: Record<string, number> = {};
  typeResult.rows.forEach((row) => {
    events_by_type[row.entity_type] = parseInt(row.count, 10);
  });

  // Events by operation
  const opResult = await pool.query(
    `SELECT operation, COUNT(*) as count
     FROM event_audit ${sinceClause}
     GROUP BY operation`,
    params
  );
  const events_by_operation: Record<string, number> = {};
  opResult.rows.forEach((row) => {
    events_by_operation[row.operation] = parseInt(row.count, 10);
  });

  // Unique actors
  const actorResult = await pool.query(
    `SELECT COUNT(DISTINCT actor) as count
     FROM event_audit ${sinceClause}`,
    params
  );
  const unique_actors = parseInt(actorResult.rows[0].count, 10);

  return {
    total_events,
    events_by_type,
    events_by_operation,
    unique_actors,
  };
}
