// Using gen_random_uuid() from PostgreSQL instead of UUID library
import { dbPool } from './pool.js';
import { logger } from '../utils/logger.js';

/**
 * Audit Logging System
 *
 * Features:
 * - Automatic audit trail for all database operations
 * - Event tracking with UUIDs for traceability
 * - JSON-based data capture (before/after states)
 * - Context-aware audit entries with metadata
 * - Batch audit operations for performance
 * - Audit log querying and filtering
 * - Sensitive data filtering
 */

export interface AuditEvent {
  id?: string;
  eventType: string;
  tableName: string;
  recordId: string;
  operation: 'INSERT' | 'UPDATE' | 'DELETE';
  oldData?: Record<string, unknown>;
  newData?: Record<string, unknown>;
  changedBy?: string;
  tags?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

export interface AuditQueryOptions {
  eventType?: string;
  tableName?: string;
  recordId?: string;
  operation?: 'INSERT' | 'UPDATE' | 'DELETE';
  changedBy?: string;
  startDate?: Date;
  endDate?: Date;
  limit?: number;
  offset?: number;
  orderBy?: 'changed_at' | 'event_type' | 'table_name';
  orderDirection?: 'ASC' | 'DESC';
}

export interface AuditFilter {
  exclude?: {
    tables?: string[];
    operations?: ('INSERT' | 'UPDATE' | 'DELETE')[];
    eventTypes?: string[];
  };
  include?: {
    tables?: string[];
    operations?: ('INSERT' | 'UPDATE' | 'DELETE')[];
    eventTypes?: string[];
  };
  sensitiveFields?: {
    [tableName: string]: string[];
  };
}

class AuditLogger {
  private auditTable = 'event_audit';
  private filter: AuditFilter = {};
  private batchQueue: AuditEvent[] = [];
  private batchTimeout: NodeJS.Timeout | null = null;
  private batchSize = 100;
  private batchTimeoutMs = 5000;

  constructor() {
    this.setupBatchProcessing();
  }

  /**
   * Configure audit filters
   */
  configureFilter(filter: AuditFilter): void {
    this.filter = { ...this.filter, ...filter };
    logger.info({ filter }, 'Audit filter configured');
  }

  /**
   * Log a single audit event
   */
  async logEvent(event: AuditEvent): Promise<void> {
    if (!this.shouldLogEvent(event)) {
      return;
    }

    const processedEvent = await this.processEvent(event);

    try {
      const query = `
        INSERT INTO ${this.auditTable}
        (event_id, event_type, table_name, record_id, operation, old_data, new_data, changed_by, tags, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      `;

      const params = [
        processedEvent.id ?? (await this.generateUUID()),
        processedEvent.eventType,
        processedEvent.tableName,
        processedEvent.recordId,
        processedEvent.operation,
        this.filterSensitiveData(processedEvent.tableName, processedEvent.oldData ?? {}),
        this.filterSensitiveData(processedEvent.tableName, processedEvent.newData ?? {}),
        processedEvent.changedBy ?? 'system',
        processedEvent.tags ?? {},
        processedEvent.metadata ?? {},
      ];

      await dbPool.query(query, params);

      logger.debug(
        {
          eventId: processedEvent.id,
          eventType: processedEvent.eventType,
          tableName: processedEvent.tableName,
          operation: processedEvent.operation,
        },
        'Audit event logged'
      );
    } catch (error) {
      logger.error({ error }, 'Failed to log audit event');
      // Don't throw - audit failures shouldn't break the main operation
    }
  }

  /**
   * Log multiple audit events in batch
   */
  async logBatchEvents(events: AuditEvent[]): Promise<void> {
    const filteredEvents = events.filter((event) => this.shouldLogEvent(event));
    const processedEvents = await Promise.all(
      filteredEvents.map((event) => this.processEvent(event))
    );

    if (processedEvents.length === 0) {
      return;
    }

    try {
      const query = `
        INSERT INTO ${this.auditTable}
        (event_id, event_type, table_name, record_id, operation, old_data, new_data, changed_by, tags, metadata)
        VALUES ${processedEvents.map((_, i) => `($${i * 10 + 1}, $${i * 10 + 2}, $${i * 10 + 3}, $${i * 10 + 4}, $${i * 10 + 5}, $${i * 10 + 6}, $${i * 10 + 7}, $${i * 10 + 8}, $${i * 10 + 9}, $${i * 10 + 10})`).join(', ')}
      `;

      const params = await Promise.all(
        processedEvents.flatMap(async (event) => [
          event.id ?? (await this.generateUUID()),
          event.eventType,
          event.tableName,
          event.recordId,
          event.operation,
          this.filterSensitiveData(event.tableName, event.oldData ?? {}),
          this.filterSensitiveData(event.tableName, event.newData ?? {}),
          event.changedBy ?? 'system',
          event.tags ?? {},
          event.metadata ?? {},
        ])
      );

      await dbPool.query(query, params);

      logger.debug({ count: processedEvents.length }, 'Batch audit events logged');
    } catch (error) {
      logger.error({ error }, 'Failed to log batch audit events');
      // Don't throw - audit failures shouldn't break the main operation
    }
  }

  /**
   * Queue an event for batch processing
   */
  async queueEvent(event: AuditEvent): Promise<void> {
    if (!this.shouldLogEvent(event)) {
      return;
    }

    this.batchQueue.push(await this.processEvent(event));

    if (this.batchQueue.length >= this.batchSize) {
      this.flushBatchQueue();
    } else {
      this.scheduleBatchFlush();
    }
  }

  /**
   * Query audit events
   */
  async queryEvents(options: AuditQueryOptions = {}): Promise<{
    events: AuditEvent[];
    total: number;
  }> {
    const {
      eventType,
      tableName,
      recordId,
      operation,
      changedBy,
      startDate,
      endDate,
      limit = 100,
      offset = 0,
      orderBy = 'changed_at',
      orderDirection = 'DESC',
    } = options;

    const conditions: string[] = [];
    const params: unknown[] = [];
    let paramIndex = 1;

    if (eventType) {
      conditions.push(`event_type = $${paramIndex++}`);
      params.push(eventType);
    }

    if (tableName) {
      conditions.push(`table_name = $${paramIndex++}`);
      params.push(tableName);
    }

    if (recordId) {
      conditions.push(`record_id = $${paramIndex++}`);
      params.push(recordId);
    }

    if (operation) {
      conditions.push(`operation = $${paramIndex++}`);
      params.push(operation);
    }

    if (changedBy) {
      conditions.push(`changed_by = $${paramIndex++}`);
      params.push(changedBy);
    }

    if (startDate) {
      conditions.push(`changed_at >= $${paramIndex++}`);
      params.push(startDate);
    }

    if (endDate) {
      conditions.push(`changed_at <= $${paramIndex++}`);
      params.push(endDate);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const orderClause = `ORDER BY ${orderBy} ${orderDirection}`;
    const limitClause = `LIMIT $${paramIndex++} OFFSET $${paramIndex++}`;
    params.push(limit, offset);

    // Query for events
    const eventsQuery = `
      SELECT
        event_id as id,
        event_type as "eventType",
        table_name as "tableName",
        record_id as "recordId",
        operation,
        old_data as "oldData",
        new_data as "newData",
        changed_by as "changedBy",
        changed_at as "changedAt",
        tags,
        metadata
      FROM ${this.auditTable}
      ${whereClause}
      ${orderClause}
      ${limitClause}
    `;

    // Query for total count
    const countQuery = `
      SELECT COUNT(*) as total
      FROM ${this.auditTable}
      ${whereClause}
    `;

    try {
      const [eventsResult, countResult] = await Promise.all([
        dbPool.query(eventsQuery, params),
        dbPool.query(countQuery, params.slice(0, -2)), // Exclude limit/offset params
      ]);

      return {
        events: eventsResult.rows as AuditEvent[],
        total: parseInt((countResult.rows[0] as Record<string, unknown>)?.total as string),
      };
    } catch (error) {
      logger.error({ error }, 'Failed to query audit events');
      throw error;
    }
  }

  /**
   * Get audit event history for a specific record
   */
  async getRecordHistory(tableName: string, recordId: string): Promise<AuditEvent[]> {
    return this.queryEvents({ tableName, recordId, orderBy: 'changed_at' }).then(
      (result) => result.events
    );
  }

  /**
   * Get recent audit activity
   */
  async getRecentActivity(hours: number = 24, limit: number = 50): Promise<AuditEvent[]> {
    const startDate = new Date();
    startDate.setHours(startDate.getHours() - hours);

    return this.queryEvents({
      startDate,
      limit,
      orderBy: 'changed_at',
      orderDirection: 'DESC',
    }).then((result) => result.events);
  }

  /**
   * Generate UUID using PostgreSQL gen_random_uuid()
   */
  private async generateUUID(): Promise<string> {
    const result = await dbPool.query('SELECT gen_random_uuid() as uuid');
    return (result.rows[0] as Record<string, unknown>)?.uuid as string;
  }

  /**
   * Check if event should be logged based on filters
   */
  private shouldLogEvent(event: AuditEvent): boolean {
    const { exclude, include } = this.filter;

    // Check exclusions
    if (exclude?.tables?.includes(event.tableName)) {
      return false;
    }

    if (exclude?.operations?.includes(event.operation)) {
      return false;
    }

    if (exclude?.eventTypes?.includes(event.eventType)) {
      return false;
    }

    // Check inclusions (if specified, only log these)
    if (include?.tables && !include.tables.includes(event.tableName)) {
      return false;
    }

    if (include?.operations && !include.operations.includes(event.operation)) {
      return false;
    }

    if (include?.eventTypes && !include.eventTypes.includes(event.eventType)) {
      return false;
    }

    return true;
  }

  /**
   * Process event for logging
   */
  private async processEvent(event: AuditEvent): Promise<AuditEvent> {
    return {
      ...event,
      id: event.id ?? (await this.generateUUID()),
      changedBy: event.changedBy ?? 'system',
      tags: event.tags ?? {},
      metadata: event.metadata ?? {},
    };
  }

  /**
   * Filter sensitive data from audit records
   */
  private filterSensitiveData(
    tableName: string,
    data: Record<string, unknown>
  ): Record<string, unknown> {
    if (!data || typeof data !== 'object') {
      return data;
    }

    const sensitiveFields = this.filter.sensitiveFields?.[tableName];
    if (!sensitiveFields) {
      return data;
    }

    const filtered = { ...data };
    for (const field of sensitiveFields) {
      if (field in filtered) {
        filtered[field] = '[REDACTED]';
      }
    }

    return filtered;
  }

  /**
   * Setup batch processing
   */
  private setupBatchProcessing(): void {
    process.on('exit', () => {
      this.flushBatchQueue();
    });

    process.on('SIGINT', () => {
      this.flushBatchQueue();
    });

    process.on('SIGTERM', () => {
      this.flushBatchQueue();
    });
  }

  /**
   * Schedule batch flush
   */
  private scheduleBatchFlush(): void {
    if (this.batchTimeout) {
      return;
    }

    this.batchTimeout = setTimeout(() => {
      this.flushBatchQueue();
    }, this.batchTimeoutMs);
  }

  /**
   * Flush batch queue
   */
  private async flushBatchQueue(): Promise<void> {
    if (this.batchQueue.length === 0) {
      return;
    }

    if (this.batchTimeout) {
      clearTimeout(this.batchTimeout);
      this.batchTimeout = null;
    }

    const eventsToLog = [...this.batchQueue];
    this.batchQueue = [];

    try {
      await this.logBatchEvents(eventsToLog);
    } catch (error) {
      logger.error({ error }, 'Failed to flush audit batch');
      // Put events back in queue for retry
      this.batchQueue.unshift(...eventsToLog);
    }
  }

  /**
   * Get audit statistics
   */
  async getStatistics(): Promise<{
    totalEvents: number;
    eventsByType: Record<string, number>;
    eventsByTable: Record<string, number>;
    eventsByOperation: Record<string, number>;
    recentActivity: {
      lastHour: number;
      last24Hours: number;
      last7Days: number;
    };
  }> {
    const queries = [
      // Total events
      'SELECT COUNT(*) as count FROM event_audit',

      // Events by type
      `SELECT event_type, COUNT(*) as count
       FROM event_audit
       GROUP BY event_type`,

      // Events by table
      `SELECT table_name, COUNT(*) as count
       FROM event_audit
       GROUP BY table_name`,

      // Events by operation
      `SELECT operation, COUNT(*) as count
       FROM event_audit
       GROUP BY operation`,

      // Recent activity
      `SELECT
         COUNT(CASE WHEN changed_at >= NOW() - INTERVAL '1 hour' THEN 1 END) as last_hour,
         COUNT(CASE WHEN changed_at >= NOW() - INTERVAL '24 hours' THEN 1 END) as last_24_hours,
         COUNT(CASE WHEN changed_at >= NOW() - INTERVAL '7 days' THEN 1 END) as last_7_days
       FROM event_audit`,
    ];

    try {
      const results = await Promise.all(queries.map((query) => dbPool.query(query)));

      return {
        totalEvents: parseInt((results[0].rows[0] as Record<string, unknown>)?.count as string),
        eventsByType: this.arrayToObject(
          results[1].rows as Record<string, unknown>[],
          'event_type',
          'count'
        ),
        eventsByTable: this.arrayToObject(
          results[2].rows as Record<string, unknown>[],
          'table_name',
          'count'
        ),
        eventsByOperation: this.arrayToObject(
          results[3].rows as Record<string, unknown>[],
          'operation',
          'count'
        ),
        recentActivity: {
          lastHour:
            parseInt((results[4].rows[0] as Record<string, unknown>)?.last_hour as string) || 0,
          last24Hours:
            parseInt((results[4].rows[0] as Record<string, unknown>)?.last_24h as string) || 0,
          last7Days:
            parseInt((results[4].rows[0] as Record<string, unknown>)?.last_7d as string) || 0,
        },
      };
    } catch (error) {
      logger.error({ error }, 'Failed to get audit statistics');
      throw error;
    }
  }

  /**
   * Convert query result array to object
   */
  private arrayToObject(
    rows: Record<string, unknown>[],
    key: string,
    value: string
  ): Record<string, number> {
    return rows.reduce(
      (obj: Record<string, number>, row) => {
        const rowKey = String(row[key]);
        const rowValue = Number(row[value]);
        if (rowKey && !isNaN(rowValue)) {
          obj[rowKey] = rowValue;
        }
        return obj;
      },
      {} as Record<string, number>
    );
  }

  /**
   * Clean up old audit events
   */
  async cleanup(olderThanDays: number = 90): Promise<number> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - olderThanDays);

    const query = `
      DELETE FROM ${this.auditTable}
      WHERE changed_at < $1
      RETURNING id
    `;

    try {
      const result = await dbPool.query(query, [cutoffDate]);
      const deletedCount = result.rowCount ?? 0;

      logger.info({ deletedCount, olderThanDays }, `Cleaned up ${deletedCount} old audit events`);

      return deletedCount;
    } catch (error) {
      logger.error({ error }, 'Failed to cleanup audit events');
      throw error;
    }
  }
}

// Export singleton instance
export const auditLogger = new AuditLogger();

// Export for testing
export { AuditLogger };

// Configure default sensitive fields
auditLogger.configureFilter({
  sensitiveFields: {
    // Add sensitive fields by table name
    users: ['password', 'password_hash', 'email', 'phone'],
    sessions: ['token', 'refresh_token'],
    api_keys: ['key', 'secret'],
    // Add more as needed
  },
});

/**
 * Legacy auditLog function for backward compatibility
 * Wraps the new auditLogger.logEvent method
 */
export async function auditLog(
  pool: unknown,
  entityType: string,
  entityId: string,
  operation: 'INSERT' | 'UPDATE' | 'DELETE',
  newData?: unknown,
  changedBy?: string
): Promise<void> {
  try {
    await auditLogger.logEvent({
      eventType: 'data_change',
      tableName: entityType,
      recordId: entityId,
      operation,
      newData:
        typeof newData === 'object' && newData !== null
          ? (newData as Record<string, unknown>)
          : undefined,
      changedBy: changedBy ?? undefined,
      metadata: {
        pool_used: !!pool,
        timestamp: new Date().toISOString(),
      },
    });
  } catch (error) {
    // Log error but don't throw to maintain backward compatibility
    logger.error({ error }, 'Audit log failed');
  }
}
