// Using UnifiedDatabaseLayer for Qdrant operations
import { QdrantOnlyDatabaseLayer as UnifiedDatabaseLayer } from './unified-database-layer-v2.js';
import { logger } from '../utils/logger.js';
import * as crypto from 'crypto';

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
  table_name: string;
  record_id: string;
  operation: 'INSERT' | 'UPDATE' | 'DELETE';
  old_data?: Record<string, unknown> | null;
  new_data?: Record<string, unknown> | null;
  changed_by?: string;
  tags?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

export interface AuditQueryOptions {
  eventType?: string;
  table_name?: string;
  record_id?: string;
  operation?: 'INSERT' | 'UPDATE' | 'DELETE';
  changed_by?: string;
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
    [table_name: string]: string[];
  };
}

class AuditLogger {
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

    const qdrantConfig: any = {
      url: process.env.QDRANT_URL || 'http://localhost:6333',
      collectionName: 'cortex-audit',
      timeout: 30000,
      batchSize: 100,
      maxRetries: 3,
    };

    if (process.env.QDRANT_API_KEY) {
      qdrantConfig.apiKey = process.env.QDRANT_API_KEY;
    }

    const db = new UnifiedDatabaseLayer({
      type: 'qdrant',
      qdrant: qdrantConfig,
    });
    await db.initialize();

    try {
      await db.create('event_audit', {
        id: processedEvent.id ?? (await this.generateUUID()),
        event_type: processedEvent.eventType,
        table_name: processedEvent.table_name,
        record_id: processedEvent.record_id,
        operation: processedEvent.operation,
        old_data: this.filterSensitiveData(
          processedEvent.table_name,
          processedEvent.old_data ?? {}
        ),
        new_data: this.filterSensitiveData(
          processedEvent.table_name,
          processedEvent.new_data ?? {}
        ),
        changed_by: processedEvent.changed_by ?? 'system',
        tags: processedEvent.tags ?? {},
        metadata: processedEvent.metadata ?? {},
        changed_at: new Date().toISOString(),
      });

      logger.debug(
        {
          eventId: processedEvent.id,
          tableName: processedEvent.table_name,
          operation: processedEvent.operation,
        },
        'Audit event logged successfully'
      );
    } catch (error) {
      logger.error({ error, event: processedEvent }, 'Failed to log audit event');
      // Don't throw - audit logging failures shouldn't break the main operation
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
      const config: any = {
        type: 'qdrant',
        qdrant: {
          url: process.env.QDRANT_URL || 'http://localhost:6333',
          collectionName: 'cortex-audit',
          timeout: 30000,
          batchSize: 100,
          maxRetries: 3,
        },
      };

      if (process.env.QDRANT_API_KEY) {
        config.qdrant.apiKey = process.env.QDRANT_API_KEY;
      }

      const db = new UnifiedDatabaseLayer(config);
      await db.initialize();

      // Use Qdrant for batch insert
      const auditData = await Promise.all(
        processedEvents.map(async (event) => ({
          id: event.id ?? (await this.generateUUID()),
          event_type: event.eventType,
          table_name: event.table_name,
          record_id: event.record_id,
          operation: event.operation,
          old_data: this.filterSensitiveData(event.table_name, event.old_data ?? {}),
          new_data: this.filterSensitiveData(event.table_name, event.new_data ?? {}),
          changed_by: event.changed_by ?? 'system',
          tags: event.tags ?? {},
          metadata: event.metadata ?? {},
          changed_at: new Date().toISOString(),
        }))
      );

      // Create audit records in batch using Qdrant
      for (const record of auditData) {
        await db.create('event_audit', record);
      }

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
    try {
      const config: any = {
        type: 'qdrant',
        qdrant: {
          url: process.env.QDRANT_URL || 'http://localhost:6333',
          collectionName: 'cortex-audit',
          timeout: 30000,
          batchSize: 100,
          maxRetries: 3,
        },
      };

      if (process.env.QDRANT_API_KEY) {
        config.qdrant.apiKey = process.env.QDRANT_API_KEY;
      }

      const db = new UnifiedDatabaseLayer(config);
      await db.initialize();

      // Build where conditions for Qdrant query
      const whereConditions: any = {};

      if (options.eventType) {
        whereConditions.event_type = options.eventType;
      }

      if (options.table_name) {
        whereConditions.table_name = options.table_name;
      }

      if (options.record_id) {
        whereConditions.record_id = options.record_id;
      }

      if (options.operation) {
        whereConditions.operation = options.operation;
      }

      if (options.changed_by) {
        whereConditions.changed_by = options.changed_by;
      }

      if (options.startDate || options.endDate) {
        whereConditions.changed_at = {};
        if (options.startDate) {
          whereConditions.changed_at.gte = options.startDate.toISOString();
        }
        if (options.endDate) {
          whereConditions.changed_at.lte = options.endDate.toISOString();
        }
      }

      // Query events using Qdrant
      const events = await db.find('event_audit', whereConditions, {
        take: options.limit || 100,
        orderBy: { [options.orderBy || 'changed_at']: options.orderDirection || 'DESC' },
      });

      // Get total count
      const totalResult = await db.query(
        `SELECT COUNT(*) as count FROM event_audit WHERE 1=1 ${
          Object.keys(whereConditions).length > 0
            ? `AND ${Object.entries(whereConditions)
                .map(([key, value]) => {
                  if (typeof value === 'object' && value !== null && 'gte' in value) {
                    return `${key} >= '${(value as any).gte}'`;
                  }
                  if (typeof value === 'object' && value !== null && 'lte' in value) {
                    return `${key} <= '${(value as any).lte}'`;
                  }
                  return `${key} = '${value}'`;
                })
                .join(' AND ')}`
            : ''
        }`
      );

      const total = parseInt(totalResult.rows[0].count);

      // Transform results to match expected format
      const transformedEvents = events.map((event: any) => ({
        id: event.id,
        eventType: event.event_type,
        table_name: event.table_name,
        record_id: event.record_id,
        operation: event.operation,
        old_data: event.old_data,
        new_data: event.new_data,
        changed_by: event.changed_by,
        tags: event.tags,
        metadata: event.metadata,
        changed_at: event.changed_at,
      }));

      return { events: transformedEvents, total };
    } catch (error) {
      logger.error({ error, options }, 'Failed to query audit events');
      throw new Error(`Audit query failed: ${(error as Error).message}`);
    }
  }

  /**
   * Get audit event history for a specific record
   */
  async getRecordHistory(table_name: string, record_id: string): Promise<AuditEvent[]> {
    return this.queryEvents({ table_name, record_id }).then((result) => result.events);
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
      orderDirection: 'DESC',
    }).then((result) => result.events);
  }

  /**
   * Generate UUID using qdrant gen_random_uuid()
   */
  /**
   * Generate UUID using Qdrant gen_random_uuid() or fallback to crypto
   */
  private async generateUUID(): Promise<string> {
    try {
      const qdrantConfig: any = {
        url: process.env.QDRANT_URL || 'http://localhost:6333',
        collectionName: 'cortex-audit',
        timeout: 30000,
        batchSize: 100,
        maxRetries: 3,
      };

      if (process.env.QDRANT_API_KEY) {
        qdrantConfig.apiKey = process.env.QDRANT_API_KEY;
      }

      const db = new UnifiedDatabaseLayer({
        type: 'qdrant',
        qdrant: qdrantConfig,
      });
      await db.initialize();

      const result = await db.query(`SELECT gen_random_uuid() as uuid`);
      return result.rows[0].uuid;
    } catch (error) {
      logger.warn({ error }, 'Failed to generate UUID with Qdrant, using fallback');
      return crypto.randomUUID();
    }
  }

  /**
   * Check if event should be logged based on filters
   */
  private shouldLogEvent(event: AuditEvent): boolean {
    const { exclude, include } = this.filter;

    // Check exclusions
    if (exclude?.tables?.includes(event.table_name)) {
      return false;
    }

    if (exclude?.operations?.includes(event.operation)) {
      return false;
    }

    if (exclude?.eventTypes?.includes(event.eventType)) {
      return false;
    }

    // Check inclusions (if specified, only log these)
    if (include?.tables && !include.tables.includes(event.table_name)) {
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
      changed_by: event.changed_by ?? 'system',
      tags: event.tags ?? {},
      metadata: event.metadata ?? {},
    };
  }

  /**
   * Filter sensitive data from audit records
   */
  private filterSensitiveData(
    table_name: string,
    data: Record<string, unknown>
  ): Record<string, unknown> {
    if (!data || typeof data !== 'object') {
      return data;
    }

    const sensitiveFields = this.filter.sensitiveFields?.[table_name];
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

    const processedEvents = [...this.batchQueue];
    this.batchQueue = [];

    try {
      const config: any = {
        type: 'qdrant',
        qdrant: {
          url: process.env.QDRANT_URL || 'http://localhost:6333',
          collectionName: 'cortex-audit',
          timeout: 30000,
          batchSize: 100,
          maxRetries: 3,
        },
      };

      if (process.env.QDRANT_API_KEY) {
        config.qdrant.apiKey = process.env.QDRANT_API_KEY;
      }

      const db = new UnifiedDatabaseLayer(config);
      await db.initialize();

      const auditData = processedEvents.map((event) => ({
        id: event.id ?? crypto.randomUUID(),
        event_type: event.eventType,
        table_name: event.table_name,
        record_id: event.record_id,
        operation: event.operation,
        old_data: this.filterSensitiveData(event.table_name, event.old_data ?? {}),
        new_data: this.filterSensitiveData(event.table_name, event.new_data ?? {}),
        changed_by: event.changed_by ?? 'system',
        tags: event.tags ?? {},
        metadata: event.metadata ?? {},
        changed_at: new Date().toISOString(),
      }));

      // Create audit records in batch using Qdrant
      for (const record of auditData) {
        await db.create('event_audit', record);
      }

      logger.debug({ count: processedEvents.length }, 'Batch audit events logged');
    } catch (error) {
      logger.error({ error }, 'Failed to log batch audit events');
      // Don't throw - audit failures shouldn't break the main operation
    }
  }

  /**
   * Get comprehensive audit statistics
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
    try {
      const config: any = {
        type: 'qdrant',
        qdrant: {
          url: process.env.QDRANT_URL || 'http://localhost:6333',
          collectionName: 'cortex-audit',
          timeout: 30000,
          batchSize: 100,
          maxRetries: 3,
        },
      };

      if (process.env.QDRANT_API_KEY) {
        config.qdrant.apiKey = process.env.QDRANT_API_KEY;
      }

      const db = new UnifiedDatabaseLayer(config);
      await db.initialize();

      const now = new Date();
      const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
      const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

      // Execute all queries in parallel for better performance using Qdrant
      const [
        totalEvents,
        eventsByType,
        eventsByTable,
        eventsByOperation,
        lastHourCount,
        last24HoursCount,
        last7DaysCount,
      ] = await Promise.all([
        // Total events
        db
          .query(`SELECT COUNT(*) as count FROM event_audit`)
          .then((r) => parseInt(r.rows[0].count)),

        // Events by type
        db
          .query(`SELECT event_type, COUNT(*) as count FROM event_audit GROUP BY event_type`)
          .then((r) =>
            r.rows.reduce(
              (acc: Record<string, number>, row: any) => ({
                ...acc,
                [row.event_type]: parseInt(row.count),
              }),
              {}
            )
          ),

        // Events by table
        db
          .query(`SELECT table_name, COUNT(*) as count FROM event_audit GROUP BY table_name`)
          .then((r) =>
            r.rows.reduce(
              (acc: Record<string, number>, row: any) => ({
                ...acc,
                [row.table_name]: parseInt(row.count),
              }),
              {}
            )
          ),

        // Events by operation
        db
          .query(`SELECT operation, COUNT(*) as count FROM event_audit GROUP BY operation`)
          .then((r) =>
            r.rows.reduce(
              (acc: Record<string, number>, row: any) => ({
                ...acc,
                [row.operation]: parseInt(row.count),
              }),
              {}
            )
          ),

        // Recent activity counts
        db
          .query(`SELECT COUNT(*) as count FROM event_audit WHERE changed_at >= $1`, [
            oneHourAgo.toISOString(),
          ])
          .then((r) => parseInt(r.rows[0].count)),
        db
          .query(`SELECT COUNT(*) as count FROM event_audit WHERE changed_at >= $1`, [
            oneDayAgo.toISOString(),
          ])
          .then((r) => parseInt(r.rows[0].count)),
        db
          .query(`SELECT COUNT(*) as count FROM event_audit WHERE changed_at >= $1`, [
            sevenDaysAgo.toISOString(),
          ])
          .then((r) => parseInt(r.rows[0].count)),
      ]);

      return {
        totalEvents,
        eventsByType,
        eventsByTable,
        eventsByOperation,
        recentActivity: {
          lastHour: lastHourCount,
          last24Hours: last24HoursCount,
          last7Days: last7DaysCount,
        },
      };
    } catch (error) {
      logger.error('Failed to get audit statistics:', error);
      throw error;
    }
  }

  /**
   * Clean up old audit events
   */
  async cleanup(olderThanDays: number = 90): Promise<number> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - olderThanDays);

    try {
      const config: any = {
        type: 'qdrant',
        qdrant: {
          url: process.env.QDRANT_URL || 'http://localhost:6333',
          collectionName: 'cortex-audit',
          timeout: 30000,
          batchSize: 100,
          maxRetries: 3,
        },
      };

      if (process.env.QDRANT_API_KEY) {
        config.qdrant.apiKey = process.env.QDRANT_API_KEY;
      }

      const db = new UnifiedDatabaseLayer(config);
      await db.initialize();

      // Use Qdrant DELETE for cleanup
      const deleteResult = await db.query(
        `DELETE FROM event_audit WHERE changed_at < $1 RETURNING COUNT(*) as count`,
        [cutoffDate.toISOString()]
      );

      const deletedCount = parseInt(deleteResult.rows[0].count);

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
  entity_type: string,
  entity_id: string,
  operation: 'INSERT' | 'UPDATE' | 'DELETE',
  new_data?: unknown,
  changed_by?: string
): Promise<void> {
  try {
    await auditLogger.logEvent({
      eventType: 'data_change',
      table_name: entity_type,
      record_id: entity_id,
      operation,
      new_data:
        typeof new_data === 'object' && new_data !== null
          ? (new_data as Record<string, unknown>)
          : null,
      ...(changed_by && { changed_by }),
      metadata: {
        pool_used: true,
        timestamp: new Date().toISOString(),
      },
    });
  } catch (error) {
    // Log error but don't throw to maintain backward compatibility
    logger.error({ error }, 'Audit log failed');
  }
}
