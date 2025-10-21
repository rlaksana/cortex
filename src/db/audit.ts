// Using gen_random_uuid() from PostgreSQL instead of UUID library
import { prisma } from './prisma-client.js';
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
  old_data?: Record<string, unknown>;
  new_data?: Record<string, unknown>;
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

    try {
      await prisma.getClient().eventAudit.create({
        data: {
          id: processedEvent.id ?? (await this.generateUUID()),
          event_type: processedEvent.eventType,
          table_name: processedEvent.table_name,
          record_id: processedEvent.record_id,
          operation: processedEvent.operation,
          old_data: this.filterSensitiveData(processedEvent.table_name, processedEvent.old_data ?? {}) as any,
          new_data: this.filterSensitiveData(processedEvent.table_name, processedEvent.new_data ?? {}) as any,
          changed_by: processedEvent.changed_by ?? 'system',
          tags: processedEvent.tags ?? {} as any,
          metadata: processedEvent.metadata ?? {} as any,
        }
      });

      logger.debug(
        {
          eventId: processedEvent.id,
          event_type: processedEvent.eventType,
          table_name: processedEvent.table_name,
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
      // Use Prisma createMany for batch insert
      const auditData = await Promise.all(
        processedEvents.map(async (event) => ({
          id: event.id ?? (await this.generateUUID()),
          event_type: event.eventType,
          table_name: event.table_name,
          record_id: event.record_id,
          operation: event.operation,
          old_data: this.filterSensitiveData(event.table_name, event.old_data ?? {}) as any,
          new_data: this.filterSensitiveData(event.table_name, event.new_data ?? {}) as any,
          changed_by: event.changed_by ?? 'system',
          tags: event.tags ?? {} as any,
          metadata: event.metadata ?? {} as any,
        }))
      );

      await prisma.getClient().eventAudit.createMany({
        data: auditData,
      });

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
      // Use Prisma to query audit events with filtering and pagination
      const whereClause: any = {};

      if (options.table_name) {
        whereClause.table_name = options.table_name;
      }

      if (options.record_id) {
        whereClause.record_id = options.record_id;
      }

      if (options.operation) {
        whereClause.operation = options.operation;
      }

      if (options.startDate || options.endDate) {
        whereClause.created_at = {};
        if (options.startDate) whereClause.created_at.gte = options.startDate;
        if (options.endDate) whereClause.created_at.lte = options.endDate;
      }

      const [eventsResult, totalResult] = await Promise.all([
        prisma.getClient().eventAudit.findMany({
          where: whereClause,
          orderBy: { created_at: (options.orderDirection?.toLowerCase() || 'desc') as 'asc' | 'desc' },
          take: options.limit || 100,
          skip: options.offset || 0,
        }),
        prisma.getClient().eventAudit.count({ where: whereClause }),
      ]);

      return {
        events: eventsResult.map((event: any) => ({
          ...event,
          eventType: event.eventType,
          table_name: event.table_name,
          record_id: event.record_id,
        })) as AuditEvent[],
        total: totalResult,
      };
    } catch (error) {
      logger.error({ error }, 'Failed to query audit events');
      throw error;
    }
  }

  /**
   * Get audit event history for a specific record
   */
  async getRecordHistory(table_name: string, record_id: string): Promise<AuditEvent[]> {
    return this.queryEvents({ table_name, record_id }).then(
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
      orderDirection: 'DESC',
    }).then((result) => result.events);
  }

  /**
   * Generate UUID using PostgreSQL gen_random_uuid()
   */
  private async generateUUID(): Promise<string> {
    const result = await prisma.getClient().$queryRaw<Array<{ uuid: string }>>`SELECT gen_random_uuid() as uuid`;
    return result[0]?.uuid || crypto.randomUUID();
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
      const now = new Date();
      const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
      const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

      // Execute all queries in parallel for better performance
      const [
        totalEvents,
        eventsByType,
        eventsByTable,
        eventsByOperation,
        lastHourCount,
        last24HoursCount,
        last7DaysCount
      ] = await Promise.all([
        // Total events
        prisma.getClient().eventAudit.count(),

        // Events by type
        prisma.getClient().eventAudit.groupBy({
          by: ['event_type'],
          _count: true,
        }),

        // Events by table
        prisma.getClient().eventAudit.groupBy({
          by: ['table_name'],
          _count: true,
        }),

        // Events by operation
        prisma.getClient().eventAudit.groupBy({
          by: ['operation'],
          _count: true,
        }),

        // Recent activity counts
        prisma.getClient().eventAudit.count({
          where: { created_at: { gte: oneHourAgo } }
        }),
        prisma.getClient().eventAudit.count({
          where: { created_at: { gte: oneDayAgo } }
        }),
        prisma.getClient().eventAudit.count({
          where: { created_at: { gte: sevenDaysAgo } }
        }),
      ]);

      // Process groupBy results
      const eventsByTypeMap: Record<string, number> = {};
      eventsByType.forEach((item: any) => {
        if (item.eventType) {
          eventsByTypeMap[item.eventType] = item._count;
        }
      });

      const eventsByTableMap: Record<string, number> = {};
      eventsByTable.forEach((item: any) => {
        if (item.table_name) {
          eventsByTableMap[item.table_name] = item._count;
        }
      });

      const eventsByOperationMap: Record<string, number> = {};
      eventsByOperation.forEach((item: any) => {
        eventsByOperationMap[item.operation] = item._count;
      });

      const statistics = {
        totalEvents,
        eventsByType: eventsByTypeMap,
        eventsByTable: eventsByTableMap,
        eventsByOperation: eventsByOperationMap,
        recentActivity: {
          lastHour: lastHourCount,
          last24Hours: last24HoursCount,
          last7Days: last7DaysCount,
        },
      };

      logger.debug({ statistics }, 'Retrieved comprehensive audit statistics');

      return statistics;
    } catch (error) {
      logger.error({ error }, 'Failed to get audit statistics');
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
      // Use Prisma deleteMany for cleanup
      const deleteResult = await prisma.getClient().eventAudit.deleteMany({
        where: {
          created_at: { lt: cutoffDate }
        }
      });
      const deletedCount = deleteResult.count;

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
          : undefined,
      changed_by: changed_by ?? undefined,
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
