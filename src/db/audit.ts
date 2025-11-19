// EMERGENCY ROLLBACK: isolatedModules export type violations and any type propagation

// Using UnifiedDatabaseLayer for Qdrant operations
import * as crypto from 'crypto';

import { logger } from '@/utils/logger.js';

import {
  type QdrantDatabaseConfig,
  QdrantOnlyDatabaseLayer as UnifiedDatabaseLayer,
} from './unified-database-layer-v2.js';
import { getKeyVaultService } from '../services/security/key-vault-service.js';
import {
  AuditCategory,
  AuditEventType,
  type AuditMetadata,
  AuditOperation,
  type AuditResult,
  AuditSource,
  type AuditValidationResult,
  type ComplianceInfo,
  createTypedAuditEvent,
  type GeographicInfo,
  SensitivityLevel,
  type TypedAuditEvent,
  type TypedAuditFilter,
  type TypedAuditQueryOptions,
  type TypedAuditQueryResult,
  validateAuditEvent,
} from '../types/audit-types.js';
import {
  type AuditEventRecord,
  safeAuditEventAccess,
} from '../utils/database-type-guards.js';

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

// Legacy interfaces for backward compatibility
export interface AuditEvent {
  id?: string;
  eventType: string;
  tableName: string;
  recordId: string;
  operation: 'INSERT' | 'UPDATE' | 'DELETE';
  oldData?: Record<string, unknown> | null;
  newData?: Record<string, unknown> | null;
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
  orderBy?: 'changed_at' | 'event_type' | 'tableName';
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

// Re-export the new typed interfaces for external use
export {
  AuditCategory,
  AuditEventType,
  type AuditOperation,
  type AuditSource,
  type AuditValidationResult,
  type ComplianceFramework,
  type ComplianceRegulation,
  type SensitivityLevel,
  type TypedAuditEvent,
  type TypedAuditFilter,
  type TypedAuditQueryResult,
  type TypedAuditStatistics,
} from '../types/audit-types.js';

class AuditLogger {
  private filter: TypedAuditFilter = {};
  private batchQueue: Partial<AuditEventRecord>[] = [];
  private batchTimeout: NodeJS.Timeout | null = null;
  private batchSize = 100;
  private batchTimeoutMs = 5000;

  constructor() {
    this.setupBatchProcessing();
  }

  /**
   * Configure audit filters
   */
  configureFilter(filter: TypedAuditFilter): void {
    this.filter = { ...this.filter, ...filter };
    logger.info({ filter }, 'Audit filter configured');
  }

  /**
   * Get Qdrant configuration from key vault with environment fallback
   */
  private async getQdrantConfig(): Promise<QdrantDatabaseConfig['qdrant']> {
    const keyVault = getKeyVaultService();

    try {
      const qdrantKey = await keyVault.get_key_by_name('qdrant_api_key');

      const config: QdrantDatabaseConfig['qdrant'] = {
        url: process.env.QDRANT_URL || 'http://localhost:6333',
        collectionName: 'cortex-audit',
        timeout: 30000,
        batchSize: 100,
        maxRetries: 3,
      };

      if (qdrantKey?.value || process.env.QDRANT_API_KEY) {
        config.apiKey = qdrantKey?.value || process.env.QDRANT_API_KEY;
      }

      return config;
    } catch (error) {
      logger.warn(
        { error },
        'Failed to get Qdrant config from key vault, using environment fallback'
      );

      // Fallback to environment variables
      const config: QdrantDatabaseConfig['qdrant'] = {
        url: process.env.QDRANT_URL || 'http://localhost:6333',
        collectionName: 'cortex-audit',
        timeout: 30000,
        batchSize: 100,
        maxRetries: 3,
      };

      if (process.env.QDRANT_API_KEY) {
        config.apiKey = process.env.QDRANT_API_KEY;
      }

      return config;
    }
  }

  private async createDatabaseLayer(): Promise<UnifiedDatabaseLayer> {
    const qdrantConfig = await this.getQdrantConfig();
    const config: QdrantDatabaseConfig = {
      type: 'qdrant',
      qdrant: qdrantConfig,
    };
    const db = new UnifiedDatabaseLayer(config);
    await db.initialize();
    return db;
  }

  /**
   * Log a single audit event (Legacy - for backward compatibility)
   */
  async logEvent(event: AuditEvent): Promise<void> {
    if (!this.shouldLogEvent(event)) {
      return;
    }

    const processedEvent = await this.processEvent(event as unknown);

    const db = await this.createDatabaseLayer();

    const safeEvent = safeAuditEventAccess(processedEvent);

    try {
      await db.create('event_audit', {
        id: safeEvent.id ?? (await this.generateUUID()),
        event_type: safeEvent.eventType,
        tableName: safeEvent.tableName,
        recordId: safeEvent.recordId,
        operation: safeEvent.operation,
        oldData: this.filterSensitiveData(safeEvent.tableName || 'unknown', safeEvent.oldData ?? {}),
        newData: this.filterSensitiveData(safeEvent.tableName || 'unknown', safeEvent.newData ?? {}),
        changedBy: safeEvent.changedBy ?? 'system',
        tags: safeEvent.tags ?? {},
        metadata: safeEvent.metadata ?? {},
        changed_at: new Date().toISOString(),
      });

      logger.debug(
        {
          eventId: safeEvent.id,
          tableName: safeEvent.tableName,
          operation: safeEvent.operation,
        },
        'Audit event logged successfully'
      );
    } catch (error) {
      logger.error({ error, event: safeEvent }, 'Failed to log audit event');
      // Don't throw - audit logging failures shouldn't break the main operation
    }
  }

  /**
   * Log a typed audit event with validation and enhanced features
   */
  async logTypedEvent(event: TypedAuditEvent): Promise<AuditValidationResult> {
    // Validate the event
    const validationResult = validateAuditEvent(event);

    if (!validationResult.isValid) {
      logger.error(
        {
          event,
          errors: validationResult.errors,
        },
        'Audit event validation failed'
      );

      // Still log the event but mark as validation failure
      const invalidEvent = createTypedAuditEvent({
        ...event,
        success: false,
        metadata: {
          ...event.metadata,
          validationErrors: validationResult.errors.join('; '),
        } as unknown as AuditMetadata,
      });

      return this.storeTypedEvent(invalidEvent);
    }

    // Log warnings if any
    if (validationResult.warnings.length > 0) {
      logger.warn(
        {
          event,
          warnings: validationResult.warnings,
        },
        'Audit event validation warnings'
      );
    }

    return this.storeTypedEvent(event);
  }

  /**
   * Store a typed audit event in the database
   */
  private async storeTypedEvent(event: TypedAuditEvent): Promise<AuditValidationResult> {
    if (!this.shouldLogTypedEvent(event)) {
      return {
        isValid: true,
        errors: [],
        warnings: ['Event filtered by audit rules'],
      };
    }

    // Get database configuration from key vault
      const db = await this.createDatabaseLayer();

    try {
      await db.create('typed_audit_events', {
        // Core identification
        id: event.id,
        event_type: event.eventType,
        category: event.category,

        // Entity information
        entity_type: event.entityType,
        entity_id: event.entityId,
        operation: event.operation,

        // Data changes
        oldData: this.filterSensitiveData(event.entityType, event.oldData),
        newData: this.filterSensitiveData(event.entityType, event.newData),
        changed_fields: event.changedFields,

        // User and session context
        user_id: event.userId,
        session_id: event.sessionId,
        request_id: event.requestId,
        correlation_id: event.correlationId,

        // System context
        source: event.source,
        component: event.component,
        version: event.version,

        // Timing information
        timestamp: event.timestamp,
        duration: event.duration,

        // Results and status
        success: event.success,
        result: event.result,

        // Metadata and tags
        metadata: event.metadata,
        tags: event.tags,

        // Security and compliance
        sensitivity: event.sensitivity,
        compliance: event.compliance,

        // Geographic and network context
        ip_address: event.ipAddress,
        user_agent: event.userAgent,
        location: event.location,
      });

      logger.debug(
        {
          eventId: event.id,
          eventType: event.eventType,
          entityType: event.entityType,
          operation: event.operation,
        },
        'Typed audit event logged successfully'
      );

      return {
        isValid: true,
        errors: [],
        warnings: [],
      };
    } catch (error) {
      logger.error({ error, event }, 'Failed to log typed audit event');
      // Don't throw - audit logging failures shouldn't break the main operation
      return {
        isValid: false,
        errors: [`Failed to store event: ${(error as Error).message}`],
        warnings: [],
      };
    }
  }

  /**
   * Log multiple audit events in batch (Legacy - for backward compatibility)
   */
  async logBatchEvents(events: AuditEvent[]): Promise<void> {
    const filteredEvents = events.filter((event) => this.shouldLogEvent(event));
    const processedEvents = await Promise.all(
      filteredEvents.map((event) => this.processEvent(event as unknown))
    );

    if (processedEvents.length === 0) {
      return;
    }

    try {
      const db = await this.createDatabaseLayer();

      // Use Qdrant for batch insert
      const auditData = await Promise.all(
        processedEvents.map(async (event) => {
          const safeEvent = safeAuditEventAccess(event);
          return {
            id: safeEvent.id ?? (await this.generateUUID()),
            event_type: safeEvent.eventType,
            tableName: safeEvent.tableName,
            recordId: safeEvent.recordId,
            operation: safeEvent.operation,
            oldData: this.filterSensitiveData(safeEvent.tableName || 'unknown', safeEvent.oldData ?? {}),
            newData: this.filterSensitiveData(safeEvent.tableName || 'unknown', safeEvent.newData ?? {}),
            changedBy: safeEvent.changedBy ?? 'system',
            tags: safeEvent.tags ?? {},
            metadata: safeEvent.metadata ?? {},
            changed_at: new Date().toISOString(),
          };
        })
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
   * Log multiple typed audit events in batch with validation
   */
  async logTypedBatchEvents(events: TypedAuditEvent[]): Promise<{
    successful: TypedAuditEvent[];
    failed: Array<{ event: TypedAuditEvent; error: string }>;
    total: number;
  }> {
    const results = {
      successful: [] as TypedAuditEvent[],
      failed: [] as Array<{ event: TypedAuditEvent; error: string }>,
      total: events.length,
    };

    // Filter and validate events
    const validEvents = events.filter((event) => {
      if (!this.shouldLogTypedEvent(event)) {
        return false;
      }

      const validation = validateAuditEvent(event);
      if (!validation.isValid) {
        results.failed.push({
          event,
          error: `Validation failed: ${validation.errors.join(', ')}`,
        });
        return false;
      }

      return true;
    });

    if (validEvents.length === 0) {
      return results;
    }

    try {
      const db = await this.createDatabaseLayer();

      // Prepare batch data
      const auditData = validEvents.map((event) => ({
        // Core identification
        id: event.id,
        event_type: event.eventType,
        category: event.category,

        // Entity information
        entity_type: event.entityType,
        entity_id: event.entityId,
        operation: event.operation,

        // Data changes
        oldData: this.filterSensitiveData(event.entityType, event.oldData),
        newData: this.filterSensitiveData(event.entityType, event.newData),
        changed_fields: event.changedFields,

        // User and session context
        user_id: event.userId,
        session_id: event.sessionId,
        request_id: event.requestId,
        correlation_id: event.correlationId,

        // System context
        source: event.source,
        component: event.component,
        version: event.version,

        // Timing information
        timestamp: event.timestamp,
        duration: event.duration,

        // Results and status
        success: event.success,
        result: event.result,

        // Metadata and tags
        metadata: event.metadata,
        tags: event.tags,

        // Security and compliance
        sensitivity: event.sensitivity,
        compliance: event.compliance,

        // Geographic and network context
        ip_address: event.ipAddress,
        user_agent: event.userAgent,
        location: event.location,
      }));

      // Create audit records in batch
      for (const record of auditData) {
        await db.create('typed_audit_events', record);
      }

      results.successful = validEvents;
      logger.debug(
        {
          successful: results.successful.length,
          failed: results.failed.length,
          total: results.total,
        },
        'Typed batch audit events logged'
      );
    } catch (error) {
      logger.error({ error }, 'Failed to log typed batch audit events');

      // Mark all events as failed
      validEvents.forEach((event) => {
        results.failed.push({
          event,
          error: `Batch storage failed: ${(error as Error).message}`,
        });
      });
    }

    return results;
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
   * Query audit events (Legacy - for backward compatibility)
   */
  async queryEvents(options: AuditQueryOptions = {}): Promise<{
    events: AuditEvent[];
    total: number;
  }> {
    try {
      const db = await this.createDatabaseLayer();

      // Build where conditions for Qdrant query
      const whereConditions: Record<string, unknown> = {};

      if (options.eventType) {
        whereConditions.event_type = options.eventType;
      }

      if (options.tableName) {
        whereConditions.tableName = options.tableName;
      }

      if (options.recordId) {
        whereConditions.recordId = options.recordId;
      }

      if (options.operation) {
        whereConditions.operation = options.operation;
      }

      if (options.changedBy) {
        whereConditions.changedBy = options.changedBy;
      }

      if (options.startDate || options.endDate) {
        whereConditions.changed_at = {};
        if (options.startDate) {
          (whereConditions.changed_at as Record<string, unknown>).gte =
            options.startDate.toISOString();
        }
        if (options.endDate) {
          (whereConditions.changed_at as Record<string, unknown>).lte =
            options.endDate.toISOString();
        }
      }

      // Query events using Qdrant
      const events = (
        await db.find('event_audit', whereConditions, {
        take: options.limit || 100,
        orderBy: { [options.orderBy || 'changed_at']: options.orderDirection || 'DESC' },
        })
      ) as Record<string, unknown>[];

      // Get total count
      const totalResult = await db.query(
        `SELECT COUNT(*) as count FROM event_audit WHERE 1=1 ${
          Object.keys(whereConditions).length > 0
            ? `AND ${Object.entries(whereConditions)
                .map(([key, value]) => {
                  if (typeof value === 'object' && value !== null && 'gte' in value) {
                    return `${key} >= '${(value as { gte?: string }).gte}'`;
                  }
                  if (typeof value === 'object' && value !== null && 'lte' in value) {
                    return `${key} <= '${(value as { lte?: string }).lte}'`;
                  }
                  return `${key} = '${value}'`;
                })
                .join(' AND ')}`
            : ''
        }`
      );

      const total = parseInt((totalResult.rows[0] as { count: string })?.count ?? '0', 10);

      // Transform results to match expected format
      const transformedEvents = events.map((event) => ({
        id: event.id as string,
        eventType: event.event_type as string,
        tableName: event.tableName as string,
        recordId: event.recordId as string,
        operation: event.operation as 'INSERT' | 'UPDATE' | 'DELETE',
        oldData: event.oldData as Record<string, unknown> | null,
        newData: event.newData as Record<string, unknown> | null,
        changedBy: event.changedBy as string | undefined,
        tags: event.tags as Record<string, unknown> | undefined,
        metadata: event.metadata as Record<string, unknown> | undefined,
        changed_at: event.changed_at as string,
      }));

      return { events: transformedEvents, total };
    } catch (error) {
      logger.error({ error, options }, 'Failed to query audit events');
      throw new Error(`Audit query failed: ${(error as Error).message}`);
    }
  }

  /**
   * Query typed audit events with enhanced filtering capabilities
   */
  async queryTypedEvents(options: TypedAuditQueryOptions = {}): Promise<TypedAuditQueryResult> {
    const startTime = Date.now();

    if (!options || typeof options !== 'object') {
      throw new Error('Invalid query options provided');
    }

    try {
      const db = await this.createDatabaseLayer();

      // Build comprehensive where conditions
      const whereConditions: Record<string, unknown> = {};

      // Event type filtering
      if (options.eventType) {
        if (Array.isArray(options.eventType)) {
          whereConditions.event_type = { $in: options.eventType };
        } else {
          whereConditions.event_type = options.eventType;
        }
      }

      // Category filtering
      if (options.category) {
        if (Array.isArray(options.category)) {
          whereConditions.category = { $in: options.category };
        } else {
          whereConditions.category = options.category;
        }
      }

      // Entity filtering
      if (options.entityType) {
        whereConditions.entity_type = options.entityType;
      }
      if (options.entityId) {
        whereConditions.entity_id = options.entityId;
      }

      // User filtering
      if (options.userId) {
        whereConditions.user_id = options.userId;
      }
      if (options.sessionId) {
        whereConditions.session_id = options.sessionId;
      }

      // Time filtering
      if (options.startDate || options.endDate) {
        whereConditions.timestamp = {};
        if (options.startDate) {
          (whereConditions.timestamp as Record<string, unknown>).gte =
            options.startDate.toISOString();
        }
        if (options.endDate) {
          (whereConditions.timestamp as Record<string, unknown>).lte =
            options.endDate.toISOString();
        }
      }

      // Time window filtering
      if (options.timeWindow) {
        const now = new Date();
        const startDate = new Date();

        switch (options.timeWindow.unit) {
          case 'minutes':
            startDate.setMinutes(startDate.getMinutes() - options.timeWindow.value);
            break;
          case 'hours':
            startDate.setHours(startDate.getHours() - options.timeWindow.value);
            break;
          case 'days':
            startDate.setDate(startDate.getDate() - options.timeWindow.value);
            break;
          case 'weeks':
            startDate.setDate(startDate.getDate() - options.timeWindow.value * 7);
            break;
          case 'months':
            startDate.setMonth(startDate.getMonth() - options.timeWindow.value);
            break;
        }

        whereConditions.timestamp = whereConditions.timestamp || {};
        (whereConditions.timestamp as Record<string, unknown>).gte = startDate.toISOString();
        (whereConditions.timestamp as Record<string, unknown>).lte = now.toISOString();
      }

      // Additional filters
      if (options.source) {
        if (Array.isArray(options.source)) {
          whereConditions.source = { $in: options.source };
        } else {
          whereConditions.source = options.source;
        }
      }

      if (options.sensitivity) {
        if (Array.isArray(options.sensitivity)) {
          whereConditions.sensitivity = { $in: options.sensitivity };
        } else {
          whereConditions.sensitivity = options.sensitivity;
        }
      }

      if (options.success !== undefined) {
        whereConditions.success = options.success;
      }

      // Query events
      const events = (
        await db.find('typed_audit_events', whereConditions, {
          take: options.limit || 100,
          skip: options.offset || 0,
          orderBy: { [options.orderBy || 'timestamp']: options.orderDirection || 'DESC' },
        })
      ) as Record<string, unknown>[];

      // Transform results to TypedAuditEvent format
      const transformedEvents: TypedAuditEvent[] = events.map((event) => this.normalizeTypedEvent(event));

      // Get total count (simplified - in production would use proper COUNT query)
      const total = transformedEvents.length;

      const executionTime = Date.now() - startTime;

      return {
        events: transformedEvents,
        total,
        hasMore: (options.offset || 0) + transformedEvents.length < total,
        nextOffset:
          (options.offset || 0) + transformedEvents.length < total
            ? (options.offset || 0) + (options.limit || 100)
            : undefined,
        executionTime,
        cached: false,
      };
    } catch (error) {
      logger.error({ error, options }, 'Failed to query typed audit events');
      throw new Error(`Typed audit query failed: ${(error as Error).message}`);
    }
  }

  /**
   * Get audit event history for a specific record
   */
  async getRecordHistory(tableName: string, recordId: string): Promise<AuditEvent[]> {
    return this.queryEvents({ tableName, recordId }).then((result) => result.events);
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
      const db = await this.createDatabaseLayer();

      const result = await db.query(`SELECT gen_random_uuid() as uuid`);
      const rows = this.castQueryResult<{ uuid: string }>(result).rows;
      return rows[0]?.uuid ?? crypto.randomUUID();
    } catch (error) {
      logger.warn({ error }, 'Failed to generate UUID with Qdrant, using fallback');
      return crypto.randomUUID();
    }
  }

  /**
   * Check if event should be logged based on filters (Legacy)
   */
  private shouldLogEvent(event: AuditEvent): boolean {
    const { exclude, include } = this.filter;

    const normalizedOperation = this.normalizeLegacyOperation(event.operation);
    const normalizedEventType = event.eventType as AuditEventType;

    // Check exclusions
    if (exclude?.tables?.includes(event.tableName)) {
      return false;
    }

    if (exclude?.operations?.includes(normalizedOperation)) {
      return false;
    }

    if (exclude?.eventTypes?.includes(normalizedEventType)) {
      return false;
    }

    // Check inclusions (if specified, only log these)
    if (include?.tables && !include.tables.includes(event.tableName)) {
      return false;
    }

    if (include?.operations && !include.operations.includes(normalizedOperation)) {
      return false;
    }

    if (include?.eventTypes && !include.eventTypes.includes(normalizedEventType)) {
      return false;
    }

    return true;
  }

  /**
   * Check if typed event should be logged based on enhanced filters
   */
  private shouldLogTypedEvent(event: TypedAuditEvent): boolean {
    const { exclude, include } = this.filter;

    // Check exclusions
    if (exclude?.eventTypes?.includes(event.eventType)) {
      return false;
    }

    if (exclude?.categories?.includes(event.category)) {
      return false;
    }

    if (exclude?.operations?.includes(event.operation)) {
      return false;
    }

    if (exclude?.sources?.includes(event.source)) {
      return false;
    }

    if (exclude?.entities?.includes(event.entityType)) {
      return false;
    }

    if (exclude?.users?.includes(event.userId || '')) {
      return false;
    }

    if (exclude?.sensitivityBelow && event.sensitivity <= exclude.sensitivityBelow) {
      return false;
    }

    // Check inclusions (if specified, only log these)
    if (include?.eventTypes && !include.eventTypes.includes(event.eventType)) {
      return false;
    }

    if (include?.categories && !include.categories.includes(event.category)) {
      return false;
    }

    if (include?.operations && !include.operations.includes(event.operation)) {
      return false;
    }

    if (include?.sources && !include.sources.includes(event.source)) {
      return false;
    }

    if (include?.entities && !include.entities.includes(event.entityType)) {
      return false;
    }

    if (include?.users && !include.users.includes(event.userId || '')) {
      return false;
    }

    if (include?.sensitivityAbove && event.sensitivity <= include.sensitivityAbove) {
      return false;
    }

    return true;
  }

  /**
   * Process event for logging
   */
  private async processEvent(event: unknown): Promise<Partial<AuditEventRecord>> {
    // Use safe property access to extract event data
    const safeEvent = safeAuditEventAccess(event);

    return {
      ...safeEvent,
      id: safeEvent.id ?? (await this.generateUUID()),
      changedBy: safeEvent.changedBy ?? 'system',
      tags: safeEvent.tags ?? {},
      metadata: safeEvent.metadata ?? {},
    };
  }

  private castToRecord(value: unknown): Record<string, unknown> | null {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      return value as Record<string, unknown>;
    }
    return null;
  }

  private normalizeTags(value: unknown): Record<string, string> {
    if (!value || typeof value !== 'object') {
      return {};
    }

    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, tagValue]) => [
        key,
        typeof tagValue === 'string' ? tagValue : JSON.stringify(tagValue),
      ])
    );
  }

  private normalizeAuditResult(value: unknown): AuditResult {
    if (!value || typeof value !== 'object') {
      return { status: 'failure' };
    }

    const record = value as Record<string, unknown>;
    return {
      status: (record.status as AuditResult['status']) ?? 'failure',
      code: record.code as string | number | undefined,
      message: record.message as string | undefined,
      details: this.castToRecord(record.details) ?? undefined,
      metrics: this.castToRecord(record.metrics) ?? undefined,
    };
  }

  private normalizeAuditMetadata(value: unknown): AuditMetadata {
    if (!value || typeof value !== 'object') {
      return {};
    }

    return value as AuditMetadata;
  }

  private normalizeCompliance(value: unknown): ComplianceInfo {
    if (!value || typeof value !== 'object') {
      return { frameworks: [], regulations: [], policies: [] };
    }

    return {
      frameworks: [],
      regulations: [],
      policies: [],
      ...(value as ComplianceInfo),
    };
  }

  private normalizeGeographicInfo(value: unknown): GeographicInfo | undefined {
    if (!value || typeof value !== 'object') {
      return undefined;
    }

    return value as GeographicInfo;
  }

  private normalizeTypedEvent(event: Record<string, unknown>): TypedAuditEvent {
    const id = typeof event.id === 'string' ? event.id : crypto.randomUUID();
    const metadata = this.castToRecord(event.metadata ?? null);
    const oldData =
      this.castToRecord(event.old_data ?? event.oldData) ?? this.castToRecord(metadata?.oldData ?? null);
    const newData =
      this.castToRecord(event.new_data ?? event.newData) ?? this.castToRecord(metadata?.newData ?? null);

    return {
      id,
      eventType: (event.event_type as AuditEventType) ?? AuditEventType.DATA_CREATE,
      category: (event.category as AuditCategory) ?? AuditCategory.SECURITY,
      entityType: (event.entity_type as string) ?? (event.entity_id as string) ?? 'unknown',
      entityId: (event.entity_id as string) ?? (event.recordId as string) ?? 'unknown',
      operation: (event.operation as AuditOperation) ?? AuditOperation.CREATE,
      oldData: oldData ?? null,
      newData: newData ?? null,
      changedFields: Array.isArray(event.changed_fields)
        ? event.changed_fields.filter((field): field is string => typeof field === 'string')
        : undefined,
      userId: event.user_id as string | undefined,
      sessionId: event.session_id as string | undefined,
      requestId: event.request_id as string | undefined,
      correlationId: event.correlation_id as string | undefined,
      source: (event.source as AuditSource) ?? AuditSource.SYSTEM,
      component: (event.component as string) ?? 'audit-logger',
      version: event.version as string | undefined,
      timestamp: (event.timestamp as string) ?? new Date().toISOString(),
      duration: typeof event.duration === 'number' ? event.duration : undefined,
      success: typeof event.success === 'boolean' ? event.success : false,
      result: this.normalizeAuditResult(event.result ?? event.results ?? {}),
      metadata: this.normalizeAuditMetadata(event.metadata ?? event.meta),
      tags: this.normalizeTags(event.tags ?? metadata?.tags),
      sensitivity:
        (event.sensitivity as SensitivityLevel) ?? SensitivityLevel.INTERNAL,
      compliance: this.normalizeCompliance(event.compliance ?? metadata?.compliance),
      ipAddress: event.ip_address as string | undefined,
      userAgent: event.user_agent as string | undefined,
      location: this.normalizeGeographicInfo(event.location ?? metadata?.location),
    };
  }

  private normalizeLegacyOperation(operation: string): AuditOperation {
    const normalized = operation.toLowerCase();
    switch (normalized) {
      case 'insert':
      case 'create':
        return AuditOperation.CREATE;
      case 'update':
        return AuditOperation.UPDATE;
      case 'delete':
        return AuditOperation.DELETE;
      case 'read':
        return AuditOperation.READ;
      case 'execute':
        return AuditOperation.EXECUTE;
      case 'access':
        return AuditOperation.ACCESS;
      case 'modify':
        return AuditOperation.MODIFY;
      case 'approve':
        return AuditOperation.APPROVE;
      case 'reject':
        return AuditOperation.REJECT;
      case 'export':
        return AuditOperation.EXPORT;
      case 'import':
        return AuditOperation.IMPORT;
      case 'backup':
        return AuditOperation.BACKUP;
      case 'restore':
        return AuditOperation.RESTORE;
      case 'migrate':
        return AuditOperation.MIGRATE;
      case 'sync':
        return AuditOperation.SYNC;
      case 'validate':
        return AuditOperation.VALIDATE;
      case 'scan':
        return AuditOperation.SCAN;
      case 'search':
        return AuditOperation.SEARCH;
      case 'download':
        return AuditOperation.DOWNLOAD;
      case 'upload':
        return AuditOperation.UPLOAD;
      default:
        return AuditOperation.CREATE;
    }
  }

  private castQueryResult<T extends Record<string, unknown>>(result: unknown): { rows: T[] } {
    if (!result || typeof result !== 'object' || Array.isArray(result)) {
      return { rows: [] };
    }

    const candidate = result as { rows?: unknown };
    if (!Array.isArray(candidate.rows)) {
      return { rows: [] };
    }

    const rows = candidate.rows.map((row) =>
      row && typeof row === 'object' && !Array.isArray(row) ? (row as T) : ({} as T)
    );

    return { rows };
  }

  private buildCountMap(result: unknown, key: string): Record<string, number> {
    return this.castQueryResult<Record<string, unknown>>(result).rows.reduce<Record<string, number>>(
      (acc, row) => {
      const rawKey = row[key];
      if (typeof rawKey !== 'string') {
        return acc;
      }
      const rawCount = row.count;
      const parsed = typeof rawCount === 'number' ? rawCount : parseInt(String(rawCount ?? '0'), 10);
      acc[rawKey] = Number.isNaN(parsed) ? 0 : parsed;
      return acc;
      },
      {}
    );
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

    const processedEvents = [...this.batchQueue];
    this.batchQueue = [];

    try {
      const db = await this.createDatabaseLayer();

      const auditData = processedEvents.map((event: unknown) => {
        const safeEvent = safeAuditEventAccess(event);
        return {
          id: safeEvent.id ?? crypto.randomUUID(),
          event_type: safeEvent.eventType,
          tableName: safeEvent.tableName,
          recordId: safeEvent.recordId,
          operation: safeEvent.operation,
          oldData: this.filterSensitiveData(safeEvent.tableName || 'unknown', safeEvent.oldData ?? {}),
          newData: this.filterSensitiveData(safeEvent.tableName || 'unknown', safeEvent.newData ?? {}),
          changedBy: safeEvent.changedBy ?? 'system',
          tags: safeEvent.tags ?? {},
          metadata: safeEvent.metadata ?? {},
          changed_at: new Date().toISOString(),
        };
      });

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
      const db = await this.createDatabaseLayer();

      const now = new Date();
      const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
      const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

      const [
        totalEventsResult,
        eventsByTypeResult,
        eventsByTableResult,
        eventsByOperationResult,
        lastHourResult,
        last24HoursResult,
        last7DaysResult,
      ] = await Promise.all([
        db.query(`SELECT COUNT(*) as count FROM event_audit`),
        db.query(`SELECT event_type, COUNT(*) as count FROM event_audit GROUP BY event_type`),
        db.query(`SELECT tableName, COUNT(*) as count FROM event_audit GROUP BY tableName`),
        db.query(`SELECT operation, COUNT(*) as count FROM event_audit GROUP BY operation`),
        db.query(`SELECT COUNT(*) as count FROM event_audit WHERE changed_at >= $1`, [
          oneHourAgo.toISOString(),
        ]),
        db.query(`SELECT COUNT(*) as count FROM event_audit WHERE changed_at >= $1`, [
          oneDayAgo.toISOString(),
        ]),
        db.query(`SELECT COUNT(*) as count FROM event_audit WHERE changed_at >= $1`, [
          sevenDaysAgo.toISOString(),
        ]),
      ]);

      const totalEvents = parseInt(
        (this.castQueryResult<{ count: string }>(totalEventsResult).rows[0]?.count ?? '0'),
        10
      );

      const eventsByType = this.buildCountMap(eventsByTypeResult, 'event_type');
      const eventsByTable = this.buildCountMap(eventsByTableResult, 'tableName');
      const eventsByOperation = this.buildCountMap(eventsByOperationResult, 'operation');

      const lastHourCount = parseInt(
        (this.castQueryResult<{ count: string }>(lastHourResult).rows[0]?.count ?? '0'),
        10
      );
      const last24HoursCount = parseInt(
        (this.castQueryResult<{ count: string }>(last24HoursResult).rows[0]?.count ?? '0'),
        10
      );
      const last7DaysCount = parseInt(
        (this.castQueryResult<{ count: string }>(last7DaysResult).rows[0]?.count ?? '0'),
        10
      );

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
      const db = await this.createDatabaseLayer();

      // Use Qdrant DELETE for cleanup
      const deleteResult = await db.query(
        `DELETE FROM event_audit WHERE changed_at < $1 RETURNING COUNT(*) as count`,
        [cutoffDate.toISOString()]
      );

      const deletedCount = parseInt(
        (this.castQueryResult<{ count: string }>(deleteResult).rows[0]?.count ?? '0'),
        10
      );

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
  exclude: {
    eventTypes: [
      // System health checks can be noisy
      AuditEventType.SYSTEM_HEALTH_CHECK,
    ],
    sensitivityBelow: SensitivityLevel.PUBLIC,
  },
  sensitiveFields: {
    // Add sensitive fields by entity type
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
  newData?: unknown,
  changedBy?: string
): Promise<void> {
  try {
    await auditLogger.logEvent({
      eventType: 'data_change',
      tableName: entity_type,
      recordId: entity_id,
      operation,
      newData:
        typeof newData === 'object' && newData !== null
          ? (newData as Record<string, unknown>)
          : null,
      ...(changedBy && { changedBy }),
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

/**
 * Enhanced typed audit log function
 * Provides full type safety and validation
 */
export async function auditLogTyped(
  eventType: AuditEventType,
  entityType: string,
  entityId: string,
  operation: AuditOperation,
  options?: {
    oldData?: Record<string, unknown> | null;
    newData?: Record<string, unknown> | null;
    userId?: string;
    sessionId?: string;
    requestId?: string;
    correlationId?: string;
    source?: AuditSource;
    component?: string;
    version?: string;
    duration?: number;
    success?: boolean;
    result?: AuditResult;
    metadata?: AuditMetadata;
    tags?: Record<string, string>;
    sensitivity?: SensitivityLevel;
    compliance?: ComplianceInfo;
    ipAddress?: string;
    userAgent?: string;
    location?: GeographicInfo;
  }
): Promise<AuditValidationResult> {
  const event = createTypedAuditEvent({
    eventType,
    category: getAuditCategoryFromType(eventType),
    entityType,
    entityId,
    operation,
    oldData: options?.oldData,
    newData: options?.newData,
    userId: options?.userId,
    sessionId: options?.sessionId,
    requestId: options?.requestId,
    correlationId: options?.correlationId,
    source: options?.source || AuditSource.SYSTEM,
    component: options?.component || 'any',
    version: options?.version,
    duration: options?.duration,
    success: options?.success ?? true,
    result: options?.result,
    metadata: options?.metadata || {},
    tags: options?.tags || {},
    sensitivity: options?.sensitivity || SensitivityLevel.INTERNAL,
    compliance: options?.compliance || {
      frameworks: [],
      regulations: [],
      policies: [],
    },
    ipAddress: options?.ipAddress,
    userAgent: options?.userAgent,
    location: options?.location,
  });

  return auditLogger.logTypedEvent(event);
}

/**
 * Utility function to determine audit category from event type
 */
function getAuditCategoryFromType(eventType: AuditEventType): AuditCategory {
  const categoryMap: Record<AuditEventType, AuditCategory> = {
    // Data operations
    [AuditEventType.DATA_CREATE]: AuditCategory.DATA,
    [AuditEventType.DATA_READ]: AuditCategory.DATA,
    [AuditEventType.DATA_UPDATE]: AuditCategory.DATA,
    [AuditEventType.DATA_DELETE]: AuditCategory.DATA,
    [AuditEventType.DATA_BULK_CREATE]: AuditCategory.DATA,
    [AuditEventType.DATA_BULK_UPDATE]: AuditCategory.DATA,
    [AuditEventType.DATA_BULK_DELETE]: AuditCategory.DATA,

    // Authentication and authorization
    [AuditEventType.AUTH_LOGIN]: AuditCategory.SECURITY,
    [AuditEventType.AUTH_LOGOUT]: AuditCategory.SECURITY,
    [AuditEventType.AUTH_FAILED_LOGIN]: AuditCategory.SECURITY,
    [AuditEventType.AUTH_PASSWORD_CHANGE]: AuditCategory.SECURITY,
    [AuditEventType.AUTH_TOKEN_REFRESH]: AuditCategory.SECURITY,
    [AuditEventType.AUTHZ_ACCESS_GRANTED]: AuditCategory.SECURITY,
    [AuditEventType.AUTHZ_ACCESS_DENIED]: AuditCategory.SECURITY,
    [AuditEventType.AUTHZ_ROLE_CHANGE]: AuditCategory.SECURITY,
    [AuditEventType.AUTHZ_PERMISSION_CHANGE]: AuditCategory.SECURITY,

    // System operations
    [AuditEventType.SYSTEM_STARTUP]: AuditCategory.SYSTEM,
    [AuditEventType.SYSTEM_SHUTDOWN]: AuditCategory.SYSTEM,
    [AuditEventType.SYSTEM_CONFIG_CHANGE]: AuditCategory.SYSTEM,
    [AuditEventType.SYSTEM_HEALTH_CHECK]: AuditCategory.SYSTEM,

    // Security events
    [AuditEventType.SECURITY_VIOLATION]: AuditCategory.SECURITY,
    [AuditEventType.SECURITY_BREACH_ATTEMPT]: AuditCategory.SECURITY,
    [AuditEventType.SECURITY_SCAN]: AuditCategory.SECURITY,
    [AuditEventType.SECURITY_INCIDENT]: AuditCategory.SECURITY,

    // Performance events
    [AuditEventType.PERFORMANCE_SLOW_QUERY]: AuditCategory.PERFORMANCE,
    [AuditEventType.PERFORMANCE_ERROR_SPIKE]: AuditCategory.PERFORMANCE,
    [AuditEventType.PERFORMANCE_RESOURCE_EXHAUSTION]: AuditCategory.PERFORMANCE,

    // Business operations
    [AuditEventType.BUSINESS_WORKFLOW_START]: AuditCategory.BUSINESS,
    [AuditEventType.BUSINESS_WORKFLOW_COMPLETE]: AuditCategory.BUSINESS,
    [AuditEventType.BUSINESS_WORKFLOW_FAIL]: AuditCategory.BUSINESS,
    [AuditEventType.BUSINESS_DECISION]: AuditCategory.BUSINESS,

    // Compliance events
    [AuditEventType.COMPLIANCE_REPORT_GENERATED]: AuditCategory.COMPLIANCE,
    [AuditEventType.COMPLIANCE_POLICY_VIOLATION]: AuditCategory.COMPLIANCE,
    [AuditEventType.COMPLIANCE_AUDIT]: AuditCategory.COMPLIANCE,

    // Data quality events
    [AuditEventType.DATA_VALIDATION_ERROR]: AuditCategory.QUALITY,
    [AuditEventType.DATA_QUALITY_CHECK]: AuditCategory.QUALITY,
    [AuditEventType.DATA_MIGRATION]: AuditCategory.DATA,
    [AuditEventType.DATA_BACKUP]: AuditCategory.DATA,
    [AuditEventType.DATA_RESTORE]: AuditCategory.DATA,
  };

  return categoryMap[eventType] || AuditCategory.SYSTEM;
}
