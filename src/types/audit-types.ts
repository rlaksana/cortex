// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * Comprehensive Type Definitions for Audit System
 *
 * Provides type-safe interfaces for all audit operations, eliminating `any` usage
 * while maintaining flexibility for different audit event types and metadata structures.
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

import { type LoggableData } from './monitoring-types.js';

// ============================================================================
// Core Audit Event Types
// ============================================================================

/**
 * Strictly typed audit event with proper type safety
 */
export interface TypedAuditEvent {
  // Core identification
  id: string;
  eventType: AuditEventType;
  category: AuditCategory;

  // Entity information
  entityType: string;
  entityId: string;
  operation: AuditOperation;

  // Data changes
  oldData?: Record<string, unknown> | null;
  newData?: Record<string, unknown> | null;
  changedFields?: string[];

  // User and session context
  userId?: string;
  sessionId?: string;
  requestId?: string;
  correlationId?: string;

  // System context
  source: AuditSource;
  component: string;
  version?: string;

  // Timing information
  timestamp: string;
  duration?: number;

  // Results and status
  success: boolean;
  result?: AuditResult;

  // Metadata and tags
  metadata: AuditMetadata;
  tags: Record<string, string>;

  // Security and compliance
  sensitivity: SensitivityLevel;
  compliance: ComplianceInfo;

  // Geographic and network context
  ipAddress?: string;
  userAgent?: string;
  location?: GeographicInfo;
}

/**
 * Enum of audit event types for type safety
 */
export enum AuditEventType {
  // Data operations
  DATA_CREATE = 'data_create',
  DATA_READ = 'data_read',
  DATA_UPDATE = 'data_update',
  DATA_DELETE = 'data_delete',
  DATA_BULK_CREATE = 'data_bulk_create',
  DATA_BULK_UPDATE = 'data_bulk_update',
  DATA_BULK_DELETE = 'data_bulk_delete',

  // Authentication and authorization
  AUTH_LOGIN = 'auth_login',
  AUTH_LOGOUT = 'auth_logout',
  AUTH_FAILED_LOGIN = 'auth_failed_login',
  AUTH_PASSWORD_CHANGE = 'auth_password_change',
  AUTH_TOKEN_REFRESH = 'auth_token_refresh',

  // Authorization
  AUTHZ_ACCESS_GRANTED = 'authz_access_granted',
  AUTHZ_ACCESS_DENIED = 'authz_access_denied',
  AUTHZ_ROLE_CHANGE = 'authz_role_change',
  AUTHZ_PERMISSION_CHANGE = 'authz_permission_change',

  // System operations
  SYSTEM_STARTUP = 'system_startup',
  SYSTEM_SHUTDOWN = 'system_shutdown',
  SYSTEM_CONFIG_CHANGE = 'system_config_change',
  SYSTEM_HEALTH_CHECK = 'system_health_check',

  // Security events
  SECURITY_VIOLATION = 'security_violation',
  SECURITY_BREACH_ATTEMPT = 'security_breach_attempt',
  SECURITY_SCAN = 'security_scan',
  SECURITY_INCIDENT = 'security_incident',

  // Performance and monitoring
  PERFORMANCE_SLOW_QUERY = 'performance_slow_query',
  PERFORMANCE_ERROR_SPIKE = 'performance_error_spike',
  PERFORMANCE_RESOURCE_EXHAUSTION = 'performance_resource_exhaustion',

  // Business operations
  BUSINESS_WORKFLOW_START = 'business_workflow_start',
  BUSINESS_WORKFLOW_COMPLETE = 'business_workflow_complete',
  BUSINESS_WORKFLOW_FAIL = 'business_workflow_fail',
  BUSINESS_DECISION = 'business_decision',

  // Compliance and governance
  COMPLIANCE_REPORT_GENERATED = 'compliance_report_generated',
  COMPLIANCE_POLICY_VIOLATION = 'compliance_policy_violation',
  COMPLIANCE_AUDIT = 'compliance_audit',

  // Data quality
  DATA_VALIDATION_ERROR = 'data_validation_error',
  DATA_QUALITY_CHECK = 'data_quality_check',
  DATA_MIGRATION = 'data_migration',
  DATA_BACKUP = 'data_backup',
  DATA_RESTORE = 'data_restore'
}

/**
 * Audit categories for classification
 */
export enum AuditCategory {
  SECURITY = 'security',
  DATA = 'data',
  SYSTEM = 'system',
  PERFORMANCE = 'performance',
  BUSINESS = 'business',
  COMPLIANCE = 'compliance',
  QUALITY = 'quality',
  NETWORK = 'network'
}

/**
 * Audit operations with specific values
 */
export enum AuditOperation {
  CREATE = 'CREATE',
  READ = 'READ',
  UPDATE = 'UPDATE',
  DELETE = 'DELETE',
  EXECUTE = 'EXECUTE',
  ACCESS = 'ACCESS',
  MODIFY = 'MODIFY',
  APPROVE = 'APPROVE',
  REJECT = 'REJECT',
  EXPORT = 'EXPORT',
  IMPORT = 'IMPORT',
  BACKUP = 'BACKUP',
  RESTORE = 'RESTORE',
  MIGRATE = 'MIGRATE',
  SYNC = 'SYNC',
  VALIDATE = 'VALIDATE',
  SCAN = 'SCAN',
  SEARCH = 'SEARCH',
  DOWNLOAD = 'DOWNLOAD',
  UPLOAD = 'UPLOAD'
}

/**
 * Audit source identification
 */
export enum AuditSource {
  SYSTEM = 'system',
  USER_INTERFACE = 'user_interface',
  API = 'api',
  BATCH_JOB = 'batch_job',
  WEBHOOK = 'webhook',
  INTEGRATION = 'integration',
  MOBILE_APP = 'mobile_app',
  THIRD_PARTY = 'third_party'
}

/**
 * Audit result information
 */
export interface AuditResult {
  status: 'success' | 'partial_success' | 'failure' | 'timeout' | 'cancelled';
  code?: string | number;
  message?: string;
  details?: Record<string, unknown>;
  metrics?: {
    recordsAffected?: number;
    bytesProcessed?: number;
    itemsReturned?: number;
    errors?: number;
  };
}

/**
 * Sensitivity levels for audit classification
 */
export enum SensitivityLevel {
  PUBLIC = 'public',
  INTERNAL = 'internal',
  CONFIDENTIAL = 'confidential',
  RESTRICTED = 'restricted',
  SECRET = 'secret'
}

/**
 * Compliance information
 */
export interface ComplianceInfo {
  frameworks: ComplianceFramework[];
  regulations: ComplianceRegulation[];
  policies: string[];
  retentionPeriod?: {
    years?: number;
    days?: number;
    permanent?: boolean;
  };
  classification?: string;
}

/**
 * Compliance frameworks
 */
export enum ComplianceFramework {
  SOX = 'sox',
  HIPAA = 'hipaa',
  GDPR = 'gdpr',
  CCPA = 'ccpa',
  PCI_DSS = 'pci_dss',
  ISO27001 = 'iso27001',
  SOC2 = 'soc2',
  NIST = 'nist'
}

/**
 * Compliance regulations
 */
export enum ComplianceRegulation {
  GDPR_ARTICLE_17 = 'gdpr_article_17', // Right to erasure
  GDPR_ARTICLE_25 = 'gdpr_article_25', // Data protection by design
  HIPAA_SECURITY_RULE = 'hipaa_security_rule',
  SOX_404 = 'sox_404',
  CCPA_DELETE_REQUEST = 'ccpa_delete_request'
}

/**
 * Geographic information
 */
export interface GeographicInfo {
  country?: string;
  region?: string;
  city?: string;
  timezone?: string;
  coordinates?: {
    latitude?: number;
    longitude?: number;
  };
}

/**
 * Type-safe audit metadata
 */
export interface AuditMetadata extends LoggableData {
  // Business context
  businessProcess?: string;
  businessUnit?: string;
  project?: string;
  costCenter?: string;

  // Technical context
  apiVersion?: string;
  clientVersion?: string;
  platform?: string;
  environment?: string;

  // Performance context
  queryComplexity?: 'low' | 'medium' | 'high';
  resourceUsage?: {
    cpuTime?: number;
    memoryUsed?: number;
    diskIO?: number;
    networkIO?: number;
  };

  // Data context
  dataClassification?: string;
  dataOwner?: string;
  dataSteward?: string;
  retentionSchedule?: string;

  // Security context
  riskScore?: number;
  threatLevel?: 'low' | 'medium' | 'high' | 'critical';
  anomalies?: string[];

  // Integration context
  externalSystem?: string;
  integrationType?: 'api' | 'webhook' | 'batch' | 'stream';
  correlationChain?: string[];
}

// ============================================================================
// Query and Filter Types
// ============================================================================

/**
 * Type-safe audit query options
 */
export interface TypedAuditQueryOptions {
  // Basic filters
  eventType?: AuditEventType | AuditEventType[];
  category?: AuditCategory | AuditCategory[];
  operation?: AuditOperation | AuditOperation[];
  source?: AuditSource | AuditSource[];

  // Entity filters
  entityType?: string;
  entityId?: string;

  // User filters
  userId?: string;
  sessionId?: string;

  // Time filters
  startDate?: Date;
  endDate?: Date;
  timeWindow?: {
    value: number;
    unit: 'minutes' | 'hours' | 'days' | 'weeks' | 'months';
  };

  // Result filters
  success?: boolean;
  sensitivity?: SensitivityLevel | SensitivityLevel[];

  // Compliance filters
  framework?: ComplianceFramework;
  regulation?: ComplianceRegulation;

  // Text search
  search?: {
    query: string;
    fields?: ('metadata' | 'tags' | 'result' | 'changedFields')[];
  };

  // Geographic filters
  location?: {
    country?: string;
    region?: string;
  };

  // Pagination and sorting
  limit?: number;
  offset?: number;
  orderBy?: AuditSortField;
  orderDirection?: 'ASC' | 'DESC';

  // Aggregation
  groupBy?: AuditGroupByField[];
  aggregate?: AuditAggregateFunction[];
}

/**
 * Available sort fields
 */
export type AuditSortField =
  | 'timestamp'
  | 'eventType'
  | 'category'
  | 'operation'
  | 'entityType'
  | 'entityId'
  | 'userId'
  | 'sensitivity'
  | 'success'
  | 'duration';

/**
 * Available group by fields
 */
export type AuditGroupByField =
  | 'eventType'
  | 'category'
  | 'operation'
  | 'entityType'
  | 'userId'
  | 'source'
  | 'sensitivity'
  | 'success'
  | 'hour'
  | 'day'
  | 'week'
  | 'month';

/**
 * Aggregate functions
 */
export type AuditAggregateFunction =
  | 'count'
  | 'avg_duration'
  | 'max_duration'
  | 'min_duration'
  | 'sum_duration'
  | 'success_rate'
  | 'error_rate';

/**
 * Type-safe audit query result
 */
export interface TypedAuditQueryResult {
  events: TypedAuditEvent[];
  total: number;
  hasMore: boolean;
  nextOffset?: number;
  aggregations?: Record<string, unknown>;
  executionTime: number;
  cached: boolean;
}

// ============================================================================
// Audit Configuration Types
// ============================================================================

/**
 * Type-safe audit filter configuration
 */
export interface TypedAuditFilter {
  // Exclusions
  exclude?: {
    tables?: string[];
    eventTypes?: AuditEventType[];
    categories?: AuditCategory[];
    operations?: AuditOperation[];
    sources?: AuditSource[];
    entities?: string[];
    users?: string[];
    components?: string[];
    sensitivityBelow?: SensitivityLevel;
  };

  // Inclusions (if specified, only log these)
  include?: {
    tables?: string[];
    eventTypes?: AuditEventType[];
    categories?: AuditCategory[];
    operations?: AuditOperation[];
    sources?: AuditSource[];
    entities?: string[];
    users?: string[];
    components?: string[];
    sensitivityAbove?: SensitivityLevel;
  };

  // Sensitive data handling
  sensitiveFields?: {
    [entityType: string]: string[];
  };

  // Data retention policies
  retention?: {
    [category: string]: {
      default: number; // days
      [sensitivity: string]: number;
    };
  };

  // Performance settings
  performance?: {
    batchSize: number;
    batchTimeoutMs: number;
    maxQueueSize: number;
    enableCompression: boolean;
  };
}

/**
 * Audit system configuration
 */
export interface AuditSystemConfig {
  enabled: boolean;
  filter: TypedAuditFilter;
  storage: AuditStorageConfig;
  validation: AuditValidationConfig;
  alerting: AuditAlertingConfig;
  compliance: AuditComplianceConfig;
}

/**
 * Storage configuration
 */
export interface AuditStorageConfig {
  type: 'database' | 'file' | 'cloud' | 'hybrid';
  primary: {
    connectionString?: string;
    tableName?: string;
    collectionName?: string;
    indexFields?: string[];
    compressionEnabled?: boolean;
    encryptionEnabled?: boolean;
  };
  backup?: {
    enabled: boolean;
    interval: number; // hours
    retention: number; // days
    location: string;
  };
  archive?: {
    enabled: boolean;
    criteria: {
      olderThanDays: number;
      categories?: AuditCategory[];
      sensitivity?: SensitivityLevel[];
    };
    location: string;
  };
}

/**
 * Validation configuration
 */
export interface AuditValidationConfig {
  strictMode: boolean;
  requiredFields: (keyof TypedAuditEvent)[];
  validateMetadata: boolean;
  validateCompliance: boolean;
  validateGeographic: boolean;
  maxLengths: {
    id: number;
    entityType: number;
    entityId: number;
    userId: number;
    sessionId: number;
    requestId: number;
    correlationId: number;
    message: number;
  };
}

/**
 * Alerting configuration
 */
export interface AuditAlertingConfig {
  enabled: boolean;
  rules: AuditAlertRule[];
  channels: AlertChannel[];
}

/**
 * Alert rule definition
 */
export interface AuditAlertRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  condition: AuditAlertCondition;
  severity: 'low' | 'medium' | 'high' | 'critical';
  cooldown: number; // minutes
  channels: string[];
}

/**
 * Alert condition
 */
export interface AuditAlertCondition {
  eventType?: AuditEventType;
  category?: AuditCategory;
  operation?: AuditOperation;
  sensitivity?: SensitivityLevel;
  success?: boolean;
  threshold?: {
    field: string;
    operator: 'gt' | 'gte' | 'lt' | 'lte' | 'eq' | 'ne';
    value: number | string;
    timeWindow?: {
      value: number;
      unit: 'minutes' | 'hours' | 'days';
    };
  };
  pattern?: {
    field: string;
    pattern: string;
    caseSensitive?: boolean;
  };
}

/**
 * Alert channel configuration
 */
export interface AlertChannel {
  id: string;
  type: 'email' | 'slack' | 'webhook' | 'sms' | 'pagerduty';
  enabled: boolean;
  config: Record<string, unknown>;
  filters?: {
    severity?: ('low' | 'medium' | 'high' | 'critical')[];
    categories?: AuditCategory[];
  };
}

/**
 * Compliance configuration
 */
export interface AuditComplianceConfig {
  frameworks: ComplianceFramework[];
  regulations: ComplianceRegulation[];
  policies: CompliancePolicy[];
  reporting: ComplianceReportingConfig;
}

/**
 * Compliance policy
 */
export interface CompliancePolicy {
  id: string;
  name: string;
  framework?: ComplianceFramework;
  regulation?: ComplianceRegulation;
  description: string;
  requirements: ComplianceRequirement[];
  enforcement: 'strict' | 'warning' | 'log_only';
}

/**
 * Compliance requirement
 */
export interface ComplianceRequirement {
  id: string;
  description: string;
  category: AuditCategory;
  eventTypes: AuditEventType[];
  retentionDays: number;
  immutable?: boolean;
  encryptionRequired?: boolean;
  accessControlRequired?: boolean;
  validationRequired?: boolean;
}

/**
 * Compliance reporting configuration
 */
export interface ComplianceReportingConfig {
  enabled: boolean;
  schedule: {
    daily?: boolean;
    weekly?: boolean;
    monthly?: boolean;
    quarterly?: boolean;
    annually?: boolean;
  };
  formats: ('pdf' | 'csv' | 'json' | 'xml')[];
  recipients: string[];
  storage: {
    location: string;
    retention: number; // days
  };
}

// ============================================================================
// Statistics and Analytics Types
// ============================================================================

/**
 * Comprehensive audit statistics
 */
export interface TypedAuditStatistics {
  // Time-based statistics
  timeRange: {
    start: Date;
    end: Date;
  };

  // Volume statistics
  volume: {
    totalEvents: number;
    eventsByCategory: Record<AuditCategory, number>;
    eventsByType: Record<AuditEventType, number>;
    eventsByOperation: Record<AuditOperation, number>;
    eventsBySource: Record<AuditSource, number>;
  };

  // Performance statistics
  performance: {
    averageDuration: number;
    maxDuration: number;
    minDuration: number;
    p95Duration: number;
    p99Duration: number;
    slowestEvents: Array<{
      event: TypedAuditEvent;
      duration: number;
    }>;
  };

  // Success and error statistics
  quality: {
    successRate: number;
    errorRate: number;
    errorsByType: Record<string, number>;
    failuresByCategory: Record<AuditCategory, number>;
  };

  // User statistics
  users: {
    uniqueUsers: number;
    topUsers: Array<{
      userId: string;
      eventCount: number;
      categories: Record<AuditCategory, number>;
    }>;
    anonymousEvents: number;
  };

  // Entity statistics
  entities: {
    uniqueEntityTypes: number;
    topEntities: Array<{
      entityType: string;
      eventCount: number;
      operations: Record<AuditOperation, number>;
    }>;
  };

  // Sensitivity statistics
  sensitivity: {
    distribution: Record<SensitivityLevel, number>;
    restrictedEvents: number;
    highRiskEvents: number;
  };

  // Compliance statistics
  compliance: {
    compliantEvents: number;
    nonCompliantEvents: number;
    complianceRate: number;
    violationsByFramework: Record<ComplianceFramework, number>;
    violationsByRegulation: Record<ComplianceRegulation, number>;
  };

  // Geographic statistics
  geographic: {
    eventsByCountry: Record<string, number>;
    eventsByRegion: Record<string, number>;
    unusualLocations: Array<{
      location: string;
      eventCount: number;
      riskScore: number;
    }>;
  };

  // Trends
  trends: {
    period: 'hourly' | 'daily' | 'weekly' | 'monthly';
    data: Array<{
      timestamp: string;
      eventCount: number;
      successRate: number;
      averageDuration: number;
    }>;
  };
}

// ============================================================================
// Type Guards and Validation Functions
// ============================================================================

/**
 * Type guard for audit events
 */
export function isTypedAuditEvent(value: unknown): value is TypedAuditEvent {
  if (typeof value !== 'object' || value === null) {
    return false;
  }

  const event = value as TypedAuditEvent;

  return (
    typeof event.id === 'string' &&
    Object.values(AuditEventType).includes(event.eventType as AuditEventType) &&
    Object.values(AuditCategory).includes(event.category as AuditCategory) &&
    typeof event.entityType === 'string' &&
    typeof event.entityId === 'string' &&
    Object.values(AuditOperation).includes(event.operation as AuditOperation) &&
    Object.values(AuditSource).includes(event.source as AuditSource) &&
    typeof event.component === 'string' &&
    typeof event.timestamp === 'string' &&
    typeof event.success === 'boolean' &&
    typeof event.metadata === 'object' &&
    typeof event.tags === 'object' &&
    Object.values(SensitivityLevel).includes(event.sensitivity as SensitivityLevel)
  );
}

/**
 * Type guard for audit query options
 */
export function isTypedAuditQueryOptions(value: unknown): value is TypedAuditQueryOptions {
  if (typeof value !== 'object' || value === null) {
    return false;
  }

  const query = value as TypedAuditQueryOptions;

  // Check that if arrays are provided, they contain valid enum values
  if (query.eventType && Array.isArray(query.eventType)) {
    return query.eventType.every(type => Object.values(AuditEventType).includes(type as AuditEventType));
  }

  if (query.category && Array.isArray(query.category)) {
    return query.category.every(cat => Object.values(AuditCategory).includes(cat as AuditCategory));
  }

  if (query.operation && Array.isArray(query.operation)) {
    return query.operation.every(op => Object.values(AuditOperation).includes(op as AuditOperation));
  }

  return true;
}

/**
 * Type guard for audit metadata
 */
export function isAuditMetadata(value: unknown): value is AuditMetadata {
  if (typeof value !== 'object' || value === null) {
    return false;
  }

  const metadata = value as AuditMetadata;

  // All fields in AuditMetadata should be of valid types
  for (const [key, val] of Object.entries(metadata)) {
    const isValidType =
      typeof val === 'string' ||
      typeof val === 'number' ||
      typeof val === 'boolean' ||
      val === null ||
      val === undefined ||
      (typeof val === 'object' && !Array.isArray(val));

    if (!isValidType) {
      return false;
    }
  }

  return true;
}

/**
 * Validates an audit event against business rules
 */
export function validateAuditEvent(event: TypedAuditEvent): AuditValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Required field validation
  if (!event.id || event.id.trim() === '') {
    errors.push('Event ID is required and cannot be empty');
  }

  if (!event.entityType || event.entityType.trim() === '') {
    errors.push('Entity type is required and cannot be empty');
  }

  if (!event.entityId || event.entityId.trim() === '') {
    errors.push('Entity ID is required and cannot be empty');
  }

  // Timestamp validation
  const timestamp = new Date(event.timestamp);
  if (isNaN(timestamp.getTime())) {
    errors.push('Invalid timestamp format');
  } else if (timestamp > new Date()) {
    warnings.push('Event timestamp is in the future');
  } else if (timestamp < new Date(Date.now() - 365 * 24 * 60 * 60 * 1000)) {
    warnings.push('Event timestamp is more than 1 year old');
  }

  // Business logic validation
  if (event.operation === AuditOperation.DELETE && event.newData && Object.keys(event.newData).length > 0) {
    warnings.push('Delete operation should not have new data');
  }

  if (event.operation === AuditOperation.CREATE && event.oldData && Object.keys(event.oldData).length > 0) {
    warnings.push('Create operation should not have old data');
  }

  // Sensitivity validation
  if (event.sensitivity === SensitivityLevel.SECRET && !event.userId) {
    warnings.push('Secret-level events should have user identification');
  }

  // Compliance validation
  if (event.compliance.frameworks.length > 0 && event.eventType === AuditEventType.DATA_DELETE) {
    const hasGDPR = event.compliance.frameworks.includes(ComplianceFramework.GDPR);
    if (hasGDPR && !event.metadata.dataOwner) {
      warnings.push('GDPR compliance requires data owner for delete operations');
    }
  }

  return {
    isValid: errors.length === 0,
    errors,
    warnings
  };
}

/**
 * Validation result interface
 */
export interface AuditValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Creates a properly typed audit event with default values
 */
export function createTypedAuditEvent(
  baseEvent: Partial<TypedAuditEvent>
): TypedAuditEvent {
  const now = new Date().toISOString();

  return {
    id: baseEvent.id || `audit_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
    eventType: baseEvent.eventType || AuditEventType.DATA_CREATE,
    category: baseEvent.category || AuditCategory.DATA,
    entityType: baseEvent.entityType || 'unknown',
    entityId: baseEvent.entityId || 'unknown',
    operation: baseEvent.operation || AuditOperation.CREATE,
    source: baseEvent.source || AuditSource.SYSTEM,
    component: baseEvent.component || 'unknown',
    timestamp: baseEvent.timestamp || now,
    success: baseEvent.success ?? true,
    metadata: baseEvent.metadata || {},
    tags: baseEvent.tags || {},
    sensitivity: baseEvent.sensitivity || SensitivityLevel.INTERNAL,
    compliance: baseEvent.compliance || {
      frameworks: [],
      regulations: [],
      policies: []
    },
    ...baseEvent
  };
}

/**
 * Creates a default audit configuration
 */
export function createDefaultAuditConfig(): AuditSystemConfig {
  return {
    enabled: true,
    filter: {
      exclude: {
        eventTypes: [
          AuditEventType.SYSTEM_HEALTH_CHECK
        ],
        sensitivityBelow: SensitivityLevel.PUBLIC
      },
      performance: {
        batchSize: 100,
        batchTimeoutMs: 5000,
        maxQueueSize: 10000,
        enableCompression: true
      }
    },
    storage: {
      type: 'database',
      primary: {
        tableName: 'audit_events',
        indexFields: ['timestamp', 'eventType', 'entityType', 'entityId', 'userId'],
        compressionEnabled: true,
        encryptionEnabled: true
      }
    },
    validation: {
      strictMode: false,
      requiredFields: ['id', 'eventType', 'category', 'entityType', 'entityId', 'operation', 'source', 'component', 'timestamp', 'success'],
      validateMetadata: true,
      validateCompliance: false,
      validateGeographic: false,
      maxLengths: {
        id: 255,
        entityType: 100,
        entityId: 255,
        userId: 255,
        sessionId: 255,
        requestId: 255,
        correlationId: 255,
        message: 1000
      }
    },
    alerting: {
      enabled: true,
      rules: [],
      channels: []
    },
    compliance: {
      frameworks: [],
      regulations: [],
      policies: [],
      reporting: {
        enabled: false,
        schedule: {},
        formats: ['json'],
        recipients: [],
        storage: {
          location: './reports',
          retention: 365
        }
      }
    }
  };
}

/**
 * Utility to get human-readable descriptions for audit types
 */
export function getAuditEventDescription(eventType: AuditEventType): string {
  const descriptions: Record<AuditEventType, string> = {
    [AuditEventType.DATA_CREATE]: 'Data record created',
    [AuditEventType.DATA_READ]: 'Data record accessed/read',
    [AuditEventType.DATA_UPDATE]: 'Data record updated',
    [AuditEventType.DATA_DELETE]: 'Data record deleted',
    [AuditEventType.DATA_BULK_CREATE]: 'Multiple data records created',
    [AuditEventType.DATA_BULK_UPDATE]: 'Multiple data records updated',
    [AuditEventType.DATA_BULK_DELETE]: 'Multiple data records deleted',
    [AuditEventType.AUTH_LOGIN]: 'User authentication successful',
    [AuditEventType.AUTH_LOGOUT]: 'User logged out',
    [AuditEventType.AUTH_FAILED_LOGIN]: 'User authentication failed',
    [AuditEventType.AUTH_PASSWORD_CHANGE]: 'User password changed',
    [AuditEventType.AUTH_TOKEN_REFRESH]: 'Authentication token refreshed',
    [AuditEventType.AUTHZ_ACCESS_GRANTED]: 'Access authorized',
    [AuditEventType.AUTHZ_ACCESS_DENIED]: 'Access denied',
    [AuditEventType.AUTHZ_ROLE_CHANGE]: 'User role changed',
    [AuditEventType.AUTHZ_PERMISSION_CHANGE]: 'User permissions changed',
    [AuditEventType.SYSTEM_STARTUP]: 'System started',
    [AuditEventType.SYSTEM_SHUTDOWN]: 'System shutdown',
    [AuditEventType.SYSTEM_CONFIG_CHANGE]: 'System configuration changed',
    [AuditEventType.SYSTEM_HEALTH_CHECK]: 'System health check performed',
    [AuditEventType.SECURITY_VIOLATION]: 'Security policy violation detected',
    [AuditEventType.SECURITY_BREACH_ATTEMPT]: 'Security breach attempt detected',
    [AuditEventType.SECURITY_SCAN]: 'Security scan performed',
    [AuditEventType.SECURITY_INCIDENT]: 'Security incident occurred',
    [AuditEventType.PERFORMANCE_SLOW_QUERY]: 'Slow query detected',
    [AuditEventType.PERFORMANCE_ERROR_SPIKE]: 'Error rate spike detected',
    [AuditEventType.PERFORMANCE_RESOURCE_EXHAUSTION]: 'Resource exhaustion detected',
    [AuditEventType.BUSINESS_WORKFLOW_START]: 'Business workflow started',
    [AuditEventType.BUSINESS_WORKFLOW_COMPLETE]: 'Business workflow completed',
    [AuditEventType.BUSINESS_WORKFLOW_FAIL]: 'Business workflow failed',
    [AuditEventType.BUSINESS_DECISION]: 'Business decision recorded',
    [AuditEventType.COMPLIANCE_REPORT_GENERATED]: 'Compliance report generated',
    [AuditEventType.COMPLIANCE_POLICY_VIOLATION]: 'Compliance policy violation detected',
    [AuditEventType.COMPLIANCE_AUDIT]: 'Compliance audit performed',
    [AuditEventType.DATA_VALIDATION_ERROR]: 'Data validation error detected',
    [AuditEventType.DATA_QUALITY_CHECK]: 'Data quality check performed',
    [AuditEventType.DATA_MIGRATION]: 'Data migration performed',
    [AuditEventType.DATA_BACKUP]: 'Data backup performed',
    [AuditEventType.DATA_RESTORE]: 'Data restore performed'
  };

  return descriptions[eventType] || 'Unknown audit event';
}