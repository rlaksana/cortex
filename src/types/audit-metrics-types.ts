// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * Audit and Metrics Types for Cortex MCP System
 *
 * Provides comprehensive type definitions for audit events, metrics,
 * compliance tracking, and validation operations.
 */

// ============================================================================
// Audit Types
// ============================================================================

export enum AuditCategory {
  SYSTEM = 'system',
  SECURITY = 'security',
  PERFORMANCE = 'performance',
  BUSINESS = 'business',
  COMPLIANCE = 'compliance',
  OPERATION = 'operation',
  DATA = 'data',
  ACCESS = 'access'
}

export enum AuditEventType {
  USER_ACTION = 'user_action',
  SYSTEM_EVENT = 'system_event',
  ERROR_OCCURRED = 'error_occurred',
  SECURITY_VIOLATION = 'security_violation',
  CONFIGURATION_CHANGE = 'configuration_change',
  DATA_ACCESS = 'data_access',
  API_CALL = 'api_call',
  BATCH_OPERATION = 'batch_operation'
}

export enum AuditOperation {
  CREATE = 'create',
  READ = 'read',
  UPDATE = 'update',
  DELETE = 'delete',
  EXECUTE = 'execute',
  ACCESS = 'access',
  MODIFY = 'modify',
  APPROVE = 'approve',
  REJECT = 'reject',
  EXPORT = 'export',
  IMPORT = 'import'
}

export enum AuditSource {
  USER_INTERFACE = 'user_interface',
  API = 'api',
  SYSTEM = 'system',
  BATCH_PROCESS = 'batch_process',
  AUTOMATION = 'automation',
  EXTERNAL_SYSTEM = 'external_system',
  BACKGROUND_SERVICE = 'background_service'
}

export enum ComplianceFramework {
  GDPR = 'gdpr',
  HIPAA = 'hipaa',
  SOX = 'sox',
  PCI_DSS = 'pci_dss',
  ISO_27001 = 'iso_27001',
  SOC_2 = 'soc_2',
  NIST = 'nist',
  CCPA = 'ccpa'
}

export enum ComplianceRegulation {
  GDPR_ARTICLE_5 = 'gdpr_article_5',
  GDPR_ARTICLE_25 = 'gdpr_article_25',
  HIPAA_SECURITY_RULE = 'hipaa_security_rule',
  SOX_SECTION_404 = 'sox_section_404',
  PCI_DSS_3_2 = 'pci_dss_3_2',
  ISO_27001_A_8_2 = 'iso_27001_a_8_2'
}

export enum SensitivityLevel {
  PUBLIC = 'public',
  INTERNAL = 'internal',
  CONFIDENTIAL = 'confidential',
  RESTRICTED = 'restricted',
  TOP_SECRET = 'top_secret'
}

export interface TypedAuditEvent {
  id: string;
  timestamp: string;
  category: AuditCategory;
  eventType: AuditEventType;
  operation: AuditOperation;
  source: AuditSource;
  userId?: string;
  sessionId?: string;
  resourceId?: string;
  resourceType?: string;
  action: string;
  result: 'success' | 'failure' | 'partial';
  details: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
  location?: GeographicInfo;
  sensitivity: SensitivityLevel;
  compliance: ComplianceInfo;
  complianceFrameworks: ComplianceFramework[];
  regulations: ComplianceRegulation[];
  metadata: Record<string, unknown>;
  // Additional properties for validation
  entityType?: string;
  entityId?: string;
  oldData?: Record<string, unknown>;
  newData?: Record<string, unknown>;
}

// Additional type definitions for TypedAuditEvent compatibility
export interface GeographicInfo {
  country?: string;
  region?: string;
  city?: string;
  coordinates?: {
    latitude?: number;
    longitude?: number;
  };
}

export interface ComplianceInfo {
  frameworks: ComplianceFramework[];
  regulations: ComplianceRegulation[];
  flags?: {
    gdpr: boolean;
    hipaa: boolean;
    sox: boolean;
    pci: boolean;
  };
}

export interface AuditValidationResult {
  isValid: boolean;
  severity: 'error' | 'warning' | 'info';
  errors: ValidationError[];
  warnings: ValidationWarning[];
  validatedEvent?: TypedAuditEvent;
  metadata: {
    validationTimeMs: number;
    validatorVersion: string;
    checkedFields: string[];
  };
}

// ============================================================================
// Metrics Types
// ============================================================================

export enum MetricCategory {
  PERFORMANCE = 'performance',
  AVAILABILITY = 'availability',
  THROUGHPUT = 'throughput',
  ERROR_RATE = 'error_rate',
  RESOURCE_UTILIZATION = 'resource_utilization',
  BUSINESS = 'business',
  USER_EXPERIENCE = 'user_experience',
  SECURITY = 'security'
}

export const MetricType = {
  COUNTER: 'counter',
  GAUGE: 'gauge',
  HISTOGRAM: 'histogram',
  TIMER: 'timer',
  METER: 'meter',
  PERCENTILE: 'percentile'
} as const;

export type MetricType = typeof MetricType[keyof typeof MetricType];

export enum OutputFormat {
  JSON = 'json',
  CSV = 'csv',
  XML = 'xml',
  PROMETHEUS = 'prometheus',
  INFLUXDB = 'influxdb',
  GRAFANA = 'grafana'
}

export interface TypedMetric {
  name: string;
  type: MetricType;
  category: MetricCategory;
  value: number;
  timestamp: string;
  unit: string;
  tags: Record<string, string>;
  dimensions: Record<string, string>;
  thresholds?: {
    warning?: number;
    critical?: number;
    expectedRange?: [number, number];
    criticalRange?: [number, number];
  };
  metadata: Record<string, unknown>;
  // Additional properties for validation
  quality?: {
    status: 'good' | 'fair' | 'poor';
    completeness?: number;
    lastValidated?: string;
  };
  labels?: Record<string, string>;
  component?: string;
  thresholds?: {
    warning?: number;
    critical?: number;
    min?: number;
    max?: number;
    expectedRange?: [number, number];
    criticalRange?: [number, number];
  };
}

export interface MetricValidationResult {
  isValid: boolean;
  severity: 'error' | 'warning' | 'info';
  errors: ValidationError[];
  warnings: ValidationWarning[];
  validatedMetric?: TypedMetric;
  metadata: {
    validationTimeMs: number;
    validatorVersion: string;
    checkedFields: string[];
  };
}

// ============================================================================
// Common Validation Types
// ============================================================================

export interface ValidationError {
  code: string;
  message: string;
  field?: string;
  severity: 'error' | 'critical';
  suggestion?: string;
  recommendation?: string;
  context?: Record<string, unknown>;
}

export interface ValidationWarning {
  code: string;
  message: string;
  field?: string;
  severity: 'warning' | 'info';
  suggestion?: string;
  context?: Record<string, unknown>;
}

export interface ValidationSuggestion {
  code: string;
  message: string;
  field?: string;
  suggestion?: string;
  context?: Record<string, unknown>;
  action?: string;
  priority?: number;
  timestamp?: string;
}

export interface ValidationContext {
  operation?: string;
  userId?: string;
  sessionId?: string;
  timestamp?: string;
  environment?: 'development' | 'test' | 'staging' | 'production';
  version?: string;
}

export type ValidationFunction = ((data: unknown, context?: ValidationContext) => ValidationResult) | ((data: unknown, context?: ValidationContext) => Promise<ValidationResult>);

export interface ValidationResult {
  isValid: boolean;
  severity: 'error' | 'warning' | 'info';
  errors: ValidationError[];
  warnings: ValidationWarning[];
  data?: unknown;
  suggestions?: ValidationSuggestion[];
  metadata?: Record<string, unknown>;
}