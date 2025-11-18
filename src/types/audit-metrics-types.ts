/**
 * Audit and Metrics Types for Cortex MCP System
 *
 * Re-exports consolidated audit types from audit-types.ts to maintain compatibility.
 * This file now focuses on metrics-specific types while providing audit type exports.
 */

// ============================================================================
// Re-export Consolidated Audit Types from audit-types.ts
// ============================================================================

// Re-export consolidated audit enums
export {
  AuditCategory,
  AuditEventType,
  AuditOperation,
  AuditSource,
  ComplianceFramework,
  ComplianceRegulation,
  SensitivityLevel,
} from './audit-types.js';

// Re-export audit types with proper type declarations for isolatedModules
export type {
  AuditValidationResult,
  ComplianceInfo,
  GeographicInfo,
  TypedAuditEvent,
} from './audit-types.js';

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
  SECURITY = 'security',
}

export const MetricType = {
  COUNTER: 'counter',
  GAUGE: 'gauge',
  HISTOGRAM: 'histogram',
  TIMER: 'timer',
  METER: 'meter',
  PERCENTILE: 'percentile',
} as const;

export type MetricType = (typeof MetricType)[keyof typeof MetricType];

export enum OutputFormat {
  JSON = 'json',
  CSV = 'csv',
  XML = 'xml',
  PROMETHEUS = 'prometheus',
  INFLUXDB = 'influxdb',
  GRAFANA = 'grafana',
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
    min?: number;
    max?: number;
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

export type ValidationFunction =
  | ((data: unknown, context?: ValidationContext) => ValidationResult)
  | ((data: unknown, context?: ValidationContext) => Promise<ValidationResult>);

export interface ValidationResult {
  isValid: boolean;
  severity: 'error' | 'warning' | 'info';
  errors: ValidationError[];
  warnings: ValidationWarning[];
  data?: unknown;
  suggestions?: ValidationSuggestion[];
  metadata?: Record<string, unknown>;
}
