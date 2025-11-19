/**
 * Type guards for monitoring data structures
 *
 * Provides runtime type checking and validation for monitoring interfaces,
 * helping to prevent property access errors and ensure type safety.
 */

import type {
  Alert,
  EnhancedAlert,
  PerformanceMetric,
  EnhancedPerformanceMetric,
  LoggableData
} from './monitoring-types.js';
import type { AlertSeverity } from '../monitoring/alert-management-service.js';
import type { TypedMetric } from './metrics-types.js';

// ============================================================================
// Alert Type Guards
// ============================================================================

/**
 * Type guard for basic Alert interface
 */
export function isAlert(obj: unknown): obj is Alert {
  return (
    obj !== null &&
    typeof obj === 'object' &&
    'id' in obj &&
    'status' in obj &&
    'severity' in obj &&
    'timestamp' in obj &&
    'title' in obj &&
    typeof (obj as Alert).id === 'string' &&
    typeof (obj as Alert).status === 'string' &&
    typeof (obj as Alert).severity === 'string' &&
    typeof (obj as Alert).title === 'string'
  );
}

/**
 * Type guard for Enhanced Alert interface
 */
export function isEnhancedAlert(obj: unknown): obj is EnhancedAlert {
  return (
    isAlert(obj) &&
    'message' in obj &&
    typeof (obj as EnhancedAlert).message === 'string'
  );
}

/**
 * Type guard to check if alert has service name
 */
export function hasServiceName(alert: Alert | EnhancedAlert): alert is Alert & { serviceName: string } {
  return 'serviceName' in alert && typeof alert.serviceName === 'string';
}

/**
 * Type guard to check if alert is acknowledged
 */
export function isAcknowledged(alert: Alert | EnhancedAlert): alert is Alert & { acknowledged: true; acknowledgedAt?: Date; acknowledgedBy?: string } {
  return 'acknowledged' in alert && alert.acknowledged === true;
}

/**
 * Type guard to check if alert is resolved
 */
export function isResolved(alert: Alert | EnhancedAlert): alert is Alert & { resolved: true; resolvedAt?: Date } {
  return 'resolved' in alert && alert.resolved === true;
}

/**
 * Type guard to check if alert is escalated
 */
export function isEscalated(alert: Alert | EnhancedAlert): alert is EnhancedAlert & { escalated: true; escalationLevel: number } {
  return isEnhancedAlert(alert) && alert.escalated === true && typeof alert.escalationLevel === 'number';
}

// ============================================================================
// Performance Metric Type Guards
// ============================================================================

/**
 * Type guard for basic PerformanceMetric interface
 */
export function isPerformanceMetric(obj: unknown): obj is PerformanceMetric {
  return (
    obj !== null &&
    typeof obj === 'object' &&
    'timestamp' in obj &&
    'operation' in obj &&
    'duration' in obj &&
    'success' in obj &&
    (typeof (obj as PerformanceMetric).timestamp === 'string' || typeof (obj as PerformanceMetric).timestamp === 'number') &&
    typeof (obj as PerformanceMetric).operation === 'string' &&
    typeof (obj as PerformanceMetric).duration === 'number' &&
    typeof (obj as PerformanceMetric).success === 'boolean'
  );
}

/**
 * Type guard for Enhanced PerformanceMetric interface
 */
export function isEnhancedPerformanceMetric(obj: unknown): obj is EnhancedPerformanceMetric {
  return (
    isPerformanceMetric(obj) &&
    'name' in obj &&
    'type' in obj &&
    'value' in obj &&
    typeof (obj as EnhancedPerformanceMetric).name === 'string' &&
    typeof (obj as EnhancedPerformanceMetric).type === 'string'
  );
}

/**
 * Type guard for TypedMetric interface
 */
export function isTypedMetric(obj: unknown): obj is TypedMetric {
  return (
    obj !== null &&
    typeof obj === 'object' &&
    'id' in obj &&
    'name' in obj &&
    'type' in obj &&
    'category' in obj &&
    'value' in obj &&
    'timestamp' in obj &&
    'component' in obj &&
    'dimensions' in obj &&
    'labels' in obj &&
    'quality' in obj &&
    'metadata' in obj &&
    typeof (obj as TypedMetric).id === 'string' &&
    typeof (obj as TypedMetric).name === 'string' &&
    typeof (obj as TypedMetric).value !== 'undefined' &&
    typeof (obj as TypedMetric).timestamp === 'string' &&
    typeof (obj as TypedMetric).component === 'string' &&
    Array.isArray((obj as TypedMetric).dimensions) &&
    typeof (obj as TypedMetric).labels === 'object' &&
    typeof (obj as TypedMetric).quality === 'object' &&
    typeof (obj as TypedMetric).metadata === 'object'
  );
}

/**
 * Type guard to check if metric has resource usage data
 */
export function hasResourceUsage(metric: PerformanceMetric | EnhancedPerformanceMetric): metric is PerformanceMetric & { resourceUsage: { cpu: number; memory: number; disk: number; network: number } } {
  return 'resourceUsage' in metric && typeof (metric as any).resourceUsage === 'object';
}

/**
 * Type guard to check if metric has error information
 */
export function hasError(metric: PerformanceMetric | EnhancedPerformanceMetric): metric is PerformanceMetric & { error: string } {
  return 'error' in metric && typeof (metric as any).error === 'string';
}

/**
 * Type guard to check if metric has throughput data
 */
export function hasThroughput(metric: PerformanceMetric | EnhancedPerformanceMetric): metric is PerformanceMetric & { throughput: number } {
  return 'throughput' in metric && typeof (metric as any).throughput === 'number';
}

// ============================================================================
// Severity and Status Type Guards
// ============================================================================

/**
 * Type guard for valid alert severity
 */
export function isValidSeverity(severity: unknown): severity is 'low' | 'medium' | 'high' | 'critical' {
  return (
    typeof severity === 'string' &&
    ['low', 'medium', 'high', 'critical'].includes(severity)
  );
}

/**
 * Type guard for valid alert status
 */
export function isValidAlertStatus(status: unknown): status is 'active' | 'resolved' | 'acknowledged' | 'suppressed' | 'firing' {
  return (
    typeof status === 'string' &&
    ['active', 'resolved', 'acknowledged', 'suppressed', 'firing'].includes(status)
  );
}

/**
 * Type guard for AlertSeverity enum
 */
export function isAlertSeverityEnum(severity: unknown): severity is AlertSeverity {
  return (
    typeof severity === 'string' &&
    Object.values(AlertSeverity).includes(severity as AlertSeverity)
  );
}

// ============================================================================
// Collection Type Guards
// ============================================================================

/**
 * Type guard for array of alerts
 */
export function isAlertArray(obj: unknown): obj is Alert[] {
  return Array.isArray(obj) && obj.every(isAlert);
}

/**
 * Type guard for array of enhanced alerts
 */
export function isEnhancedAlertArray(obj: unknown): obj is EnhancedAlert[] {
  return Array.isArray(obj) && obj.every(isEnhancedAlert);
}

/**
 * Type guard for array of performance metrics
 */
export function isPerformanceMetricArray(obj: unknown): obj is PerformanceMetric[] {
  return Array.isArray(obj) && obj.every(isPerformanceMetric);
}

/**
 * Type guard for array of typed metrics
 */
export function isTypedMetricArray(obj: unknown): obj is TypedMetric[] {
  return Array.isArray(obj) && obj.every(isTypedMetric);
}

// ============================================================================
// Safe Property Access Helpers
// ============================================================================

/**
 * Safely get severity from alert with fallback
 */
export function getAlertSeverity(alert: Alert | EnhancedAlert): string {
  if (typeof alert.severity === 'string') {
    return alert.severity;
  }
  return 'unknown';
}

/**
 * Safely get service name from alert with fallback
 */
export function getAlertServiceName(alert: Alert | EnhancedAlert): string {
  if (hasServiceName(alert)) {
    return alert.serviceName;
  }
  return 'unknown';
}

/**
 * Safely get timestamp from metric with fallback
 */
export function getMetricTimestamp(metric: PerformanceMetric | EnhancedPerformanceMetric | TypedMetric): number {
  if (typeof metric.timestamp === 'number') {
    return metric.timestamp;
  }
  if (typeof metric.timestamp === 'string') {
    const parsed = new Date(metric.timestamp).getTime();
    return isNaN(parsed) ? Date.now() : parsed;
  }
  return Date.now();
}

/**
 * Safely get value from metric with fallback
 */
export function getMetricValue(metric: PerformanceMetric | EnhancedPerformanceMetric | TypedMetric): number {
  if (typeof metric.value === 'number') {
    return metric.value;
  }
  if (typeof metric.value === 'string') {
    const parsed = parseFloat(metric.value);
    return isNaN(parsed) ? 0 : parsed;
  }
  return 0;
}

/**
 * Safely get operation name from metric with fallback
 */
export function getMetricOperation(metric: PerformanceMetric | EnhancedPerformanceMetric | TypedMetric): string {
  if ('operation' in metric && typeof metric.operation === 'string') {
    return metric.operation;
  }
  if ('name' in metric && typeof metric.name === 'string') {
    return metric.name;
  }
  return 'unknown';
}

// ============================================================================
// LoggableData Type Guards
// ============================================================================

/**
 * Type guard for LoggableData
 */
export function isLoggableData(obj: unknown): obj is LoggableData {
  if (obj === null || typeof obj !== 'object') {
    return false;
  }

  const checkValue = (value: unknown): boolean => {
    if (value === null || value === undefined) {
      return true;
    }
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
      return true;
    }
    if (Array.isArray(value)) {
      return value.every(checkValue);
    }
    if (typeof value === 'object') {
      return isLoggableData(value);
    }
    return false;
  };

  return Object.values(obj as Record<string, unknown>).every(checkValue);
}

// ============================================================================
// Generic Type Guards
// ============================================================================

/**
 * Type guard for objects with specific property
 */
export function hasProperty<T extends string>(
  obj: unknown,
  prop: T
): obj is Record<T, unknown> {
  return (
    obj !== null &&
    typeof obj === 'object' &&
    prop in obj
  );
}

/**
 * Type guard for objects with specific string property
 */
export function hasStringProperty<T extends string>(
  obj: unknown,
  prop: T
): obj is Record<T, string> {
  return hasProperty(obj, prop) && typeof (obj as Record<T, unknown>)[prop] === 'string';
}

/**
 * Type guard for objects with specific number property
 */
export function hasNumberProperty<T extends string>(
  obj: unknown,
  prop: T
): obj is Record<T, number> {
  return hasProperty(obj, prop) && typeof (obj as Record<T, unknown>)[prop] === 'number';
}

/**
 * Type guard for objects with specific boolean property
 */
export function hasBooleanProperty<T extends string>(
  obj: unknown,
  prop: T
): obj is Record<T, boolean> {
  return hasProperty(obj, prop) && typeof (obj as Record<T, unknown>)[prop] === 'boolean';
}