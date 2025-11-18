/**
 * Type guards and validation utilities for monitoring and logging system
 * Provides runtime type checking and validation for all monitoring data structures
 *
 * TypeScript Recovery: Phase 2.2e - Assessing remaining TypeScript compatibility issues
 */

import { OperationType } from '../monitoring/operation-types.js';
import type {
  ErrorInfo,
  LoggableData,
  LogLevel,
  OperationMetadata,
  QueryDetails,
  RequestContext,
  ResultMetrics,
  SlowQueryAnalysis,
  SlowQueryContext,
  SlowQuerySystemState,
  StructuredLogEntry,
  SystemHealth,
  TTLInfo,
  TypedPerformanceAlert,
  TypedPerformanceMetric,
  TypedPerformanceSummary,
  UserContext,
} from '../types/monitoring-types.js';
import { DeduplicationStrategy, SearchStrategy } from '../types/monitoring-types.js';

// ============================================================================
// Basic Type Guards
// ============================================================================

/**
 * Type guard for LoggableData
 */
export function isLoggableData(value: unknown): value is LoggableData {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.values(value as Record<string, unknown>).every(
      (val) =>
        typeof val === 'string' ||
        typeof val === 'number' ||
        typeof val === 'boolean' ||
        val === null ||
        val === undefined ||
        isLoggableData(val) ||
        (Array.isArray(val) && val.every(isLoggableData))
    )
  );
}

/**
 * Type guard for LogLevel
 */
export function isLogLevel(value: unknown): value is LogLevel {
  return typeof value === 'string' && ['debug', 'info', 'warn', 'error'].includes(value);
}

/**
 * Type guard for OperationType
 */
export function isOperationType(value: unknown): value is OperationType {
  return typeof value === 'string' && Object.values(OperationType).includes(value as OperationType);
}

/**
 * Type guard for SearchStrategy
 */
export function isSearchStrategy(value: unknown): value is SearchStrategy {
  return (
    typeof value === 'string' && Object.values(SearchStrategy).includes(value as SearchStrategy)
  );
}

/**
 * Type guard for DeduplicationStrategy
 */
export function isDeduplicationStrategy(value: unknown): value is DeduplicationStrategy {
  return (
    typeof value === 'string' &&
    Object.values(DeduplicationStrategy).includes(value as DeduplicationStrategy)
  );
}

// ============================================================================
// Complex Type Guards
// ============================================================================

/**
 * Type guard for UserContext
 */
export function isUserContext(value: unknown): value is UserContext {
  if (!isLoggableData(value)) return false;

  const ctx = value as Record<string, unknown>;
  return (
    typeof ctx.user_id === 'string' &&
    typeof ctx.username === 'string' &&
    typeof ctx.role === 'string' &&
    Array.isArray(ctx.scopes) &&
    ctx.scopes.every((scope: unknown) => typeof scope === 'string')
  );
}

/**
 * Type guard for RequestContext
 */
export function isRequestContext(value: unknown): value is RequestContext {
  if (!isLoggableData(value)) return false;

  const ctx = value as Record<string, unknown>;
  return (
    (ctx.query === undefined || typeof ctx.query === 'string') &&
    (ctx.mode === undefined || typeof ctx.mode === 'string') &&
    (ctx.limit === undefined || typeof ctx.limit === 'number') &&
    (ctx.types === undefined ||
      (Array.isArray(ctx.types) && ctx.types.every((t: unknown) => typeof t === 'string'))) &&
    (ctx.scope === undefined || isLoggableData(ctx.scope)) &&
    (ctx.expand === undefined || typeof ctx.expand === 'string')
  );
}

/**
 * Type guard for ErrorInfo
 */
export function isErrorInfo(value: unknown): value is ErrorInfo {
  if (!isLoggableData(value)) return false;

  const error = value as Record<string, unknown>;
  return (
    typeof error.type === 'string' &&
    typeof error.message === 'string' &&
    (error.stack === undefined || typeof error.stack === 'string') &&
    (error.code === undefined ||
      typeof error.code === 'string' ||
      typeof error.code === 'number') &&
    (error.context === undefined || isLoggableData(error.context))
  );
}

/**
 * Type guard for OperationMetadata
 */
export function isOperationMetadata(value: unknown): value is OperationMetadata {
  if (!isLoggableData(value)) return false;

  const metadata = value as Record<string, unknown>;
  return (
    (metadata.strategy === undefined || typeof metadata.strategy === 'string') &&
    (metadata.deduplication === undefined || typeof metadata.deduplication === 'string') &&
    (metadata.result_count === undefined || typeof metadata.result_count === 'number') &&
    (metadata.duplicates_found === undefined || typeof metadata.duplicates_found === 'number') &&
    (metadata.cache_hit === undefined || typeof metadata.cache_hit === 'boolean') &&
    (metadata.ttl_hours === undefined || typeof metadata.ttl_hours === 'number')
  );
}

/**
 * Type guard for SystemHealth
 */
export function isSystemHealth(value: unknown): value is SystemHealth {
  if (!isLoggableData(value)) return false;

  const health = value as Record<string, unknown>;
  return (
    (health.qdrant_status === undefined ||
      ['healthy', 'degraded', 'unhealthy'].includes(health.qdrant_status as string)) &&
    (health.database_status === undefined ||
      ['connected', 'error', 'timeout'].includes(health.database_status as string)) &&
    (health.embedding_service_status === undefined ||
      ['healthy', 'error'].includes(health.embedding_service_status as string)) &&
    (health.memory_usage_mb === undefined || typeof health.memory_usage_mb === 'number') &&
    (health.cpu_usage_percent === undefined || typeof health.cpu_usage_percent === 'number') &&
    (health.active_connections === undefined || typeof health.active_connections === 'number')
  );
}

/**
 * Type guard for ResultMetrics
 */
export function isResultMetrics(value: unknown): value is ResultMetrics {
  if (!isLoggableData(value)) return false;

  const metrics = value as Record<string, unknown>;
  return (
    (metrics.total_count === undefined || typeof metrics.total_count === 'number') &&
    (metrics.result_count === undefined || typeof metrics.result_count === 'number') &&
    (metrics.duplicates_found === undefined || typeof metrics.duplicates_found === 'number') &&
    (metrics.newer_versions_allowed === undefined ||
      typeof metrics.newer_versions_allowed === 'number') &&
    (metrics.chunks_created === undefined || typeof metrics.chunks_created === 'number') &&
    (metrics.cache_hit === undefined || typeof metrics.cache_hit === 'boolean')
  );
}

/**
 * Type guard for TTLInfo
 */
export function isTTLInfo(value: unknown): value is TTLInfo {
  if (!isLoggableData(value)) return false;

  const ttl = value as Record<string, unknown>;
  return (
    (ttl.ttl_hours === undefined || typeof ttl.ttl_hours === 'number') &&
    (ttl.ttl_preset === undefined || typeof ttl.ttl_preset === 'string') &&
    (ttl.expires_at === undefined || typeof ttl.expires_at === 'string')
  );
}

/**
 * Type guard for QueryDetails
 */
export function isQueryDetails(value: unknown): value is QueryDetails {
  if (!isLoggableData(value)) return false;

  const query = value as Record<string, unknown>;
  return (
    typeof query.text === 'string' &&
    typeof query.mode === 'string' &&
    typeof query.limit === 'number' &&
    Array.isArray(query.types) &&
    query.types.every((t: unknown) => typeof t === 'string') &&
    typeof query.expand === 'string' &&
    (query.batch_size === undefined || typeof query.batch_size === 'number') &&
    (query.deduplication === undefined || typeof query.deduplication === 'boolean') &&
    (query.chunking === undefined || typeof query.chunking === 'boolean')
  );
}

/**
 * Type guard for SlowQueryContext
 */
export function isSlowQueryContext(value: unknown): value is SlowQueryContext {
  if (!isLoggableData(value)) return false;

  const ctx = value as Record<string, unknown>;
  return (
    (ctx.user_id === undefined || typeof ctx.user_id === 'string') &&
    (ctx.organization === undefined || typeof ctx.organization === 'string') &&
    (ctx.project === undefined || typeof ctx.project === 'string') &&
    (ctx.branch === undefined || typeof ctx.branch === 'string') &&
    (ctx.session_id === undefined || typeof ctx.session_id === 'string') &&
    (ctx.request_id === undefined || typeof ctx.request_id === 'string')
  );
}

/**
 * Type guard for SlowQueryAnalysis
 */
export function isSlowQueryAnalysis(value: unknown): value is SlowQueryAnalysis {
  if (!isLoggableData(value)) return false;

  const analysis = value as Record<string, unknown>;
  return (
    ['low', 'medium', 'high', 'critical'].includes(analysis.severity as string) &&
    typeof analysis.slowdown_factor === 'number' &&
    Array.isArray(analysis.potential_bottlenecks) &&
    analysis.potential_bottlenecks.every((b: unknown) => typeof b === 'string') &&
    Array.isArray(analysis.optimization_suggestions) &&
    analysis.optimization_suggestions.every((s: unknown) => typeof s === 'string') &&
    (analysis.bottleneck_scores === undefined || isLoggableData(analysis.bottleneck_scores)) &&
    (analysis.optimization_impact === undefined || isLoggableData(analysis.optimization_impact))
  );
}

/**
 * Type guard for SlowQuerySystemState
 */
export function isSlowQuerySystemState(value: unknown): value is SlowQuerySystemState {
  if (!isLoggableData(value)) return false;

  const state = value as Record<string, unknown>;
  return (
    typeof state.memory_usage_mb === 'number' &&
    typeof state.concurrent_queries === 'number' &&
    typeof state.cache_hit_rate === 'number' &&
    (state.cpu_usage_percent === undefined || typeof state.cpu_usage_percent === 'number') &&
    (state.active_connections === undefined || typeof state.active_connections === 'number') &&
    (state.queue_depth === undefined || typeof state.queue_depth === 'number')
  );
}

// ============================================================================
// Performance Type Guards
// ============================================================================

/**
 * Type guard for TypedPerformanceMetric
 */
export function isTypedPerformanceMetric(value: unknown): value is TypedPerformanceMetric {
  if (!isLoggableData(value)) return false;

  const metric = value as Record<string, unknown>;
  return (
    isOperationType(metric.operation) &&
    typeof metric.startTime === 'number' &&
    typeof metric.endTime === 'number' &&
    typeof metric.duration === 'number' &&
    typeof metric.success === 'boolean' &&
    (metric.metadata === undefined || isOperationMetadata(metric.metadata)) &&
    (metric.tags === undefined ||
      (Array.isArray(metric.tags) && metric.tags.every((t: unknown) => typeof t === 'string'))) &&
    (metric.correlationId === undefined || typeof metric.correlationId === 'string') &&
    (metric.userId === undefined || typeof metric.userId === 'string')
  );
}

/**
 * Type guard for TypedPerformanceSummary
 */
export function isTypedPerformanceSummary(value: unknown): value is TypedPerformanceSummary {
  if (!isLoggableData(value)) return false;

  const summary = value as Record<string, unknown>;
  return (
    isOperationType(summary.operation) &&
    typeof summary.count === 'number' &&
    typeof summary.totalDuration === 'number' &&
    typeof summary.averageDuration === 'number' &&
    typeof summary.minDuration === 'number' &&
    typeof summary.maxDuration === 'number' &&
    typeof summary.p95 === 'number' &&
    typeof summary.p99 === 'number' &&
    typeof summary.successRate === 'number' &&
    typeof summary.errorCount === 'number' &&
    typeof summary.timestamp === 'number'
  );
}

/**
 * Type guard for TypedPerformanceAlert
 */
export function isTypedPerformanceAlert(value: unknown): value is TypedPerformanceAlert {
  if (!isLoggableData(value)) return false;

  const alert = value as Record<string, unknown>;
  return (
    isOperationType(alert.operation) &&
    ['slow_query', 'high_error_rate', 'memory_usage', 'connection_pool', 'rate_limit'].includes(
      alert.alertType as string
    ) &&
    typeof alert.threshold === 'number' &&
    typeof alert.currentValue === 'number' &&
    ['low', 'medium', 'high', 'critical'].includes(alert.severity as string) &&
    typeof alert.message === 'string' &&
    typeof alert.timestamp === 'number' &&
    (alert.correlationId === undefined || typeof alert.correlationId === 'string') &&
    (alert.userId === undefined || typeof alert.userId === 'string') &&
    (alert.context === undefined || isLoggableData(alert.context))
  );
}

// ============================================================================
// Structured Log Entry Type Guards
// ============================================================================

/**
 * Type guard for StructuredLogEntry
 */
export function isStructuredLogEntry(value: unknown): value is StructuredLogEntry {
  if (!isLoggableData(value)) return false;

  const entry = value as Record<string, unknown>;
  return (
    typeof entry.timestamp === 'string' &&
    isOperationType(entry.operation) &&
    isLogLevel(entry.level) &&
    typeof entry.correlation_id === 'string' &&
    typeof entry.latency_ms === 'number' &&
    typeof entry.success === 'boolean' &&
    (entry.user_context === undefined || isUserContext(entry.user_context)) &&
    (entry.request_context === undefined || isRequestContext(entry.request_context)) &&
    (entry.result_metrics === undefined || isResultMetrics(entry.result_metrics)) &&
    (entry.system_health === undefined || isSystemHealth(entry.system_health)) &&
    (entry.ttl_info === undefined || isTTLInfo(entry.ttl_info)) &&
    (entry.strategy === undefined || isSearchStrategy(entry.strategy)) &&
    (entry.deduplication === undefined || isDeduplicationStrategy(entry.deduplication)) &&
    (entry.error === undefined || isErrorInfo(entry.error)) &&
    (entry.metadata === undefined || isOperationMetadata(entry.metadata))
  );
}

// ============================================================================
// Validation Functions
// ============================================================================

/**
 * Validate and sanitize user context
 */
export function validateUserContext(value: unknown): UserContext | null {
  if (!isUserContext(value)) return null;

  return {
    user_id: String(value.user_id),
    username: String(value.username),
    role: String(value.role),
    scopes: Array.isArray(value.scopes) ? value.scopes.map(String) : [],
  };
}

/**
 * Validate and sanitize request context
 */
export function validateRequestContext(value: unknown): RequestContext | null {
  if (!isRequestContext(value)) return null;

  const ctx: RequestContext = {};

  if (value.query !== undefined) ctx.query = String(value.query);
  if (value.mode !== undefined) ctx.mode = String(value.mode);
  if (value.limit !== undefined) ctx.limit = Number(value.limit);
  if (value.types !== undefined)
    ctx.types = Array.isArray(value.types) ? value.types.map(String) : [];
  if (value.scope !== undefined) ctx.scope = isLoggableData(value.scope) ? value.scope : {};
  if (value.expand !== undefined) ctx.expand = String(value.expand);

  return ctx;
}

/**
 * Validate and sanitize error info
 */
export function validateErrorInfo(value: unknown): ErrorInfo | null {
  if (!isErrorInfo(value)) return null;

  return {
    type: String(value.type),
    message: String(value.message),
    stack: value.stack ? String(value.stack) : undefined,
    code: value.code !== undefined ? value.code : undefined,
    context: value.context && isLoggableData(value.context) ? value.context : undefined,
  };
}

/**
 * Validate and sanitize operation metadata
 */
export function validateOperationMetadata(value: unknown): OperationMetadata | null {
  if (!isOperationMetadata(value)) return null;

  const metadata: OperationMetadata = {};

  Object.entries(value).forEach(([key, val]) => {
    if (val !== undefined && val !== null) {
      metadata[key] = val;
    }
  });

  return metadata;
}

/**
 * Validate structured log entry
 */
export function validateStructuredLogEntry(value: unknown): StructuredLogEntry | null {
  if (!isStructuredLogEntry(value)) return null;

  return {
    timestamp: String(value.timestamp),
    operation: value.operation,
    level: value.level,
    correlation_id: String(value.correlation_id),
    latency_ms: Number(value.latency_ms),
    success: Boolean(value.success),
    user_context: value.user_context
      ? validateUserContext(value.user_context)
      : value.user_context || undefined,
    request_context: value.request_context
      ? validateRequestContext(value.request_context)
      : value.request_context || undefined,
    result_metrics: value.result_metrics || undefined,
    system_health: value.system_health || undefined,
    ttl_info: value.ttl_info || undefined,
    strategy: value.strategy || undefined,
    deduplication: value.deduplication || undefined,
    error: value.error ? validateErrorInfo(value.error) : value.error || undefined,
    metadata: value.metadata
      ? validateOperationMetadata(value.metadata)
      : value.metadata || undefined,
  };
}

// ============================================================================
// Runtime Validation Utilities
// ============================================================================

/**
 * Safe type assertion with runtime check
 */
export function assertType<T>(
  value: unknown,
  guard: (value: unknown) => value is T,
  errorMessage?: string
): asserts value is T {
  if (!guard(value)) {
    throw new TypeError(
      errorMessage || `Type assertion failed: ${value} does not match expected type`
    );
  }
}

/**
 * Safe type coercion with fallback
 */
export function coerceType<T>(
  value: unknown,
  guard: (value: unknown) => value is T,
  fallback: T
): T {
  return guard(value) ? value : fallback;
}

/**
 * Validate array of items
 */
export function validateArray<T>(items: unknown[], guard: (value: unknown) => value is T): T[] {
  return items.filter(guard);
}

/**
 * Validate record with typed values
 */
export function validateRecord<T extends Record<string, unknown>>(
  record: unknown,
  valueGuard: (value: unknown) => value is T[keyof T]
): record is T {
  if (!isLoggableData(record)) return false;

  return Object.entries(record).every(([, value]) => valueGuard(value));
}

// ============================================================================
// Schema Validation for External Input
// ============================================================================

/**
 * Validate external log input (e.g., from API or external system)
 */
export function validateExternalLogInput(input: unknown): StructuredLogEntry | null {
  try {
    // First, ensure it's an object
    if (!isLoggableData(input)) return null;

    // Validate required fields
    const entry = input as Record<string, unknown>;

    if (!entry.operation || !isOperationType(entry.operation)) {
      return null;
    }

    if (!entry.level || !isLogLevel(entry.level)) {
      return null;
    }

    if (!entry.correlation_id || typeof entry.correlation_id !== 'string') {
      return null;
    }

    // Validate and sanitize the entry
    return validateStructuredLogEntry(entry);
  } catch {
    return null;
  }
}

/**
 * Validate performance metric input
 */
export function validatePerformanceMetricInput(input: unknown): TypedPerformanceMetric | null {
  try {
    if (!isTypedPerformanceMetric(input)) return null;

    // Ensure timestamps are valid
    const metric = input as TypedPerformanceMetric;
    const now = Date.now();

    if (metric.startTime > now || metric.endTime > now) {
      return null; // Future timestamps are invalid
    }

    if (metric.startTime > metric.endTime) {
      return null; // Start must be before end
    }

    return input as TypedPerformanceMetric;
  } catch {
    return null;
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Create a type-safe log entry from partial data
 */
export function createLogEntry(partial: Partial<StructuredLogEntry>): StructuredLogEntry | null {
  const entry = {
    timestamp: partial.timestamp || new Date().toISOString(),
    operation: partial.operation || OperationType.SYSTEM,
    level: partial.level || 'info',
    correlation_id: partial.correlation_id || `unknown_${Date.now()}`,
    latency_ms: partial.latency_ms || 0,
    success: partial.success ?? true,
    user_context: partial.user_context,
    request_context: partial.request_context,
    result_metrics: partial.result_metrics,
    system_health: partial.system_health,
    ttl_info: partial.ttl_info,
    strategy: partial.strategy,
    deduplication: partial.deduplication,
    error: partial.error,
    metadata: partial.metadata,
  };

  return validateStructuredLogEntry(entry);
}

/**
 * Check if a log entry represents an error
 */
export function isErrorLogEntry(entry: StructuredLogEntry): boolean {
  return entry.level === 'error' || entry.success === false || !!entry.error;
}

/**
 * Check if a log entry represents a slow operation
 */
export function isSlowLogEntry(entry: StructuredLogEntry, thresholdMs: number = 1000): boolean {
  return entry.latency_ms > thresholdMs;
}

/**
 * Get severity level from log entry
 */
export function getLogEntrySeverity(
  entry: StructuredLogEntry
): 'low' | 'medium' | 'high' | 'critical' {
  if (entry.level === 'error' && entry.error) {
    return 'critical';
  }

  if (entry.latency_ms > 5000) {
    return 'high';
  }

  if (entry.latency_ms > 2000) {
    return 'medium';
  }

  return 'low';
}
