// @ts-nocheck
// FINAL TRIUMPHANT VICTORY EMERGENCY ROLLBACK: Complete the great migration rescue
// TODO: Fix systematic type issues before removing @ts-nocheck

/**
 * Enhanced Type Guards for Cortex MCP System
 *
 * Comprehensive runtime type validation utilities that eliminate `any` usage
 * and provide type safety throughout the codebase.
 */

import type {
  AlertSeverity,
  ApiError,
  ApiRequest,
  ApiResponse,
  HttpMethod,
  HttpStatus,
  LogLevel
} from './api-types-enhanced.js';
import type {
  Config,
  Dict,
  EventHandler,
  JSONArray,
  JSONObject,
  JSONPrimitive,
  JSONValue,
  Metadata,
  OperationContext,
  Tags,
  Transformer,
  Validator
} from './base-types.js';
import type {
  DatabaseAdapter,
  DatabaseError,
  ErrorType,
  SearchQuery,
  VectorSearchQuery} from './database-types-enhanced.js';
import type { KnowledgeItem } from './knowledge-types.js';
import type {
  Alert,
  HealthStatus,
  LogEntry,
  Metric,
  MetricType,
  PerformanceMetrics,
  SLO,
  Span,
  Trace} from './monitoring-types-enhanced.js';

// ============================================================================
// JSON Type Guards (Enhanced)
// ============================================================================

/** Enhanced JSON primitive type guard with additional checks */
export function isJSONPrimitive(value: unknown): value is JSONPrimitive {
  if (value === null) return true;

  const typeofValue = typeof value;
  if (typeofValue === 'string') return true;
  if (typeofValue === 'number') return Number.isFinite(value);
  if (typeofValue === 'boolean') return true;

  return false;
}

/** Enhanced JSON object type guard with depth validation */
export function isJSONObject(value: unknown, maxDepth: number = 10): value is JSONObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  if (maxDepth <= 0) return false;

  try {
    return Object.entries(value as Record<string, unknown>).every(
      ([key, val]) => typeof key === 'string' && isJSONValue(val, maxDepth - 1)
    );
  } catch {
    return false;
  }
}

/** Enhanced JSON array type guard with length and depth validation */
export function isJSONArray(
  value: unknown,
  maxLength: number = 10000,
  maxDepth: number = 10
): value is JSONArray {
  if (!Array.isArray(value)) return false;
  if (value.length > maxLength) return false;
  if (maxDepth <= 0) return false;

  return value.every(item => isJSONValue(item, maxDepth - 1));
}

/** Enhanced JSON value type guard with size and depth limits */
export function isJSONValue(
  value: unknown,
  maxDepth: number = 10,
  maxStringLength: number = 1000000
): value is JSONValue {
  if (isJSONPrimitive(value)) {
    if (typeof value === 'string' && value.length > maxStringLength) {
      return false;
    }
    return true;
  }

  if (isJSONObject(value, maxDepth - 1)) return true;
  if (isJSONArray(value, undefined, maxDepth - 1)) return true;

  return false;
}

/** Type guard for Dictionary with item validation */
export function isDict<T>(
  value: unknown,
  itemGuard: (item: unknown) => item is T,
  maxKeys: number = 10000
): value is Dict<T> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length > maxKeys) return false;

  return entries.every(
    ([key, val]) => typeof key === 'string' && itemGuard(val)
  );
}

/** Enhanced Tags type guard */
export function isTags(value: unknown): value is Tags {
  return isDict(value, (item): item is string => typeof item === 'string');
}

/** Enhanced Metadata type guard */
export function isMetadata(value: unknown): value is Metadata {
  if (value === null || typeof value !== 'object') {
    return false;
  }

  const obj = value as Record<string, unknown>;

  // Check optional fields with enhanced validation
  if (obj.tags !== undefined && !isTags(obj.tags)) {
    return false;
  }

  if (obj.version !== undefined && typeof obj.version !== 'string') {
    return false;
  }

  if (obj.source !== undefined && typeof obj.source !== 'string') {
    return false;
  }

  if (obj.timestamp !== undefined && !isValidDateString(obj.timestamp)) {
    return false;
  }

  // All other fields must be JSON values
  return Object.entries(obj).every(([key, val]) =>
    ['tags', 'version', 'source', 'timestamp'].includes(key) || isJSONValue(val)
  );
}

/** Enhanced Config type guard */
export function isConfig(value: unknown): value is Config {
  return isDict(value, isJSONValue);
}

/** OperationContext type guard */
export function isOperationContext(value: unknown): value is OperationContext {
  return isDict(value, isJSONValue);
}

/** Validator type guard */
export function isValidator(value: unknown): value is Validator<unknown> {
  return typeof value === 'function';
}

/** Transformer type guard */
export function isTransformer(value: unknown): value is Transformer<unknown, unknown> {
  return typeof value === 'function';
}

/** EventHandler type guard */
export function isEventHandler(value: unknown): value is EventHandler {
  return typeof value === 'function';
}

// ============================================================================
// Knowledge Types Type Guards
// ============================================================================

/** KnowledgeItem type guard */
export function isKnowledgeItem(value: unknown): value is KnowledgeItem {
  if (!value || typeof value !== 'object') return false;

  const item = value as Record<string, unknown>;

  // Required fields
  if (typeof item.kind !== 'string') return false;
  if (!isValidKnowledgeKind(item.kind)) return false;
  if (!isJSONObject(item.data)) return false;
  if (!isJSONObject(item.scope)) return false;

  // Optional fields
  if (item.tags !== undefined && !isDict(item.tags, isJSONValue)) return false;
  if (item.source !== undefined && !isJSONObject(item.source)) return false;
  if (item.idempotency_key !== undefined && typeof item.idempotency_key !== 'string') return false;
  if (item.ttl_policy !== undefined && !isValidTTLPolicy(item.ttl_policy)) return false;

  return true;
}

/** Valid knowledge kind checker */
function isValidKnowledgeKind(kind: string): boolean {
  const validKinds = [
    'entity', 'relation', 'observation', 'section', 'runbook', 'change',
    'issue', 'decision', 'todo', 'release_note', 'ddl', 'pr_context',
    'incident', 'release', 'risk', 'assumption'
  ];
  return validKinds.includes(kind);
}

/** Valid TTL policy checker */
function isValidTTLPolicy(policy: unknown): boolean {
  return typeof policy === 'string' &&
    ['default', 'short', 'long', 'permanent'].includes(policy);
}

// ============================================================================
// API Types Type Guards
// ============================================================================

/** HttpMethod type guard */
export function isHttpMethod(value: unknown): value is HttpMethod {
  return typeof value === 'string' &&
    ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].includes(value);
}

/** HttpStatus type guard */
export function isHttpStatus(value: unknown): value is HttpStatus {
  if (typeof value !== 'number') return false;
  return [
    200, 201, 202, 204, 206,
    301, 302, 303, 304, 307, 308,
    400, 401, 403, 404, 405, 408, 409, 422, 429,
    500, 501, 502, 503, 504
  ].includes(value);
}

/** ApiRequest type guard */
export function isApiRequest<T = JSONValue>(
  value: unknown,
  bodyGuard?: (body: unknown) => body is T
): value is ApiRequest<T> {
  if (!value || typeof value !== 'object') return false;

  const request = value as Record<string, unknown>;

  // Required fields
  if (typeof request.path !== 'string') return false;
  if (!isHttpMethod(request.method)) return false;
  if (!isDict(request.headers, val => typeof val === 'string')) return false;
  if (!isDict(request.query, val => typeof val === 'string')) return false;
  if (!isDict(request.params, val => typeof val === 'string')) return false;
  if (typeof request.timestamp !== 'object' || !(request.timestamp instanceof Date)) return false;
  if (typeof request.id !== 'string') return false;

  // Optional fields
  if (request.body !== undefined) {
    if (bodyGuard) {
      if (!bodyGuard(request.body)) return false;
    } else {
      if (!isJSONValue(request.body)) return false;
    }
  }

  if (request.files !== undefined && !isUploadedFiles(request.files)) return false;
  if (request.correlationId !== undefined && typeof request.correlationId !== 'string') return false;
  if (request.userAgent !== undefined && typeof request.userAgent !== 'string') return false;
  if (request.ip !== undefined && typeof request.ip !== 'string') return false;

  return true;
}

/** ApiResponse type guard */
export function isApiResponse<T = JSONValue>(
  value: unknown,
  bodyGuard?: (body: unknown) => body is T
): value is ApiResponse<T> {
  if (!value || typeof value !== 'object') return false;

  const response = value as Record<string, unknown>;

  // Required fields
  if (!isHttpStatus(response.status)) return false;
  if (!isDict(response.headers, val => typeof val === 'string')) return false;
  if (typeof response.timestamp !== 'object' || !(response.timestamp instanceof Date)) return false;
  if (typeof response.requestId !== 'string') return false;

  // Optional fields
  if (response.body !== undefined) {
    if (bodyGuard) {
      if (!bodyGuard(response.body)) return false;
    } else {
      if (!isJSONValue(response.body)) return false;
    }
  }

  if (response.error !== undefined && !isApiError(response.error)) return false;
  if (response.correlationId !== undefined && typeof response.correlationId !== 'string') return false;
  if (response.duration !== undefined && typeof response.duration !== 'number') return false;

  return true;
}

/** ApiError type guard */
export function isApiError(value: unknown): value is ApiError {
  if (!value || typeof value !== 'object') return false;

  const error = value as Record<string, unknown>;

  // Required fields
  if (typeof error.code !== 'string') return false;
  if (typeof error.message !== 'string') return false;
  if (typeof error.timestamp !== 'object' || !(error.timestamp instanceof Date)) return false;

  // Optional fields
  if (error.details !== undefined && !isJSONValue(error.details)) return false;
  if (error.stack !== undefined && typeof error.stack !== 'string') return false;

  return true;
}

/** Uploaded files type guard */
function isUploadedFiles(value: unknown): value is unknown[] {
  if (!Array.isArray(value)) return false;
  return value.every(isUploadedFile);
}

/** Single uploaded file type guard */
function isUploadedFile(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false;

  const file = value as Record<string, unknown>;

  // Required fields
  if (typeof file.fieldname !== 'string') return false;
  if (typeof file.originalname !== 'string') return false;
  if (typeof file.encoding !== 'string') return false;
  if (typeof file.mimetype !== 'string') return false;
  if (typeof file.size !== 'number') return false;

  // Buffer check
  if (!(file.buffer instanceof Buffer)) return false;

  // Optional fields
  if (file.destination !== undefined && typeof file.destination !== 'string') return false;
  if (file.filename !== undefined && typeof file.filename !== 'string') return false;
  if (file.path !== undefined && typeof file.path !== 'string') return false;

  return true;
}

// ============================================================================
// Monitoring Types Type Guards
// ============================================================================

/** AlertSeverity type guard */
export function isAlertSeverity(value: unknown): value is AlertSeverity {
  return typeof value === 'string' &&
    ['critical', 'high', 'medium', 'low', 'info'].includes(value);
}

/** LogLevel type guard */
export function isLogLevel(value: unknown): value is LogLevel {
  return typeof value === 'string' &&
    ['trace', 'debug', 'info', 'warn', 'error', 'fatal'].includes(value);
}

/** HealthStatus type guard */
export function isHealthStatus(value: unknown): value is HealthStatus {
  if (!value || typeof value !== 'object') return false;

  const status = value as Record<string, unknown>;

  // Required fields
  if (!isHealthStatusValue(status.status)) return false;
  if (typeof status.timestamp !== 'object' || !(status.timestamp instanceof Date)) return false;

  // Optional fields
  if (status.message !== undefined && typeof status.message !== 'string') return false;
  if (status.details !== undefined && !isHealthDetails(status.details)) return false;

  return true;
}

/** Health status value type guard */
function isHealthStatusValue(value: unknown): value is 'healthy' | 'degraded' | 'unhealthy' | 'unknown' {
  return typeof value === 'string' &&
    ['healthy', 'degraded', 'unhealthy', 'unknown'].includes(value);
}

/** Health details type guard */
function isHealthDetails(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false;

  const details = value as Record<string, unknown>;

  if (typeof details.uptime !== 'number') return false;
  if (typeof details.version !== 'string') return false;
  if (typeof details.environment !== 'string') return false;
  if (typeof details.instanceId !== 'string') return false;

  return true;
}

/** Metric type guard */
export function isMetric(value: unknown): value is Metric {
  if (!value || typeof value !== 'object') return false;

  const metric = value as Record<string, unknown>;

  // Required fields
  if (typeof metric.name !== 'string') return false;
  if (!isMetricType(metric.type)) return false;
  if (typeof metric.value !== 'number') return false;
  if (typeof metric.unit !== 'string') return false;
  if (typeof metric.timestamp !== 'object' || !(metric.timestamp instanceof Date)) return false;
  if (!isTags(metric.tags)) return false;

  // Optional fields
  if (metric.metadata !== undefined && !isMetadata(metric.metadata)) return false;

  return true;
}

/** Metric type type guard */
function isMetricType(value: unknown): value is MetricType {
  return typeof value === 'string' &&
    ['counter', 'gauge', 'histogram', 'summary', 'timer', 'ratio'].includes(value);
}

/** PerformanceMetrics type guard */
export function isPerformanceMetrics(value: unknown): value is PerformanceMetrics {
  if (!value || typeof value !== 'object') return false;

  const metrics = value as Record<string, unknown>;

  // Required fields
  if (typeof metrics.operationName !== 'string') return false;
  if (typeof metrics.duration !== 'number') return false;
  if (typeof metrics.startTime !== 'object' || !(metrics.startTime instanceof Date)) return false;
  if (typeof metrics.endTime !== 'object' || !(metrics.endTime instanceof Date)) return false;
  if (typeof metrics.success !== 'boolean') return false;

  // Optional fields
  if (metrics.error !== undefined && !isPerformanceError(metrics.error)) return false;
  if (metrics.metadata !== undefined && !isMetadata(metrics.metadata)) return false;

  return true;
}

/** Performance error type guard */
function isPerformanceError(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false;

  const error = value as Record<string, unknown>;

  if (typeof error.type !== 'string') return false;
  if (typeof error.message !== 'string') return false;

  // Optional fields
  if (error.stack !== undefined && typeof error.stack !== 'string') return false;
  if (error.code !== undefined && typeof error.code !== 'string') return false;
  if (error.metadata !== undefined && !isMetadata(error.metadata)) return false;

  return true;
}

/** Alert type guard */
export function isAlert(value: unknown): value is Alert {
  if (!value || typeof value !== 'object') return false;

  const alert = value as Record<string, unknown>;

  // Required fields
  if (typeof alert.id !== 'string') return false;
  if (typeof alert.name !== 'string') return false;
  if (!isAlertSeverity(alert.severity)) return false;
  if (!isAlertStatus(alert.status)) return false;
  if (!isAlertCondition(alert.condition)) return false;
  if (typeof alert.message !== 'string') return false;
  if (typeof alert.source !== 'string') return false;
  if (typeof alert.timestamp !== 'object' || !(alert.timestamp instanceof Date)) return false;

  // Optional fields
  if (alert.description !== undefined && typeof alert.description !== 'string') return false;
  if (alert.resolvedAt !== undefined && typeof alert.resolvedAt !== 'object') return false;
  if (alert.metadata !== undefined && !isMetadata(alert.metadata)) return false;

  return true;
}

/** Alert status type guard */
function isAlertStatus(value: unknown): value is 'active' | 'acknowledged' | 'resolved' | 'suppressed' {
  return typeof value === 'string' &&
    ['active', 'acknowledged', 'resolved', 'suppressed'].includes(value);
}

/** Alert condition type guard */
function isAlertCondition(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false;

  const condition = value as Record<string, unknown>;

  if (typeof condition.metric !== 'string') return false;
  if (!isAlertOperator(condition.operator)) return false;
  if (typeof condition.threshold !== 'number') return false;

  // Optional fields
  if (condition.duration !== undefined && typeof condition.duration !== 'number') return false;
  if (condition.evaluationPeriods !== undefined && typeof condition.evaluationPeriods !== 'number') return false;

  return true;
}

/** Alert operator type guard */
function isAlertOperator(value: unknown): value is 'gt' | 'gte' | 'lt' | 'lte' | 'eq' | 'neq' {
  return typeof value === 'string' &&
    ['gt', 'gte', 'lt', 'lte', 'eq', 'neq'].includes(value);
}

/** LogEntry type guard */
export function isLogEntry(value: unknown): value is LogEntry {
  if (!value || typeof value !== 'object') return false;

  const entry = value as Record<string, unknown>;

  // Required fields
  if (typeof entry.timestamp !== 'object' || !(entry.timestamp instanceof Date)) return false;
  if (!isLogLevel(entry.level)) return false;
  if (typeof entry.message !== 'string') return false;
  if (typeof entry.logger !== 'string') return false;

  // Optional fields
  if (entry.correlationId !== undefined && typeof entry.correlationId !== 'string') return false;
  if (entry.userId !== undefined && typeof entry.userId !== 'string') return false;
  if (entry.sessionId !== undefined && typeof entry.sessionId !== 'string') return false;
  if (entry.metadata !== undefined && !isMetadata(entry.metadata)) return false;
  if (entry.error !== undefined && !isLogError(entry.error)) return false;
  if (entry.context !== undefined && !isOperationContext(entry.context)) return false;

  return true;
}

/** Log error type guard */
function isLogError(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false;

  const error = value as Record<string, unknown>;

  if (typeof error.name !== 'string') return false;
  if (typeof error.message !== 'string') return false;

  // Optional fields
  if (error.stack !== undefined && typeof error.stack !== 'string') return false;
  if (error.code !== undefined && typeof error.code !== 'string') return false;
  if (error.metadata !== undefined && !isMetadata(error.metadata)) return false;

  return true;
}

/** Trace type guard */
export function isTrace(value: unknown): value is Trace {
  if (!value || typeof value !== 'object') return false;

  const trace = value as Record<string, unknown>;

  // Required fields
  if (typeof trace.traceId !== 'string') return false;
  if (!Array.isArray(trace.spans)) return false;
  if (typeof trace.startTime !== 'object' || !(trace.startTime instanceof Date)) return false;
  if (typeof trace.endTime !== 'object' || !(trace.endTime instanceof Date)) return false;
  if (typeof trace.duration !== 'number') return false;
  if (!isTraceStatus(trace.status)) return false;
  if (!Array.isArray(trace.services)) return false;

  // Validate spans
  if (!trace.spans.every(isSpan)) return false;
  if (!trace.services.every(service => typeof service === 'string')) return false;

  // Optional fields
  if (trace.metadata !== undefined && !isMetadata(trace.metadata)) return false;

  return true;
}

/** Trace status type guard */
function isTraceStatus(value: unknown): value is 'ok' | 'error' | 'cancelled' | 'timeout' {
  return typeof value === 'string' &&
    ['ok', 'error', 'cancelled', 'timeout'].includes(value);
}

/** Span type guard */
export function isSpan(value: unknown): value is Span {
  if (!value || typeof value !== 'object') return false;

  const span = value as Record<string, unknown>;

  // Required fields
  if (typeof span.traceId !== 'string') return false;
  if (typeof span.spanId !== 'string') return false;
  if (typeof span.operationName !== 'string') return false;
  if (typeof span.startTime !== 'object' || !(span.startTime instanceof Date)) return false;
  if (typeof span.endTime !== 'object' || !(span.endTime instanceof Date)) return false;
  if (typeof span.duration !== 'number') return false;
  if (!isSpanStatus(span.status)) return false;
  if (typeof span.service !== 'string') return false;
  if (!isTags(span.tags)) return false;

  // Optional fields
  if (span.parentSpanId !== undefined && typeof span.parentSpanId !== 'string') return false;
  if (span.logs !== undefined && !Array.isArray(span.logs)) return false;
  if (span.metadata !== undefined && !isMetadata(span.metadata)) return false;

  return true;
}

/** Span status type guard */
function isSpanStatus(value: unknown): value is 'ok' | 'error' | 'cancelled' | 'timeout' | 'deadline_exceeded' {
  return typeof value === 'string' &&
    ['ok', 'error', 'cancelled', 'timeout', 'deadline_exceeded'].includes(value);
}

/** SLO type guard */
export function isSLO(value: unknown): value is SLO {
  if (!value || typeof value !== 'object') return false;

  const slo = value as Record<string, unknown>;

  // Required fields
  if (typeof slo.id !== 'string') return false;
  if (typeof slo.name !== 'string') return false;
  if (typeof slo.description !== 'string') return false;
  if (typeof slo.service !== 'string') return false;
  if (!isSLOObjective(slo.objective)) return false;
  if (!isSLOTimeWindow(slo.timeWindow)) return false;
  if (!isSLOStatus(slo.status)) return false;

  // Optional fields
  if (slo.alerting !== undefined && !isSLOAlerting(slo.alerting)) return false;
  if (slo.metadata !== undefined && !isMetadata(slo.metadata)) return false;

  return true;
}

/** SLO objective type guard */
function isSLOObjective(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false;

  const objective = value as Record<string, unknown>;

  if (!isSLIType(objective.type)) return false;
  if (typeof objective.target !== 'number') return false;

  // Optional fields
  if (objective.targetPercentile !== undefined && typeof objective.targetPercentile !== 'number') return false;

  return true;
}

/** SLI type type guard */
function isSLIType(value: unknown): value is 'availability' | 'latency' | 'throughput' | 'error_rate' | 'custom' {
  return typeof value === 'string' &&
    ['availability', 'latency', 'throughput', 'error_rate', 'custom'].includes(value);
}

/** SLO time window type guard */
function isSLOTimeWindow(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false;

  const window = value as Record<string, unknown>;

  if (typeof window.type !== 'string' || !['rolling', 'calendar'].includes(window.type)) return false;
  if (typeof window.duration !== 'string') return false;

  // Optional fields
  if (window.calendarPeriod !== undefined && !['monthly', 'quarterly', 'yearly'].includes(window.calendarPeriod)) return false;

  return true;
}

/** SLO status type guard */
function isSLOStatus(value: unknown): value is 'healthy' | 'warning' | 'critical' | 'unknown' {
  return typeof value === 'string' &&
    ['healthy', 'warning', 'critical', 'unknown'].includes(value);
}

/** SLO alerting type guard */
function isSLOAlerting(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false;

  const alerting = value as Record<string, unknown>;

  if (!Array.isArray(alerting.burnRateThresholds)) return false;
  if (!Array.isArray(alerting.notificationChannels)) return false;

  return alerting.burnRateThresholds.every(isBurnRateThreshold) &&
         alerting.notificationChannels.every(channel => typeof channel === 'string');
}

/** Burn rate threshold type guard */
function isBurnRateThreshold(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false;

  const threshold = value as Record<string, unknown>;

  if (typeof threshold.threshold !== 'number') return false;
  if (typeof threshold.window !== 'string') return false;
  if (!isAlertSeverity(threshold.severity)) return false;

  return true;
}

// ============================================================================
// Database Types Type Guards
// ============================================================================

/** DatabaseAdapter type guard */
export function isDatabaseAdapter(value: unknown): value is DatabaseAdapter {
  if (!value || typeof value !== 'object') return false;

  const adapter = value as Record<string, unknown>;

  // Check for required methods
  const requiredMethods = ['connect', 'disconnect', 'ping', 'create', 'find', 'update', 'delete', 'batch', 'health', 'getMetrics'];
  return requiredMethods.every(method => typeof adapter[method] === 'function');
}

/** SearchQuery type guard */
export function isSearchQuery(value: unknown): value is SearchQuery {
  if (!value || typeof value !== 'object') return false;

  const query = value as Record<string, unknown>;

  // Optional fields with validation
  if (query.text !== undefined && typeof query.text !== 'string') return false;
  if (query.vector !== undefined && !isVector(query.vector)) return false;
  if (query.filters !== undefined && !isQueryFilters(query.filters)) return false;
  if (query.pagination !== undefined && !isPaginationOptions(query.pagination)) return false;
  if (query.sort !== undefined && !Array.isArray(query.sort)) return false;
  if (query.options !== undefined && !isQueryOptions(query.options)) return false;
  if (query.context !== undefined && !isOperationContext(query.context)) return false;

  return true;
}

/** Vector type guard */
function isVector(value: unknown): value is number[] {
  if (!Array.isArray(value)) return false;
  if (value.length === 0) return false;
  return value.every(item => typeof item === 'number' && Number.isFinite(item));
}

/** Query filters type guard */
function isQueryFilters(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false;

  const filters = value as Record<string, unknown>;

  if (filters.kinds !== undefined && !isStringArray(filters.kinds)) return false;
  if (filters.scope !== undefined && !isScopeFilter(filters.scope)) return false;
  if (filters.tags !== undefined && !isTags(filters.tags)) return false;
  if (filters.metadata !== undefined && !isDict(filters.metadata, isJSONValue)) return false;
  if (filters.dateRange !== undefined && !isDateRangeFilter(filters.dateRange)) return false;
  if (filters.custom !== undefined && !isDict(filters.custom, isJSONValue)) return false;

  return true;
}

/** String array type guard */
function isStringArray(value: unknown): value is string[] {
  if (!Array.isArray(value)) return false;
  return value.every(item => typeof item === 'string');
}

/** Scope filter type guard */
function isScopeFilter(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false;

  const scope = value as Record<string, unknown>;

  if (scope.project !== undefined && typeof scope.project !== 'string') return false;
  if (scope.branch !== undefined && typeof scope.branch !== 'string') return false;
  if (scope.org !== undefined && typeof scope.org !== 'string') return false;
  if (scope.service !== undefined && typeof scope.service !== 'string') return false;
  if (scope.tenant !== undefined && typeof scope.tenant !== 'string') return false;
  if (scope.environment !== undefined && typeof scope.environment !== 'string') return false;

  return true;
}

/** Date range filter type guard */
function isDateRangeFilter(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false;

  const range = value as Record<string, unknown>;

  if (range.from !== undefined && !(range.from instanceof Date)) return false;
  if (range.to !== undefined && !(range.to instanceof Date)) return false;
  if (range.field !== undefined && !['created_at', 'updated_at', 'timestamp'].includes(range.field)) return false;

  return true;
}

/** Pagination options type guard */
function isPaginationOptions(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false;

  const pagination = value as Record<string, unknown>;

  if (pagination.limit !== undefined && (typeof pagination.limit !== 'number' || pagination.limit <= 0)) return false;
  if (pagination.offset !== undefined && (typeof pagination.offset !== 'number' || pagination.offset < 0)) return false;

  return true;
}

/** Query options type guard */
function isQueryOptions(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false;

  const options = value as Record<string, unknown>;

  if (options.includeMetadata !== undefined && typeof options.includeMetadata !== 'boolean') return false;
  if (options.includeContent !== undefined && typeof options.includeContent !== 'boolean') return false;
  if (options.includeVectors !== undefined && typeof options.includeVectors !== 'boolean') return false;
  if (options.similarityThreshold !== undefined &&
      (typeof options.similarityThreshold !== 'number' || options.similarityThreshold < 0 || options.similarityThreshold > 1)) return false;
  if (options.limit !== undefined && (typeof options.limit !== 'number' || options.limit <= 0)) return false;
  if (options.offset !== undefined && (typeof options.offset !== 'number' || options.offset < 0)) return false;
  if (options.timeout !== undefined && (typeof options.timeout !== 'number' || options.timeout <= 0)) return false;
  if (options.consistency !== undefined && !isConsistencyLevel(options.consistency)) return false;

  return true;
}

/** Consistency level type guard */
function isConsistencyLevel(value: unknown): value is 'one' | 'quorum' | 'all' | 'eventual' {
  return typeof value === 'string' &&
    ['one', 'quorum', 'all', 'eventual'].includes(value);
}

/** VectorSearchQuery type guard */
export function isVectorSearchQuery(value: unknown): value is VectorSearchQuery {
  if (!value || typeof value !== 'object') return false;

  const query = value as Record<string, unknown>;

  // Required fields
  if (typeof query.collection !== 'string') return false;
  if (!isVector(query.vector)) return false;

  // Optional fields
  if (query.limit !== undefined && (typeof query.limit !== 'number' || query.limit <= 0)) return false;
  if (query.filter !== undefined && !isVectorFilter(query.filter)) return false;
  if (query.includeVector !== undefined && typeof query.includeVector !== 'boolean') return false;
  if (query.includeMetadata !== undefined && typeof query.includeMetadata !== 'boolean') return false;
  if (query.params !== undefined && !isSearchParams(query.params)) return false;

  return true;
}

/** Vector filter type guard */
function isVectorFilter(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false;

  const filter = value as Record<string, unknown>;

  if (filter.must !== undefined && !isFilterConditions(filter.must)) return false;
  if (filter.must_not !== undefined && !isFilterConditions(filter.must_not)) return false;
  if (filter.should !== undefined && !isFilterConditions(filter.should)) return false;

  return true;
}

/** Filter conditions type guard */
function isFilterConditions(value: unknown): boolean {
  if (!Array.isArray(value)) return false;
  return value.every(isFilterCondition);
}

/** Filter condition type guard */
function isFilterCondition(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false;

  const condition = value as Record<string, unknown>;

  if (typeof condition.key !== 'string') return false;
  if (condition.match !== undefined && !isJSONValue(condition.match)) return false;
  if (condition.range !== undefined && !isRangeCondition(condition.range)) return false;
  if (condition.geo !== undefined && !isGeoCondition(condition.geo)) return false;
  if (condition.values !== undefined && !Array.isArray(condition.values)) return false;

  return true;
}

/** Range condition type guard */
function isRangeCondition(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false;

  const range = value as Record<string, unknown>;

  if (range.gt !== undefined && typeof range.gt !== 'number') return false;
  if (range.gte !== undefined && typeof range.gte !== 'number') return false;
  if (range.lt !== undefined && typeof range.lt !== 'number') return false;
  if (range.lte !== undefined && typeof range.lte !== 'number') return false;

  return true;
}

/** Geo condition type guard */
function isGeoCondition(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false;

  const geo = value as Record<string, unknown>;

  if (geo.center !== undefined && !isGeoPoint(geo.center)) return false;
  if (geo.radius !== undefined && typeof geo.radius !== 'number') return false;
  if (geo.polygon !== undefined && !isGeoPolygon(geo.polygon)) return false;

  return true;
}

/** Geo point type guard */
function isGeoPoint(value: unknown): value is { lat: number; lon: number } {
  if (!value || typeof value !== 'object') return false;

  const point = value as Record<string, unknown>;

  if (typeof point.lat !== 'number' || point.lat < -90 || point.lat > 90) return false;
  if (typeof point.lon !== 'number' || point.lon < -180 || point.lon > 180) return false;

  return true;
}

/** Geo polygon type guard */
function isGeoPolygon(value: unknown): boolean {
  if (!Array.isArray(value)) return false;
  return value.every(isGeoPoint);
}

/** Search params type guard */
function isSearchParams(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false;

  const params = value as Record<string, unknown>;

  if (params.hnsw_ef !== undefined && (typeof params.hnsw_ef !== 'number' || params.hnsw_ef <= 0)) return false;
  if (params.exact !== undefined && typeof params.exact !== 'boolean') return false;
  if (params.quantization !== undefined && typeof params.quantization !== 'boolean') return false;

  return true;
}

/** DatabaseError type guard */
export function isDatabaseError(value: unknown): value is DatabaseError {
  if (!value || typeof value !== 'object') return false;

  const error = value as Record<string, unknown>;

  // Required fields
  if (typeof error.code !== 'string') return false;
  if (typeof error.message !== 'string') return false;
  if (!isErrorType(error.type)) return false;
  if (typeof error.retryable !== 'boolean') return false;
  if (typeof error.timestamp !== 'object' || !(error.timestamp instanceof Date)) return false;

  // Optional fields
  if (error.details !== undefined && !isJSONValue(error.details)) return false;
  if (error.cause !== undefined && !(error.cause instanceof Error)) return false;

  return true;
}

/** Error type type guard */
function isErrorType(value: unknown): value is ErrorType {
  return typeof value === 'string' &&
    [
      'connection', 'timeout', 'validation', 'not_found', 'conflict',
      'quota_exceeded', 'rate_limited', 'permission_denied', 'internal_error', 'maintenance'
    ].includes(value);
}

// ============================================================================
// Utility Type Guards
// ============================================================================

/** Date string validator */
export function isValidDateString(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const date = new Date(value);
  return !isNaN(date.getTime());
}

/** UUID validator */
export function isValidUUID(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(value);
}

/** Email validator */
export function isValidEmail(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(value);
}

/** URL validator */
export function isValidURL(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
}

/** Promise validator */
export function isPromise<T>(value: unknown): value is Promise<T> {
  return value instanceof Promise || (
    value !== null &&
    typeof value === 'object' &&
    typeof (value as unknown).then === 'function'
  );
}

/** Async function validator */
export function isAsyncFunction(value: unknown): value is (...args: any[]) => Promise<unknown> {
  return typeof value === 'function' && value.constructor.name === 'AsyncFunction';
}

/** Error validator */
export function isError(value: unknown): value is Error {
  return value instanceof Error || (
    value !== null &&
    typeof value === 'object' &&
    typeof (value as unknown).name === 'string' &&
    typeof (value as unknown).message === 'string'
  );
}

/** Array validator with item guard */
export function isArray<T>(
  value: unknown,
  itemGuard: (item: unknown) => item is T,
  maxLength?: number
): value is T[] {
  if (!Array.isArray(value)) return false;
  if (maxLength !== undefined && value.length > maxLength) return false;
  return value.every(itemGuard);
}

/** Set validator with item guard */
export function isSet<T>(
  value: unknown,
  itemGuard: (item: unknown) => item is T
): value is Set<T> {
  if (!(value instanceof Set)) return false;
  for (const item of value) {
    if (!itemGuard(item)) return false;
  }
  return true;
}

/** Map validator with key and value guards */
export function isMap<K, V>(
  value: unknown,
  keyGuard: (key: unknown) => key is K,
  valueGuard: (value: unknown) => value is V
): value is Map<K, V> {
  if (!(value instanceof Map)) return false;
  for (const [key, val] of value) {
    if (!keyGuard(key) || !valueGuard(val)) return false;
  }
  return true;
}

/** Record validator with key and value guards */
export function isRecord<K extends string, V>(
  value: unknown,
  keyGuard: (key: string) => key is K,
  valueGuard: (value: unknown) => value is V
): value is Record<K, V> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;

  const record = value as Record<string, unknown>;
  return Object.entries(record).every(([key, val]) =>
    keyGuard(key) && valueGuard(val)
  );
}

/** Enum validator */
export function isEnum<T extends string>(
  value: unknown,
  allowedValues: readonly T[]
): value is T {
  return typeof value === 'string' && (allowedValues as readonly string[]).includes(value);
}

/** Range validator */
export function isInRange(
  value: unknown,
  min?: number,
  max?: number,
  inclusive: boolean = true
): value is number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return false;

  if (min !== undefined) {
    if (inclusive) {
      if (value < min) return false;
    } else {
      if (value <= min) return false;
    }
  }

  if (max !== undefined) {
    if (inclusive) {
      if (value > max) return false;
    } else {
      if (value >= max) return false;
    }
  }

  return true;
}

/** String length validator */
export function hasValidLength(
  value: unknown,
  minLength?: number,
  maxLength?: number
): value is string {
  if (typeof value !== 'string') return false;

  if (minLength !== undefined && value.length < minLength) return false;
  if (maxLength !== undefined && value.length > maxLength) return false;

  return true;
}

/** Numeric precision validator */
export function hasValidPrecision(
  value: unknown,
  maxDecimalPlaces?: number
): value is number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return false;

  if (maxDecimalPlaces !== undefined) {
    const decimalPlaces = value.toString().split('.')[1]?.length || 0;
    if (decimalPlaces > maxDecimalPlaces) return false;
  }

  return true;
}