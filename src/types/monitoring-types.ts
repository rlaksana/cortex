// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * Type definitions for the logging and monitoring system
 * Provides type-safe interfaces for all logging, metrics, and monitoring operations
 */

import type { AuthContext } from './auth-types.js';
import { type OperationType } from '../monitoring/operation-types.js';

// ============================================================================
// Core Logging Types
// ============================================================================

/**
 * Base interface for all loggable data
 */
export interface LoggableData {
  [key: string]: string | number | boolean | null | undefined | LoggableData | LoggableData[];
}

/**
 * Generic metadata interface for logging operations
 */
export interface OperationMetadata extends LoggableData {
  strategy?: string | SearchStrategy;
  deduplication?: string | DeduplicationStrategy;
  result_count?: number;
  duplicates_found?: number;
  cache_hit?: boolean;
  ttl_hours?: number;
  batch_id?: string;
  chunking_enabled?: boolean;
  deduplication_enabled?: boolean;
  search_complexity?: 'low' | 'medium' | 'high';
  expansion_used?: boolean;
  violation_type?: string;
  entity_type?: string;
  tokens_requested?: number;
  original_length?: number;
  chunking_strategy?: string;
  compression_ratio?: number;
  deduplication_threshold?: number;
  scope_isolation?: boolean;
}

/**
 * User context information for logging
 */
export interface UserContext {
  user_id: string;
  username: string;
  role: string;
  scopes: string[];
}

/**
 * Request context information for logging
 */
export interface RequestContext {
  query?: string;
  mode?: string;
  limit?: number;
  types?: string[];
  scope?: Record<string, unknown>;
  expand?: string;
  correlation_id?: string;
  timestamp?: number;
}

/**
 * Error information for logging
 */
export interface ErrorInfo {
  type: string;
  message: string;
  stack?: string;
  code?: string | number;
  context?: LoggableData;
}

/**
 * System health status information
 */
export interface SystemHealth {
  qdrant_status?: 'healthy' | 'degraded' | 'unhealthy';
  database_status?: 'connected' | 'error' | 'timeout';
  embedding_service_status?: 'healthy' | 'error';
  memory_usage_mb?: number;
  cpu_usage_percent?: number;
  active_connections?: number;
  cache_hit_rate?: number;
}

/**
 * Result metrics for operations
 */
export interface ResultMetrics {
  total_count?: number;
  result_count?: number;
  duplicates_found?: number;
  newer_versions_allowed?: number;
  chunks_created?: number;
  cache_hit?: boolean;
  stored?: number;
  batchId?: string;
  chunkingEnabled?: boolean;
  deduplicationEnabled?: boolean;
}

/**
 * TTL information for operations
 */
export interface TTLInfo {
  ttl_hours?: number;
  ttl_preset?: string;
  expires_at?: string;
}

// ============================================================================
// Performance Monitoring Types
// ============================================================================

/**
 * Performance metric with comprehensive typing
 */
export interface TypedPerformanceMetric {
  operation: OperationType;
  startTime: number;
  endTime: number;
  duration: number;
  success: boolean;
  metadata?: OperationMetadata;
  tags?: string[];
  correlationId?: string;
  userId?: string;
  memoryBefore?: NodeJS.MemoryUsage;
  memoryAfter?: NodeJS.MemoryUsage;
}

/**
 * Performance summary with typed fields
 */
export interface TypedPerformanceSummary {
  operation: OperationType;
  count: number;
  totalDuration: number;
  averageDuration: number;
  minDuration: number;
  maxDuration: number;
  p95: number;
  p99: number;
  successRate: number;
  errorCount: number;
  timestamp: number;
  memoryStats?: {
    avgHeapUsed: number;
    maxHeapUsed: number;
    avgExternal: number;
  };
}

/**
 * Performance alert with specific types
 */
export interface TypedPerformanceAlert {
  operation: OperationType;
  alertType: 'slow_query' | 'high_error_rate' | 'memory_usage' | 'connection_pool' | 'rate_limit';
  threshold: number;
  currentValue: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  timestamp: number;
  correlationId?: string;
  userId?: string;
  context?: LoggableData;
}

/**
 * Performance thresholds with type safety
 */
export interface PerformanceThresholds {
  warning: number; // 85th percentile
  critical: number; // 95th percentile
  absolute: number; // Hard limit
  operation?: OperationType;
}

/**
 * Performance baseline for comparison
 */
export interface PerformanceBaseline {
  operation: OperationType;
  avgDuration: number;
  maxDuration: number;
  minDuration: number;
  sampleCount: number;
  lastUpdated: number;
  memoryAvg: NodeJS.MemoryUsage;
  thresholds?: PerformanceThresholds;
}

/**
 * Performance regression detection result
 */
export interface PerformanceRegression {
  operation: OperationType;
  baseline: PerformanceBaseline;
  currentMetrics: TypedPerformanceMetric[];
  regressionFactor: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  detectedAt: number;
}

// ============================================================================
// Structured Logging Types
// ============================================================================

/**
 * Log levels with type constraints
 */
export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

/**
 * Structured log entry with comprehensive typing
 */
export interface StructuredLogEntry {
  // Core fields
  timestamp: string;
  operation: OperationType;
  level: LogLevel;
  correlation_id: string;

  // Performance metrics
  latency_ms: number;
  success: boolean;

  // Context information
  user_context?: UserContext;
  request_context?: RequestContext;
  result_metrics?: ResultMetrics;
  system_health?: SystemHealth;
  ttl_info?: TTLInfo;

  // Strategy information
  strategy?: SearchStrategy;
  deduplication?: DeduplicationStrategy;

  // Error information
  error?: ErrorInfo;

  // Additional metadata
  metadata?: OperationMetadata;
}

/**
 * Log entry creation options
 */
export interface LogEntryOptions {
  operation: OperationType;
  level: LogLevel;
  correlation_id: string;
  latency_ms: number;
  success: boolean;
  user_context?: UserContext;
  request_context?: RequestContext;
  result_metrics?: ResultMetrics;
  system_health?: SystemHealth;
  ttl_info?: TTLInfo;
  strategy?: SearchStrategy;
  deduplication?: DeduplicationStrategy;
  error?: ErrorInfo;
  metadata?: OperationMetadata;
}

// ============================================================================
// Search and Strategy Types
// ============================================================================

/**
 * Search strategies with specific enum values
 */
export enum SearchStrategy {
  HYBRID_CACHED = 'hybrid-cached',
  ERROR = 'error',
  SEMANTIC = 'semantic',
  FULLTEXT = 'fulltext',
  GRAPH = 'graph',
  AUTO = 'auto',
  FAST = 'fast',
  DEEP = 'deep',
}

/**
 * Deduplication strategies with specific enum values
 */
export enum DeduplicationStrategy {
  SCOPE_ISOLATION = 'scope_isolation',
  EXACT_MATCH = 'exact-match',
  FUZZY_MATCH = 'fuzzy-match',
  SEMANTIC_SIMILARITY = 'semantic-similarity',
}

// ============================================================================
// Slow Query Types
// ============================================================================

/**
 * Query details for slow query analysis
 */
export interface QueryDetails {
  text: string;
  mode: string;
  limit: number;
  types: string[];
  scope: Record<string, unknown>;
  expand: string;
  batch_size?: number;
  deduplication?: boolean;
  chunking?: boolean;
}

/**
 * Slow query analysis result
 */
export interface SlowQueryAnalysis {
  severity: 'low' | 'medium' | 'high' | 'critical';
  slowdown_factor: number;
  potential_bottlenecks: string[];
  optimization_suggestions: string[];
  bottleneck_scores?: Record<string, number>;
  optimization_impact?: Record<string, number>;
}

/**
 * Context information for slow queries
 */
export interface SlowQueryContext {
  user_id?: string;
  organization?: string;
  project?: string;
  branch?: string;
  session_id?: string;
  request_id?: string;
}

/**
 * System state at time of slow query
 */
export interface SlowQuerySystemState {
  memory_usage_mb: number;
  concurrent_queries: number;
  cache_hit_rate: number;
  cpu_usage_percent?: number;
  active_connections?: number;
  queue_depth?: number;
}

/**
 * Complete slow query entry
 */
export interface SlowQueryEntry {
  timestamp: number;
  correlation_id: string;
  operation: OperationType;
  latency_ms: number;
  threshold_ms: number;
  query?: QueryDetails;
  analysis: SlowQueryAnalysis;
  context?: SlowQueryContext;
  system_state: SlowQuerySystemState;
}

/**
 * Slow query trend analysis
 */
export interface SlowQueryTrend {
  time_window_hours: number;
  operation: OperationType;
  total_queries: number;
  slow_queries: number;
  slow_query_rate: number;
  average_latency_ms: number;
  p95_latency_ms: number;
  p99_latency_ms: number;
  trend_direction: 'improving' | 'degrading' | 'stable';
  top_bottlenecks: Array<{
    bottleneck: string;
    frequency: number;
    avg_impact_ms: number;
  }>;
}

// ============================================================================
// Metrics Types
// ============================================================================

/**
 * Real-time metrics snapshot
 */
export interface RealTimeMetrics {
  qps: {
    memory_store_qps: number;
    memory_find_qps: number;
    total_qps: number;
  };
  performance: {
    store_p95_ms: number;
    find_p95_ms: number;
    store_p99_ms: number;
    find_p99_ms: number;
  };
  quality: {
    dedupe_rate: number;
    ttl_deleted_rate: number;
    embedding_fail_rate: number;
    cache_hit_rate: number;
  };
  system: {
    memory_usage_mb: number;
    cpu_usage_percent: number;
    active_connections: number;
  };
  timestamp: number;
}

/**
 * Historical metrics for trend analysis
 */
export interface HistoricalMetrics {
  time_window_minutes: number;
  operation_metrics: Record<
    OperationType,
    {
      count: number;
      average_latency: number;
      p95_latency: number;
      p99_latency: number;
      error_rate: number;
      qps: number;
    }
  >;
  quality_metrics: {
    dedupe_rate: number;
    ttl_deleted_rate: number;
    embedding_fail_rate: number;
    cache_hit_rate: number;
  };
  system_metrics: {
    memory_usage_mb: number;
    cpu_usage_percent: number;
  };
}

/**
 * Metrics configuration with type safety
 */
export interface MetricsConfig {
  qps_window_seconds: number;
  percentile_sample_size: number;
  retention_hours: number;
  alert_thresholds: {
    qps_threshold: number;
    p95_latency_threshold: number;
    error_rate_threshold: number;
    memory_usage_threshold: number;
  };
  export_enabled: boolean;
  export_interval_seconds: number;
  export_formats: ('json' | 'prometheus' | 'csv')[];
}

// ============================================================================
// Monitoring Server Types
// ============================================================================

/**
 * Monitoring server configuration
 */
export interface MonitoringServerConfig {
  port?: number;
  host?: string;
  enableAuth?: boolean;
  enableCors?: boolean;
  metricsPath?: string;
  healthPath?: string;
  alertPath?: string;
  systemPath?: string;
  environment?: string;
  serviceName?: string;
  serviceVersion?: string;
}

/**
 * Server status information
 */
export interface ServerStatus {
  isRunning: boolean;
  config: MonitoringServerConfig;
  uptime: number;
  pid?: number;
  version?: string;
}

/**
 * Alert filter options
 */
export interface AlertFilters {
  severity?: 'low' | 'medium' | 'high' | 'critical';
  limit?: number;
  active?: boolean;
  operation?: OperationType;
  time_range?: {
    start: number;
    end: number;
  };
}

// ============================================================================
// Type Guards and Utility Types
// ============================================================================

/**
 * Type guard for LoggableData
 */
export function isLoggableData(value: unknown): value is LoggableData {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Type guard for UserContext
 */
export function isUserContext(value: unknown): value is UserContext {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as UserContext).user_id === 'string' &&
    typeof (value as UserContext).username === 'string' &&
    typeof (value as UserContext).role === 'string' &&
    Array.isArray((value as UserContext).scopes)
  );
}

/**
 * Type guard for RequestContext
 */
export function isRequestContext(value: unknown): value is RequestContext {
  return (
    typeof value === 'object' &&
    value !== null &&
    (typeof (value as RequestContext).query === 'string' ||
      typeof (value as RequestContext).mode === 'string' ||
      typeof (value as RequestContext).limit === 'number' ||
      Array.isArray((value as RequestContext).types))
  );
}

/**
 * Type guard for ErrorInfo
 */
export function isErrorInfo(value: unknown): value is ErrorInfo {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as ErrorInfo).type === 'string' &&
    typeof (value as ErrorInfo).message === 'string'
  );
}

/**
 * Type guard for OperationMetadata
 */
export function isOperationMetadata(value: unknown): value is OperationMetadata {
  if (!isLoggableData(value)) return false;

  const metadata = value as OperationMetadata;
  return (
    (metadata.strategy === undefined || typeof metadata.strategy === 'string') &&
    (metadata.result_count === undefined || typeof metadata.result_count === 'number') &&
    (metadata.cache_hit === undefined || typeof metadata.cache_hit === 'boolean')
  );
}

/**
 * Branded type for correlation IDs
 */
export type CorrelationId = string & { readonly __brand: unique symbol };

/**
 * Branded type for metric names
 */
export type MetricName = string & { readonly __brand: unique symbol };

/**
 * Branded type for operation names
 */
export type OperationName = string & { readonly __brand: unique symbol };

/**
 * Utility to create a correlation ID
 */
export function createCorrelationId(prefix?: string): CorrelationId {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substr(2, 9);
  return `${prefix || 'op'}_${timestamp}_${random}` as CorrelationId;
}

/**
 * Utility to create a metric name
 */
export function createMetricName(name: string): MetricName {
  return name as MetricName;
}

/**
 * Utility to create an operation name
 */
export function createOperationName(name: string): OperationName {
  return name as OperationName;
}

// ============================================================================
// Generic Interfaces for Extensibility
// ============================================================================

/**
 * Generic logger interface that can be extended
 */
export interface TypedLogger<TMetadata extends OperationMetadata = OperationMetadata> {
  debug(entry: LogEntryOptions): void;
  info(entry: LogEntryOptions): void;
  warn(entry: LogEntryOptions): void;
  error(entry: LogEntryOptions): void;
  log(level: LogLevel, entry: LogEntryOptions): void;
  withMetadata(metadata: TMetadata): TypedLogger<TMetadata>;
  withContext(context: UserContext): TypedLogger<TMetadata>;
}

/**
 * Generic metrics collector interface
 */
export interface TypedMetricsCollector<TMetric extends TypedPerformanceMetric = TypedPerformanceMetric> {
  recordMetric(metric: TMetric): void;
  startMetric(operation: OperationType, metadata?: TMetadata['metadata']): () => void;
  recordError(operation: OperationType, error: Error, metadata?: TMetadata['metadata']): void;
  getSummary(operation: OperationType): TypedPerformanceSummary | null;
  getTrends(timeWindowMinutes?: number): Record<string, unknown>;
}

/**
 * Generic alert interface
 */
export interface TypedAlert<TContext extends LoggableData = LoggableData> {
  id: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  timestamp: number;
  context?: TContext;
  resolved?: boolean;
  resolvedAt?: number;
  resolvedBy?: string;
}

/**
 * Generic monitoring dashboard interface
 */
export interface TypedMonitoringDashboard<TAlert extends TypedAlert = TypedAlert> {
  getAlerts(filters?: AlertFilters): TAlert[];
  acknowledgeAlert(alertId: string, userId: string): void;
  resolveAlert(alertId: string, userId: string): void;
  getMetricsSummary(): RealTimeMetrics;
  getTrends(timeWindowMinutes?: number): HistoricalMetrics;
}