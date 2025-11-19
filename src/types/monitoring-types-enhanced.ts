/**
 * Enhanced Monitoring & Metrics Types for Cortex MCP System
 *
 * Consolidated and type-safe monitoring interface definitions that eliminate `any` usage
 * and provide consistent patterns for system observability.
 */

import type {
  BaseEvent,
  Dict,
  JSONValue,
  Metadata,
  OperationContext,
  Result,
  Tags,
} from './base-types.js';

// ============================================================================
// Core Monitoring Types
// ============================================================================

export interface HealthStatus {
  readonly status: 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
  readonly timestamp: Date;
  readonly message?: string;
  readonly details?: HealthDetails;
  readonly checks?: readonly HealthCheck[];
}

export interface HealthDetails {
  readonly uptime: number;
  readonly version: string;
  readonly environment: string;
  readonly region?: string;
  readonly instanceId: string;
  readonly dependencies?: DependencyHealth[];
}

export interface HealthCheck {
  readonly name: string;
  readonly status: HealthStatus['status'];
  readonly duration: number;
  readonly message?: string;
  readonly lastChecked: Date;
  readonly metadata?: Metadata;
}

export interface DependencyHealth {
  readonly name: string;
  readonly type: 'database' | 'cache' | 'external_service' | 'queue' | 'filesystem';
  readonly status: HealthStatus['status'];
  readonly responseTime?: number;
  readonly errorRate?: number;
  readonly lastChecked: Date;
  readonly metadata?: Metadata;
}

// ============================================================================
// Metrics Types
// ============================================================================

export interface Metric {
  readonly name: string;
  readonly type: MetricType;
  readonly value: number;
  readonly unit: string;
  readonly timestamp: Date;
  readonly tags: Tags;
  readonly metadata?: Metadata;
}

export type MetricType = 'counter' | 'gauge' | 'histogram' | 'summary' | 'timer' | 'ratio';

export interface Counter {
  readonly name: string;
  readonly value: number;
  readonly labels: Tags;
  readonly timestamp: Date;
}

export interface Gauge {
  readonly name: string;
  readonly value: number;
  readonly labels: Tags;
  readonly timestamp: Date;
}

export interface Histogram {
  readonly name: string;
  readonly buckets: HistogramBucket[];
  readonly count: number;
  readonly sum: number;
  readonly labels: Tags;
  readonly timestamp: Date;
}

export interface HistogramBucket {
  readonly upperBound: number;
  readonly count: number;
}

export interface Summary {
  readonly name: string;
  readonly count: number;
  readonly sum: number;
  readonly quantiles: readonly Quantile[];
  readonly labels: Tags;
  readonly timestamp: Date;
}

export interface Quantile {
  readonly quantile: number;
  readonly value: number;
}

// ============================================================================
// Performance Monitoring Types
// ============================================================================

export interface PerformanceMetrics {
  readonly operationName: string;
  readonly duration: number;
  readonly startTime: Date;
  readonly endTime: Date;
  readonly success: boolean;
  readonly error?: PerformanceError;
  readonly metadata?: Metadata;
  readonly spans?: readonly PerformanceSpan[];
}

export interface PerformanceError {
  readonly type: string;
  readonly message: string;
  readonly stack?: string;
  readonly code?: string;
  readonly metadata?: Metadata;
}

export interface PerformanceSpan {
  readonly name: string;
  readonly startTime: Date;
  readonly endTime: Date;
  readonly duration: number;
  readonly parentId?: string;
  readonly metadata?: Metadata;
  readonly tags?: Tags;
}

export interface PerformanceProfile {
  readonly operationName: string;
  readonly samples: readonly PerformanceMetrics[];
  readonly averageDuration: number;
  readonly p50Duration: number;
  readonly p95Duration: number;
  readonly p99Duration: number;
  readonly maxDuration: number;
  readonly minDuration: number;
  readonly errorRate: number;
  readonly throughput: number;
  readonly timestamp: Date;
}

// ============================================================================
// Alert Types
// ============================================================================

export interface Alert {
  readonly id: string;
  readonly name: string;
  readonly severity: AlertSeverity;
  readonly status: AlertStatus;
  readonly condition: AlertCondition;
  readonly message: string;
  readonly description?: string;
  readonly source: string;
  readonly timestamp: Date;
  readonly resolvedAt?: Date;
  readonly metadata?: Metadata;
  readonly actions?: readonly AlertAction[];
}

export type AlertSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type AlertStatus = 'active' | 'acknowledged' | 'resolved' | 'suppressed';

export interface AlertCondition {
  readonly metric: string;
  readonly operator: AlertOperator;
  readonly threshold: number;
  readonly duration?: number;
  readonly evaluationPeriods?: number;
}

export type AlertOperator = 'gt' | 'gte' | 'lt' | 'lte' | 'eq' | 'neq';

export interface AlertAction {
  readonly type: 'webhook' | 'email' | 'slack' | 'pagerduty' | 'custom';
  readonly config: Dict<JSONValue>;
  readonly executedAt?: Date;
  readonly result?: ActionResult;
}

export interface ActionResult {
  readonly success: boolean;
  readonly message: string;
  readonly details?: JSONValue;
  readonly timestamp: Date;
}

// ============================================================================
// Log Types
// ============================================================================

export interface LogEntry {
  readonly timestamp: Date;
  readonly level: LogLevel;
  readonly message: string;
  readonly logger: string;
  readonly correlationId?: string;
  readonly userId?: string;
  readonly sessionId?: string;
  readonly metadata?: Metadata;
  readonly error?: LogError;
  readonly context?: OperationContext;
}

export type LogLevel = 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal';

export interface LogError {
  readonly name: string;
  readonly message: string;
  readonly stack?: string;
  readonly code?: string;
  readonly metadata?: Metadata;
}

export interface LogQuery {
  readonly level?: LogLevel | readonly LogLevel[];
  readonly logger?: string;
  readonly correlationId?: string;
  readonly userId?: string;
  readonly startTime?: Date;
  readonly endTime?: Date;
  readonly message?: string;
  readonly tags?: Tags;
  readonly limit?: number;
  readonly offset?: number;
}

// ============================================================================
// Tracing Types
// ============================================================================

export interface Trace {
  readonly traceId: string;
  readonly spans: readonly Span[];
  readonly startTime: Date;
  readonly endTime: Date;
  readonly duration: number;
  readonly status: TraceStatus;
  readonly services: readonly string[];
  readonly metadata?: Metadata;
}

export interface Span {
  readonly traceId: string;
  readonly spanId: string;
  readonly parentSpanId?: string;
  readonly operationName: string;
  readonly startTime: Date;
  readonly endTime: Date;
  readonly duration: number;
  readonly status: SpanStatus;
  readonly service: string;
  readonly tags: Tags;
  readonly logs?: readonly LogEntry[];
  readonly metadata?: Metadata;
}

export type TraceStatus = 'ok' | 'error' | 'cancelled' | 'timeout';

export type SpanStatus = 'ok' | 'error' | 'cancelled' | 'timeout' | 'deadline_exceeded';

// ============================================================================
// SLO/SLI Types
// ============================================================================

export interface SLO {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly service: string;
  readonly objective: SLOObjective;
  readonly timeWindow: SLOTimeWindow;
  readonly alerting?: SLOAlerting;
  readonly status: SLOStatus;
  readonly metadata?: Metadata;
}

export interface SLOObjective {
  readonly type: SLIType;
  readonly target: number;
  readonly targetPercentile?: number;
}

export type SLIType = 'availability' | 'latency' | 'throughput' | 'error_rate' | 'custom';

export interface SLOTimeWindow {
  readonly type: 'rolling' | 'calendar';
  readonly duration: string; // e.g., "30d", "1h"
  readonly calendarPeriod?: 'monthly' | 'quarterly' | 'yearly';
}

export interface SLOAlerting {
  readonly burnRateThresholds: readonly BurnRateThreshold[];
  readonly notificationChannels: readonly string[];
  readonly escalationPolicy?: string;
}

export interface BurnRateThreshold {
  readonly threshold: number;
  readonly window: string;
  readonly severity: AlertSeverity;
}

export type SLOStatus = 'healthy' | 'warning' | 'critical' | 'unknown';

export interface SLOResult {
  readonly sloId: string;
  readonly timeWindow: string;
  readonly value: number;
  readonly target: number;
  readonly status: SLOStatus;
  readonly timestamp: Date;
  readonly dataPoints: readonly number[];
  readonly metadata?: Metadata;
}

// ============================================================================
// Dashboard Types
// ============================================================================

export interface Dashboard {
  readonly id: string;
  readonly name: string;
  readonly description?: string;
  readonly panels: readonly Panel[];
  readonly timeRange: TimeRange;
  readonly refreshInterval?: number;
  readonly tags: Tags;
  readonly metadata?: Metadata;
}

export interface Panel {
  readonly id: string;
  readonly title: string;
  readonly type: PanelType;
  readonly queries: readonly Query[];
  readonly position: PanelPosition;
  readonly options?: PanelOptions;
  readonly links?: readonly PanelLink[];
}

export type PanelType =
  | 'graph'
  | 'single_stat'
  | 'table'
  | 'heatmap'
  | 'gauge'
  | 'progress_bar'
  | 'logs'
  | 'trace';

export interface Query {
  readonly refId: string;
  readonly type: string;
  readonly expression: string;
  readonly legend?: string;
  readonly options?: QueryOptions;
}

export interface QueryOptions {
  readonly step?: number;
  readonly fill?: 'zero' | 'null' | 'previous';
  readonly instant?: boolean;
  readonly [key: string]: JSONValue;
}

export interface PanelPosition {
  readonly x: number;
  readonly y: number;
  readonly width: number;
  readonly height: number;
}

export interface PanelOptions {
  readonly unit?: string;
  readonly decimals?: number;
  readonly min?: number;
  readonly max?: number;
  readonly thresholds?: readonly Threshold[];
  readonly colors?: readonly string[];
}

export interface Threshold {
  readonly value: number;
  readonly color: string;
  readonly operator?: 'gt' | 'gte' | 'lt' | 'lte';
}

export interface PanelLink {
  readonly title: string;
  readonly url: string;
  readonly targetBlank?: boolean;
  readonly tooltip?: string;
}

export interface TimeRange {
  readonly from: Date;
  readonly to: Date;
  readonly timezone?: string;
}

// ============================================================================
// Event Types
// ============================================================================

export interface MonitoringEvent extends BaseEvent {
  readonly source: string;
  readonly correlationId?: string;
  readonly userId?: string;
  readonly sessionId?: string;
  readonly operation?: string;
  readonly duration?: number;
  readonly error?: MonitoringError;
}

export interface MonitoringError {
  readonly type: string;
  readonly message: string;
  readonly stack?: string;
  readonly code?: string;
  readonly context?: OperationContext;
}

// ============================================================================
// Collector Types
// ============================================================================

export interface MetricsCollector {
  readonly name: string;
  readonly type: CollectorType;
  readonly config: CollectorConfig;
  readonly status: CollectorStatus;
  readonly lastCollection?: Date;
  readonly metadata?: Metadata;
}

export type CollectorType = 'prometheus' | 'influxdb' | 'statsd' | 'jmx' | 'custom';

export type CollectorStatus = 'active' | 'inactive' | 'error' | 'disabled';

export interface CollectorConfig {
  readonly endpoint?: string;
  readonly interval?: number;
  readonly timeout?: number;
  readonly authentication?: CollectorAuth;
  readonly headers?: Dict<string>;
  readonly queries?: readonly string[];
}

export interface CollectorAuth {
  readonly type: 'basic' | 'bearer' | 'api_key';
  readonly credentials: Dict<string>;
}

// ============================================================================
// Report Types
// ============================================================================

export interface MonitoringReport {
  readonly id: string;
  readonly type: ReportType;
  readonly period: ReportPeriod;
  readonly generatedAt: Date;
  readonly data: ReportData;
  readonly metadata?: Metadata;
}

export type ReportType = 'performance' | 'availability' | 'error' | 'usage' | 'slo' | 'custom';

export interface ReportPeriod {
  readonly start: Date;
  readonly end: Date;
  readonly type: 'hourly' | 'daily' | 'weekly' | 'monthly';
}

export interface ReportData {
  readonly summary: ReportSummary;
  readonly sections: readonly ReportSection[];
  readonly recommendations?: readonly string[];
  readonly charts?: readonly ChartData[];
}

export interface ReportSummary {
  readonly totalRequests?: number;
  readonly errorRate?: number;
  readonly averageResponseTime?: number;
  readonly uptime?: number;
  readonly [key: string]: JSONValue;
}

export interface ReportSection {
  readonly title: string;
  readonly content: string;
  readonly metrics?: readonly Metric[];
  readonly charts?: readonly ChartData[];
}

export interface ChartData {
  readonly type: ChartType;
  readonly title: string;
  readonly data: ChartDataPoint[];
  readonly options?: ChartOptions;
}

export type ChartType = 'line' | 'bar' | 'pie' | 'heatmap' | 'scatter';

export interface ChartDataPoint {
  readonly x: number | string;
  readonly y: number;
  readonly label?: string;
}

export interface ChartOptions {
  readonly xAxis?: ChartAxis;
  readonly yAxis?: ChartAxis;
  readonly legend?: boolean;
  readonly colors?: readonly string[];
}

export interface ChartAxis {
  readonly label?: string;
  readonly min?: number;
  readonly max?: number;
  readonly format?: string;
}

// ============================================================================
// Utility Types
// ============================================================================

export type MonitoringResult<T> = Result<T, MonitoringError>;

export interface MonitoringContext extends OperationContext {
  readonly correlationId?: string;
  readonly userId?: string;
  readonly sessionId?: string;
  readonly operation?: string;
  readonly service?: string;
  readonly version?: string;
}

export interface MetricFilter {
  readonly name?: string;
  readonly type?: MetricType;
  readonly tags?: Tags;
  readonly startTime?: Date;
  readonly endTime?: Date;
  readonly service?: string;
}

export interface MetricAggregation {
  readonly function: AggregationFunction;
  readonly interval?: string;
  readonly groupBy?: readonly string[];
}

export type AggregationFunction =
  | 'sum'
  | 'avg'
  | 'min'
  | 'max'
  | 'count'
  | 'rate'
  | 'increase'
  | 'percentile';
