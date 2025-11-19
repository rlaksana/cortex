/**
 * Comprehensive Type Definitions for Metrics System
 *
 * Provides type-safe interfaces for all metrics operations, eliminating `any` usage
 * while maintaining flexibility for different metric types and aggregation strategies.
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

import type { AlertThreshold } from './slo-interfaces.js';
import { type OperationType } from '../monitoring/operation-types.js';

// ============================================================================
// Core Metric Types
// ============================================================================

/**
 * Base metric interface with strict typing
 */
export interface TypedMetric {
  // Core identification
  id: string;
  name: string;
  type: MetricType;
  category: MetricCategory;

  // Value and unit
  value: number | string;
  unit?: string;

  // Timing information
  timestamp: string;
  interval?: number; // for rate/gauge metrics

  // Context information
  operation?: OperationType;
  component: string;
  version?: string;

  // Dimensions and labels
  dimensions: MetricDimension[];
  labels: Record<string, string>;

  // Quality indicators
  quality: MetricQuality;

  // Metadata
  metadata: MetricMetadata;

  // Relationships
  parentMetricId?: string;
  childMetricIds?: string[];

  // Aggregation information
  aggregation?: MetricAggregation;

  // Alert thresholds (convenience access to metadata.thresholds)
  thresholds?: MetricThreshold[];
}

/**
 * Metric type enumeration for type safety
 */
export enum MetricType {
  COUNTER = 'counter',
  GAUGE = 'gauge',
  HISTOGRAM = 'histogram',
  TIMER = 'timer',
  METER = 'meter',
  RATE = 'rate',
  RATIO = 'ratio',
  PERCENTILE = 'percentile',
  AVERAGE = 'average',
  SUM = 'sum',
  MIN = 'min',
  MAX = 'max',
}

/**
 * Metric categories for classification
 */
export enum MetricCategory {
  PERFORMANCE = 'performance',
  AVAILABILITY = 'availability',
  THROUGHPUT = 'throughput',
  LATENCY = 'latency',
  ERROR = 'error',
  BUSINESS = 'business',
  SYSTEM = 'system',
  NETWORK = 'network',
  DATABASE = 'database',
  SECURITY = 'security',
  QUALITY = 'quality',
  CUSTOM = 'custom',
}

/**
 * Metric dimension with type safety
 */
export interface MetricDimension {
  name: string;
  value: string;
  type: DimensionType;
}

/**
 * Dimension types
 */
export enum DimensionType {
  STRING = 'string',
  NUMBER = 'number',
  BOOLEAN = 'boolean',
  ENUM = 'enum',
}

/**
 * Metric quality indicators
 */
export interface MetricQuality {
  accuracy: number; // 0-1 scale
  completeness: number; // 0-1 scale
  consistency: number; // 0-1 scale
  timeliness: number; // 0-1 scale
  validity: number; // 0-1 scale
  reliability: number; // 0-1 scale
  lastValidated: string;
}

/**
 * Type-safe metric metadata
 */
export interface MetricMetadata {
  // Data source information
  source?: string;
  collectionMethod?: CollectionMethod;

  // Sampling information
  sampleRate?: number;
  sampleSize?: number;
  confidenceInterval?: {
    lower: number;
    upper: number;
    confidence: number; // 0-1 scale
  };

  // Thresholds and bounds
  thresholds?: MetricThreshold[];
  bounds?: {
    min?: number;
    max?: number;
    expectedRange?: [number, number];
    criticalRange?: [number, number];
  };

  // Correlations and relationships
  correlations?: MetricCorrelation[];
  dependencies?: string[]; // metric IDs this metric depends on

  // Processing information
  processedAt?: string;
  processingLatency?: number;
  transformations?: MetricTransformation[];

  // Business context
  businessImpact?: string;
  owner?: string;
  team?: string;
  service?: string;

  // Technical context
  environment?: string;
  version?: string;
  deployment?: string;
}

/**
 * Collection methods
 */
export enum CollectionMethod {
  ACTIVE = 'active',
  PASSIVE = 'passive',
  PUSH = 'push',
  PULL = 'pull',
  BATCH = 'batch',
  STREAMING = 'streaming',
  CALCULATED = 'calculated',
  AGGREGATED = 'aggregated',
}

/**
 * Metric thresholds for alerting
 */
export interface MetricThreshold {
  type: ThresholdType;
  operator: ComparisonOperator;
  value: number;
  severity: AlertSeverity;
  duration?: number; // seconds
  cooldown?: number; // seconds
  enabled: boolean;
}

/**
 * Threshold types
 */
export enum ThresholdType {
  ABSOLUTE = 'absolute',
  PERCENTAGE = 'percentage',
  RATE = 'rate',
  DELTA = 'delta',
}

/**
 * Comparison operators
 */
export enum ComparisonOperator {
  EQUALS = 'eq',
  NOT_EQUALS = 'ne',
  GREATER_THAN = 'gt',
  GREATER_THAN_OR_EQUAL = 'gte',
  LESS_THAN = 'lt',
  LESS_THAN_OR_EQUAL = 'lte',
  CONTAINS = 'contains',
  NOT_CONTAINS = 'not_contains',
  REGEX_MATCH = 'regex_match',
  REGEX_NOT_MATCH = 'regex_not_match',
}

/**
 * Alert severity levels
 */
export enum AlertSeverity {
  DEBUG = 'debug',
  INFO = 'info',
  WARNING = 'warning',
  ERROR = 'error',
  CRITICAL = 'critical',
}

/**
 * Metric correlation information
 */
export interface MetricCorrelation {
  metricId: string;
  correlationType: CorrelationType;
  strength: number; // 0-1 scale
  lagTime?: number; // seconds
  confidence: number; // 0-1 scale
  description: string;
}

/**
 * Correlation types
 */
export enum CorrelationType {
  DIRECT = 'direct',
  INVERSE = 'inverse',
  LEADING = 'leading',
  LAGGING = 'lagging',
  CAUSAL = 'causal',
  COINCIDENTAL = 'coincidental',
}

/**
 * Metric transformation applied during processing
 */
export interface MetricTransformation {
  type: TransformationType;
  parameters: Record<string, unknown>;
  appliedAt: string;
  result?: {
    before: number;
    after: number;
  };
}

/**
 * Transformation types
 */
export enum TransformationType {
  NORMALIZATION = 'normalization',
  SMOOTHING = 'smoothing',
  DERIVATIVE = 'derivative',
  INTEGRATION = 'integration',
  RESCALING = 'rescaling',
  LOG_TRANSFORM = 'log_transform',
  Z_SCORE = 'z_score',
  MOVING_AVERAGE = 'moving_average',
  EXPONENTIAL_SMOOTHING = 'exponential_smoothing',
  OUTLIER_REMOVAL = 'outlier_removal',
}

/**
 * Metric aggregation information
 */
export interface MetricAggregation {
  function: AggregationFunction;
  window: AggregationWindow;
  groupBy?: string[];
  filter?: MetricFilter;
}

/**
 * Aggregation functions
 */
export enum AggregationFunction {
  SUM = 'sum',
  AVERAGE = 'avg',
  MIN = 'min',
  MAX = 'max',
  COUNT = 'count',
  DISTINCT_COUNT = 'distinct_count',
  MEDIAN = 'median',
  PERCENTILE = 'percentile',
  STDDEV = 'stddev',
  VARIANCE = 'variance',
  RATE = 'rate',
  INCREASE = 'increase',
}

/**
 * Aggregation window
 */
export interface AggregationWindow {
  size: number;
  unit: TimeUnit;
  alignment?: WindowAlignment;
}

/**
 * Time units
 */
export enum TimeUnit {
  SECONDS = 'seconds',
  MINUTES = 'minutes',
  HOURS = 'hours',
  DAYS = 'days',
  WEEKS = 'weeks',
  MONTHS = 'months',
  YEARS = 'years',
}

/**
 * Window alignment
 */
export enum WindowAlignment {
  START = 'start',
  END = 'end',
  CENTER = 'center',
}

// ============================================================================
// Metric Collections and Series
// ============================================================================

/**
 * Time series of typed metrics
 */
export interface TypedMetricSeries {
  id: string;
  name: string;
  type: MetricType;
  category: MetricCategory;
  dimensions: MetricDimension[];
  labels: Record<string, string>;

  // Data points
  dataPoints: TypedMetricDataPoint[];

  // Series metadata
  startTime: string;
  endTime: string;
  resolution: number; // seconds between points
  totalPoints: number;

  // Quality information
  dataQuality: SeriesDataQuality;

  // Aggregation information
  aggregation?: MetricAggregation;

  // Statistical summaries
  statistics?: MetricStatistics;
}

/**
 * Individual metric data point
 */
export interface TypedMetricDataPoint {
  timestamp: string;
  value: number | string;
  quality: number; // 0-1 scale
  annotations?: Record<string, unknown>;
}

/**
 * Data quality for a metric series
 */
export interface SeriesDataQuality {
  completeness: number; // percentage of expected data points
  accuracy: number; // average accuracy of data points
  consistency: number; // temporal consistency score
  staleness: number; // age of newest data point (seconds)
  gaps: number; // number of gaps in data
  outliers: number; // number of outliers detected
  lastUpdated: string;
}

/**
 * Statistical summary of metric data
 */
export interface MetricStatistics {
  count: number;
  sum: number;
  average: number;
  median: number;
  min: number;
  max: number;
  variance: number;
  standardDeviation: number;
  percentiles: Record<number, number>; // e.g., { 50: 100, 95: 200, 99: 500 }
  trend: TrendDirection;
  seasonality?: SeasonalityInfo;
}

/**
 * Trend direction
 */
export enum TrendDirection {
  INCREASING = 'increasing',
  DECREASING = 'decreasing',
  STABLE = 'stable',
  VOLATILE = 'volatile',
  UNKNOWN = 'unknown',
}

/**
 * Seasonality information
 */
export interface SeasonalityInfo {
  detected: boolean;
  period: number; // in data points
  strength: number; // 0-1 scale
  pattern: SeasonalPattern[];
}

/**
 * Seasonal pattern
 */
export interface SeasonalPattern {
  phase: number; // 0-1, position in seasonal cycle
  amplitude: number;
  frequency: number;
}

// ============================================================================
// Query and Filter Types
// ============================================================================

/**
 * Type-safe metric query options
 */
export interface TypedMetricQuery {
  // Basic selection
  metricNames?: string[];
  metricTypes?: MetricType[];
  metricCategories?: MetricCategory[];
  components?: string[];

  // Time range
  timeRange: {
    start: string;
    end: string;
    resolution?: number; // optional data point resolution
  };

  // Filtering
  filters?: MetricFilter[];
  dimensions?: MetricDimension[];

  // Aggregation
  aggregation?: MetricAggregation[];

  // Grouping
  groupBy?: string[];

  // Ordering and pagination
  orderBy?: MetricOrderBy[];
  limit?: number;
  offset?: number;

  // Output format
  format?: OutputFormat;
}

/**
 * Metric filter with type safety
 */
export interface MetricFilter {
  field: MetricField;
  operator: ComparisonOperator;
  value: string | number | boolean | Array<string | number>;
  caseSensitive?: boolean;
}

/**
 * Metric fields that can be filtered
 */
export enum MetricField {
  NAME = 'name',
  TYPE = 'type',
  CATEGORY = 'category',
  COMPONENT = 'component',
  VALUE = 'value',
  TIMESTAMP = 'timestamp',
  QUALITY = 'quality',
  LABEL = 'label',
  DIMENSION = 'dimension',
}

/**
 * Order by clause for metric queries
 */
export interface MetricOrderBy {
  field: MetricField;
  direction: 'ASC' | 'DESC';
}

/**
 * Output formats
 */
export enum OutputFormat {
  JSON = 'json',
  CSV = 'csv',
  PROMETHEUS = 'prometheus',
  INFLUXDB = 'influxdb',
  GRAPHITE = 'graphite',
  WAVEFRONT = 'wavefront',
}

/**
 * Typed metric query result
 */
export interface TypedMetricQueryResult {
  query: TypedMetricQuery;
  series: TypedMetricSeries[];
  totalCount: number;
  hasMore: boolean;
  nextOffset?: number;
  executionTime: number;
  cached: boolean;
  warnings?: string[];
}

// ============================================================================
// Metrics Collection Types
// ============================================================================

/**
 * Metrics collector configuration
 */
export interface MetricsCollectorConfig {
  enabled: boolean;
  type: CollectorType;
  interval: number; // seconds
  buffer: CollectorBufferConfig;
  filtering: CollectorFilterConfig;
  aggregation: CollectorAggregationConfig;
  retention: CollectorRetentionConfig;
  export: CollectorExportConfig;
}

/**
 * Collector types
 */
export enum CollectorType {
  PULL = 'pull', // Metrics are pulled from sources
  PUSH = 'push', // Metrics are pushed to the system
  HYBRID = 'hybrid', // Both pull and push
}

/**
 * Buffer configuration
 */
export interface CollectorBufferConfig {
  enabled: boolean;
  maxSize: number;
  flushInterval: number;
  compression: boolean;
  encryption: boolean;
  persistence: boolean;
}

/**
 * Filter configuration for collectors
 */
export interface CollectorFilterConfig {
  include?: {
    metricNames?: string[];
    metricTypes?: MetricType[];
    components?: string[];
    labels?: Record<string, string>;
  };
  exclude?: {
    metricNames?: string[];
    metricTypes?: MetricType[];
    components?: string[];
    labels?: Record<string, string>;
  };
  sampling?: {
    rate: number; // 0-1, percentage of metrics to collect
    strategy: SamplingStrategy;
  };
}

/**
 * Sampling strategies
 */
export enum SamplingStrategy {
  RANDOM = 'random',
  SYSTEMATIC = 'systematic',
  STRATIFIED = 'stratified',
  ADAPTIVE = 'adaptive',
  PRIORITY = 'priority',
}

/**
 * Aggregation configuration for collectors
 */
export interface CollectorAggregationConfig {
  enabled: boolean;
  rules: AggregationRule[];
}

/**
 * Aggregation rule
 */
export interface AggregationRule {
  name: string;
  metricPattern: string; // regex or glob pattern
  function: AggregationFunction;
  window: AggregationWindow;
  groupBy?: string[];
  dimensions?: string[];
  labels?: Record<string, string>;
}

/**
 * Retention configuration
 */
export interface CollectorRetentionConfig {
  default: RetentionPolicy;
  byCategory?: Record<MetricCategory, RetentionPolicy>;
  byType?: Record<MetricType, RetentionPolicy>;
  byComponent?: Record<string, RetentionPolicy>;
}

/**
 * Retention policy
 */
export interface RetentionPolicy {
  duration: number; // seconds
  resolution: number; // seconds, data point resolution
  compression: boolean;
  archive: boolean;
  archiveDuration?: number; // seconds
}

/**
 * Export configuration
 */
export interface CollectorExportConfig {
  enabled: boolean;
  destinations: ExportDestination[];
  format: OutputFormat;
  compression: boolean;
  encryption: boolean;
}

/**
 * Export destination
 */
export interface ExportDestination {
  type: ExportType;
  config: Record<string, unknown>;
  enabled: boolean;
  priority: number;
  retryPolicy?: RetryPolicy;
}

/**
 * Export types
 */
export enum ExportType {
  PROMETHEUS = 'prometheus',
  INFLUXDB = 'influxdb',
  GRAPHITE = 'graphite',
  WAVEFRONT = 'wavefront',
  DATADOG = 'datadog',
  NEW_RELIC = 'newrelic',
  SPLUNK = 'splunk',
  ELASTICSEARCH = 'elasticsearch',
  KAFKA = 'kafka',
  S3 = 's3',
  GCS = 'gcs',
  AZURE_BLOB = 'azure_blob',
  HTTP = 'http',
  TCP = 'tcp',
  UDP = 'udp',
  FILE = 'file',
}

/**
 * Retry policy for exports
 */
export interface RetryPolicy {
  maxRetries: number;
  backoffType: BackoffType;
  initialDelay: number; // milliseconds
  maxDelay: number; // milliseconds
  multiplier?: number;
  jitter?: boolean;
}

/**
 * Backoff types
 */
export enum BackoffType {
  FIXED = 'fixed',
  LINEAR = 'linear',
  EXPONENTIAL = 'exponential',
  EXPONENTIAL_WITH_JITTER = 'exponential_with_jitter',
}

// ============================================================================
// Performance Monitoring Types
// ============================================================================

/**
 * Performance metrics with specific typing
 */
export interface TypedPerformanceMetrics {
  operation: OperationType;
  measurements: PerformanceMeasurement[];
  summary: PerformanceSummary;
  trends: PerformanceTrend[];
  anomalies: PerformanceAnomaly[];
}

/**
 * Individual performance measurement
 */
export interface PerformanceMeasurement {
  timestamp: string;
  duration: number;
  success: boolean;
  memoryBefore: NodeJS.MemoryUsage;
  memoryAfter: NodeJS.MemoryUsage;
  cpuUsage: NodeJS.CpuUsage;
  context: PerformanceContext;
  tags: Record<string, string>;
}

/**
 * Performance context
 */
export interface PerformanceContext {
  userId?: string;
  sessionId?: string;
  requestId?: string;
  correlationId?: string;
  endpoint?: string;
  method?: string;
  statusCode?: number;
  errorType?: string;
  cacheHit?: boolean;
  databaseQueries?: number;
  externalCalls?: number;
  payloadSize?: number;
}

/**
 * Performance summary
 */
export interface PerformanceSummary {
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  averageDuration: number;
  minDuration: number;
  maxDuration: number;
  p50Duration: number;
  p90Duration: number;
  p95Duration: number;
  p99Duration: number;
  errorRate: number;
  throughput: number; // requests per second
  memoryUsage: {
    average: number;
    peak: number;
    trend: TrendDirection;
  };
  cpuUsage: {
    average: number;
    peak: number;
    trend: TrendDirection;
  };
}

/**
 * Performance trend information
 */
export interface PerformanceTrend {
  metric: string;
  direction: TrendDirection;
  changeRate: number; // percentage change
  confidence: number; // 0-1 scale
  timeWindow: number; // seconds
  significance: SignificanceLevel;
}

/**
 * Significance levels
 */
export enum SignificanceLevel {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  VERY_HIGH = 'very_high',
}

/**
 * Performance anomaly
 */
export interface PerformanceAnomaly {
  id: string;
  type: AnomalyType;
  severity: AlertSeverity;
  timestamp: string;
  description: string;
  affectedMetrics: string[];
  score: number; // 0-1 anomaly score
  confidence: number; // 0-1 confidence
  context: AnomalyContext;
  detectedBy: string;
}

/**
 * Anomaly types
 */
export enum AnomalyType {
  SPIKE = 'spike',
  DROP = 'drop',
  DRIFT = 'drift',
  OUTLIER = 'outlier',
  PATTERN_CHANGE = 'pattern_change',
  MISSING_DATA = 'missing_data',
  STALE_DATA = 'stale_data',
  CORRELATION_BREAK = 'correlation_break',
}

/**
 * Anomaly context
 */
export interface AnomalyContext {
  relatedOperations?: OperationType[];
  relatedComponents?: string[];
  recentChanges?: string[];
  environmentalFactors?: string[];
  userImpact?: string;
}

// ============================================================================
// Alerting and Notification Types
// ============================================================================

/**
 * Metric alert with comprehensive typing
 */
export interface TypedMetricAlert {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  severity: AlertSeverity;

  // Alert condition
  condition: AlertCondition;

  // Alert state
  state: AlertState;
  stateHistory: AlertStateTransition[];

  // Scheduling
  schedule?: AlertSchedule;

  // Notifications
  notifications: AlertNotification[];
  escalationPolicy?: EscalationPolicy;

  // Metadata
  metadata: AlertMetadata;
}

/**
 * Alert condition
 */
export interface AlertCondition {
  metricQuery: TypedMetricQuery;
  evaluation: AlertEvaluation;
  thresholds: AlertThreshold[];
  operator: LogicalOperator;
  for?: number; // duration in seconds
}

/**
 * Alert evaluation
 */
export interface AlertEvaluation {
  interval: number; // seconds
  method: EvaluationMethod;
  window?: AggregationWindow;
  missingData: MissingDataPolicy;
}

/**
 * Evaluation methods
 */
export enum EvaluationMethod {
  LATEST = 'latest',
  AVERAGE = 'average',
  MAX = 'max',
  MIN = 'min',
  SUM = 'sum',
  COUNT = 'count',
}

/**
 * Missing data policy
 */
export enum MissingDataPolicy {
  IGNORE = 'ignore',
  TREAT_AS_ZERO = 'treat_as_zero',
  TREAT_AS_NULL = 'treat_as_null',
  TREAT_AS_LAST = 'treat_as_last',
  TRIGGER_ALERT = 'trigger_alert',
}

/**
 * Logical operators for alert conditions
 */
export enum LogicalOperator {
  AND = 'and',
  OR = 'or',
  NOT = 'not',
}

/**
 * Alert states
 */
export enum AlertState {
  OK = 'ok',
  WARNING = 'warning',
  CRITICAL = 'critical',
  UNKNOWN = 'unknown',
  PAUSED = 'paused',
  RESOLVED = 'resolved',
}

/**
 * Alert state transition
 */
export interface AlertStateTransition {
  from: AlertState;
  to: AlertState;
  timestamp: string;
  reason: string;
  value: number;
  threshold?: number;
}

/**
 * Alert schedule
 */
export interface AlertSchedule {
  timezone: string;
  activeHours?: {
    start: string; // HH:mm
    end: string; // HH:mm
  };
  activeDays?: number[]; // 0-6, Sunday = 0
  holidays?: string[]; // ISO date strings
  maintenanceWindows?: MaintenanceWindow[];
}

/**
 * Maintenance window
 */
export interface MaintenanceWindow {
  start: string; // ISO datetime
  end: string; // ISO datetime
  description: string;
  recurring?: RecurringPattern;
}

/**
 * Recurring pattern
 */
export interface RecurringPattern {
  type: RecurringType;
  interval: number;
  daysOfWeek?: number[];
  dayOfMonth?: number;
  endDate?: string; // ISO date
}

/**
 * Recurring types
 */
export enum RecurringType {
  DAILY = 'daily',
  WEEKLY = 'weekly',
  MONTHLY = 'monthly',
  YEARLY = 'yearly',
}

/**
 * Alert notification
 */
export interface AlertNotification {
  id: string;
  type: NotificationType;
  enabled: boolean;
  config: NotificationConfig;
  filters: NotificationFilter[];
  template?: NotificationTemplate;
  retryPolicy?: RetryPolicy;
}

/**
 * Notification types
 */
export enum NotificationType {
  EMAIL = 'email',
  SLACK = 'slack',
  WEBHOOK = 'webhook',
  SMS = 'sms',
  PAGERDUTY = 'pagerduty',
  OPSGENIE = 'opsgenie',
  VICTOROPS = 'victorops',
  JIRA = 'jira',
  TELEGRAM = 'telegram',
  DISCORD = 'discord',
  MSTEAMS = 'msteams',
}

/**
 * Notification configuration
 */
export interface NotificationConfig {
  recipients: string[];
  subject?: string;
  message?: string;
  priority?: NotificationPriority;
  channels?: string[];
  attachments?: NotificationAttachment[];
}

/**
 * Notification priority
 */
export enum NotificationPriority {
  LOW = 'low',
  NORMAL = 'normal',
  HIGH = 'high',
  URGENT = 'urgent',
}

/**
 * Notification attachment
 */
export interface NotificationAttachment {
  type: AttachmentType;
  name: string;
  content: string | object;
  mimeType?: string;
}

/**
 * Attachment types
 */
export enum AttachmentType {
  TEXT = 'text',
  JSON = 'json',
  CSV = 'csv',
  PNG = 'png',
  SVG = 'svg',
  PDF = 'pdf',
}

/**
 * Notification filter
 */
export interface NotificationFilter {
  field: NotificationField;
  operator: ComparisonOperator;
  value: string | number | boolean;
}

/**
 * Notification fields
 */
export enum NotificationField {
  SEVERITY = 'severity',
  STATE = 'state',
  METRIC_NAME = 'metric_name',
  COMPONENT = 'component',
  TIME_OF_DAY = 'time_of_day',
  DAY_OF_WEEK = 'day_of_week',
}

/**
 * Notification template
 */
export interface NotificationTemplate {
  name: string;
  subject?: string;
  body: string;
  variables: TemplateVariable[];
  format: OutputFormat;
}

/**
 * Template variable
 */
export interface TemplateVariable {
  name: string;
  type: VariableType;
  required: boolean;
  defaultValue?: string | number;
  description?: string;
}

/**
 * Variable types
 */
export enum VariableType {
  STRING = 'string',
  NUMBER = 'number',
  BOOLEAN = 'boolean',
  DATE = 'date',
  DURATION = 'duration',
  PERCENTAGE = 'percentage',
}

/**
 * Escalation policy
 */
export interface EscalationPolicy {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  steps: EscalationStep[];
  timeout: number; // minutes
}

/**
 * Escalation step
 */
export interface EscalationStep {
  order: number;
  delay: number; // minutes
  notifications: string[]; // notification IDs
  conditions?: AlertCondition[];
}

/**
 * Alert metadata
 */
export interface AlertMetadata {
  created: string;
  updated: string;
  createdBy: string;
  updatedBy: string;
  tags: string[];
  owner?: string;
  team?: string;
  service?: string;
  runbook?: string;
  documentation?: string;
  relatedAlerts?: string[];
}

// ============================================================================
// Type Guards and Validation Functions
// ============================================================================

/**
 * Type guard for typed metrics
 */
export function isTypedMetric(value: unknown): value is TypedMetric {
  if (typeof value !== 'object' || value === null) {
    return false;
  }

  const metric = value as TypedMetric;

  return (
    typeof metric.id === 'string' &&
    typeof metric.name === 'string' &&
    Object.values(MetricType).includes(metric.type as MetricType) &&
    Object.values(MetricCategory).includes(metric.category as MetricCategory) &&
    (typeof metric.value === 'number' || typeof metric.value === 'string') &&
    typeof metric.timestamp === 'string' &&
    typeof metric.component === 'string' &&
    Array.isArray(metric.dimensions) &&
    typeof metric.labels === 'object' &&
    typeof metric.quality === 'object' &&
    typeof metric.metadata === 'object'
  );
}

/**
 * Type guard for metric query
 */
export function isTypedMetricQuery(value: unknown): value is TypedMetricQuery {
  if (typeof value !== 'object' || value === null) {
    return false;
  }

  const query = value as TypedMetricQuery;

  return (
    typeof query.timeRange === 'object' &&
    typeof query.timeRange.start === 'string' &&
    typeof query.timeRange.end === 'string' &&
    (query.metricTypes === undefined || Array.isArray(query.metricTypes)) &&
    (query.metricCategories === undefined || Array.isArray(query.metricCategories))
  );
}

/**
 * Validates a metric against business rules
 */
export function validateTypedMetric(metric: TypedMetric): MetricValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Required field validation
  if (!metric.id || metric.id.trim() === '') {
    errors.push('Metric ID is required and cannot be empty');
  }

  if (!metric.name || metric.name.trim() === '') {
    errors.push('Metric name is required and cannot be empty');
  }

  if (!metric.component || metric.component.trim() === '') {
    errors.push('Component is required and cannot be empty');
  }

  // Timestamp validation
  const timestamp = new Date(metric.timestamp);
  if (isNaN(timestamp.getTime())) {
    errors.push('Invalid timestamp format');
  } else if (timestamp > new Date()) {
    warnings.push('Metric timestamp is in the future');
  }

  // Value validation
  if (typeof metric.value === 'number') {
    if (isNaN(metric.value)) {
      errors.push('Metric value cannot be NaN');
    }
    if (!isFinite(metric.value)) {
      errors.push('Metric value must be finite');
    }
  }

  // Quality validation
  if (metric.quality.accuracy < 0 || metric.quality.accuracy > 1) {
    errors.push('Quality accuracy must be between 0 and 1');
  }
  if (metric.quality.completeness < 0 || metric.quality.completeness > 1) {
    errors.push('Quality completeness must be between 0 and 1');
  }

  // Dimension validation
  for (const dimension of metric.dimensions) {
    if (!dimension.name || !dimension.value) {
      errors.push('Dimension name and value are required');
    }
    if (!Object.values(DimensionType).includes(dimension.type as DimensionType)) {
      errors.push(`Invalid dimension type: ${dimension.type}`);
    }
  }

  // Threshold validation
  if (metric.thresholds) {
    for (const threshold of metric.thresholds) {
      if (!Object.values(ThresholdType).includes(threshold.type as ThresholdType)) {
        errors.push(`Invalid threshold type: ${threshold.type}`);
      }
      if (!Object.values(ComparisonOperator).includes(threshold.operator as ComparisonOperator)) {
        errors.push(`Invalid comparison operator: ${threshold.operator}`);
      }
      if (typeof threshold.value !== 'number') {
        errors.push('Threshold value must be a number');
      }
    }
  }

  // Business logic validation
  if (metric.type === MetricType.COUNTER && typeof metric.value === 'number' && metric.value < 0) {
    warnings.push('Counter metrics should have non-negative values');
  }

  if (
    metric.type === MetricType.PERCENTILE &&
    (typeof metric.value !== 'number' || metric.value < 0 || metric.value > 100)
  ) {
    warnings.push('Percentile metrics should be between 0 and 100');
  }

  return {
    isValid: errors.length === 0,
    errors,
    warnings,
  };
}

/**
 * Validation result interface
 */
export interface MetricValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Creates a properly typed metric with default values
 */
export function createTypedMetric(baseMetric: Partial<TypedMetric>): TypedMetric {
  const now = new Date().toISOString();

  return {
    id: baseMetric.id || `metric_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
    name: baseMetric.name || 'unnamed_metric',
    type: baseMetric.type || MetricType.GAUGE,
    category: baseMetric.category || MetricCategory.SYSTEM,
    value: baseMetric.value ?? 0,
    unit: baseMetric.unit,
    timestamp: baseMetric.timestamp || now,
    interval: baseMetric.interval,
    operation: baseMetric.operation,
    component: baseMetric.component || 'unknown',
    version: baseMetric.version,
    dimensions: baseMetric.dimensions || [],
    labels: baseMetric.labels || {},
    quality: baseMetric.quality || {
      accuracy: 1.0,
      completeness: 1.0,
      consistency: 1.0,
      timeliness: 1.0,
      validity: 1.0,
      reliability: 1.0,
      lastValidated: now,
    },
    metadata: baseMetric.metadata || {},
    parentMetricId: baseMetric.parentMetricId,
    childMetricIds: baseMetric.childMetricIds || [],
    aggregation: baseMetric.aggregation,
  };
}

/**
 * Creates a default metrics collector configuration
 */
export function createDefaultCollectorConfig(): MetricsCollectorConfig {
  return {
    enabled: true,
    type: CollectorType.HYBRID,
    interval: 60,
    buffer: {
      enabled: true,
      maxSize: 10000,
      flushInterval: 30,
      compression: true,
      encryption: false,
      persistence: false,
    },
    filtering: {
      sampling: {
        rate: 1.0,
        strategy: SamplingStrategy.RANDOM,
      },
    },
    aggregation: {
      enabled: true,
      rules: [],
    },
    retention: {
      default: {
        duration: 86400 * 7, // 7 days
        resolution: 60, // 1 minute
        compression: true,
        archive: false,
      },
      byCategory: {
        [MetricCategory.PERFORMANCE]: {
          duration: 86400 * 30, // 30 days
          resolution: 60,
          compression: true,
          archive: true,
          archiveDuration: 86400 * 365, // 1 year archive
        },
        [MetricCategory.BUSINESS]: {
          duration: 86400 * 365 * 3, // 3 years
          resolution: 300, // 5 minutes
          compression: true,
          archive: true,
          archiveDuration: 86400 * 365 * 7, // 7 years archive
        },
      },
    },
    export: {
      enabled: true,
      destinations: [],
      format: OutputFormat.JSON,
      compression: true,
      encryption: false,
    },
  };
}

/**
 * Utility to get human-readable descriptions for metric types
 */
export function getMetricTypeDescription(type: MetricType): string {
  const descriptions: Record<MetricType, string> = {
    [MetricType.COUNTER]: 'Counter metric that only increases',
    [MetricType.GAUGE]: 'Gauge metric that can increase or decrease',
    [MetricType.HISTOGRAM]: 'Histogram metric for value distributions',
    [MetricType.TIMER]: 'Timer metric for duration measurements',
    [MetricType.METER]: 'Meter metric for rate measurements',
    [MetricType.RATE]: 'Rate metric showing change over time',
    [MetricType.RATIO]: 'Ratio metric showing relationship between values',
    [MetricType.PERCENTILE]: 'Percentile metric showing distribution percentiles',
    [MetricType.AVERAGE]: 'Average metric calculated from multiple values',
    [MetricType.SUM]: 'Sum metric showing total of multiple values',
    [MetricType.MIN]: 'Minimum metric showing smallest value',
    [MetricType.MAX]: 'Maximum metric showing largest value',
  };

  return descriptions[type] || 'Unknown metric type';
}
