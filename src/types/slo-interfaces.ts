/**
 * Service Level Objective (SLO) and Service Level Indicator (SLI) Framework
 *
 * Comprehensive framework for defining, monitoring, and reporting on service level objectives
 * with real-time monitoring, alerting, and analysis capabilities.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { HealthStatus } from '../types/unified-health-interfaces';

// ============================================================================
// Core SLO/SLI Interfaces
// ============================================================================

/**
 * Service Level Indicator (SLI) - Raw measurement of service performance
 */
export interface SLI {
  id: string;
  name: string;
  description: string;
  type: SLIType;
  unit: string;
  measurement: {
    source: string;
    method: string;
    aggregation: SLIAggregation;
    window: TimeWindow;
  };
  thresholds: {
    target: number;
    warning?: number;
    critical?: number;
  };
  tags: Record<string, string>;
  metadata: Record<string, any>;
}

/**
 * Service Level Objective (SLO) - Target goal for service performance
 */
export interface SLO {
  id: string;
  name: string;
  description: string;
  sli: string; // Reference to SLI ID
  objective: {
    target: number; // Percentage (0-100)
    period: SLOPeriod;
    window: TimeWindow;
  };
  budgeting: {
    errorBudget: number; // Percentage of allowable failures
    burnRateAlerts: BurnRateAlert[];
  };
  alerting: {
    enabled: boolean;
    thresholds: AlertThreshold[];
    notificationChannels: string[];
    escalationPolicy?: string;
  };
  ownership: {
    team: string;
    individuals: string[];
    contact: ContactInfo;
  };
  status: SLOStatus;
  active?: boolean; // Whether the SLO is currently active for evaluation
  metadata: {
    createdAt: Date;
    updatedAt: Date;
    lastEvaluated?: Date;
    businessImpact: string;
    dependencies: string[];
    relatedSLOs?: string[];
  };
}

/**
 * Service Level Agreement (SLA) - Formal agreement with customers
 */
export interface SLA {
  id: string;
  name: string;
  description: string;
  customer: string;
  service: string;
  sloReferences: string[]; // SLOs included in this SLA
  terms: {
    availability: number; // Percentage
    responseTime: number; // Milliseconds
    errorRate: number; // Percentage
    credits: {
      enabled: boolean;
      rate: number; // Percentage per violation
      calculation: SLACreditCalculation;
    };
  };
  period: {
    start: Date;
    end: Date;
    billingCycle: 'monthly' | 'quarterly' | 'yearly';
  };
  status: SLAStatus;
  compliance: SLAComplianceMetrics;
  metadata: {
    createdAt: Date;
    updatedAt: Date;
    approvedBy: string;
    contractValue?: number;
  };
}

// ============================================================================
// Enumerations
// ============================================================================

/**
 * SLI types
 */
export enum SLIType {
  AVAILABILITY = 'availability',
  RESPONSE_TIME = 'response_time',
  ERROR_RATE = 'error_rate',
  THROUGHPUT = 'throughput',
  LATENCY = 'latency',
  SUCCESS_RATE = 'success_rate',
  SATISFACTION = 'satisfaction',
  CUSTOM = 'custom',
}

/**
 * SLI aggregation methods
 */
export enum SLIAggregation {
  COUNT = 'count',
  SUM = 'sum',
  AVERAGE = 'average',
  MEDIAN = 'median',
  P50 = 'p50',
  P90 = 'p90',
  P95 = 'p95',
  P99 = 'p99',
  P99_9 = 'p99_9',
  MAX = 'max',
  MIN = 'min',
  RATE = 'rate',
  RATIO = 'ratio',
}

/**
 * SLO periods
 */
export enum SLOPeriod {
  ROLLING_7_DAYS = 'rolling_7_days',
  ROLLING_30_DAYS = 'rolling_30_days',
  ROLLING_90_DAYS = 'rolling_90_days',
  CALENDAR_MONTH = 'calendar_month',
  CALENDAR_QUARTER = 'calendar_quarter',
  CALENDAR_YEAR = 'calendar_year',
  FISCAL_QUARTER = 'fiscal_quarter',
  FISCAL_YEAR = 'fiscal_year',
}

/**
 * SLO status
 */
export enum SLOStatus {
  ACTIVE = 'active',
  PAUSED = 'paused',
  DISABLED = 'disabled',
  ARCHIVED = 'archived',
}

/**
 * SLA status
 */
export enum SLAStatus {
  ACTIVE = 'active',
  EXPIRED = 'expired',
  TERMINATED = 'terminated',
  DRAFT = 'draft',
  PENDING_APPROVAL = 'pending_approval',
}

/**
 * Time window configuration
 */
export interface TimeWindow {
  type: 'rolling' | 'calendar' | 'fixed';
  duration: number; // Duration in milliseconds
  start?: Date; // For fixed windows
  end?: Date; // For fixed windows
}

// ============================================================================
// Monitoring and Alerting
// ============================================================================

/**
 * Alert threshold configuration
 */
export interface AlertThreshold {
  name: string;
  condition: AlertCondition;
  severity: AlertSeverity;
  threshold: number;
  duration: number; // Duration before alerting (ms)
  cooldown: number; // Cooldown period between alerts (ms)
  enabled: boolean;
}

/**
 * Alert condition
 */
export interface AlertCondition {
  operator: 'gt' | 'gte' | 'lt' | 'lte' | 'eq' | 'ne';
  value: number;
  evaluationWindow: TimeWindow;
}

/**
 * Burn rate alert configuration
 */
export interface BurnRateAlert {
  name: string;
  threshold: number; // Burn rate multiplier
  window: TimeWindow;
  severity: AlertSeverity;
  alertWhenRemaining: number; // Percentage of budget remaining
}

/**
 * Contact information
 */
export interface ContactInfo {
  email?: string;
  slack?: string;
  phone?: string;
  pager?: string;
}

/**
 * SLA credit calculation method
 */
export enum SLACreditCalculation {
  PER_DAY_DOWN = 'per_day_down',
  PER_PERCENTAGE_DOWN = 'per_percentage_down',
  PER_INCIDENT = 'per_incident',
  CUMULATIVE = 'cumulative',
}

/**
 * SLA compliance metrics
 */
export interface SLAComplianceMetrics {
  period: {
    start: Date;
    end: Date;
  };
  availability: {
    achieved: number;
    target: number;
    compliance: number;
  };
  responseTime: {
    achieved: number;
    target: number;
    compliance: number;
  };
  errorRate: {
    achieved: number;
    target: number;
    compliance: number;
  };
  credits: {
    earned: number;
    paid: number;
    pending: number;
  };
  violations: SLAViolation[];
}

/**
 * SLA violation record
 */
export interface SLAViolation {
  id: string;
  timestamp: Date;
  metric: string;
  achieved: number;
  target: number;
  duration: number; // Duration of violation (ms)
  impact: {
    usersAffected: number;
    revenueImpact?: number;
  };
  resolution?: {
    timestamp: Date;
    rootCause: string;
    correctiveActions: string[];
  };
}

// ============================================================================
// Real-time Monitoring Data
// ============================================================================

/**
 * SLI measurement data point
 */
export interface SLIMeasurement {
  id: string;
  sliId: string;
  timestamp: Date;
  value: number;
  quality: DataQuality;
  metadata: Record<string, any>;
}

/**
 * Data quality indicators
 */
export interface DataQuality {
  completeness: number; // Percentage of expected data
  accuracy: number; // Confidence in measurement accuracy
  timeliness: number; // How recent is the data
  validity: boolean; // Is the data valid
  issues?: string[];
}

/**
 * SLO evaluation result
 */
export interface SLOEvaluation {
  id: string;
  sloId: string;
  timestamp: Date;
  period: {
    start: Date;
    end: Date;
  };
  objective: {
    target: number;
    achieved: number;
    compliance: number;
  };
  budget: {
    total: number;
    consumed: number;
    remaining: number;
    burnRate: number;
    trend: BurnRateTrend;
  };
  status: SLOEvaluationStatus;
  alerts: SLOAlert[];
  value?: number; // Current evaluation value
  metadata: {
    evaluationDuration: number;
    dataPoints: number;
    confidence: number;
  };
}

/**
 * SLO evaluation status
 */
export enum SLOEvaluationStatus {
  COMPLIANT = 'compliant',
  VIOLATION = 'violation',
  WARNING = 'warning',
  INSUFFICIENT_DATA = 'insufficient_data',
  EVALUATING = 'evaluating',
}

/**
 * Burn rate trend
 */
export enum BurnRateTrend {
  INCREASING = 'increasing',
  DECREASING = 'decreasing',
  STABLE = 'stable',
  UNKNOWN = 'unknown',
}

/**
 * SLO alert
 */
export interface SLOAlert {
  id: string;
  sloId: string;
  type: SLOAlertType;
  severity: AlertSeverity;
  title: string;
  message: string;
  timestamp: Date;
  acknowledged: boolean;
  acknowledgedBy?: string;
  acknowledgedAt?: Date;
  resolved: boolean;
  resolvedAt?: Date;
  metadata: {
    threshold: number;
    actualValue: number;
    evaluationWindow: TimeWindow;
  };
}

/**
 * SLO alert types
 */
export enum SLOAlertType {
  BUDGET_EXHAUSTED = 'budget_exhausted',
  BURN_RATE_HIGH = 'burn_rate_high',
  COMPLIANCE_WARNING = 'compliance_warning',
  SLO_VIOLATION = 'slo_violation',
  DATA_QUALITY = 'data_quality',
  EVALUATION_FAILED = 'evaluation_failed',
}

// ============================================================================
// Analytics and Reporting
// ============================================================================

/**
 * SLO trend analysis
 */
export interface SLOTrendAnalysis {
  sloId: string;
  period: {
    start: Date;
    end: Date;
  };
  metrics: {
    compliance: TrendData[];
    burnRate: TrendData[];
    errorBudget: TrendData[];
  };
  patterns: {
    seasonal?: SeasonalPattern;
    cyclical?: CyclicalPattern;
    anomalies: Anomaly[];
  };
  predictions: {
    nextPeriod: Prediction;
    riskAssessment: RiskAssessment;
  };
  recommendations: SLORecommendation[];
}

/**
 * Trend data point
 */
export interface TrendData {
  timestamp: Date;
  value: number;
  confidence: number;
}

/**
 * Seasonal pattern
 */
export interface SeasonalPattern {
  period: 'daily' | 'weekly' | 'monthly' | 'quarterly' | 'yearly';
  amplitude: number;
  phase: number;
  confidence: number;
}

/**
 * Cyclical pattern
 */
export interface CyclicalPattern {
  period: number; // Duration in milliseconds
  amplitude: number;
  phase: number;
  confidence: number;
}

/**
 * Anomaly detection
 */
export interface Anomaly {
  timestamp: Date;
  type: AnomalyType;
  severity: AnomalySeverity;
  description: string;
  score: number;
  expectedValue: number;
  actualValue: number;
  deviation: number;
}

/**
 * Anomaly types
 */
export enum AnomalyType {
  SPIKE = 'spike',
  DROP = 'drop',
  TREND_CHANGE = 'trend_change',
  PATTERN_BREAK = 'pattern_break',
  OUTLIER = 'outlier',
}

/**
 * Anomaly severity
 */
export enum AnomalySeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

/**
 * Prediction data
 */
export interface Prediction {
  value: number;
  confidence: number;
  upperBound: number;
  lowerBound: number;
  methodology: string;
}

/**
 * Risk assessment
 */
export interface RiskAssessment {
  level: 'low' | 'medium' | 'high' | 'critical';
  probability: number; // 0-1
  impact: number; // 0-1
  score: number; // 0-100
  factors: RiskFactor[];
  mitigation: string[];
}

/**
 * Risk factor
 */
export interface RiskFactor {
  name: string;
  weight: number;
  value: number;
  impact: string;
}

/**
 * SLO recommendation
 */
export interface SLORecommendation {
  id: string;
  type: RecommendationType;
  priority: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  expectedImpact: string;
  effort: 'low' | 'medium' | 'high';
  dependencies: string[];
  implementation: {
    steps: string[];
    timeline: string;
    owner: string;
  };
}

/**
 * Recommendation types
 */
export enum RecommendationType {
  ADJUST_THRESHOLD = 'adjust_threshold',
  CHANGE_PERIOD = 'change_period',
  IMPROVE_RELABILITY = 'improve_reliability',
  OPTIMIZE_PERFORMANCE = 'optimize_performance',
  ADD_MONITORING = 'add_monitoring',
  MODIFY_ALERTING = 'modify_alerting',
}

// ============================================================================
// Dashboard and Visualization
// ============================================================================

/**
 * SLO dashboard configuration
 */
export interface SLODashboard {
  id: string;
  name: string;
  description: string;
  owner: string;
  layout: DashboardLayout;
  widgets: DashboardWidget[];
  filters: DashboardFilter[];
  refreshInterval: number; // Milliseconds
  autoRefresh: boolean;
  sharing: {
    enabled: boolean;
    public: boolean;
    allowedUsers?: string[];
    allowedTeams?: string[];
  };
  metadata: {
    createdAt: Date;
    updatedAt: Date;
    lastViewed?: Date;
    version: number;
  };
}

/**
 * Dashboard layout
 */
export interface DashboardLayout {
  type: 'grid' | 'flex' | 'custom';
  columns: number;
  rowHeight: number;
  margin: number;
  padding: number;
}

/**
 * Dashboard widget
 */
export interface DashboardWidget {
  id: string;
  type: WidgetType;
  title: string;
  position: {
    x: number;
    y: number;
    width: number;
    height: number;
  };
  config: WidgetConfig;
  dataSource: DataSource;
  visualization: VisualizationConfig;
  refreshInterval?: number; // Override dashboard refresh interval
}

/**
 * Widget types
 */
export enum WidgetType {
  SLO_STATUS = 'slo_status',
  COMPLIANCE_CHART = 'compliance_chart',
  BURN_RATE = 'burn_rate',
  ERROR_BUDGET = 'error_budget',
  TREND_ANALYSIS = 'trend_analysis',
  SERVICE_HEALTH = 'service_health',
  ALERT_SUMMARY = 'alert_summary',
  PERFORMANCE_METRICS = 'performance_metrics',
  CUSTOM_CHART = 'custom_chart',
  TEXT_PANEL = 'text_panel',
  STAT_PANEL = 'stat_panel',
}

/**
 * Widget configuration
 */
export interface WidgetConfig {
  sloIds?: string[];
  sliIds?: string[];
  timeRange?: TimeRange;
  thresholds?: number[];
  colors?: string[];
  legend?: boolean;
  annotations?: Annotation[];
}

/**
 * Data source configuration
 */
export interface DataSource {
  type: 'slo_evaluations' | 'sli_measurements' | 'alerts' | 'custom_query';
  query?: string;
  filters?: Record<string, any>;
  aggregation?: SLIAggregation;
}

/**
 * Visualization configuration
 */
export interface VisualizationConfig {
  type: ChartType;
  axes?: {
    x: AxisConfig;
    y: AxisConfig;
  };
  series?: SeriesConfig[];
  colors?: string[];
  interactive?: boolean;
}

/**
 * Chart types
 */
export enum ChartType {
  LINE = 'line',
  AREA = 'area',
  BAR = 'bar',
  PIE = 'pie',
  GAUGE = 'gauge',
  HEATMAP = 'heatmap',
  SCATTER = 'scatter',
  HISTOGRAM = 'histogram',
  TABLE = 'table',
  STAT = 'stat',
}

/**
 * Axis configuration
 */
export interface AxisConfig {
  label: string;
  format?: string;
  min?: number;
  max?: number;
  scale?: 'linear' | 'logarithmic';
}

/**
 * Series configuration
 */
export interface SeriesConfig {
  name: string;
  source: string;
  color?: string;
  type?: 'line' | 'area' | 'bar';
  yAxis?: number;
}

/**
 * Time range
 */
export interface TimeRange {
  type: 'relative' | 'absolute';
  from?: Date;
  to?: Date;
  duration?: number; // For relative ranges (ms)
}

/**
 * Dashboard filter
 */
export interface DashboardFilter {
  name: string;
  field: string;
  type: FilterType;
  options?: FilterOption[];
  defaultValue?: any;
  required: boolean;
}

/**
 * Filter types
 */
export enum FilterType {
  SELECT = 'select',
  MULTI_SELECT = 'multi_select',
  TEXT = 'text',
  DATE_RANGE = 'date_range',
  NUMBER_RANGE = 'number_range',
  BOOLEAN = 'boolean',
}

/**
 * Filter option
 */
export interface FilterOption {
  label: string;
  value: any;
  description?: string;
}

/**
 * Annotation
 */
export interface Annotation {
  timestamp: Date;
  title: string;
  description: string;
  type: 'incident' | 'deployment' | 'maintenance' | 'custom';
  color?: string;
}

// ============================================================================
// Configuration and Management
// ============================================================================

/**
 * SLO framework configuration
 */
export interface SLOFrameworkConfig {
  monitoring: {
    evaluationInterval: number; // Milliseconds
    dataRetentionPeriod: number; // Milliseconds
    batchSize: number;
    maxConcurrency: number;
  };
  storage: {
    type: 'influxdb' | 'prometheus' | 'timescaledb' | 'custom';
    connection: Record<string, any>;
    retention: {
      raw: number; // Milliseconds
      hourly: number; // Milliseconds
      daily: number; // Milliseconds
    };
  };
  alerting: {
    enabled: boolean;
    defaultChannels: string[];
    rateLimiting: {
      maxAlertsPerMinute: number;
      maxAlertsPerHour: number;
    };
  };
  dashboard: {
    enabled: boolean;
    defaultRefreshInterval: number;
    maxWidgets: number;
  };
  analytics: {
    enabled: boolean;
    predictionWindow: number; // Milliseconds
    anomalyDetection: {
      enabled: boolean;
      sensitivity: number; // 0-1
      minConfidence: number; // 0-1
    };
  };
  security: {
    authentication: {
      enabled: boolean;
      method: 'oauth' | 'jwt' | 'basic' | 'custom';
    };
    authorization: {
      enabled: boolean;
      roles: Record<string, string[]>;
    };
  };
}

// ============================================================================
// Error Budget Interfaces
// ============================================================================

/**
 * Error Budget - represents the remaining error budget for an SLO
 */
export interface ErrorBudget {
  sloId: string;
  period: BudgetPeriod;
  total: number;
  consumed: number;
  remaining: number;
  burnRate: number;
  lastUpdated: Date;
  consumption?: {
    current: number;
    rate: number;
    trend: 'increasing' | 'decreasing' | 'stable';
  };

  metadata?: unknown

  utilization?: unknown
}

/**
 * Budget Projection - future projections for error budget consumption
 */
export interface BudgetProjection {
  sloId: string;
  projectionPeriod: BudgetPeriod;
  projectedConsumption: number;
  projectedExhaustion: Date | null;
  confidence: number;
  assumptions: string[];
  scenarios: {
    optimistic: Date | null;
    realistic: Date | null;
    pessimistic: Date | null;
  };

  exhaustionProbability?: unknown

  metadata?: unknown
}

/**
 * Burn Rate Analysis - analysis of error budget burn rate patterns
 */
export interface BurnRateAnalysis {
  sloId: string;
  analysisPeriod: BudgetPeriod;
  currentRate: number;
  averageRate: number;
  peakRate: number;
  trend: 'stable' | 'increasing' | 'decreasing' | 'volatile';
  velocity: number;
  timeToExhaustion: number | null;
  factors: {
    recentIncidents: number;
    degradedOperations: number;
    seasonalFactors: number;
  };

  period?: unknown

  sloName?: unknown

  health?: unknown

  metadata?: unknown
}

/**
 * Budget Alert - alert configuration and state for error budget
 */
export interface BudgetAlert {
  id: string;
  sloId: string;
  type: 'burn_rate' | 'exhaustion' | 'consumption' | 'projection';
  severity: 'info' | 'warning' | 'critical';
  threshold: number;
  currentValue: number;
  enabled: boolean;
  triggered: boolean;
  lastTriggered?: Date;
  acknowledged: boolean;
  acknowledgedBy?: string;
  acknowledgedAt?: Date;
  resolutionNotes?: string;
  alertType?: string;
  burnRate?: number;

  resolved?: unknown

  resolvedBy?: unknown

  resolvedAt?: unknown

  resolution?: unknown
}

/**
 * Budget Consumption - detailed consumption tracking
 */
export interface BudgetConsumption {
  sloId: string;
  period: BudgetPeriod;
  consumption: {
    total: number;
    byCategory: Record<string, number>;
    byTimeSlot: Array<{
      timeSlot: Date;
      consumption: number;
      operations: number;
    }>;
  };
  sources: Array<{
    type: string;
    contribution: number;
    details: Record<string, any>;
  }>;

  currentRate?: unknown
}

/**
 * Budget Period - time period for budget calculations
 */
export interface BudgetPeriod {
  start: Date;
  end: Date;
  type: 'rolling' | 'calendar' | 'custom';
  length: number; // milliseconds
}

/**
 * Error Budget Policy - policies governing error budget management
 */
export interface ErrorBudgetPolicy {
  id: string;
  name: string;
  description: string;
  sloIds: string[];
  rules: {
    deploymentHalt: {
      enabled: boolean;
      threshold: number; // percentage of budget consumed
    };
    approvalRequired: {
      enabled: boolean;
      threshold: number; // percentage of budget consumed
      approvers: string[];
    };
    emergencyMode: {
      enabled: boolean;
      threshold: number; // percentage of budget consumed
      actions: string[];
    };
    notificationChannels: {
      info: string[];
      warning: string[];
      critical: string[];
    };
  };
}

/**
 * Budget Utilization - comprehensive budget utilization metrics
 */
export interface BudgetUtilization {
  sloId: string;
  period: BudgetPeriod;
  utilization: {
    percentage: number;
    trend: 'improving' | 'degrading' | 'stable';
    efficiency: number;
  };
  breakdown: {
    successfulOperations: number;
    failedOperations: number;
    degradedOperations: number;
    excludedOperations: number;
  };
  recommendations: string[];
}

// Define AlertSeverity as both type and enum for compatibility
export type AlertSeverity = 'info' | 'warning' | 'critical' | 'error';
export const AlertSeverity = {
  INFO: 'info' as AlertSeverity,
  WARNING: 'warning' as AlertSeverity,
  CRITICAL: 'critical' as AlertSeverity,
  ERROR: 'error' as AlertSeverity,
  EMERGENCY: 'error' as AlertSeverity, // Map EMERGENCY to ERROR for now
} as const;

// ============================================================================
// Type Guards and Validation
// ============================================================================

/**
 * Type guard for SLI
 */
export function isSLI(obj: any): obj is SLI {
  return (
    obj &&
    typeof obj === 'object' &&
    'id' in obj &&
    'name' in obj &&
    'type' in obj &&
    'measurement' in obj &&
    'thresholds' in obj
  );
}

/**
 * Type guard for SLO
 */
export function isSLO(obj: any): obj is SLO {
  return (
    obj &&
    typeof obj === 'object' &&
    'id' in obj &&
    'name' in obj &&
    'sli' in obj &&
    'objective' in obj &&
    'budgeting' in obj &&
    'status' in obj
  );
}

/**
 * Type guard for SLO evaluation
 */
export function isSLOEvaluation(obj: any): obj is SLOEvaluation {
  return (
    obj &&
    typeof obj === 'object' &&
    'id' in obj &&
    'sloId' in obj &&
    'timestamp' in obj &&
    'objective' in obj &&
    'budget' in obj &&
    'status' in obj
  );
}

/**
 * Validate SLO configuration
 */
export function validateSLO(slo: SLO): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Basic validation
  if (!slo.id || slo.id.trim() === '') {
    errors.push('SLO ID is required');
  }

  if (!slo.name || slo.name.trim() === '') {
    errors.push('SLO name is required');
  }

  if (!slo.sli || slo.sli.trim() === '') {
    errors.push('SLI reference is required');
  }

  // Objective validation
  if (slo.objective.target < 0 || slo.objective.target > 100) {
    errors.push('SLO target must be between 0 and 100');
  }

  if (slo.objective.target < 90) {
    warnings.push('SLO target is below 90% - consider setting a more ambitious target');
  }

  // Budget validation
  if (slo.budgeting.errorBudget < 0 || slo.budgeting.errorBudget > 100 - slo.objective.target) {
    errors.push('Error budget must be valid and not exceed the gap between 100% and target');
  }

  // Alerting validation
  if (slo.alerting.enabled && (!slo.alerting.thresholds || slo.alerting.thresholds.length === 0)) {
    warnings.push('Alerting is enabled but no thresholds are configured');
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

/**
 * Validation result
 */
export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

// ============================================================================
// Additional SLO Monitoring Interfaces
// ============================================================================

/**
 * Circuit Breaker Statistics
 */
export interface CircuitBreakerStats {
  name: string;
  state: 'closed' | 'open' | 'half_open';
  failureCount: number;
  successCount: number;
  lastFailureTime?: Date;
  lastSuccessTime?: Date;
  threshold: number;
  timeout: number;
}

/**
 * Monitoring Dashboard Configuration
 */
export interface MonitoringDashboardConfig {
  id: string;
  name: string;
  description: string;
  refreshInterval: number;
  widgets: Array<{
    id: string;
    type: 'metric' | 'chart' | 'table' | 'alert';
    title: string;
    query: string;
    position: { x: number; y: number; width: number; height: number };
  }>;
  timeRange: {
    start: Date;
    end: Date;
  };
  filters: Record<string, any>;

  layout?: unknown

  variables?: unknown

  tags?: unknown
}

/**
 * Dashboard Template
 */
export interface DashboardTemplate {
  id: string;
  name: string;
  description: string;
  category: string;
  widgets: Array<{
    type: string;
    title: string;
    query: string;
    defaultPosition: { x: number; y: number; width: number; height: number };
  }>;
  variables: Array<{
    name: string;
    type: 'query' | 'constant' | 'list';
    values: string[];
  }>;

  tags?: unknown
}

/**
 * Metric Definition
 */
export interface MetricDefinition {
  name: string;
  type: 'counter' | 'gauge' | 'histogram' | 'summary';
  description: string;
  unit: string;
  labels: Record<string, string>;
  aggregation?: 'sum' | 'avg' | 'min' | 'max' | 'count';
}

/**
 * Alert Rule (extended)
 */
export interface AlertRule {
  id: string;
  name: string;
  description: string;
  query: string;
  condition: string;
  threshold: number;
  severity: AlertSeverity;
  enabled: boolean;
  duration: number;
  labels: Record<string, string>;
  annotations: Record<string, string>;
  notificationChannels: string[];
}

/**
 * SLO Breach Incident
 */
export interface SLOBreachIncident {
  id: string;
  sloId: string;
  timestamp: Date;
  severity: BreachSeverity;
  description: string;
  impact: string;
  affectedServices: string[];
  metrics: {
    actualValue: number;
    targetValue: number;
    deviation: number;
  };
  status: IncidentStatus;
  response: IncidentResponse;
  escalation: EscalationLevel;
  communication: {
    stakeholders: string[];
    channels: string[];
    frequency: string;
  };
  resolution?: {
    timestamp: Date;
    actions: string[];
    rootCause: string;
    preventiveMeasures: string[];
  };

  metadata?: unknown

  detectedAt?: unknown

  notifications?: unknown

  sloName?: unknown

  impactAssessment?: unknown
}

/**
 * Breach Severity
 */
export type BreachSeverity = 'minor' | 'major' | 'critical' | 'catastrophic';

/**
 * Notification Channel
 */
export interface NotificationChannel {
  id: string;
  name: string;
  type: 'email' | 'slack' | 'pagerduty' | 'webhook' | 'sms';
  config: Record<string, any>;
  enabled: boolean;
  rateLimit?: {
    maxPerMinute: number;
    maxPerHour: number;
  };
}

/**
 * Incident Status
 */
export type IncidentStatus = 'open' | 'investigating' | 'identified' | 'monitoring' | 'resolved' | 'closed';

/**
 * Incident Response
 */
export interface IncidentResponse {
  commander: string;
  team: string[];
  communications: {
    internal: string[];
    external: string[];
  };
  actions: Array<{
    timestamp: Date;
    action: string;
    owner: string;
    status: 'pending' | 'in_progress' | 'completed';
  }>;
  timeline: Array<{
    timestamp: Date;
    event: string;
    details: string;
  }>;

  status?: unknown

  completedAt?: unknown

  error?: unknown
}

/**
 * Escalation Level
 */
export type EscalationLevel = 'l1' | 'l2' | 'l3' | 'l4' | 'executive';

/**
 * Impact Assessment
 */
export interface ImpactAssessment {
  businessImpact: 'low' | 'medium' | 'high' | 'critical';
  customerImpact: 'none' | 'partial' | 'significant' | 'total';
  financialImpact: {
    estimatedLoss: number;
    currency: string;
    confidence: number;
  };
  operationalImpact: {
    affectedSystems: string[];
    degradedServices: string[];
    capacityReduction: number;
  };
  reputationalImpact: 'low' | 'medium' | 'high' | 'severe';

  score?: unknown

  revenueImpact?: unknown

  usersAffected?: unknown
}

/**
 * SLO Monitoring Configuration
 */
export interface SLOMonitoringConfig {
  evaluationInterval?: number;
  breachCheckInterval?: number;
  errorBudgetCalculationInterval?: number;
  circuitBreakerCheckInterval?: number;
  dashboardRefreshInterval?: number;
  automatedResponseEnabled?: boolean;
  incidentCreationEnabled?: boolean;
  alertCorrelationEnabled?: boolean;
  escalationEnabled?: boolean;
  alerting?: {
    enabled: boolean;
    channels: string[];
    thresholds: Array<{
      type: 'burn_rate' | 'consumption' | 'exhaustion';
      threshold: number;
      severity: AlertSeverity;
    }>;
  };
  dashboarding?: {
    enabled: boolean;
    refreshInterval: number;
    templates: string[];
  };
  reporting?: {
    enabled: boolean;
    frequency: 'daily' | 'weekly' | 'monthly';
    recipients: string[];
  };
}

/**
 * Integrated Monitoring Snapshot
 */
export interface IntegratedMonitoringSnapshot {
  timestamp: Date;
  slos: Array<{
    sloId: string;
    status: 'healthy' | 'warning' | 'critical';
    budgetRemaining: number;
    burnRate: number;
    achievement: number;
  }>;
  services: Array<{
    name: string;
    status: 'operational' | 'degraded' | 'down';
    sli: Record<string, number>;
    dependencies: string[];
  }>;
  incidents: Array<{
    id: string;
    severity: AlertSeverity;
    status: IncidentStatus;
    impact: string;
    duration: number;
  }>;
  alerts: Array<{
    id: string;
    rule: string;
    severity: AlertSeverity;
    state: 'firing' | 'resolved';
    value: number;
  }>;
}

/**
 * SLO Health Status
 */
export interface SLOHealthStatus {
  overall: 'healthy' | 'warning' | 'critical';
  score: number; // 0-100
  slos: Array<{
    id: string;
    name: string;
    status: 'healthy' | 'warning' | 'critical';
    achievement: number;
    budgetRemaining: number;
    trend: 'improving' | 'stable' | 'degrading';
  }>;
  services: Array<{
    name: string;
    status: 'operational' | 'degraded' | 'down';
    healthScore: number;
    issues: string[];
  }>;
  lastUpdated: Date;
}

/**
 * Alert Correlation
 */
export interface AlertCorrelation {
  id: string;
  timestamp: Date;
  alerts: Array<{
    id: string;
    rule: string;
    severity: AlertSeverity;
    service: string;
    value: number;
  }>;
  correlationType: 'service' | 'dependency' | 'infrastructure' | 'unknown';
  confidence: number; // 0-1
  rootCauseHypothesis: string;
  relatedSLOs: string[];
  impactedServices: string[];
  recommendations: string[];
}

/**
 * Automated Response
 */
export interface AutomatedResponse {
  id: string;
  trigger: {
    type: 'alert' | 'slo_breach' | 'incident';
    id: string;
  };
  actions: Array<{
    type: 'custom' | 'rollback' | 'notification' | 'scaling' | 'restart';
    target: string;
    parameters: Record<string, any>;
    status: 'pending' | 'executing' | 'completed' | 'failed';
    result?: any;
    error?: string;
  }>;
  status: 'pending' | 'executing' | 'completed' | 'failed' | 'cancelled';
  startedAt: Date;
  completedAt?: Date;
  effectiveness: {
    resolvedIssue: boolean;
    timeToResolution: number;
    sideEffects: string[];
  };
}