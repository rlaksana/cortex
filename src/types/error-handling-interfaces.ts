/**
 * Error Handling System Interfaces
 *
 * Comprehensive type definitions for the error handling utilities system
 * covering error classification, recovery mechanisms, reporting, analytics,
 * user messaging, prevention, and monitoring integration.
 */

export interface ErrorClassification {
  type: string;
  category:
    | 'validation'
    | 'infrastructure'
    | 'external_service'
    | 'business_logic'
    | 'security'
    | 'throttling';
  severity: 'info' | 'warning' | 'error' | 'critical';
  recoverable: boolean;
  recovery_priority: 'low' | 'medium' | 'high' | 'critical';
  context: Record<string, unknown>;
}

export interface ErrorRecoveryStrategy {
  type: 'exponential_backoff' | 'linear_backoff' | 'fixed_delay' | 'immediate';
  maxAttempts: number;
  baseDelay?: number;
  maxDelay?: number;
  backoffMultiplier?: number;
  jitter?: boolean;
}

export interface ErrorFallbackConfig {
  primary_service: string;
  fallback_services: string[];
  fallback_criteria: string[];
  quality_thresholds: Record<string, number>;
  performance_thresholds: Record<string, number>;
}

export interface CircuitBreakerConfig {
  failureThreshold: number;
  recoveryTimeout: number;
  monitoringPeriod: number;
  halfOpenMaxCalls?: number;
}

export interface ErrorReport {
  metadata: {
    report_type: string;
    format: 'json' | 'html' | 'csv' | 'pdf';
    generated_at: string;
    period: { start: string; end: string };
  };
  summary: {
    total_errors: number;
    critical_errors: number;
    unique_error_types: number;
    mean_time_to_resolution: number;
  };
  breakdown: {
    by_type: Record<string, number>;
    by_severity: Record<string, number>;
    by_service: Record<string, number>;
  };
  trends: {
    direction: 'increasing' | 'decreasing' | 'stable';
    rate: number;
    predictions: string[];
  };
}

export interface ErrorAnalytics {
  aggregation: {
    byType: Record<string, { count: number; severity_breakdown: Record<string, number> }>;
    byTimePeriod: Record<string, number>;
    total: number;
    period: { start: string; end: string };
  };
  trends: {
    trend: 'increasing' | 'decreasing' | 'stable';
    growth_rate: number;
    pattern: {
      cyclical: boolean;
      seasonal: boolean;
      spike_detected: boolean;
      spike_date?: string;
    };
    predictions: {
      next_day_expected: number;
      confidence: number;
      factors: string[];
    };
    recommendations: string[];
  };
  impact: {
    overall_impact: 'low' | 'medium' | 'high' | 'critical';
    user_impact: {
      total_affected: number;
      percentage_of_user_base: number;
      severity_breakdown: Record<string, number>;
    };
    business_impact: {
      total_revenue_impact: number;
      sla_compliance: number;
      customer_satisfaction_impact: string;
    };
    system_impact: {
      performance_degradation: number;
      availability_impact: number;
      resource_utilization_increase: number;
    };
    recommended_actions: string[];
  };
}

export interface ErrorMessage {
  title: string;
  message: string;
  details?: {
    field?: string;
    expected_format?: string;
    suggestions?: string[];
    technical_details?: Record<string, unknown>;
  };
  help_resources?: Array<{
    title: string;
    url: string;
  }>;
  resolution_guidance?: {
    immediate_actions: string[];
    long_term_solutions: string[];
    estimated_resolution_time: string;
    follow_up_required: boolean;
  };
}

export interface ErrorPreventionRule {
  field: string;
  required?: boolean;
  type?: 'string' | 'number' | 'boolean' | 'email' | 'url';
  format?: string;
  minLength?: number;
  maxLength?: number;
  min?: number;
  max?: number;
  pattern?: RegExp;
  custom?: (value: unknown) => boolean | string;
}

export interface ErrorBoundaryConfig {
  maxErrorsPerMinute: number;
  maxErrorRate: number;
  isolationTimeout: number;
  recoveryStrategy: 'graceful_degradation' | 'fail_fast' | 'circuit_breaker';
}

export interface ErrorMonitoringIntegration {
  logging: {
    enabled: boolean;
    levels: string[];
    indices: string[];
    retention_days: number;
  };
  alerting: {
    enabled: boolean;
    channels: string[];
    thresholds: Record<string, number>;
    escalation_rules: Record<string, string[]>;
  };
  correlation: {
    enabled: boolean;
    trace_headers: string[];
    correlation_window: number;
    min_correlation_strength: number;
  };
  analytics: {
    enabled: boolean;
    metrics_interval: number;
    aggregation_windows: number[];
    export_formats: string[];
  };
}

export interface ErrorContext {
  error: Error | string;
  classification?: ErrorClassification;
  recovery?: {
    strategy: string;
    steps: string[];
    estimated_time?: number;
    automatic?: boolean;
  };
  user_context?: {
    user_id?: string;
    plan?: string;
    request_critical?: boolean;
  };
  system_context?: {
    current_load?: string;
    available_fallbacks?: string[];
    service_health?: Record<string, unknown>;
  };
  timestamp: string;
}

export interface ValidationError {
  valid: boolean;
  errors: string[];
  warnings?: string[];
  sanitizedData?: Record<string, unknown>;
}

export interface ErrorDetectionResult {
  type: string;
  severity: 'info' | 'warning' | 'error' | 'critical';
  message: string;
  details?: Record<string, unknown>;
  recommendations?: string[];
}

export interface ErrorBoundaryResult {
  shouldReject: boolean;
  triggerBoundary?: () => {
    isolation: boolean;
    timeout: number;
    strategy: string;
    message: string;
  };
}

export interface GracefulDegradationResult {
  success: boolean;
  method?: string;
  result?: unknown;
  degradation_level: 'none' | 'partial' | 'full' | 'complete';
  error?: string;
}

export interface ErrorLoggingResult {
  logged: boolean;
  log_id?: string;
  indices?: string[];
  retention_days?: number;
  searchable_fields?: string[];
  error?: string;
}

export interface ErrorAlertResult {
  alert_id: string;
  triggered: boolean;
  type: string;
  channel: string[];
  escalation: boolean;
  timestamp: string;
  details?: Record<string, unknown>;
}

export interface PerformanceImpactResult {
  overall_impact: 'low' | 'medium' | 'high' | 'critical';
  degradation_factors: {
    response_time_degradation: number;
    throughput_degradation: number;
    error_rate_increase: number;
  };
  primary_causes: Array<{
    cause: string;
    contribution: number;
  }>;
  recommendations: string[];
  estimated_time_to_recovery: string;
  business_impact: {
    user_experience: string;
    revenue_impact: string;
    sla_compliance: string;
  };
}

export interface ErrorCorrelationResult {
  correlation_groups: Array<{
    group_id: string;
    primary_error: string;
    related_errors: string[];
    trace_id?: string;
    affected_services: string[];
    correlation_strength: number;
    root_cause_hypothesis: string;
  }>;
  total_correlated_errors: number;
  unique_error_patterns: number;
  recommended_investigations: string[];
}

export interface ErrorRecoveryWorkflow {
  steps: Array<{
    action: string;
    retry: boolean;
    timeout?: number;
    fallback?: string;
  }>;
}

export interface ErrorRecoveryResult {
  success: boolean;
  strategy?: string;
  attempts?: number;
  result?: unknown;
  error?: string;
  recovery_time?: number;
}

export interface ErrorAggregationOptions {
  groupBy: string[];
  timeWindow?: string;
  filters?: Record<string, unknown>;
  includePredictions?: boolean;
}

export interface ErrorTrendOptions {
  period: { start: string; end: string };
  granularity: 'hour' | 'day' | 'week' | 'month';
  includeSeasonality?: boolean;
  predictionDays?: number;
}

export interface ErrorImpactContext {
  errors: Array<{
    type: string;
    affected_users: number;
    duration: number;
    revenue_impact: number;
  }>;
  system_metrics: {
    availability: number;
    response_time_p95: number;
    error_rate: number;
  };
  business_metrics?: {
    revenue_loss?: number;
    customer_churn_risk?: number;
    sla_penalties?: number;
  };
}

export interface ErrorReportingOptions {
  format: 'json' | 'html' | 'csv' | 'pdf';
  includeDetails: boolean;
  includeTrends: boolean;
  includeRecommendations: boolean;
  audience: 'technical' | 'business' | 'executive';
}

export interface ErrorLocalizationContext {
  language: string;
  role: 'developer' | 'admin' | 'end_user' | 'support';
  technical_level: 'basic' | 'intermediate' | 'advanced';
  includeTechnicalDetails: boolean;
}

export interface ErrorPreventionContext {
  operation: string;
  data: unknown;
  user_context?: {
    plan: string;
    current_usage: Record<string, number>;
    limits: Record<string, number>;
  };
  service_context?: {
    current_load: string;
    dependencies: string[];
    health_status: Record<string, unknown>;
  };
}

export interface ErrorMonitoringContext {
  error: unknown;
  classification?: ErrorClassification;
  recovery?: unknown;
  user_context?: Record<string, unknown>;
  trace_id?: string;
  span_id?: string;
}

// Type guards and utility types
export type ErrorSeverity = 'info' | 'warning' | 'error' | 'critical';
export type ErrorCategory =
  | 'validation'
  | 'infrastructure'
  | 'external_service'
  | 'business_logic'
  | 'security'
  | 'throttling';
export type RecoveryStrategy =
  | 'retry'
  | 'fallback'
  | 'circuit_breaker'
  | 'graceful_degradation'
  | 'fail_fast';
export type ErrorFormat = 'json' | 'html' | 'csv' | 'pdf';
export type UserRole = 'developer' | 'admin' | 'end_user' | 'support';
export type TechnicalLevel = 'basic' | 'intermediate' | 'advanced';

// Utility type for error handling configuration
export interface ErrorHandlingConfig {
  classification: {
    enabled: boolean;
    custom_rules?: Record<string, (error: unknown) => ErrorClassification>;
  };
  recovery: {
    default_strategies: Record<string, ErrorRecoveryStrategy>;
    fallback_configs: Record<string, ErrorFallbackConfig>;
    circuit_breaker_defaults: CircuitBreakerConfig;
  };
  reporting: {
    enabled: boolean;
    default_format: ErrorFormat;
    retention_days: number;
    export_schedules: string[];
  };
  messaging: {
    default_language: string;
    fallback_language: string;
    enable_localization: boolean;
  };
  prevention: {
    enabled: boolean;
    validation_rules: Record<string, ErrorPreventionRule[]>;
    error_boundaries: Record<string, ErrorBoundaryConfig>;
  };
  monitoring: {
    enabled: boolean;
    logging: ErrorMonitoringIntegration['logging'];
    alerting: ErrorMonitoringIntegration['alerting'];
    correlation: ErrorMonitoringIntegration['correlation'];
    analytics: ErrorMonitoringIntegration['analytics'];
  };
}
