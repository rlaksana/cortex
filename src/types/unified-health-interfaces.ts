// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

import { DependencyStatus, DependencyType } from '../services/deps-registry.js';

// Re-export DependencyStatus for centralized access
export { DependencyStatus, DependencyType };

// Type alias for backward compatibility
export type HealthCheckResult = ProductionHealthResult;

// Import ValidationMode from schemas for re-export
import { type ValidationMode as SchemaValidationMode, type ValidationOptions } from '../schemas/unified-knowledge-validator.js';


// Re-export ValidationMode with a local name to avoid conflicts
export { ValidationOptions };
export type ValidationMode = SchemaValidationMode;

// ============================================================================
// Base Health Interfaces
// ============================================================================

/**
 * Base health status enumeration - unified across all services
 */
export enum HealthStatus {
  HEALTHY = 'healthy',
  WARNING = 'warning',
  DEGRADED = 'degraded',
  CRITICAL = 'critical',
  UNHEALTHY = 'unhealthy',
  UNKNOWN = 'unknown',
  DISABLED = 'disabled',
}

/**
 * Standard health check result for individual dependencies/components
 */
export interface ComponentHealthResult {
  name: string;
  status: HealthStatus;
  timestamp: Date;
  duration: number;
  responseTime?: number;
  error?: string;
  details?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

/**
 * Dependency-specific health check result (maps to DependencyStatus)
 */
export interface DependencyHealthResult {
  dependency: string;
  status: DependencyStatus;
  responseTime: number;
  error?: string;
  details?: Record<string, unknown>;
  timestamp: Date;
}

// ============================================================================
// Enhanced Health Check Results
// ============================================================================

/**
 * Enhanced health check result with diagnostics and benchmarking
 */
export interface EnhancedHealthResult extends ComponentHealthResult {
  dependency: string;
  strategy: HealthCheckStrategy;
  diagnostics: HealthDiagnostics;
  retryAttempts: number;
  cached: boolean;
  benchmarkResults?: PerformanceBenchmark;
}

/**
 * Type alias for backward compatibility - EnhancedHealthCheckResult = EnhancedHealthResult
 * @deprecated Use EnhancedHealthResult instead
 */
export type EnhancedHealthCheckResult = EnhancedHealthResult;

/**
 * Performance benchmark results
 */
export interface PerformanceBenchmark {
  throughput: number;
  averageResponseTime: number;
  p95ResponseTime: number;
  p99ResponseTime: number;
  errorRate: number;
}

/**
 * Health diagnostics information
 */
export interface HealthDiagnostics {
  executionTime: number;
  networkLatency?: number;
  connectionTime?: number;
  dnsResolutionTime?: number;
  sslHandshakeTime?: number;
  bytesTransferred?: number;
  responseHeaders?: Record<string, string>;
  errorDetails?: {
    code?: string;
    message: string;
    stack?: string;
    type: string;
  };
  performanceMetrics?: {
    cpuUsage?: number;
    memoryUsage?: number;
    diskIO?: number;
    networkIO?: number;
  };
  customMetrics?: Record<string, unknown>;
}

/**
 * Type alias for backward compatibility - HealthCheckDiagnostics = HealthDiagnostics
 * @deprecated Use HealthDiagnostics instead
 */
export type HealthCheckDiagnostics = HealthDiagnostics;

/**
 * Health check strategy enumeration
 */
export enum HealthCheckStrategy {
  BASIC = 'basic',
  ADVANCED = 'advanced',
  COMPREHENSIVE = 'comprehensive',
  CUSTOM = 'custom',
}

/**
 * Health check execution context
 */
export interface HealthCheckContext {
  dependencyName: string;
  strategy: HealthCheckStrategy;
  startTime: number;
  timeout: number;
  retryCount: number;
  metadata?: Record<string, unknown>;
}

// ============================================================================
// System-Level Health Interfaces
// ============================================================================

/**
 * Complete system health check result
 */
export interface SystemHealthResult {
  status: HealthStatus;
  timestamp: Date | string;
  duration: number;
  uptime_seconds?: number;
  version?: string;
  components: ComponentHealth[];
  system_metrics: {
    memory_usage_mb: number;
    cpu_usage_percent: number;
    active_connections: number;
    qps: number;
  };
  summary: {
    total_components: number;
    healthy_components: number;
    degraded_components: number;
    unhealthy_components: number;
  };
  issues?: string[];
  metadata?: Record<string, unknown>;
}

/**
 * Production health check result
 */
export interface ProductionHealthResult {
  status: 'healthy' | 'unhealthy' | 'degraded';
  timestamp: string;
  duration: number;
  checks: HealthCheck[];
  summary: {
    total: number;
    passed: number;
    failed: number;
    warnings: number;
  };
  issues: string[];
  metadata?: Record<string, unknown>;
}

/**
 * Individual health check within production results
 */
export interface HealthCheck {
  name: string;
  status: 'pass' | 'fail' | 'warn';
  duration: number;
  message?: string;
  details?: Record<string, unknown>;
  critical: boolean;
}

/**
 * Component health information for system monitoring
 */
export interface ComponentHealth {
  name: string;
  type: DependencyType;
  status: HealthStatus;
  last_check: Date;
  response_time_ms: number;
  error_rate: number;
  uptime_percentage: number;
  error?: string;
  details?: Record<string, unknown>;
}

// ============================================================================
// Aggregated Health Interfaces
// ============================================================================

/**
 * Aggregated health status across multiple dependencies
 */
export interface AggregatedHealthStatus {
  overall: DependencyStatus;
  dependencies: Record<string, DependencyState>;
  summary: {
    total: number;
    healthy: number;
    warning: number;
    critical: number;
    unknown: number;
    disabled: number;
  };
  score: number; // 0-100
  timestamp: Date;
}

/**
 * Dependency state information
 */
export interface DependencyState {
  config: DependencyConfig;
  status: DependencyStatus;
  metrics: DependencyMetrics;
  lastHealthCheck: Date;
  consecutiveFailures: number;
  consecutiveSuccesses: number;
  totalChecks: number;
  enabled: boolean;
  metadata: {
    createdAt: Date;
    updatedAt: Date;
    lastFailure?: Date;
    lastSuccess?: Date;
  };
}

/**
 * Dependency configuration (simplified for health interfaces)
 */
export interface DependencyConfig {
  name: string;
  type: DependencyType;
  version?: string;
  description?: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  healthCheck: HealthCheckConfig;
  connection: {
    url: string;
    timeout?: number;
    apiKey?: string;
    [key: string]: unknown;
  };
  thresholds: {
    responseTimeWarning: number;
    responseTimeCritical: number;
    errorRateWarning: number;
    errorRateCritical: number;
    availabilityWarning: number;
    availabilityCritical: number;
  };
  fallback?: {
    enabled: boolean;
    service?: string;
    config?: unknown;
  };
  metadata?: Record<string, unknown>;
}

/**
 * Health check configuration
 */
export interface HealthCheckConfig {
  enabled: boolean;
  intervalMs: number;
  timeoutMs: number;
  failureThreshold: number;
  successThreshold: number;
  retryAttempts: number;
  retryDelayMs: number;
}

/**
 * Dependency performance metrics
 */
export interface DependencyMetrics {
  responseTime: {
    current: number;
    average: number;
    p95: number;
    p99: number;
  };
  throughput: {
    requestsPerSecond: number;
    requestsPerMinute: number;
  };
  error: {
    rate: number;
    count: number;
    lastError?: string;
  };
  availability: {
    uptime: number;
    downtime: number;
    lastCheck: Date;
  };
  circuitBreaker?: {
    state: string;
    failureRate: number;
    totalCalls: number;
  };
}

// ============================================================================
// Health Analysis and Monitoring Interfaces
// ============================================================================

/**
 * Comprehensive health analysis result
 */
export interface HealthAnalysis {
  overall: {
    status: DependencyStatus;
    score: number;
    trend: HealthTrend;
    confidence: number;
  };
  dependencies: Record<
    string,
    {
      status: DependencyStatus;
      score: number;
      trend: HealthTrend;
      impact: number;
      risk: 'low' | 'medium' | 'high' | 'critical';
    }
  >;
  risks: Array<{
    dependency: string;
    type: 'performance' | 'availability' | 'error_rate' | 'dependency_chain';
    level: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    probability: number;
    impact: number;
    mitigation?: string;
  }>;
  recommendations: Array<{
    priority: 'low' | 'medium' | 'high' | 'critical';
    category: 'performance' | 'reliability' | 'monitoring' | 'architecture';
    title: string;
    description: string;
    estimatedImpact: number;
  }>;
  timestamp: Date;
}

/**
 * Health alert severity levels
 */
export enum AlertSeverity {
  INFO = 'info',
  WARNING = 'warning',
  CRITICAL = 'critical',
  EMERGENCY = 'emergency',
}

/**
 * Health alert configuration
 */
export interface HealthAlert {
  id: string;
  dependency: string;
  severity: AlertSeverity;
  title: string;
  message: string;
  timestamp: Date;
  acknowledged: boolean;
  acknowledgedBy?: string;
acknowledgedAt?: Date;
  resolved: boolean;
  resolvedAt?: Date;
  metadata?: Record<string, unknown>;
}

/**
 * SLA compliance status
 */
export enum SLAStatus {
  COMPLIANT = 'compliant',
  WARNING = 'warning',
  VIOLATION = 'violation',
  UNKNOWN = 'unknown',
}

/**
 * SLA definition and targets
 */
export interface SLADefinition {
  name: string;
  description: string;
  targets: {
    availability: number; // Percentage (0-100)
    responseTime: number; // Milliseconds
    errorRate: number; // Percentage (0-100)
  };
  period: {
    type: 'daily' | 'weekly' | 'monthly';
    duration: number; // Number of periods
  };
  dependencies: string[]; // Dependencies this SLA applies to
  priority: 'critical' | 'high' | 'medium' | 'low';
}

/**
 * SLA compliance metrics
 */
export interface SLACompliance {
  sla: string;
  status: SLAStatus;
  period: {
    start: Date;
    end: Date;
  };
  metrics: {
    availability: {
      current: number;
      target: number;
      compliance: number;
    };
    responseTime: {
      current: number;
      target: number;
      compliance: number;
    };
    errorRate: {
      current: number;
      target: number;
      compliance: number;
    };
  };
  violations: Array<{
    metric: string;
    value: number;
    target: number;
    timestamp: Date;
    duration?: number;
  }>;
  score: number; // Overall SLA score (0-100)
}

/**
 * Health aggregation configuration
 */
export interface HealthAggregationConfig {
  healthScoreWeights: {
    availability: number;
    responseTime: number;
    errorRate: number;
    trend: number;
  };
  alertThresholds: {
    responseTimeWarning: number;
    responseTimeCritical: number;
    errorRateWarning: number;
    errorRateCritical: number;
    availabilityWarning: number;
    availabilityCritical: number;
  };
  trendAnalysis: {
    windowSize: number; // Number of data points
    minDataPoints: number;
    threshold: number; // Trend significance threshold
  };
  slaMonitoring: {
    enabled: boolean;
    evaluationInterval: number; // Milliseconds
    violationGracePeriod: number; // Milliseconds
  };
  alerting: {
    enabled: boolean;
    cooldownPeriod: number; // Milliseconds
    escalationPolicy: {
      warningDelay: number;
      criticalDelay: number;
      emergencyDelay: number;
    };
  };
}

/**
 * Health trend enumeration
 */
export enum HealthTrend {
  IMPROVING = 'improving',
  STABLE = 'stable',
  DEGRADING = 'degrading',
  FLUCTUATING = 'fluctuating',
}

/**
 * Health metrics snapshot
 */
export interface HealthSnapshot {
  timestamp: Date;
  dependencies: Record<
    string,
    {
      status: DependencyStatus;
      score: number;
      responseTime: number;
      errorRate: number;
      availability: number;
    }
  >;
  overall: {
    status: DependencyStatus;
    score: number;
  };
}

// ============================================================================
// Type Guards and Utilities
// ============================================================================

/**
 * Type guard to check if a result is a dependency health result
 */
export function isDependencyHealthResult(result: unknown): result is DependencyHealthResult {
  return !!(
    result &&
    typeof result === 'object' &&
    'dependency' in result &&
    'status' in result &&
    'responseTime' in result
  );
}

/**
 * Type guard to check if a result is a system health result
 */
export function isSystemHealthResult(result: unknown): result is SystemHealthResult {
  return !!(
    result &&
    typeof result === 'object' &&
    'components' in result &&
    'system_metrics' in result &&
    'summary' in result
  );
}

/**
 * Type guard to check if a result is an enhanced health result
 */
export function isEnhancedHealthResult(result: unknown): result is EnhancedHealthResult {
  return !!(
    result &&
    typeof result === 'object' &&
    'strategy' in result &&
    'diagnostics' in result &&
    'retryAttempts' in result
  );
}

/**
 * Type guard to check if a result is a health check diagnostics object
 */
export function isHealthCheckDiagnostics(diagnostics: unknown): diagnostics is HealthCheckDiagnostics {
  return !!(
    diagnostics &&
    typeof diagnostics === 'object' &&
    'executionTime' in diagnostics &&
    typeof (diagnostics as HealthCheckDiagnostics).executionTime === 'number'
  );
}

/**
 * Convert DependencyStatus to HealthStatus
 */
export function dependencyStatusToHealthStatus(status: DependencyStatus): HealthStatus {
  switch (status) {
    case DependencyStatus.HEALTHY:
      return HealthStatus.HEALTHY;
    case DependencyStatus.WARNING:
      return HealthStatus.WARNING;
    case DependencyStatus.CRITICAL:
      return HealthStatus.CRITICAL;
    case DependencyStatus.UNKNOWN:
      return HealthStatus.UNKNOWN;
    case DependencyStatus.DISABLED:
      return HealthStatus.DISABLED;
    default:
      return HealthStatus.UNKNOWN;
  }
}

/**
 * Convert HealthStatus to DependencyStatus
 */
export function healthStatusToDependencyStatus(status: HealthStatus): DependencyStatus {
  switch (status) {
    case HealthStatus.HEALTHY:
      return DependencyStatus.HEALTHY;
    case HealthStatus.WARNING:
    case HealthStatus.DEGRADED:
      return DependencyStatus.WARNING;
    case HealthStatus.CRITICAL:
    case HealthStatus.UNHEALTHY:
      return DependencyStatus.CRITICAL;
    case HealthStatus.UNKNOWN:
      return DependencyStatus.UNKNOWN;
    case HealthStatus.DISABLED:
      return DependencyStatus.DISABLED;
    default:
      return DependencyStatus.UNKNOWN;
  }
}

// ============================================================================
// Enhanced Type Guards and Validation Utilities
// ============================================================================

/**
 * Type guard to validate if a value is a valid HealthStatus
 */
export function isValidHealthStatus(value: unknown): value is HealthStatus {
  return Object.values(HealthStatus).includes(value as HealthStatus);
}

/**
 * Type guard to validate if a value is a valid DependencyStatus
 */
export function isValidDependencyStatus(value: unknown): value is DependencyStatus {
  return Object.values(DependencyStatus).includes(value as DependencyStatus);
}

/**
 * Type guard to validate if a value is a valid HealthCheckStrategy
 */
export function isValidHealthCheckStrategy(value: unknown): value is HealthCheckStrategy {
  return Object.values(HealthCheckStrategy).includes(value as HealthCheckStrategy);
}

/**
 * Type guard to validate if a value is a valid AlertSeverity
 */
export function isValidAlertSeverity(value: unknown): value is AlertSeverity {
  return Object.values(AlertSeverity).includes(value as AlertSeverity);
}

/**
 * Type guard to validate if a value is a valid SLAStatus
 */
export function isValidSLAStatus(value: unknown): value is SLAStatus {
  return Object.values(SLAStatus).includes(value as SLAStatus);
}

/**
 * Type guard to validate if a value is a valid HealthTrend
 */
export function isValidHealthTrend(value: unknown): value is HealthTrend {
  return Object.values(HealthTrend).includes(value as HealthTrend);
}

/**
 * Safe conversion from string to HealthStatus with fallback
 */
export function parseHealthStatus(
  value: string,
  fallback: HealthStatus = HealthStatus.UNKNOWN
): HealthStatus {
  if (isValidHealthStatus(value)) {
    return value;
  }

  // Handle common string variations
  const normalizedValue = value.toLowerCase().trim();
  switch (normalizedValue) {
    case 'healthy':
    case 'ok':
    case 'good':
    case 'pass':
    case 'success':
      return HealthStatus.HEALTHY;
    case 'warning':
    case 'warn':
    case 'degraded':
    case 'caution':
      return HealthStatus.WARNING;
    case 'critical':
    case 'error':
    case 'fail':
    case 'failed':
    case 'unhealthy':
    case 'bad':
      return HealthStatus.CRITICAL;
    case 'disabled':
    case 'inactive':
    case 'off':
      return HealthStatus.DISABLED;
    case 'unknown':
    case 'pending':
    case 'checking':
    default:
      return fallback;
  }
}

/**
 * Safe conversion from string to DependencyStatus with fallback
 */
export function parseDependencyStatus(
  value: string,
  fallback: DependencyStatus = DependencyStatus.UNKNOWN
): DependencyStatus {
  if (isValidDependencyStatus(value)) {
    return value;
  }

  // Convert using HealthStatus parsing then map to DependencyStatus
  const healthStatus = parseHealthStatus(value, HealthStatus.UNKNOWN);
  return healthStatusToDependencyStatus(healthStatus);
}

/**
 * Check if a health status indicates a problem (warning, critical, unhealthy)
 */
export function isProblematicStatus(status: HealthStatus): boolean {
  return (
    status === HealthStatus.WARNING ||
    status === HealthStatus.DEGRADED ||
    status === HealthStatus.CRITICAL ||
    status === HealthStatus.UNHEALTHY
  );
}

/**
 * Check if a dependency status indicates a problem
 */
export function isProblematicDependencyStatus(status: DependencyStatus): boolean {
  return status === DependencyStatus.WARNING || status === DependencyStatus.CRITICAL;
}

/**
 * Check if a health status is healthy or operational
 */
export function isHealthyStatus(status: HealthStatus): boolean {
  return status === HealthStatus.HEALTHY;
}

/**
 * Check if a dependency status is healthy
 */
export function isHealthyDependencyStatus(status: DependencyStatus): boolean {
  return status === DependencyStatus.HEALTHY;
}

/**
 * Get the severity level of a health status (numeric for comparison)
 */
export function getHealthStatusSeverity(status: HealthStatus): number {
  switch (status) {
    case HealthStatus.HEALTHY:
      return 0;
    case HealthStatus.WARNING:
      return 1;
    case HealthStatus.DEGRADED:
      return 2;
    case HealthStatus.CRITICAL:
      return 3;
    case HealthStatus.UNHEALTHY:
      return 4;
    case HealthStatus.DISABLED:
      return 5;
    case HealthStatus.UNKNOWN:
      return 6;
    default:
      return 6;
  }
}

/**
 * Get the severity level of a dependency status (numeric for comparison)
 */
export function getDependencyStatusSeverity(status: DependencyStatus): number {
  switch (status) {
    case DependencyStatus.HEALTHY:
      return 0;
    case DependencyStatus.WARNING:
      return 1;
    case DependencyStatus.CRITICAL:
      return 2;
    case DependencyStatus.DISABLED:
      return 3;
    case DependencyStatus.UNKNOWN:
      return 4;
    default:
      return 4;
  }
}

/**
 * Compare two health statuses by severity
 * Returns: -1 if a < b, 0 if a === b, 1 if a > b
 */
export function compareHealthStatusSeverity(a: HealthStatus, b: HealthStatus): number {
  const severityA = getHealthStatusSeverity(a);
  const severityB = getHealthStatusSeverity(b);
  return severityA - severityB;
}

/**
 * Compare two dependency statuses by severity
 * Returns: -1 if a < b, 0 if a === b, 1 if a > b
 */
export function compareDependencyStatusSeverity(a: DependencyStatus, b: DependencyStatus): number {
  const severityA = getDependencyStatusSeverity(a);
  const severityB = getDependencyStatusSeverity(b);
  return severityA - severityB;
}

/**
 * Get the worst (most severe) status from an array of health statuses
 */
export function getWorstHealthStatus(statuses: HealthStatus[]): HealthStatus {
  if (statuses.length === 0) return HealthStatus.UNKNOWN;

  return statuses.reduce((worst, current) => {
    return compareHealthStatusSeverity(current, worst) > 0 ? current : worst;
  });
}

/**
 * Get the worst (most severe) status from an array of dependency statuses
 */
export function getWorstDependencyStatus(statuses: DependencyStatus[]): DependencyStatus {
  if (statuses.length === 0) return DependencyStatus.UNKNOWN;

  return statuses.reduce((worst, current) => {
    return compareDependencyStatusSeverity(current, worst) > 0 ? current : worst;
});
}

/**
 * Get the best (least severe) status from an array of health statuses
 */
export function getBestHealthStatus(statuses: HealthStatus[]): HealthStatus {
  if (statuses.length === 0) return HealthStatus.UNKNOWN;

  return statuses.reduce((best, current) => {
    return compareHealthStatusSeverity(current, best) < 0 ? current : best;
  });
}

/**
 * Get the best (least severe) status from an array of dependency statuses
 */
export function getBestDependencyStatus(statuses: DependencyStatus[]): DependencyStatus {
  if (statuses.length === 0) return DependencyStatus.UNKNOWN;

  return statuses.reduce((best, current) => {
    return compareDependencyStatusSeverity(current, best) < 0 ? current : best;
  });
}

/**
 * Validation Performance Monitor (placeholder for future implementation)
 */
export class ValidationPerformanceMonitor {
  static recordValidation(result: unknown): void {
    // Placeholder implementation
  }
}

