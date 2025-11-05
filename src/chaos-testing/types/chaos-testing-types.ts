/**
 * Chaos Testing Framework - Types and Interfaces
 *
 * This module defines the core types and interfaces for the chaos testing system
 * that validates vector store resilience under various failure scenarios.
 */

export interface ChaosExperimentConfig {
  id: string;
  name: string;
  description: string;
  hypothesis: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  duration: number; // in seconds
  blastRadius: 'component' | 'service' | 'cluster';
  safetyChecks: SafetyCheck[];
  steadyStateDuration: number; // time to establish baseline
  experimentDuration: number; // time to run chaos injection
  recoveryDuration: number; // time to monitor recovery
}

export interface SafetyCheck {
  type: 'health_check' | 'performance_threshold' | 'error_rate' | 'resource_usage';
  threshold: number;
  comparison: 'less_than' | 'greater_than' | 'equals';
  metric: string;
  enabled: boolean;
}

export interface ChaosScenario {
  id: string;
  name: string;
  type: ChaosScenarioType;
  config: ChaosScenarioConfig;
  injectionPoint: InjectionPoint;
  verification: VerificationCriteria;
}

export type ChaosScenarioType =
  | 'qdrant_connection_failure'
  | 'network_latency'
  | 'packet_loss'
  | 'query_timeout'
  | 'resource_exhaustion'
  | 'memory_pressure'
  | 'disk_exhaustion'
  | 'circuit_breaker_trip'
  | 'cascade_failure'
  | 'partial_partition';

export interface ChaosScenarioConfig {
  intensity: number; // 0-100 scale
  probability?: number; // for probabilistic scenarios
  duration: number; // in seconds
  rampUpTime: number; // gradual injection time
  parameters: Record<string, any>;
}

export interface InjectionPoint {
  component: string;
  method?: string;
  layer: 'network' | 'application' | 'database' | 'infrastructure';
  target: string;
}

export interface VerificationCriteria {
  gracefulDegradation: DegradationVerification;
  alerting: AlertingVerification;
  recovery: RecoveryVerification;
  performance: PerformanceVerification;
}

export interface DegradationVerification {
  expectedFallback: boolean;
  maxDegradationTime: number; // ms
  minServiceAvailability: number; // percentage
  expectedCircuitBreakerState: 'open' | 'closed' | 'half_open';
  userFacingErrors: UserFacingErrorExpectation[];
}

export interface UserFacingErrorExpectation {
  errorType: string;
  message: string;
  expectedRate: number; // percentage
  retryable: boolean;
}

export interface AlertingVerification {
  expectedAlerts: ExpectedAlert[];
  maxAlertDelay: number; // ms
  alertEscalation: boolean;
  expectedSeverity: ('info' | 'warning' | 'error' | 'critical')[];
}

export interface ExpectedAlert {
  name: string;
  severity: 'info' | 'warning' | 'error' | 'critical';
  source: string;
  conditions: string[];
}

export interface RecoveryVerification {
  maxRecoveryTime: number; // ms
  expectedFinalState: 'healthy' | 'degraded' | 'failed';
  dataConsistency: boolean;
  autoRecovery: boolean;
}

export interface PerformanceVerification {
  maxResponseTimeIncrease: number; // percentage
  maxThroughputDecrease: number; // percentage
  maxErrorRate: number; // percentage
  resourceLimits: ResourceLimits;
}

export interface ResourceLimits {
  maxCPUUsage: number; // percentage
  maxMemoryUsage: number; // percentage
  maxDiskIO: number; // percentage
  maxNetworkIO: number; // percentage
}

export interface ChaosExperimentResult {
  experimentId: string;
  scenario: ChaosScenario;
  startTime: Date;
  endTime: Date;
  status: ExperimentStatus;
  steadyStateMetrics: SystemMetrics;
  chaosMetrics: ChaosMetrics;
  recoveryMetrics: RecoveryMetrics;
  verificationResults: VerificationResults;
  mttrMetrics: MTTRMetrics;
  incidentReport?: IncidentReport;
}

export type ExperimentStatus =
  | 'pending'
  | 'running'
  | 'completed'
  | 'failed'
  | 'aborted'
  | 'safety_check_failed';

export interface SystemMetrics {
  timestamp: Date;
  responseTime: ResponseTimeMetrics;
  throughput: ThroughputMetrics;
  errorRate: ErrorRateMetrics;
  resourceUsage: ResourceMetrics;
  circuitBreaker: CircuitBreakerMetrics;
  health: HealthMetrics;
}

export interface ResponseTimeMetrics {
  mean: number;
  p50: number;
  p95: number;
  p99: number;
  max: number;
}

export interface ThroughputMetrics {
  requestsPerSecond: number;
  operationsPerSecond: number;
  bytesPerSecond: number;
}

export interface ErrorRateMetrics {
  totalErrors: number;
  errorRate: number;
  errorsByType: Record<string, number>;
}

export interface ResourceMetrics {
  cpu: number;
  memory: number;
  diskIO: number;
  networkIO: number;
  openConnections: number;
}

export interface CircuitBreakerMetrics {
  state: 'closed' | 'open' | 'half_open';
  failureRate: number;
  numberOfCalls: number;
  numberOfSuccessfulCalls: number;
  numberOfFailedCalls: number;
}

export interface HealthMetrics {
  overallStatus: 'healthy' | 'degraded' | 'unhealthy';
  componentStatus: Record<string, 'healthy' | 'degraded' | 'unhealthy'>;
  lastHealthCheck: Date;
}

export interface ChaosMetrics {
  injectionEffectiveness: number;
  systemImpact: SystemImpact;
  degradationPatterns: DegradationPattern[];
  alertingResponse: AlertingResponse;
}

export interface SystemImpact {
  responseTimeImpact: number; // percentage increase
  throughputImpact: number; // percentage decrease
  errorRateImpact: number; // percentage increase
  availabilityImpact: number; // percentage decrease
}

export interface DegradationPattern {
  timestamp: Date;
  type: 'graceful' | 'abrupt' | 'cascade';
  severity: 'low' | 'medium' | 'high' | 'critical';
  component: string;
  description: string;
}

export interface AlertingResponse {
  alertsTriggered: TriggeredAlert[];
  averageAlertDelay: number;
  alertAccuracy: number;
  falsePositives: number;
}

export interface TriggeredAlert {
  alertId: string;
  name: string;
  severity: string;
  triggeredAt: Date;
  resolvedAt?: Date;
  delay: number; // ms from incident start
}

export interface RecoveryMetrics {
  recoveryTime: number; // ms
  recoveryPattern: RecoveryPattern;
  dataConsistencyCheck: DataConsistencyResult;
  componentRecoveryOrder: ComponentRecoverySequence;
}

export interface RecoveryPattern {
  type: 'immediate' | 'gradual' | 'step_function' | 'oscillating';
  timeToFirstSignOfRecovery: number;
  timeToFullRecovery: number;
  recoveryStability: number; // 0-1 scale
}

export interface DataConsistencyResult {
  consistent: boolean;
  inconsistencies: DataInconsistency[];
  verificationTime: number;
}

export interface DataInconsistency {
  type: 'missing_data' | 'corrupted_data' | 'duplicate_data' | 'stale_data';
  count: number;
  severity: 'low' | 'medium' | 'high';
  location: string;
}

export interface ComponentRecoverySequence {
  sequence: string[];
  timeline: RecoveryStep[];
}

export interface RecoveryStep {
  component: string;
  recoveredAt: Date;
  recoveryTime: number; // ms
  method: 'auto' | 'manual' | 'cascade';
}

export interface VerificationResults {
  gracefulDegradation: GracefulDegradationResult;
  alerting: AlertingVerificationResult;
  recovery: RecoveryVerificationResult;
  performance: PerformanceVerificationResult;
  overall: OverallVerificationResult;
}

export interface GracefulDegradationResult {
  passed: boolean;
  fallbackActivated: boolean;
  degradationTime: number;
  serviceAvailability: number;
  circuitBreakerState: string;
  userFacingErrors: UserFacingErrorResult[];
}

export interface UserFacingErrorResult {
  errorType: string;
  actualRate: number;
  expectedRate: number;
  withinThreshold: boolean;
}

export interface AlertingVerificationResult {
  passed: boolean;
  alertsTriggered: number;
  expectedAlerts: number;
  averageAlertDelay: number;
  maxAlertDelay: number;
  escalationOccurred: boolean;
}

export interface RecoveryVerificationResult {
  passed: boolean;
  recoveryTime: number;
  expectedRecoveryTime: number;
  finalState: string;
  dataConsistent: boolean;
  autoRecovery: boolean;
}

export interface PerformanceVerificationResult {
  passed: boolean;
  responseTimeIncrease: number;
  throughputDecrease: number;
  errorRate: number;
  withinResourceLimits: boolean;
}

export interface OverallVerificationResult {
  passed: boolean;
  score: number; // 0-100
  confidence: number; // 0-1
  recommendations: string[];
  criticalFailures: string[];
}

export interface MTTRMetrics {
  meanTimeToDetect: number; // ms
  meanTimeToRespond: number; // ms
  meanTimeToResolve: number; // ms
  meanTimeToRecover: number; // ms
  overallMTTR: number; // ms
}

export interface IncidentReport {
  incidentId: string;
  severity: string;
  startTime: Date;
  endTime: Date;
  duration: number;
  rootCause: RootCauseAnalysis;
  impact: ImpactAssessment;
  lessonsLearned: string[];
  actionItems: ActionItem[];
}

export interface RootCauseAnalysis {
  primaryCause: string;
  contributingFactors: string[];
  evidence: string[];
  confidence: number; // 0-1
}

export interface ImpactAssessment {
  userImpact: UserImpact;
  businessImpact: BusinessImpact;
  technicalImpact: TechnicalImpact;
}

export interface UserImpact {
  affectedUsers: number;
  totalUsers: number;
  impactPercentage: number;
  functionalityAffected: string[];
}

export interface BusinessImpact {
  revenueImpact: number;
  customerSatisfactionImpact: number;
  brandImpact: string;
  complianceImpact: string;
}

export interface TechnicalImpact {
  componentsAffected: string[];
  dataLoss: boolean;
  systemDowntime: number;
  recoveryComplexity: 'low' | 'medium' | 'high';
}

export interface ActionItem {
  id: string;
  description: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  assignee?: string;
  dueDate?: Date;
  status: 'open' | 'in_progress' | 'completed';
}

// Chaos Injection Strategy Types
export interface ChaosInjectionStrategy {
  name: string;
  description: string;
  implementation: string;
  parameters: Record<string, any>;
  rollbackProcedure: string;
}

// Experiment Execution Context
export interface ExperimentExecutionContext {
  experimentId: string;
  environment: 'development' | 'staging' | 'production';
  systemState: 'normal' | 'degraded' | 'recovering';
  blastRadiusControl: BlastRadiusControl;
  monitoring: MonitoringContext;
  safety: SafetyContext;
}

export interface BlastRadiusControl {
  maxAffectedComponents: number;
  isolationZones: string[];
  failSafes: FailSafe[];
}

export interface FailSafe {
  trigger: string;
  action: 'abort_experiment' | 'reduce_intensity' | 'extend_duration';
  threshold: number;
}

export interface MonitoringContext {
  metricsCollectionInterval: number;
  alertingEnabled: boolean;
  loggingLevel: 'debug' | 'info' | 'warn' | 'error';
  tracingEnabled: boolean;
}

export interface SafetyContext {
  emergencyShutdown: boolean;
  maxAllowedDowntime: number;
  maxAllowedErrorRate: number;
  healthCheckEndpoints: string[];
  rollbackProcedures: string[];
}

export interface ExperimentReport {
  id: string;
  title: string;
  summary: string;
  results: ChaosExperimentResult[];
  createdAt: Date;
  generatedBy: string;
}