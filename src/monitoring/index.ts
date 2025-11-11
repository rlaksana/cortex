
/**
 * MCP Cortex Monitoring Module - Complete Alerting System
 *
 * This module provides comprehensive monitoring and alerting capabilities for the MCP Cortex system.
 * It includes:
 * - Health monitoring and checks
 * - Alert management and routing
 * - Multi-channel notifications
 * - On-call management and escalation
 * - Runbook integration and execution
 * - Alert testing and validation
 * - Metrics collection and dashboards
 * - End-to-end alerting system integration
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

// Core health monitoring
export { HealthCheckService, monitoringHealthCheckService } from './health-check-service.js';
export { HealthEndpointManager as healthEndpoint } from './health-endpoint.js';
export { ProductionHealthChecker as productionHealthChecker } from './production-health-checker.js';

// Alert management system
export {
  type Alert,
  type AlertAction,
  AlertManagementService,
  alertManagementService,
  type AlertMetrics,
  type AlertRule,
  type AlertTestResult,
  type AlertTestScenario,
  type EscalationPolicy,
  type EscalationRule,
  type NotificationAttempt,
  type Runbook,
  type RunbookStep,
} from './alert-management-service.js';

// Notification channels
export {
  type EmailConfig,
  EmailNotificationChannel,
  type NotificationChannel,
  notificationChannelRegistry,
  type NotificationResult,
  type PagerDutyConfig,
  PagerDutyNotificationChannel,
  type SlackConfig,
  SlackNotificationChannel,
  type SNSConfig,
  SNSNotificationChannel,
  type TeamsConfig,
  TeamsNotificationChannel,
  type WebhookConfig,
  WebhookNotificationChannel,
} from './notification-channels.js';

// On-call management
export {
  type AlertAssignmentOptions,
  type EscalationLevel,
  type EscalationPath,
  type EscalationResult,
  // type OnCallAssignment, // exported from oncall-management-service
  type OnCallHandoff,
  OnCallManagementService,
  onCallManagementService,
  type OnCallMetrics,
  type OnCallRotation,
  type OnCallSchedule,
  type OnCallUser,
  type UserWorkload,
} from './oncall-management-service.js';

// Runbook integration
export {
  type ExecutionResult,
  type Runbook as RunbookDefinition,
  type RunbookExecution,
  RunbookIntegrationService,
  runbookIntegrationService,
  type RunbookRecommendation,
  type RunbookStep as RunbookStepDefinition,
  type RunbookTemplate,
  type StepExecution,
} from './runbook-integration-service.js';

// Alert testing and validation
export {
  type AlertTestExecution,
  AlertTestingService,
  alertTestingService,
  type AlertTestSuite,
  type FaultInjection,
  type LoadTestConfig,
  type LoadTestResult,
  type TestEnvironment,
  type TestStep,
} from './alert-testing-service.js';

// Metrics and dashboard integration
export {
  type AlertMetrics as AlertMetricsDefinition,
  AlertMetricsService,
  alertMetricsService,
  type DashboardConfig,
  type DashboardMetrics,
  type DashboardPanel,
  type MetricSeries,
  type PanelData,
  type PredictionMetrics,
  type TimeRange,
  type TrendMetrics,
} from './alert-metrics-service.js';

// System integration
export {
  type AlertSystemConfig,
  type AlertSystemIntegrations,
  AlertSystemIntegrationService,
  alertSystemIntegrationService,
  type AlertSystemStatus,
  type ComponentStatus,
  type FaultScenario,
  type FaultScenarioTestResult,
  type SystemHealthStatus,
  type SystemTestResults,
} from './alert-system-integration.js';

// Existing monitoring components
// (Removed duplicate exports and non-existent healthStructuredLogger)

// Core monitoring components
export {
  type CircuitBreakerEvent,
  type CircuitBreakerEventType,
  type CircuitBreakerHealthStatus,
  circuitBreakerMonitor,
  type CircuitBreakerMonitorConfig,
} from './circuit-breaker-monitor.js';
export {
  type ContainerHealthState,
  type ContainerProbeConfig,
  containerProbesHandler,
  type ProbeResult,
} from './container-probes.js';
export {
  enhancedPerformanceCollector,
  type EnhancedPerformanceCollectorConfig,
  type HistogramData,
  type MCPOperationMetrics,
  type MetricData,
  MetricType,
  type SystemPerformanceMetrics,
} from './enhanced-performance-collector.js';
export {
  type HealthHistoryEntry,
  type MCPServerHealthConfig,
  type MCPServerHealthMetrics,
  mcpServerHealthMonitor,
} from './mcp-server-health-monitor.js';
export {
  QdrantConnectionStatus,
  type QdrantHealthCheckResult,
  QdrantHealthMonitor,
  type QdrantHealthMonitorConfig,
  type QdrantPerformanceMetrics,
} from './qdrant-health-monitor.js';

// dropped non-existent logger named exports

export {
  type APIResponse,
  type DashboardSummary,
  type HealthAlert,
  type HealthDashboardAPIConfig,
  healthDashboardAPIHandler,
  type HistoricalHealthData,
  type RealTimeHealthData,
} from './health-dashboard-api.js';

// Re-export existing monitoring components
// export { monitoringHealthCheckService } from './health-check-service.js';
// export { monitoringServer } from './monitoring-server.js';
// export { performanceCollector } from './performance-collector.js';
// export { metricsService } from './metrics-service.js';

// Utility functions
export {
  type ComponentHealth,
  DependencyStatus,
  DependencyType,
  HealthStatus,
  type ProductionHealthResult,
  type SystemHealthResult,
} from '../types/unified-health-interfaces.js';

// Health monitoring manager class

// HealthMonitoringManager removed to avoid unresolved cross-module references in aggregator.

