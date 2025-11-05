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
export { productionHealthChecker } from './production-health-checker.js';
export { healthEndpoint } from './health-endpoint.js';

// Alert management system
export {
  AlertManagementService,
  alertManagementService,
  type Alert,
  type AlertRule,
  type AlertAction,
  type EscalationPolicy,
  type EscalationRule,
  type AlertTestScenario,
  type AlertTestResult,
  type NotificationAttempt,
  type OnCallAssignment,
  type Runbook,
  type RunbookStep,
  type AlertMetrics,
} from './alert-management-service.js';

// Notification channels
export {
  EmailNotificationChannel,
  SlackNotificationChannel,
  PagerDutyNotificationChannel,
  TeamsNotificationChannel,
  WebhookNotificationChannel,
  SNSNotificationChannel,
  notificationChannelRegistry,
  type NotificationChannel,
  type NotificationResult,
  type EmailConfig,
  type SlackConfig,
  type PagerDutyConfig,
  type TeamsConfig,
  type WebhookConfig,
  type SNSConfig,
} from './notification-channels.js';

// On-call management
export {
  OnCallManagementService,
  onCallManagementService,
  type OnCallUser,
  type OnCallSchedule,
  type OnCallRotation,
  type OnCallAssignment,
  type OnCallHandoff,
  type EscalationPath,
  type EscalationLevel,
  type OnCallMetrics,
  type UserWorkload,
  type AlertAssignmentOptions,
  type EscalationResult,
} from './oncall-management-service.js';

// Runbook integration
export {
  RunbookIntegrationService,
  runbookIntegrationService,
  type Runbook as RunbookDefinition,
  type RunbookStep as RunbookStepDefinition,
  type RunbookExecution,
  type StepExecution,
  type ExecutionResult,
  type RunbookRecommendation,
  type RunbookTemplate,
  type RunbookTestResult,
  type TestScenario,
  type ExpectedTestResults,
} from './runbook-integration-service.js';

// Alert testing and validation
export {
  AlertTestingService,
  alertTestingService,
  type AlertTestSuite,
  type AlertTestExecution,
  type FaultInjection,
  type LoadTestConfig,
  type LoadTestResult,
  type TestEnvironment,
  type TestStep,
  type TestResult,
} from './alert-testing-service.js';

// Metrics and dashboard integration
export {
  AlertMetricsService,
  alertMetricsService,
  type DashboardMetrics,
  type AlertMetrics as AlertMetricsDefinition,
  type DashboardConfig,
  type DashboardPanel,
  type PanelData,
  type MetricSeries,
  type TimeRange,
  type TrendMetrics,
  type PredictionMetrics,
} from './alert-metrics-service.js';

// System integration
export {
  AlertSystemIntegrationService,
  alertSystemIntegrationService,
  type AlertSystemConfig,
  type AlertSystemStatus,
  type SystemHealthStatus,
  type ComponentStatus,
  type AlertSystemIntegrations,
  type SystemTestResults,
  type FaultScenario,
  type FaultScenarioTestResult,
} from './alert-system-integration.js';

// Existing monitoring components
export { mcpServerHealthMonitor } from './mcp-server-health-monitor.js';
export { enhancedPerformanceCollector } from './enhanced-performance-collector.js';
export { circuitBreakerMonitor } from './circuit-breaker-monitor.js';
export { healthStructuredLogger } from './health-structured-logger.js';
export { QdrantHealthMonitor } from './qdrant-health-monitor.js';
export { HealthStatus, DependencyType } from '../types/unified-health-interfaces.js';

// Core monitoring components
export {
  mcpServerHealthMonitor,
  type MCPServerHealthMetrics,
  type MCPServerHealthConfig,
  type HealthHistoryEntry,
} from './mcp-server-health-monitor.js';

export {
  QdrantHealthMonitor,
  QdrantConnectionStatus,
  type QdrantHealthCheckResult,
  type QdrantPerformanceMetrics,
  type QdrantHealthMonitorConfig,
} from './qdrant-health-monitor.js';

export {
  circuitBreakerMonitor,
  type CircuitBreakerHealthStatus,
  type CircuitBreakerEvent,
  type CircuitBreakerEventType,
  type CircuitBreakerMonitorConfig,
} from './circuit-breaker-monitor.js';

export {
  enhancedPerformanceCollector,
  MetricType,
  type SystemPerformanceMetrics,
  type MCPOperationMetrics,
  type MetricData,
  type HistogramData,
  type EnhancedPerformanceCollectorConfig,
} from './enhanced-performance-collector.js';

export {
  containerProbesHandler,
  type ContainerProbeConfig,
  type ProbeResult,
  type ContainerHealthState,
} from './container-probes.js';

export {
  healthStructuredLogger,
  LogLevel,
  HealthEventCategory,
  type StructuredLogEntry,
  type HealthStructuredLoggerConfig,
} from './health-structured-logger.js';

export {
  healthDashboardAPIHandler,
  type HealthDashboardAPIConfig,
  type APIResponse,
  type DashboardSummary,
  type RealTimeHealthData,
  type HistoricalHealthData,
  type HealthAlert,
} from './health-dashboard-api.js';

// Re-export existing monitoring components
export { monitoringHealthCheckService } from './health-check-service.js';
export { monitoringServer } from './monitoring-server.js';
export { performanceCollector } from './performance-collector.js';
export { metricsService } from './metrics-service.js';

// Utility functions
export {
  HealthStatus,
  DependencyType,
  DependencyStatus,
  type SystemHealthResult,
  type ComponentHealth,
  type ProductionHealthResult,
} from '../types/unified-health-interfaces.js';

// Health monitoring manager class
export class HealthMonitoringManager {
  private isStarted = false;
  private components: string[] = [];

  /**
   * Start all health monitoring components
   */
  async start(config?: {
    mcpServer?: Partial<any>;
    qdrant?: any;
    performance?: Partial<any>;
    circuitBreaker?: Partial<any>;
    container?: Partial<any>;
    logger?: Partial<any>;
    api?: Partial<any>;
  }): Promise<void> {
    if (this.isStarted) {
      console.warn('Health monitoring is already started');
      return;
    }

    try {
      console.info('Starting comprehensive health monitoring system...');

      // Start core monitoring components
      mcpServerHealthMonitor.start();
      this.components.push('mcp-server');

      enhancedPerformanceCollector.start();
      this.components.push('performance-collector');

      circuitBreakerMonitor.start();
      this.components.push('circuit-breaker');

      // Start Qdrant monitoring if URL is configured
      const qdrantUrl = process.env.QDRANT_URL;
      if (qdrantUrl) {
        const qdrantMonitor = new QdrantHealthMonitor({
          url: qdrantUrl,
          apiKey: process.env.QDRANT_API_KEY,
          ...config?.qdrant,
        });
        qdrantMonitor.start();
        this.components.push('qdrant');
      }

      // Start container probes if enabled
      if (process.env.ENABLE_CONTAINER_PROBES !== 'false') {
        // Container probes are handled via HTTP middleware, no separate start needed
        this.components.push('container-probes');
      }

      // Configure structured logger
      if (config?.logger) {
        healthStructuredLogger.updateConfig(config.logger);
      }
      this.components.push('structured-logger');

      this.isStarted = true;
      console.info(`Health monitoring started successfully with ${this.components.length} components`, {
        components: this.components,
        environment: process.env.NODE_ENV,
        version: process.env.npm_package_version,
      });

    } catch (error) {
      console.error('Failed to start health monitoring:', error);
      throw error;
    }
  }

  /**
   * Stop all health monitoring components
   */
  async stop(): Promise<void> {
    if (!this.isStarted) {
      console.warn('Health monitoring is not started');
      return;
    }

    try {
      console.info('Stopping health monitoring system...');

      // Stop components in reverse order
      mcpServerHealthMonitor.stop();
      enhancedPerformanceCollector.stop();
      circuitBreakerMonitor.stop();

      // Note: Qdrant monitor instance would need to be tracked for proper cleanup
      // Container probes don't need explicit stopping
      // Structured logger cleanup
      healthStructuredLogger.cleanup();

      this.components = [];
      this.isStarted = false;

      console.info('Health monitoring stopped successfully');

    } catch (error) {
      console.error('Error stopping health monitoring:', error);
      throw error;
    }
  }

  /**
   * Get current health status summary
   */
  getHealthSummary(): {
    overall: HealthStatus;
    components: Array<{
      name: string;
      status: HealthStatus;
      lastCheck: Date;
      details?: any;
    }>;
    uptime: number;
    alerts: number;
  } {
    const components = [];

    // MCP Server health
    const mcpStatus = mcpServerHealthMonitor.getCurrentStatus();
    components.push({
      name: 'MCP Server',
      status: mcpStatus,
      lastCheck: new Date(),
    });

    // Circuit breaker health
    const circuitHealth = circuitBreakerMonitor.getAllHealthStatuses();
    let circuitStatus = HealthStatus.HEALTHY;
    for (const [name, health] of circuitHealth) {
      components.push({
        name: `Circuit: ${name}`,
        status: health.healthStatus,
        lastCheck: new Date(),
        details: health.metrics,
      });
      if (health.healthStatus !== HealthStatus.HEALTHY) {
        circuitStatus = HealthStatus.DEGRADED;
      }
    }

    // Performance health
    const systemMetrics = enhancedPerformanceCollector.getSystemMetrics();
    let perfStatus = HealthStatus.HEALTHY;
    if (systemMetrics.memoryUsage.heapUsagePercent > 90 || systemMetrics.eventLoop.lag > 1000) {
      perfStatus = HealthStatus.DEGRADED;
    }
    components.push({
      name: 'System Performance',
      status: perfStatus,
      lastCheck: new Date(),
      details: systemMetrics,
    });

    // Calculate overall status
    const overall = [mcpStatus, circuitStatus, perfStatus].reduce((worst, current) => {
      if (current === HealthStatus.UNHEALTHY || worst === HealthStatus.UNHEALTHY) return HealthStatus.UNHEALTHY;
      if (current === HealthStatus.DEGRADED || worst === HealthStatus.DEGRADED) return HealthStatus.DEGRADED;
      return HealthStatus.HEALTHY;
    }, HealthStatus.HEALTHY);

    return {
      overall,
      components,
      uptime: process.uptime(),
      alerts: circuitBreakerMonitor.getActiveAlerts().length,
    };
  }

  /**
   * Get monitoring status
   */
  getStatus(): {
    started: boolean;
    components: string[];
    environment: string;
    version: string;
    uptime: number;
  } {
    return {
      started: this.isStarted,
      components: [...this.components],
      environment: process.env.NODE_ENV || 'development',
      version: process.env.npm_package_version || '2.0.1',
      uptime: process.uptime(),
    };
  }

  /**
   * Perform comprehensive health check
   */
  async performHealthCheck(): Promise<{
    status: HealthStatus;
    timestamp: Date;
    components: any[];
    issues: string[];
    metrics: any;
  }> {
    const results = [];
    const issues = [];

    try {
      // MCP Server health check
      const mcpHealth = await mcpServerHealthMonitor.performHealthCheck();
      results.push({
        name: 'MCP Server',
        status: mcpHealth.status,
        details: mcpHealth,
      });

      // Circuit breaker health check
      const circuitReport = circuitBreakerMonitor.generateHealthReport();
      results.push({
        name: 'Circuit Breakers',
        status: circuitReport.overallHealth,
        details: circuitReport,
      });

      // Performance metrics
      const systemMetrics = enhancedPerformanceCollector.getSystemMetrics();
      const mcpMetrics = enhancedPerformanceCollector.getMCPMetrics();
      results.push({
        name: 'Performance',
        status: systemMetrics.memoryUsage.heapUsagePercent > 90 ? HealthStatus.DEGRADED : HealthStatus.HEALTHY,
        details: { system: systemMetrics, mcp: mcpMetrics },
      });

      // Collect issues
      if (circuitReport.summary.criticalIssues.length > 0) {
        issues.push(...circuitReport.summary.criticalIssues);
      }
      if (circuitReport.summary.warnings.length > 0) {
        issues.push(...circuitReport.summary.warnings);
      }

      // Calculate overall status
      const overallStatus = results.reduce((worst, component) => {
        if (component.status === HealthStatus.UNHEALTHY) return HealthStatus.UNHEALTHY;
        if (component.status === HealthStatus.DEGRADED && worst !== HealthStatus.UNHEALTHY) return HealthStatus.DEGRADED;
        return worst;
      }, HealthStatus.HEALTHY);

      return {
        status: overallStatus,
        timestamp: new Date(),
        components: results,
        issues,
        metrics: {
          system: systemMetrics,
          mcp: mcpMetrics,
        },
      };

    } catch (error) {
      return {
        status: HealthStatus.UNHEALTHY,
        timestamp: new Date(),
        components: [],
        issues: [`Health check failed: ${error instanceof Error ? error.message : 'Unknown error'}`],
        metrics: {},
      };
    }
  }

  /**
   * Get Prometheus metrics
   */
  getPrometheusMetrics(): string {
    return enhancedPerformanceCollector.getPrometheusMetrics();
  }

  /**
   * Get active alerts
   */
  getActiveAlerts(): Array<{
    component: string;
    type: string;
    severity: string;
    message: string;
    count: number;
  }> {
    return circuitBreakerMonitor.getActiveAlerts();
  }

  /**
   * Force health check for testing
   */
  async forceHealthCheck(): Promise<any> {
    return this.performHealthCheck();
  }
}

// Re-export existing monitoring components
export { monitoringServer } from './monitoring-server.js';
export { performanceCollector } from './performance-collector.js';
export { metricsService } from './metrics-service.js';

// Utility functions
export {
  type SystemHealthResult,
  type ComponentHealth,
  type ProductionHealthResult,
  type DependencyStatus,
  type ValidationMode,
  type ValidationOptions,
} from '../types/unified-health-interfaces.js';

// Convenience exports for commonly used types
export type {
  AlertSeverity,
  ExecutionStatus,
  TestCategory,
  StepType,
  CommandType,
  VerificationType,
  PanelType,
  QueryType,
  AggregationType,
  VisualizationType,
} from './alert-management-service.js';

/**
 * Factory function to create a complete alerting system
 */
export function createAlertingSystem(config?: Partial<AlertSystemConfig>) {
  const system = new AlertSystemIntegrationService(config);
  return {
    system,
    alertManagement: alertManagementService,
    notifications: notificationChannelRegistry,
    onCall: onCallManagementService,
    runbooks: runbookIntegrationService,
    testing: alertTestingService,
    metrics: alertMetricsService,
    healthCheck: monitoringHealthCheckService,
  };
}

/**
 * Quick start function for basic alerting setup
 */
export async function quickStartAlerting() {
  console.log('🚀 Starting MCP Cortex Alerting System...');

  const alertingSystem = createAlertingSystem({
    enabled: true,
    environment: 'development',
    healthCheckInterval: 30000,
    alertEvaluationInterval: 10000,
    metricsCollectionInterval: 60000,
    testingEnabled: true,
    dashboardEnabled: true,
  });

  await alertingSystem.system.start();

  console.log('✅ MCP Cortex Alerting System started successfully!');
  console.log('📊 System status:', alertingSystem.system.getSystemStatus().health.status);

  return alertingSystem;
}

/**
 * Health check utility function
 */
export async function performHealthCheck() {
  const healthService = monitoringHealthCheckService;
  const result = await healthService.performHealthCheck();

  return {
    status: result.status,
    score: calculateHealthScore(result),
    components: result.components.map(c => ({
      name: c.name,
      status: c.status,
      responseTime: c.response_time_ms,
      errorRate: c.error_rate,
    })),
    recommendations: generateHealthRecommendations(result),
  };
}

/**
 * Calculate overall health score
 */
function calculateHealthScore(healthResult: SystemHealthResult): number {
  const totalComponents = healthResult.components.length;
  const healthyComponents = healthResult.components.filter(c => c.status === HealthStatus.HEALTHY).length;

  if (totalComponents === 0) return 100;

  return Math.round((healthyComponents / totalComponents) * 100);
}

/**
 * Generate health recommendations
 */
function generateHealthRecommendations(healthResult: SystemHealthResult): string[] {
  const recommendations: string[] = [];

  for (const component of healthResult.components) {
    if (component.error_rate > 10) {
      recommendations.push(`${component.name}: High error rate (${component.error_rate.toFixed(1)}%)`);
    }

    if (component.response_time_ms > 5000) {
      recommendations.push(`${component.name}: High response time (${component.response_time_ms}ms)`);
    }

    if (component.uptime_percentage < 95) {
      recommendations.push(`${component.name}: Low availability (${component.uptime_percentage.toFixed(1)}%)`);
    }
  }

  if (recommendations.length === 0) {
    recommendations.push('All systems are operating normally');
  }

  return recommendations;
}

// Export singleton instances
export const healthMonitoringManager = new (await import('./monitoring-server.js')).monitoringServer;

// Auto-start if configured
if (process.env.AUTO_START_HEALTH_MONITORING === 'true') {
  quickStartAlerting().catch(error => {
    console.error('Failed to auto-start health monitoring:', error);
  });
}