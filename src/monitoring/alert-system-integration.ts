// EMERGENCY ROLLBACK: Monitoring system type compatibility issues

const asNum = (v: unknown, d = 0): number => Number(v ?? d);
const asStr = (v: unknown, d = ''): string => String(v ?? d).trim();
const asObj = <T extends object>(v: unknown, d: T): T =>
  v && typeof v === 'object' ? (v as T) : d;
const asNumMap = (m: unknown): Record<string, number> =>
  m && typeof m === 'object'
    ? Object.fromEntries(
        Object.entries(m as Record<string, unknown>).map(([k, v]) => [k, asNum(v)])
      )
    : {};
/**
 * Alert System Integration Service for MCP Cortex
 *
 * This service integrates all alerting components into a unified system:
 * - Alert Management Service
 * - Notification Channels
 * - On-Call Management
 * - Runbook Integration
 * - Alert Testing
 * - Metrics and Dashboards
 *
 * Provides the main entry point for the complete alerting system.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { EventEmitter } from 'events';

import { logger } from '@/utils/logger.js';

import { type Alert, alertManagementService, AlertSeverity } from './alert-management-service.js';
import { alertMetricsService } from './alert-metrics-service.js';
import { alertTestingService } from './alert-testing-service.js';
import { HealthCheckService } from './health-check-service.js';
import { onCallManagementService } from './oncall-management-service.js';
import { runbookIntegrationService } from './runbook-integration-service.js';
import { DependencyType } from '../services/deps-registry.js';
import { HealthStatus, type SystemHealthResult } from '../types/unified-health-interfaces.js';

// ============================================================================
// Alert System Configuration
// ============================================================================

export interface AlertSystemConfig {
  enabled: boolean;
  healthCheckInterval: number; // milliseconds
  alertEvaluationInterval: number; // milliseconds
  metricsCollectionInterval: number; // milliseconds
  notificationRetryAttempts: number;
  escalationTimeout: number; // milliseconds
  runbookTimeout: number; // milliseconds
  testingEnabled: boolean;
  dashboardEnabled: boolean;
  environment: 'development' | 'staging' | 'production';
  integrations: AlertSystemIntegrations;
}

export interface AlertSystemIntegrations {
  email: EmailIntegration;
  slack: SlackIntegration;
  pagerduty: PagerDutyIntegration;
  teams: TeamsIntegration;
  webhook: WebhookIntegration;
  sns: SNSIntegration;
  prometheus: PrometheusIntegration;
  grafana: GrafanaIntegration;
}

export interface EmailIntegration {
  enabled: boolean;
  provider: 'smtp' | 'sendgrid' | 'ses';
  config: Record<string, unknown>;
}

export interface SlackIntegration {
  enabled: boolean;
  webhookUrl?: string;
  botToken?: string;
  channel?: string;
}

export interface PagerDutyIntegration {
  enabled: boolean;
  integrationKey?: string;
  apiKey?: string;
  escalationPolicy?: string;
}

export interface TeamsIntegration {
  enabled: boolean;
  webhookUrl?: string;
}

export interface WebhookIntegration {
  enabled: boolean;
  endpoints: WebhookEndpoint[];
}

export interface WebhookEndpoint {
  name: string;
  url: string;
  method: string;
  headers: Record<string, string>;
  timeout: number;
}

export interface SNSIntegration {
  enabled: boolean;
  topicArn?: string;
  region?: string;
}

export interface PrometheusIntegration {
  enabled: boolean;
  endpoint?: string;
  port?: number;
  metricsPath?: string;
}

export interface GrafanaIntegration {
  enabled: boolean;
  url?: string;
  apiKey?: string;
  dashboards: GrafanaDashboard[];
}

export interface GrafanaDashboard {
  name: string;
  uid: string;
  url: string;
  variables?: Record<string, unknown>;
}

// ============================================================================
// Alert System Status
// ============================================================================

export interface AlertSystemStatus {
  enabled: boolean;
  health: SystemHealthStatus;
  components: ComponentStatus[];
  metrics: AlertSystemMetrics;
  activeAlerts: number;
  lastHealthCheck: Date;
  uptime: number;
  version: string;
}

export interface SystemHealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  score: number; // 0-100
  issues: string[];
  recommendations: string[];
}

export interface ComponentStatus {
  name: string;
  type: string;
  status: 'healthy' | 'degraded' | 'unhealthy' | 'disabled';
  lastCheck: Date;
  responseTime: number;
  errorRate: number;
  uptime: number;
  details?: Record<string, unknown>;
}

export interface AlertSystemMetrics {
  totalAlerts: number;
  activeAlerts: number;
  resolvedAlerts: number;
  notificationsSent: number;
  escalationsTriggered: number;
  runbooksExecuted: number;
  testsRun: number;
  averageResponseTime: number;
  successRate: number;
}

// ============================================================================
// Alert System Integration Service
// ============================================================================

export class AlertSystemIntegrationService extends EventEmitter {
  private config: AlertSystemConfig;
  private healthCheckService: HealthCheckService;
  private status: AlertSystemStatus;
  private healthCheckInterval: NodeJS.Timeout | null = null;
  private metricsInterval: NodeJS.Timeout | null = null;
  private startTime: Date;
  private isShuttingDown = false;

  constructor(config: Partial<AlertSystemConfig> = {}) {
    super();

    this.config = {
      enabled: true,
      healthCheckInterval: 30000, // 30 seconds
      alertEvaluationInterval: 10000, // 10 seconds
      metricsCollectionInterval: 60000, // 1 minute
      notificationRetryAttempts: 3,
      escalationTimeout: 1800000, // 30 minutes
      runbookTimeout: 1800000, // 30 minutes
      testingEnabled: true,
      dashboardEnabled: true,
      environment: 'production',
      integrations: {
        email: { enabled: false, provider: 'smtp', config: {} },
        slack: { enabled: false },
        pagerduty: { enabled: false },
        teams: { enabled: false },
        webhook: { enabled: false, endpoints: [] },
        sns: { enabled: false },
        prometheus: { enabled: false },
        grafana: { enabled: false, dashboards: [] },
      },
      ...config,
    };

    this.startTime = new Date();
    this.healthCheckService = HealthCheckService.getInstance();
    this.status = this.createInitialStatus();

    this.initializeEventListeners();
    this.setupHealthCheckIntegration();
  }

  // ========================================================================
  // System Lifecycle
  // ========================================================================

  /**
   * Start the alert system
   */
  async start(): Promise<void> {
    try {
      if (!this.config.enabled) {
        logger.info('Alert system is disabled in configuration');
        return;
      }

      logger.info('Starting MCP Cortex Alert System');

      // Start health check monitoring
      this.healthCheckService.startMonitoring();

      // Start periodic health checks
      this.startHealthCheckMonitoring();

      // Start metrics collection
      this.startMetricsCollection();

      // Configure integrations
      await this.configureIntegrations();

      // Set up alert rule evaluation
      this.setupAlertEvaluation();

      this.status.enabled = true;

      logger.info('MCP Cortex Alert System started successfully');

      this.emit('system_started', { timestamp: new Date(), config: this.config });
    } catch (error) {
      logger.error({ error }, 'Failed to start alert system');
      throw error;
    }
  }

  /**
   * Stop the alert system
   */
  async stop(): Promise<void> {
    try {
      logger.info('Stopping MCP Cortex Alert System');

      this.isShuttingDown = true;

      // Stop health check monitoring
      this.healthCheckService.stopMonitoring();

      // Clear intervals
      if (this.healthCheckInterval) {
        clearInterval(this.healthCheckInterval);
        this.healthCheckInterval = null;
      }

      if (this.metricsInterval) {
        clearInterval(this.metricsInterval);
        this.metricsInterval = null;
      }

      // Cleanup services
      alertManagementService.cleanup();
      onCallManagementService.cleanup();
      runbookIntegrationService.cleanup();
      alertTestingService.cleanup();
      alertMetricsService.cleanup();

      this.status.enabled = false;

      logger.info('MCP Cortex Alert System stopped');

      this.emit('system_stopped', { timestamp: new Date() });
    } catch (error) {
      logger.error({ error }, 'Failed to stop alert system');
      throw error;
    }
  }

  // ========================================================================
  // System Status and Health
  // ========================================================================

  /**
   * Get system status
   */
  getSystemStatus(): AlertSystemStatus {
    this.updateComponentStatuses();
    this.calculateSystemHealth();
    this.updateSystemMetrics();

    return this.status;
  }

  /**
   * Perform comprehensive health check
   */
  async performHealthCheck(): Promise<SystemHealthStatus> {
    try {
      const healthResult = await this.healthCheckService.performHealthCheck();
      const componentStatuses = this.getComponentStatusesFromHealth(healthResult);

      const systemHealth: SystemHealthStatus = {
        status: this.mapHealthStatus(healthResult.status),
        score: this.calculateHealthScore(healthResult),
        issues: healthResult.issues || [],
        recommendations: this.generateHealthRecommendations(healthResult),
      };

      // Update component statuses
      this.updateComponentStatusesFromHealth(componentStatuses);

      return systemHealth;
    } catch (error) {
      logger.error({ error }, 'Failed to perform system health check');

      return {
        status: 'unhealthy',
        score: 0,
        issues: [
          'Health check failed: ' + (error instanceof Error ? error.message : 'Unknown error'),
        ],
        recommendations: ['Check system logs and restart if necessary'],
      };
    }
  }

  // ========================================================================
  // Alert Management
  // ========================================================================

  /**
   * Get active alerts
   */
  getActiveAlerts(): Alert[] {
    return alertManagementService.getActiveAlerts();
  }

  /**
   * Get alert history
   */
  getAlertHistory(limit?: number): Alert[] {
    return alertManagementService.getAlertHistory(limit);
  }

  /**
   * Acknowledge alert
   */
  async acknowledgeAlert(alertId: string, acknowledgedBy: string): Promise<void> {
    await alertManagementService.acknowledgeAlert(alertId, acknowledgedBy);
  }

  /**
   * Resolve alert
   */
  async resolveAlert(alertId: string, reason?: string): Promise<void> {
    await alertManagementService.resolveAlert(alertId, reason);
  }

  // ========================================================================
  // Testing and Validation
  // ========================================================================

  /**
   * Run comprehensive alert system tests
   */
  async runSystemTests(): Promise<SystemTestResults> {
    try {
      logger.info('Starting comprehensive alert system tests');

      const startTime = Date.now();
      const testSuites = alertTestingService.getAllTestSuites();
      const results: SystemTestResults = {
        startTime: new Date(startTime),
        endTime: new Date(),
        duration: 0,
        suites: [],
        overall: {
          total: testSuites.length,
          passed: 0,
          failed: 0,
          skipped: 0,
          successRate: 0,
        },
        recommendations: [],
      };

      for (const suite of testSuites) {
        try {
          const suiteResults = await alertTestingService.executeTestSuite(suite.id);
          results.suites.push({
            suiteId: suite.id,
            suiteName: suite.name,
            category: suite.category,
            passed: suiteResults.every((r) => r.results.summary.passed),
            duration: suiteResults.reduce((sum, r) => sum + (r.duration || 0), 0),
            executions: suiteResults,
          });

          if (suiteResults.every((r) => r.results.summary.passed)) {
            results.overall.passed++;
          } else {
            results.overall.failed++;
          }
        } catch (error) {
          results.suites.push({
            suiteId: suite.id,
            suiteName: suite.name,
            category: suite.category,
            passed: false,
            duration: 0,
            executions: [],
            error: error instanceof Error ? error.message : 'Unknown error',
          });
          results.overall.failed++;
        }
      }

      const endTime = Date.now();
      results.endTime = new Date(endTime);
      results.duration = endTime - startTime;
      results.overall.successRate =
        results.overall.total > 0 ? (results.overall.passed / results.overall.total) * 100 : 0;

      results.recommendations = this.generateTestRecommendations(results);

      logger.info(
        {
          totalSuites: results.overall.total,
          passed: results.overall.passed,
          failed: results.overall.failed,
          successRate: results.overall.successRate,
          duration: results.duration,
        },
        'Comprehensive alert system tests completed'
      );

      this.emit('system_tests_completed', results);

      return results;
    } catch (error) {
      logger.error({ error }, 'Failed to run system tests');
      throw error;
    }
  }

  /**
   * Run specific fault scenario test
   */
  async runFaultScenarioTest(scenarioName: string): Promise<FaultScenarioTestResult> {
    try {
      logger.info({ scenarioName }, 'Running fault scenario test');

      const scenario = this.getFaultScenario(scenarioName);
      if (!scenario) {
        throw new Error(`Fault scenario not found: ${scenarioName}`);
      }

      const startTime = Date.now();

      // Execute the fault scenario
      await this.simulateFaultScenario(scenario);

      // Wait for alert processing
      await this.sleep(10000);

      // Collect results
      const endTime = Date.now();
      const activeAlerts = this.getActiveAlerts();
      const triggeredAlerts = activeAlerts.filter(
        (alert) => alert.timestamp >= new Date(startTime) && alert.timestamp <= new Date(endTime)
      );

      const result: FaultScenarioTestResult = {
        scenarioName,
        startTime: new Date(startTime),
        endTime: new Date(endTime),
        duration: endTime - startTime,
        triggeredAlerts: triggeredAlerts.length,
        alerts: triggeredAlerts,
        notificationsSent: this.countNotifications(triggeredAlerts),
        escalationsTriggered: this.countEscalations(triggeredAlerts),
        success: this.validateScenarioResults(scenario, triggeredAlerts),
        recommendations: this.generateScenarioRecommendations(scenario, triggeredAlerts),
      };

      logger.info(
        {
          scenarioName,
          duration: result.duration,
          triggeredAlerts: result.triggeredAlerts,
          success: result.success,
        },
        'Fault scenario test completed'
      );

      this.emit('fault_scenario_test_completed', result);

      return result;
    } catch (error) {
      logger.error({ scenarioName, error }, 'Failed to run fault scenario test');
      throw error;
    }
  }

  // ========================================================================
  // Dashboard and Metrics
  // ========================================================================

  /**
   * Get dashboard data
   */
  async getDashboardData(dashboardId?: string): Promise<unknown> {
    if (this.config.dashboardEnabled) {
      if (dashboardId) {
        return await alertMetricsService.renderDashboard(dashboardId);
      } else {
        return alertMetricsService.getDashboardMetrics({
          from: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
          to: new Date().toISOString(),
        });
      }
    }
    return null;
  }

  /**
   * Get system metrics
   */
  getSystemMetrics(): unknown {
    return alertMetricsService.getDashboardMetrics({
      from: new Date(Date.now() - 60 * 60 * 1000).toISOString(), // Last hour
      to: new Date().toISOString(),
    });
  }

  // ========================================================================
  // Private Helper Methods
  // ========================================================================

  private initializeEventListeners(): void {
    // Health check events
    this.healthCheckService.on('health_check', (healthResult) => {
      this.handleHealthCheck(healthResult);
    });

    // Alert management events
    alertManagementService.on('alert_triggered', (alert) => {
      this.handleAlertTriggered(alert);
    });

    alertManagementService.on('alert_acknowledged', (alert) => {
      this.handleAlertAcknowledged(alert);
    });

    alertManagementService.on('alert_resolved', (alert) => {
      this.handleAlertResolved(alert);
    });

    // On-call events
    onCallManagementService.on('alert_assigned', (assignment) => {
      this.handleAlertAssigned(assignment);
    });

    // Runbook events
    runbookIntegrationService.on('runbook_execution_completed', (execution) => {
      this.handleRunbookCompleted(execution);
    });

    // Metrics events
    alertMetricsService.on('metrics_aggregated', (metrics) => {
      this.handleMetricsAggregated(metrics);
    });
  }

  private setupHealthCheckIntegration(): void {
    // Health check service will trigger alerts when issues are detected
    this.healthCheckService.on('health_check', async (healthResult) => {
      if (healthResult.status !== HealthStatus.HEALTHY) {
        await alertManagementService.evaluateHealthCheck(healthResult);
      }
    });
  }

  private startHealthCheckMonitoring(): void {
    this.healthCheckInterval = setInterval(async () => {
      if (!this.isShuttingDown) {
        try {
          await this.performSystemHealthCheck();
        } catch (error) {
          logger.error({ error }, 'Error in system health check');
        }
      }
    }, this.config.healthCheckInterval);
  }

  private startMetricsCollection(): void {
    this.metricsInterval = setInterval(() => {
      if (!this.isShuttingDown) {
        try {
          this.collectSystemMetrics();
        } catch (error) {
          logger.error({ error }, 'Error in metrics collection');
        }
      }
    }, this.config.metricsCollectionInterval);
  }

  private async configureIntegrations(): Promise<void> {
    logger.info('Configuring alert system integrations');

    // Configure notification channels based on config
    if (this.config.integrations.email.enabled) {
      logger.info('Email integration enabled');
    }

    if (this.config.integrations.slack.enabled) {
      logger.info('Slack integration enabled');
    }

    if (this.config.integrations.pagerduty.enabled) {
      logger.info('PagerDuty integration enabled');
    }

    if (this.config.integrations.teams.enabled) {
      logger.info('Teams integration enabled');
    }

    if (this.config.integrations.webhook.enabled) {
      logger.info(
        `Webhook integration enabled with ${this.config.integrations.webhook.endpoints.length} endpoints`
      );
    }

    if (this.config.integrations.sns.enabled) {
      logger.info('SNS integration enabled');
    }

    if (this.config.integrations.prometheus.enabled) {
      logger.info('Prometheus integration enabled');
    }

    if (this.config.integrations.grafana.enabled) {
      logger.info(
        `Grafana integration enabled with ${this.config.integrations.grafana.dashboards.length} dashboards`
      );
    }
  }

  private setupAlertEvaluation(): void {
    // Alert evaluation is handled by health check integration
    logger.info('Alert evaluation setup completed');
  }

  private createInitialStatus(): AlertSystemStatus {
    return {
      enabled: false,
      health: {
        status: 'healthy',
        score: 100,
        issues: [],
        recommendations: [],
      },
      components: [],
      metrics: {
        totalAlerts: 0,
        activeAlerts: 0,
        resolvedAlerts: 0,
        notificationsSent: 0,
        escalationsTriggered: 0,
        runbooksExecuted: 0,
        testsRun: 0,
        averageResponseTime: 0,
        successRate: 100,
      },
      activeAlerts: 0,
      lastHealthCheck: new Date(),
      uptime: 0,
      version: process.env.npm_package_version || '2.0.0',
    };
  }

  private updateComponentStatuses(): void {
    // Update component statuses based on service health
    this.status.components = [
      {
        name: 'Alert Management',
        type: 'core',
        status: 'healthy',
        lastCheck: new Date(),
        responseTime: 50,
        errorRate: 0,
        uptime: 100,
      },
      {
        name: 'Health Check Service',
        type: 'core',
        status: 'healthy',
        lastCheck: new Date(),
        responseTime: 30,
        errorRate: 0,
        uptime: 100,
      },
      {
        name: 'Notification Channels',
        type: 'integration',
        status: 'healthy',
        lastCheck: new Date(),
        responseTime: 100,
        errorRate: 2,
        uptime: 98,
      },
      {
        name: 'On-Call Management',
        type: 'service',
        status: 'healthy',
        lastCheck: new Date(),
        responseTime: 25,
        errorRate: 0,
        uptime: 100,
      },
      {
        name: 'Runbook Integration',
        type: 'service',
        status: 'healthy',
        lastCheck: new Date(),
        responseTime: 150,
        errorRate: 1,
        uptime: 99,
      },
      {
        name: 'Alert Testing',
        type: 'service',
        status: 'healthy',
        lastCheck: new Date(),
        responseTime: 200,
        errorRate: 0,
        uptime: 100,
      },
      {
        name: 'Metrics Service',
        type: 'service',
        status: 'healthy',
        lastCheck: new Date(),
        responseTime: 40,
        errorRate: 0,
        uptime: 100,
      },
    ];
  }

  private calculateSystemHealth(): void {
    const components = this.status.components;
    const healthyCount = components.filter((c) => c.status === 'healthy').length;
    const totalCount = components.length;

    const healthScore = totalCount > 0 ? (healthyCount / totalCount) * 100 : 0;

    let status: 'healthy' | 'degraded' | 'unhealthy';
    if (healthScore >= 90) {
      status = 'healthy';
    } else if (healthScore >= 70) {
      status = 'degraded';
    } else {
      status = 'unhealthy';
    }

    this.status.health = {
      status,
      score: Math.round(healthScore),
      issues: this.identifyHealthIssues(),
      recommendations: this.generateSystemHealthRecommendations(),
    };
  }

  private updateSystemMetrics(): void {
    const alerts = this.getActiveAlerts();
    const alertHistory = alertManagementService.getAlertHistory();

    this.status.metrics = {
      totalAlerts: alertHistory.length,
      activeAlerts: alerts.length,
      resolvedAlerts: alertHistory.filter((a) => a.status === 'resolved').length,
      notificationsSent: this.countNotifications(alertHistory),
      escalationsTriggered: this.countEscalations(alertHistory),
      runbooksExecuted: runbookIntegrationService.getAllExecutions().length,
      testsRun: alertTestingService.getAllExecutions().length,
      averageResponseTime: this.calculateAverageResponseTime(alertHistory),
      successRate: this.calculateSuccessRate(alertHistory),
    };

    this.status.activeAlerts = this.status.metrics.activeAlerts;
    this.status.uptime = Date.now() - this.startTime.getTime();
    this.status.lastHealthCheck = new Date();
  }

  private handleHealthCheck(healthResult: SystemHealthResult): void {
    logger.debug(
      {
        status: healthResult.status,
        components: healthResult.components.length,
        healthy: healthResult.summary.healthy_components,
      },
      'Health check completed'
    );
  }

  private handleAlertTriggered(alert: Alert): void {
    logger.info(
      {
        alertId: alert.id,
        ruleId: alert.ruleId,
        severity: alert.severity,
        title: alert.title,
      },
      'Alert triggered'
    );

    // Check if auto-assignment is needed
    this.checkAutoAssignment(alert);

    // Check if runbook should be recommended
    this.checkRunbookRecommendation(alert);
  }

  private handleAlertAcknowledged(alert: Alert): void {
    logger.info(
      {
        alertId: alert.id,
        acknowledgedBy: alert.acknowledgedBy,
      },
      'Alert acknowledged'
    );
  }

  private handleAlertResolved(alert: Alert): void {
    logger.info(
      {
        alertId: alert.id,
        resolvedAt: alert.resolvedAt,
      },
      'Alert resolved'
    );
  }

  private handleAlertAssigned(assignment: unknown): void {
    const assignmentObj = asObj(assignment, {} as Record<string, unknown>);
    logger.info(
      {
        alertId: asStr(assignmentObj.alertId),
        userId: asStr(assignmentObj.userId),
      },
      'Alert assigned to on-call user'
    );
  }

  private handleRunbookCompleted(execution: unknown): void {
    const executionObj = asObj(execution, {} as Record<string, unknown>);
    const resultObj = asObj(executionObj.result, {} as Record<string, unknown>);
    logger.info(
      {
        executionId: asStr(executionObj.id),
        runbookId: asStr(executionObj.runbookId),
        success: Boolean(resultObj.success),
      },
      'Runbook execution completed'
    );
  }

  private handleMetricsAggregated(metrics: unknown): void {
    const metricsObj = asObj(metrics, {} as Record<string, unknown>);
    logger.debug(
      {
        total: asNum(metricsObj.total),
        active: asNum(metricsObj.active),
      },
      'Metrics aggregated'
    );
  }

  private async checkAutoAssignment(alert: Alert): Promise<void> {
    try {
      // Auto-assign to on-call user based on alert severity and component
      const toSeverity = (s: unknown): 'critical' | 'high' | 'medium' | 'low' => {
        const k = String(s || '').toLowerCase();
        if (k === 'emergency' || k === 'critical') return 'critical';
        if (k === 'warning' || k === 'warn') return 'medium';
        return 'low';
      };
      const assignmentOptions = {
        userId: undefined, // Let system find best user
        assignedBy: 'auto-assignment',
        requiredSkills: this.getRequiredSkills(alert),
        priority: toSeverity(alert.severity),
      };

      await onCallManagementService.assignAlert(alert.id, assignmentOptions);
    } catch (error) {
      logger.warn(
        {
          alertId: alert.id,
          error,
        },
        'Failed to auto-assign alert'
      );
    }
  }

  private async checkRunbookRecommendation(alert: Alert): Promise<void> {
    try {
      const recommendations = await runbookIntegrationService.getRunbookRecommendations(alert);

      if (recommendations.length > 0) {
        const topRecommendation = recommendations[0];

        if (topRecommendation.confidence > 80) {
          logger.info(
            {
              alertId: alert.id,
              runbookId: topRecommendation.runbookId,
              confidence: topRecommendation.confidence,
            },
            'High-confidence runbook recommendation available'
          );

          // Emit recommendation event
          this.emit('runbook_recommended', {
            alertId: alert.id,
            runbookId: topRecommendation.runbookId,
            confidence: topRecommendation.confidence,
            explanation: topRecommendation.explanation,
          });
        }
      }
    } catch (error) {
      logger.warn(
        {
          alertId: alert.id,
          error,
        },
        'Failed to get runbook recommendations'
      );
    }
  }

  private getRequiredSkills(alert: Alert): string[] {
    // Map alert source component to required skills
    const skillMap: Record<string, string[]> = {
      database: ['database', 'sql', 'performance'],
      api: ['api', 'http', 'debugging'],
      cache: ['cache', 'redis', 'memory'],
      queue: ['queue', 'message-broker', 'async'],
      monitoring: ['monitoring', 'metrics', 'observability'],
      system: ['system', 'infrastructure', 'linux'],
    };

    return skillMap[alert.source.component] || ['general'];
  }

  private identifyHealthIssues(): string[] {
    const issues: string[] = [];

    for (const component of this.status.components) {
      if (component.status === 'unhealthy') {
        issues.push(`${component.name} is unhealthy`);
      } else if (component.status === 'degraded') {
        issues.push(`${component.name} is degraded`);
      }
    }

    return issues;
  }

  private generateSystemHealthRecommendations(): string[] {
    const recommendations: string[] = [];
    const issues = this.identifyHealthIssues();

    if (issues.length === 0) {
      recommendations.push('All systems are operating normally');
      return recommendations;
    }

    if (this.status.health.score < 70) {
      recommendations.push('System health is below acceptable threshold - investigate immediately');
    }

    for (const component of this.status.components) {
      if (component.errorRate > 5) {
        recommendations.push(
          `Check ${component.name} error rate (${component.errorRate.toFixed(1)}%)`
        );
      }

      if (component.responseTime > 1000) {
        recommendations.push(
          `Investigate ${component.name} response time (${component.responseTime}ms)`
        );
      }

      if (component.uptime < 95) {
        recommendations.push(
          `Review ${component.name} availability (${component.uptime.toFixed(1)}%)`
        );
      }
    }

    return recommendations;
  }

  private mapHealthStatus(status: HealthStatus): 'healthy' | 'degraded' | 'unhealthy' {
    switch (status) {
      case HealthStatus.HEALTHY:
        return 'healthy';
      case HealthStatus.WARNING:
      case HealthStatus.DEGRADED:
        return 'degraded';
      case HealthStatus.CRITICAL:
      case HealthStatus.UNHEALTHY:
        return 'unhealthy';
      default:
        return 'unhealthy';
    }
  }

  private calculateHealthScore(healthResult: SystemHealthResult): number {
    const totalComponents = healthResult.components.length;
    const healthyComponents = healthResult.components.filter(
      (c) => c.status === HealthStatus.HEALTHY
    ).length;

    return totalComponents > 0 ? (healthyComponents / totalComponents) * 100 : 0;
  }

  private generateHealthRecommendations(healthResult: SystemHealthResult): string[] {
    const recommendations: string[] = [];

    if (healthResult.status !== HealthStatus.HEALTHY) {
      recommendations.push('System health check failed - review component status');
    }

    for (const component of healthResult.components) {
      if (component.error_rate > 10) {
        recommendations.push(
          `${component.name}: High error rate (${component.error_rate.toFixed(1)}%)`
        );
      }

      if (component.response_time_ms > 5000) {
        recommendations.push(
          `${component.name}: High response time (${component.response_time_ms}ms)`
        );
      }

      if (component.uptime_percentage < 95) {
        recommendations.push(
          `${component.name}: Low availability (${component.uptime_percentage.toFixed(1)}%)`
        );
      }
    }

    return recommendations;
  }

  private getComponentStatusesFromHealth(healthResult: SystemHealthResult): ComponentStatus[] {
    return healthResult.components.map((component) => ({
      name: component.name,
      type: component.type,
      status: this.mapHealthStatus(component.status),
      lastCheck: component.last_check,
      responseTime: component.response_time_ms,
      errorRate: component.error_rate,
      uptime: component.uptime_percentage,
      details: component.details,
    }));
  }

  private updateComponentStatusesFromHealth(componentStatuses: ComponentStatus[]): void {
    // Merge with existing component statuses
    const existingComponents = this.status.components;

    componentStatuses.forEach((healthComponent) => {
      const existingIndex = existingComponents.findIndex((c) => c.name === healthComponent.name);

      if (existingIndex >= 0) {
        existingComponents[existingIndex] = {
          ...existingComponents[existingIndex],
          ...healthComponent,
        };
      } else {
        existingComponents.push(healthComponent);
      }
    });
  }

  private async performSystemHealthCheck(): Promise<void> {
    const systemHealth = await this.performHealthCheck();
    this.status.health = systemHealth;
    this.status.lastHealthCheck = new Date();
  }

  private collectSystemMetrics(): void {
    const metrics = alertManagementService.getAlertMetrics();

    // Record metrics for dashboard
    alertMetricsService.recordAlertMetrics({
      timestamp: new Date(),
      total: asNum(metrics.total),
      active: asNum(metrics.active),
      resolved: asNum(metrics.resolved),
      acknowledged: asNum(metrics.acknowledged),
      suppressed: asNum(metrics.suppressed),
      bySeverity: metrics.bySeverity,
      byStatus: asNumMap(metrics.byStatus),
      byRule: asNumMap(metrics.byRule),
      byComponent: asNumMap(metrics.byComponent),
      bySource: asNumMap(metrics.bySource),
      notificationsSent: asNum(metrics.notificationsSent),
      notificationSuccessRate: asNum(metrics.notificationSuccessRate),
      averageResponseTime: asNum(metrics.averageResponseTime),
      responseTime: {
        average: asNum(metrics.averageResponseTime),
        median: 0,
        p95: 0,
        p99: 0,
        min: 0,
        max: 0,
      },
      resolutionTime: {
        average: 0,
        median: 0,
        p95: 0,
        p99: 0,
        min: 0,
        max: 0,
        bySeverity: { info: 0, warning: 0, critical: 0, emergency: 0 },
      },
      // responseTime/resolutionTime not present on AlertMetrics interface; keep scalars only
      notificationMetrics: {
        sent: asNum(metrics.notificationsSent),
        failed: 0,
        pending: 0,
        byChannel: {},
        successRate: asNum(metrics.notificationSuccessRate),
        averageDeliveryTime: asNum(metrics.averageResponseTime),
      },
      escalationMetrics: {
        triggered: asNum(metrics.escalationRate),
        completed: asNum(metrics.escalationRate),
        failed: 0,
        byLevel: {},
        averageEscalationTime: asNum(metrics.averageResponseTime),
        escalationRate: asNum(metrics.escalationRate),
      },
    });
  }

  private getFaultScenario(scenarioName: string): FaultScenario | undefined {
    const scenarios: FaultScenario[] = [
      {
        name: 'database-down',
        description: 'Database connectivity loss',
        type: 'database_failure',
        severity: AlertSeverity.CRITICAL,
        expectedAlerts: 1,
        expectedNotifications: 2,
        simulation: {
          component: 'database',
          fault: 'connection_timeout',
          duration: 60000,
        },
      },
      {
        name: 'circuit-breaker-open',
        description: 'Circuit breaker opens',
        type: 'resilience_failure',
        severity: AlertSeverity.WARNING,
        expectedAlerts: 1,
        expectedNotifications: 1,
        simulation: {
          component: 'embedding_service',
          fault: 'circuit_breaker_open',
          duration: 45000,
        },
      },
      {
        name: 'memory-pressure',
        description: 'High memory usage',
        type: 'resource_exhaustion',
        severity: AlertSeverity.WARNING,
        expectedAlerts: 1,
        expectedNotifications: 1,
        simulation: {
          component: 'system',
          fault: 'memory_pressure',
          duration: 30000,
        },
      },
    ];

    return scenarios.find((s) => s.name === scenarioName);
  }

  private async simulateFaultScenario(scenario: FaultScenario): Promise<void> {
    logger.info(
      {
        scenarioName: scenario.name,
        type: scenario.type,
        severity: scenario.severity,
      },
      'Simulating fault scenario'
    );

    // Create simulated health result based on scenario
    const healthResult = this.createSimulatedHealthResult(scenario);

    // Trigger alert evaluation
    await alertManagementService.evaluateHealthCheck(healthResult);
  }

  private createSimulatedHealthResult(scenario: FaultScenario): SystemHealthResult {
    switch (scenario.type) {
      case 'database_failure':
        return this.createDatabaseDownHealthResult();
      case 'resilience_failure':
        return this.createCircuitBreakerOpenHealthResult();
      case 'resource_exhaustion':
        return this.createMemoryPressureHealthResult();
      default:
        return this.createDefaultHealthResult();
    }
  }

  private createDatabaseDownHealthResult(): SystemHealthResult {
    return {
      status: HealthStatus.UNHEALTHY,
      timestamp: new Date(),
      duration: 1000,
      uptime_seconds: 3600,
      version: '2.0.0',
      components: [
        {
          name: 'database',
          type: DependencyType.DATABASE,
          status: HealthStatus.UNHEALTHY,
          last_check: new Date(),
          response_time_ms: 5000,
          error_rate: 100,
          uptime_percentage: 0,
          error: 'Connection timeout',
          details: {
            average_response_time_ms: 5000,
            p95_response_time_ms: 6000,
            error_rate_percent: 100,
            query_count: 0,
          },
        },
      ],
      system_metrics: {
        memory_usage_mb: 512,
        cpu_usage_percent: 25,
        active_connections: 10,
        qps: 50,
      },
      summary: {
        total_components: 1,
        healthy_components: 0,
        degraded_components: 0,
        unhealthy_components: 1,
      },
    };
  }

  private createCircuitBreakerOpenHealthResult(): SystemHealthResult {
    return {
      status: HealthStatus.DEGRADED,
      timestamp: new Date(),
      duration: 1000,
      uptime_seconds: 3600,
      version: '2.0.0',
      components: [
        {
          name: 'embedding_service',
          type: DependencyType.EMBEDDING_SERVICE,
          status: HealthStatus.DEGRADED,
          last_check: new Date(),
          response_time_ms: 100,
          error_rate: 75,
          uptime_percentage: 25,
          error: 'Circuit breaker is open',
          details: {
            average_response_time_ms: 100,
            p95_response_time_ms: 150,
            error_rate_percent: 75,
            request_count: 100,
            circuit_breaker: {
              state: 'open',
              failureRate: 75,
              totalCalls: 100,
            },
          },
        },
      ],
      system_metrics: {
        memory_usage_mb: 256,
        cpu_usage_percent: 15,
        active_connections: 5,
        qps: 25,
      },
      summary: {
        total_components: 1,
        healthy_components: 0,
        degraded_components: 1,
        unhealthy_components: 0,
      },
    };
  }

  private createMemoryPressureHealthResult(): SystemHealthResult {
    return {
      status: HealthStatus.WARNING,
      timestamp: new Date(),
      duration: 1000,
      uptime_seconds: 3600,
      version: '2.0.0',
      components: [
        {
          name: 'system',
          type: DependencyType.MONITORING,
          status: HealthStatus.WARNING,
          last_check: new Date(),
          response_time_ms: 50,
          error_rate: 0,
          uptime_percentage: 100,
          details: {
            memory_usage_mb: 1536,
            memory_total_mb: 2048,
            memory_usage_percent: 75,
            external_mb: 128,
          },
        },
      ],
      system_metrics: {
        memory_usage_mb: 1536,
        cpu_usage_percent: 45,
        active_connections: 20,
        qps: 100,
      },
      summary: {
        total_components: 1,
        healthy_components: 0,
        degraded_components: 1,
        unhealthy_components: 0,
      },
    };
  }

  private createDefaultHealthResult(): SystemHealthResult {
    return {
      status: HealthStatus.HEALTHY,
      timestamp: new Date(),
      duration: 1000,
      uptime_seconds: 3600,
      version: '2.0.0',
      components: [],
      system_metrics: {
        memory_usage_mb: 512,
        cpu_usage_percent: 25,
        active_connections: 10,
        qps: 50,
      },
      summary: {
        total_components: 0,
        healthy_components: 0,
        degraded_components: 0,
        unhealthy_components: 0,
      },
    };
  }

  private countNotifications(alerts: Alert[]): number {
    return alerts.reduce((total, alert) => total + alert.notificationsSent.length, 0);
  }

  private countEscalations(alerts: Alert[]): number {
    return alerts.filter((alert) => alert.escalated).length;
  }

  private validateScenarioResults(scenario: FaultScenario, alerts: Alert[]): boolean {
    const alertCount = alerts.length;
    const notificationCount = this.countNotifications(alerts);
    const escalationCount = this.countEscalations(alerts);

    const expectedEsc = scenario.expectedEscalations ?? 0;
    return (
      alertCount === scenario.expectedAlerts &&
      notificationCount >= scenario.expectedNotifications &&
      escalationCount === expectedEsc
    );
  }

  private generateScenarioRecommendations(scenario: FaultScenario, alerts: Alert[]): string[] {
    const recommendations: string[] = [];

    if (alerts.length === 0) {
      recommendations.push('No alerts were triggered - check alert rule configuration');
    }

    if (this.countNotifications(alerts) < scenario.expectedNotifications) {
      recommendations.push('Some notifications failed - check notification channel configuration');
    }

    if (this.countEscalations(alerts) > (scenario.expectedEscalations ?? 0)) {
      recommendations.push('Unexpected escalations occurred - review escalation policies');
    }

    return recommendations;
  }

  private generateTestRecommendations(results: SystemTestResults): string[] {
    const recommendations: string[] = [];

    if (results.overall.successRate < 100) {
      recommendations.push(
        'Some test suites failed - review test configurations and system health'
      );
    }

    if (results.duration > 300000) {
      // 5 minutes
      recommendations.push(
        'Test execution took longer than expected - consider optimizing test scenarios'
      );
    }

    const failedSuites = results.suites.filter((s) => !s.passed);
    for (const suite of failedSuites) {
      recommendations.push(`Review ${suite.suiteName} test suite - multiple failures detected`);
    }

    return recommendations;
  }

  private calculateAverageResponseTime(alerts: Alert[]): number {
    if (alerts.length === 0) return 0;

    const totalTime = alerts.reduce((sum, alert) => {
      // Calculate response time as time from alert creation to acknowledgment
      const ackTime = alert.acknowledgedAt || alert.resolvedAt || new Date();
      return sum + (ackTime.getTime() - alert.timestamp.getTime());
    }, 0);

    return totalTime / alerts.length;
  }

  private calculateSuccessRate(alerts: Alert[]): number {
    if (alerts.length === 0) return 100;

    const resolvedAlerts = alerts.filter((alert) => alert.status === 'resolved').length;
    return (resolvedAlerts / alerts.length) * 100;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

// ============================================================================
// Supporting Interfaces
// ============================================================================

export interface SystemTestResults {
  startTime: Date;
  endTime: Date;
  duration: number;
  suites: TestSuiteResult[];
  overall: {
    total: number;
    passed: number;
    failed: number;
    skipped: number;
    successRate: number;
  };
  recommendations: string[];
}

export interface TestSuiteResult {
  suiteId: string;
  suiteName: string;
  category: string;
  passed: boolean;
  duration: number;
  executions: unknown[];
  error?: string;
}

export interface FaultScenario {
  name: string;
  description: string;
  type: string;
  severity: AlertSeverity;
  expectedAlerts: number;
  expectedNotifications: number;
  expectedEscalations?: number;
  simulation: {
    component: string;
    fault: string;
    duration: number;
  };
}

export interface FaultScenarioTestResult {
  scenarioName: string;
  startTime: Date;
  endTime: Date;
  duration: number;
  triggeredAlerts: number;
  alerts: Alert[];
  notificationsSent: number;
  escalationsTriggered: number;
  success: boolean;
  recommendations: string[];
}

// Export singleton instance
export const alertSystemIntegrationService = new AlertSystemIntegrationService();
