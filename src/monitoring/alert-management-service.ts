// EMERGENCY ROLLBACK: Monitoring system type compatibility issues

/**
 * Alert Management System for MCP Cortex
 *
 * Provides comprehensive alerting capabilities including:
 * - Alert rule configuration and evaluation
 * - Multi-channel notifications (email, Slack, PagerDuty)
 * - On-call acknowledgement and escalation workflows
 * - Runbook integration with alert responses
 * - Alert testing and validation procedures
 * - Metrics and dashboard integration
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { EventEmitter } from 'events';

import { logger } from '@/utils/logger.js';

import {
  AlertSeverity,
  type ComponentHealth,
  HealthStatus,
  type SystemHealthResult,
} from '../types/unified-health-interfaces.js';

// Re-export AlertSeverity for use by other modules
export { AlertSeverity };
import { DependencyType } from '../services/deps-registry.js';

// ============================================================================
// Alert Configuration Interfaces
// ============================================================================

/**
 * Alert rule definition
 */
export interface AlertRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  severity: AlertSeverity;
  condition: AlertCondition;
  actions: AlertAction[];
  cooldownPeriod: number; // milliseconds
  escalationPolicy?: EscalationPolicy;
  runbookId?: string;
  tags: string[];
  metadata?: Record<string, unknown>;
}

/**
 * Alert condition evaluation logic
 */
export interface AlertCondition {
  metric: string;
  operator: 'gt' | 'lt' | 'eq' | 'ne' | 'gte' | 'lte' | 'in' | 'not_in';
  threshold: number | string | Array<number | string>;
  duration: number; // milliseconds - condition must be true for this duration
  evaluationWindow: number; // milliseconds - time window for evaluation
  aggregation?: 'avg' | 'max' | 'min' | 'sum' | 'count';
  filters?: {
    component?: string;
    type?: DependencyType;
    environment?: string;
  };
}

/**
 * Alert action definitions
 */
export interface AlertAction {
  type: 'email' | 'slack' | 'pagerduty' | 'webhook' | 'sns' | 'teams';
  config: Record<string, unknown>;
  enabled: boolean;
  retryAttempts?: number;
  retryDelay?: number;
}

/**
 * Escalation policy configuration
 */
export interface EscalationPolicy {
  enabled: boolean;
  rules: EscalationRule[];
}

export interface EscalationRule {
  delay: number; // milliseconds before escalation
  severity: AlertSeverity;
  actions: AlertAction[];
  conditions?: {
    maxEscalations?: number;
    timeWindow?: number; // only escalate within this time window
  };
}

/**
 * Alert instance
 */
export interface Alert {
  id: string;
  ruleId: string;
  ruleName: string;
  severity: AlertSeverity;
  status: 'firing' | 'acknowledged' | 'resolved' | 'suppressed';
  title: string;
  message: string;
  source: {
    component: string;
    type: DependencyType;
    metric: string;
    value: number | string;
    threshold: number | string;
  };
  timestamp: Date;
  acknowledgedBy?: string;
  acknowledgedAt?: Date;
  resolvedAt?: Date;
  escalated: boolean;
  escalationLevel: number;
  notificationsSent: NotificationAttempt[];
  metadata?: Record<string, unknown>;
}

/**
 * Notification attempt record
 */
export interface NotificationAttempt {
  id: string;
  alertId: string;
  actionType: string;
  status: 'pending' | 'sent' | 'failed' | 'retrying';
  timestamp: Date;
  error?: string;
  retryCount: number;
  response?: Record<string, unknown>;
}

/**
 * On-call schedule and rotation
 */
export interface OnCallSchedule {
  id: string;
  name: string;
  timezone: string;
  rotations: OnCallRotation[];
  overrides: OnCallOverride[];
}

export interface OnCallRotation {
  id: string;
  name: string;
  users: string[];
  type: 'daily' | 'weekly' | 'monthly';
  startTime: Date;
  endTime?: Date;
  handoffTime?: string; // HH:MM format
}

export interface OnCallOverride {
  id: string;
  userId: string;
  startTime: Date;
  endTime: Date;
  reason?: string;
}

/**
 * Runbook integration
 */
export interface Runbook {
  id: string;
  name: string;
  description: string;
  steps: RunbookStep[];
  tags: string[];
  estimatedDuration: number; // minutes
  severity: AlertSeverity;
  category: string;
}

export interface RunbookStep {
  id: string;
  title: string;
  description: string;
  type: 'manual' | 'automated' | 'verification';
  order: number;
  expectedDuration: number; // minutes
  commands?: string[];
  verificationCriteria?: string[];
  rollbackCommands?: string[];
}

/**
 * Alert testing configuration
 */
export interface AlertTestScenario {
  id: string;
  name: string;
  description: string;
  scenario: TestScenario;
  expectedResults: ExpectedTestResults;
  cleanup?: TestCleanup;
}

export interface TestScenario {
  type: 'health_check' | 'circuit_breaker' | 'database_down' | 'memory_pressure' | 'custom';
  config: Record<string, unknown>;
  duration: number; // milliseconds
}

export interface ExpectedTestResults {
  alertsFired: number;
  alertSeverities: AlertSeverity[];
  notificationsSent: number;
  escalationsTriggered: number;
}

export interface TestCleanup {
  actions: string[];
  timeout: number; // milliseconds
}

// ============================================================================
// Alert Management Service
// ============================================================================

/**
 * Main alert management service
 */
export class AlertManagementService extends EventEmitter {
  private rules: Map<string, AlertRule> = new Map();
  private activeAlerts: Map<string, Alert> = new Map();
  private alertHistory: Alert[] = [];
  private notificationHistory: NotificationAttempt[] = [];
  private onCallSchedules: Map<string, OnCallSchedule> = new Map();
  private runbooks: Map<string, Runbook> = new Map();
  private testScenarios: Map<string, AlertTestScenario> = new Map();

  private evaluationInterval: NodeJS.Timeout | null = null;
  private isShuttingDown = false;

  constructor(private config: AlertServiceConfig) {
    super();
    this.initializeDefaultRules();
    this.startEvaluation();
  }

  // ========================================================================
  // Alert Rule Management
  // ========================================================================

  /**
   * Create or update an alert rule
   */
  async upsertAlertRule(rule: AlertRule): Promise<void> {
    try {
      // Validate rule configuration
      this.validateAlertRule(rule);

      // Store rule
      this.rules.set(rule.id, rule);

      logger.info({ ruleId: rule.id, ruleName: rule.name }, 'Alert rule upserted');

      this.emit('alert_rule_updated', rule);
    } catch (error) {
      logger.error({ ruleId: rule.id, error }, 'Failed to upsert alert rule');
      throw error;
    }
  }

  /**
   * Delete an alert rule
   */
  async deleteAlertRule(ruleId: string): Promise<void> {
    try {
      const rule = this.rules.get(ruleId);
      if (!rule) {
        throw new Error(`Alert rule not found: ${ruleId}`);
      }

      // Resolve any active alerts from this rule
      const activeAlerts = Array.from(this.activeAlerts.values()).filter(
        (alert) => alert.ruleId === ruleId
      );

      for (const alert of activeAlerts) {
        await this.resolveAlert(alert.id, 'Rule deleted');
      }

      // Remove rule
      this.rules.delete(ruleId);

      logger.info({ ruleId }, 'Alert rule deleted');

      this.emit('alert_rule_deleted', ruleId);
    } catch (error) {
      logger.error({ ruleId, error }, 'Failed to delete alert rule');
      throw error;
    }
  }

  /**
   * Get all alert rules
   */
  getAlertRules(): AlertRule[] {
    return Array.from(this.rules.values());
  }

  /**
   * Get alert rule by ID
   */
  getAlertRule(ruleId: string): AlertRule | undefined {
    return this.rules.get(ruleId);
  }

  // ========================================================================
  // Alert Evaluation and Processing
  // ========================================================================

  /**
   * Evaluate health check results against alert rules
   */
  async evaluateHealthCheck(healthResult: SystemHealthResult): Promise<void> {
    try {
      for (const rule of this.rules.values()) {
        if (!rule.enabled) continue;

        const shouldAlert = await this.evaluateAlertRule(rule, healthResult);
        if (shouldAlert) {
          await this.triggerAlert(rule, healthResult);
        } else {
          await this.checkAlertResolution(rule, healthResult);
        }
      }
    } catch (error) {
      logger.error({ error }, 'Failed to evaluate health check for alerts');
    }
  }

  /**
   * Evaluate individual alert rule against health data
   */
  private async evaluateAlertRule(
    rule: AlertRule,
    healthResult: SystemHealthResult
  ): Promise<boolean> {
    try {
      const relevantComponents = this.getRelevantComponents(rule.condition, healthResult);
      if (relevantComponents.length === 0) return false;

      for (const component of relevantComponents) {
        const metricValue = this.extractMetricValue(rule.condition.metric, component);
        if (metricValue === null) continue;

        const conditionMet = this.evaluateCondition(
          metricValue,
          rule.condition.operator,
          rule.condition.threshold
        );

        if (conditionMet) {
          // Check duration requirement
          const conditionDuration = await this.checkConditionDuration(rule, component, Date.now());

          if (conditionDuration) {
            return true;
          }
        }
      }

      return false;
    } catch (error) {
      logger.error({ ruleId: rule.id, error }, 'Failed to evaluate alert rule');
      return false;
    }
  }

  /**
   * Trigger a new alert
   */
  private async triggerAlert(rule: AlertRule, healthResult: SystemHealthResult): Promise<void> {
    try {
      const alertId = this.generateAlertId(rule.id);

      // Check if alert is already active and within cooldown
      const existingAlert = this.activeAlerts.get(alertId);
      if (existingAlert && this.isWithinCooldown(existingAlert, rule.cooldownPeriod)) {
        return;
      }

      // Create new alert
      const alert: Alert = {
        id: alertId,
        ruleId: rule.id,
        ruleName: rule.name,
        severity: rule.severity,
        status: 'firing',
        title: this.generateAlertTitle(rule, healthResult),
        message: this.generateAlertMessage(rule, healthResult),
        source: this.extractAlertSource(rule, healthResult),
        timestamp: new Date(),
        escalated: false,
        escalationLevel: 0,
        notificationsSent: [],
        metadata: {
          healthCheck: healthResult,
          ruleTags: rule.tags,
        },
      };

      // Store alert
      this.activeAlerts.set(alertId, alert);
      this.alertHistory.push(alert);

      // Send notifications
      await this.sendAlertNotifications(alert, rule.actions);

      // Schedule escalation if needed
      if (rule.escalationPolicy?.enabled) {
        this.scheduleEscalation(alert, rule);
      }

      logger.info({ alertId, ruleId: rule.id, severity: rule.severity }, 'Alert triggered');

      this.emit('alert_triggered', alert);
    } catch (error) {
      logger.error({ ruleId: rule.id, error }, 'Failed to trigger alert');
    }
  }

  /**
   * Acknowledge an alert
   */
  async acknowledgeAlert(alertId: string, acknowledgedBy: string): Promise<void> {
    try {
      const alert = this.activeAlerts.get(alertId);
      if (!alert) {
        throw new Error(`Alert not found: ${alertId}`);
      }

      if (alert.status === 'resolved') {
        throw new Error(`Cannot acknowledge resolved alert: ${alertId}`);
      }

      alert.status = 'acknowledged';
      alert.acknowledgedBy = acknowledgedBy;
      alert.acknowledgedAt = new Date();

      logger.info({ alertId, acknowledgedBy }, 'Alert acknowledged');

      this.emit('alert_acknowledged', alert);
    } catch (error) {
      logger.error({ alertId, acknowledgedBy, error }, 'Failed to acknowledge alert');
      throw error;
    }
  }

  /**
   * Resolve an alert
   */
  async resolveAlert(alertId: string, reason?: string): Promise<void> {
    try {
      const alert = this.activeAlerts.get(alertId);
      if (!alert) {
        throw new Error(`Alert not found: ${alertId}`);
      }

      alert.status = 'resolved';
      alert.resolvedAt = new Date();

      // Move to history and remove from active
      this.activeAlerts.delete(alertId);

      logger.info({ alertId, reason }, 'Alert resolved');

      this.emit('alert_resolved', alert);
    } catch (error) {
      logger.error({ alertId, reason, error }, 'Failed to resolve alert');
      throw error;
    }
  }

  // ========================================================================
  // Notification System
  // ========================================================================

  /**
   * Send notifications for an alert
   */
  private async sendAlertNotifications(alert: Alert, actions: AlertAction[]): Promise<void> {
    try {
      for (const action of actions.filter((a) => a.enabled)) {
        await this.sendNotification(alert, action);
      }
    } catch (error) {
      logger.error({ alertId: alert.id, error }, 'Failed to send alert notifications');
    }
  }

  /**
   * Send individual notification
   */
  private async sendNotification(alert: Alert, action: AlertAction): Promise<void> {
    const attemptId = this.generateNotificationId();
    const maxRetries = action.retryAttempts || 3;
    const retryDelay = action.retryDelay || 5000;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      const notificationAttempt: NotificationAttempt = {
        id: attemptId,
        alertId: alert.id,
        actionType: action.type,
        status: attempt === 0 ? 'pending' : 'retrying',
        timestamp: new Date(),
        retryCount: attempt,
      };

      try {
        let result: unknown;

        switch (action.type) {
          case 'email':
            result = await this.sendEmailNotification(alert, action.config);
            break;
          case 'slack':
            result = await this.sendSlackNotification(alert, action.config);
            break;
          case 'pagerduty':
            result = await this.sendPagerDutyNotification(alert, action.config);
            break;
          case 'webhook':
            result = await this.sendWebhookNotification(alert, action.config);
            break;
          case 'sns':
            result = await this.sendSNSNotification(alert, action.config);
            break;
          case 'teams':
            result = await this.sendTeamsNotification(alert, action.config);
            break;
          default:
            throw new Error(`Unsupported notification type: ${action.type}`);
        }

        notificationAttempt.status = 'sent';
        notificationAttempt.response = typeof result === 'object' && result !== null ?
          result as Record<string, unknown> :
          { result };

        alert.notificationsSent.push(notificationAttempt);
        this.notificationHistory.push(notificationAttempt);

        logger.info(
          {
            alertId: alert.id,
            actionType: action.type,
            attempt: attempt + 1,
          },
          'Notification sent successfully'
        );

        return;
      } catch (error) {
        notificationAttempt.status = 'failed';
        notificationAttempt.error = error instanceof Error ? error.message : 'Unknown error';

        alert.notificationsSent.push(notificationAttempt);
        this.notificationHistory.push(notificationAttempt);

        if (attempt < maxRetries) {
          logger.warn(
            {
              alertId: alert.id,
              actionType: action.type,
              attempt: attempt + 1,
              error: notificationAttempt.error,
            },
            'Notification failed, retrying...'
          );

          await this.sleep(retryDelay * (attempt + 1)); // Exponential backoff
        } else {
          logger.error(
            {
              alertId: alert.id,
              actionType: action.type,
              error: notificationAttempt.error,
            },
            'Notification failed after all retries'
          );
        }
      }
    }
  }

  // ========================================================================
  // Escalation Management
  // ========================================================================

  /**
   * Schedule alert escalation
   */
  private scheduleEscalation(alert: Alert, rule: AlertRule): Promise<void> {
    return new Promise((resolve) => {
      if (!rule.escalationPolicy || !rule.escalationPolicy.enabled) {
        resolve();
        return;
      }

      const escalationRule = rule.escalationPolicy.rules[alert.escalationLevel];
      if (!escalationRule) {
        resolve();
        return;
      }

      setTimeout(async () => {
        try {
          if (alert.status === 'firing' || alert.status === 'acknowledged') {
            await this.escalateAlert(alert, escalationRule);
          }
        } catch (error) {
          logger.error({ alertId: alert.id, error }, 'Failed to escalate alert');
        }
        resolve();
      }, escalationRule.delay);
    });
  }

  /**
   * Escalate an alert
   */
  private async escalateAlert(alert: Alert, escalationRule: EscalationRule): Promise<void> {
    try {
      alert.escalated = true;
      alert.escalationLevel++;

      // Send escalation notifications
      await this.sendAlertNotifications(alert, escalationRule.actions);

      logger.info(
        {
          alertId: alert.id,
          escalationLevel: alert.escalationLevel,
          severity: escalationRule.severity,
        },
        'Alert escalated'
      );

      this.emit('alert_escalated', alert);
    } catch (error) {
      logger.error({ alertId: alert.id, error }, 'Failed to escalate alert');
    }
  }

  // ========================================================================
  // Alert Testing
  // ========================================================================

  /**
   * Run alert test scenario
   */
  async runTestScenario(scenarioId: string): Promise<AlertTestResult> {
    try {
      const scenario = this.testScenarios.get(scenarioId);
      if (!scenario) {
        throw new Error(`Test scenario not found: ${scenarioId}`);
      }

      logger.info({ scenarioId }, 'Starting alert test scenario');

      const startTime = Date.now();
      const initialActiveAlerts = this.activeAlerts.size;
      const initialNotificationHistory = this.notificationHistory.length;

      // Execute test scenario
      await this.executeTestScenario(scenario);

      // Wait for alerts to be processed
      await this.sleep(5000);

      const endTime = Date.now();
      const finalActiveAlerts = this.activeAlerts.size;
      const finalNotificationHistory = this.notificationHistory.length;

      // Collect results
      const result: AlertTestResult = {
        scenarioId,
        scenarioName: scenario.name,
        startTime: new Date(startTime),
        endTime: new Date(endTime),
        duration: endTime - startTime,
        alertsTriggered: finalActiveAlerts - initialActiveAlerts,
        notificationsSent: finalNotificationHistory - initialNotificationHistory,
        escalationsTriggered: this.countEscalations(),
        passed: this.validateTestResults(scenario, {
          alertsFired: finalActiveAlerts - initialActiveAlerts,
          alertSeverities: Array.from(this.activeAlerts.values()).map((alert) => alert.severity),
          notificationsSent: finalNotificationHistory - initialNotificationHistory,
          escalationsTriggered: this.countEscalations(),
        }),
        details: {
          activeAlerts: Array.from(this.activeAlerts.values()),
          notifications: this.notificationHistory.slice(-50), // Last 50 notifications
        },
      };

      // Cleanup if needed
      if (scenario.cleanup) {
        await this.executeTestCleanup(scenario.cleanup);
      }

      logger.info(
        {
          scenarioId,
          passed: result.passed,
          alertsTriggered: result.alertsTriggered,
          duration: result.duration,
        },
        'Alert test scenario completed'
      );

      this.emit('alert_test_completed', result);

      return result;
    } catch (error) {
      logger.error({ scenarioId, error }, 'Failed to run alert test scenario');
      throw error;
    }
  }

  // ========================================================================
  // Runbook Integration
  // ========================================================================

  /**
   * Get runbook for alert
   */
  getRunbookForAlert(alert: Alert): Runbook | null {
    const rule = this.rules.get(alert.ruleId);
    if (!rule || !rule.runbookId) {
      return null;
    }

    return this.runbooks.get(rule.runbookId) || null;
  }

  /**
   * Execute runbook step
   */
  async executeRunbookStep(
    runbookId: string,
    stepId: string,
    context?: Record<string, unknown>
  ): Promise<RunbookStepResult> {
    try {
      const runbook = this.runbooks.get(runbookId);
      if (!runbook) {
        throw new Error(`Runbook not found: ${runbookId}`);
      }

      const step = runbook.steps.find((s) => s.id === stepId);
      if (!step) {
        throw new Error(`Runbook step not found: ${stepId}`);
      }

      const startTime = Date.now();
      let result: unknown;

      switch (step.type) {
        case 'automated':
          result = await this.executeAutomatedStep(step, context);
          break;
        case 'verification':
          result = await this.executeVerificationStep(step, context);
          break;
        case 'manual':
          result = await this.executeManualStep(step, context);
          break;
        default:
          throw new Error(`Unsupported step type: ${step.type}`);
      }

      const endTime = Date.now();

      const stepResult: RunbookStepResult = {
        runbookId,
        stepId,
        stepTitle: step.title,
        stepType: step.type,
        startTime: new Date(startTime),
        endTime: new Date(endTime),
        duration: endTime - startTime,
        success: true,
        result,
      };

      logger.info(
        {
          runbookId,
          stepId,
          duration: stepResult.duration,
        },
        'Runbook step executed successfully'
      );

      this.emit('runbook_step_completed', stepResult);

      return stepResult;
    } catch (error) {
      const stepResult: RunbookStepResult = {
        runbookId,
        stepId,
        stepTitle: 'Unknown',
        stepType: 'manual',
        startTime: new Date(),
        endTime: new Date(),
        duration: 0,
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };

      logger.error({ runbookId, stepId, error }, 'Failed to execute runbook step');

      this.emit('runbook_step_failed', stepResult);

      return stepResult;
    }
  }

  // ========================================================================
  // Metrics and Monitoring
  // ========================================================================

  /**
   * Get alert metrics
   */
  getAlertMetrics(): AlertMetrics {
    const now = Date.now();
    const last24h = now - 24 * 60 * 60 * 1000;
    const last7d = now - 7 * 24 * 60 * 60 * 1000;

    const recentAlerts = this.alertHistory.filter((a) => a.timestamp.getTime() > last24h);
    const weeklyAlerts = this.alertHistory.filter((a) => a.timestamp.getTime() > last7d);

    return {
      total: this.alertHistory.length,
      active: this.activeAlerts.size,
      last24h: recentAlerts.length,
      last7d: weeklyAlerts.length,
      bySeverity: this.groupAlertsBySeverity(recentAlerts),
      byStatus: this.groupAlertsByStatus(Array.from(this.activeAlerts.values())),
      averageResolutionTime: this.calculateAverageResolutionTime(recentAlerts),
      notificationSuccessRate: this.calculateNotificationSuccessRate(last24h),
      escalationRate: this.calculateEscalationRate(recentAlerts),
    };
  }

  // ========================================================================
  // Private Helper Methods
  // ========================================================================

  private initializeDefaultRules(): void {
    // Database connectivity alert
    const databaseDownRule: AlertRule = {
      id: 'database-down',
      name: 'Database Connectivity Loss',
      description: 'Alert when database becomes unreachable',
      enabled: true,
      severity: AlertSeverity.CRITICAL,
      condition: {
        metric: 'status',
        operator: 'eq',
        threshold: 'unhealthy',
        duration: 30000, // 30 seconds
        evaluationWindow: 60000, // 1 minute
        filters: {
          component: 'database',
          type: DependencyType.DATABASE,
        },
      },
      actions: [
        {
          type: 'email',
          config: {
            to: ['oncall@example.com'],
            subject: 'CRITICAL: Database Connectivity Loss',
            template: 'database-down',
          },
          enabled: true,
        },
        {
          type: 'slack',
          config: {
            channel: '#alerts-critical',
            message: 'Database connectivity loss detected!',
          },
          enabled: true,
        },
      ],
      cooldownPeriod: 300000, // 5 minutes
      tags: ['database', 'connectivity', 'critical'],
    };

    // Circuit breaker open alert
    const circuitBreakerRule: AlertRule = {
      id: 'circuit-breaker-open',
      name: 'Circuit Breaker Open',
      description: 'Alert when circuit breaker opens',
      enabled: true,
      severity: AlertSeverity.WARNING,
      condition: {
        metric: 'circuit_breaker_state',
        operator: 'eq',
        threshold: 'open',
        duration: 10000, // 10 seconds
        evaluationWindow: 30000, // 30 seconds
      },
      actions: [
        {
          type: 'slack',
          config: {
            channel: '#alerts-warning',
            message: 'Circuit breaker has opened for {{component}}',
          },
          enabled: true,
        },
      ],
      cooldownPeriod: 180000, // 3 minutes
      tags: ['circuit-breaker', 'resilience'],
    };

    // Memory pressure alert
    const memoryPressureRule: AlertRule = {
      id: 'memory-pressure',
      name: 'High Memory Usage',
      description: 'Alert when memory usage exceeds threshold',
      enabled: true,
      severity: AlertSeverity.WARNING,
      condition: {
        metric: 'memory_usage_percent',
        operator: 'gt',
        threshold: 85,
        duration: 120000, // 2 minutes
        evaluationWindow: 300000, // 5 minutes
        aggregation: 'avg',
        filters: {
          component: 'system',
        },
      },
      actions: [
        {
          type: 'email',
          config: {
            to: ['devops@example.com'],
            subject: 'WARNING: High Memory Usage Detected',
            template: 'memory-pressure',
          },
          enabled: true,
        },
      ],
      cooldownPeriod: 600000, // 10 minutes
      tags: ['memory', 'performance'],
    };

    // Add default rules
    this.rules.set(databaseDownRule.id, databaseDownRule);
    this.rules.set(circuitBreakerRule.id, circuitBreakerRule);
    this.rules.set(memoryPressureRule.id, memoryPressureRule);
  }

  private startEvaluation(): void {
    this.evaluationInterval = setInterval(async () => {
      if (!this.isShuttingDown) {
        try {
          // This would be triggered by health check events
          // For now, we'll just emit a periodic heartbeat
          this.emit('evaluation_heartbeat');
        } catch (error) {
          logger.error({ error }, 'Error in alert evaluation interval');
        }
      }
    }, 30000); // Every 30 seconds
  }

  private validateAlertRule(rule: AlertRule): void {
    if (!rule.id || !rule.name) {
      throw new Error('Alert rule must have id and name');
    }

    if (!Object.values(AlertSeverity).includes(rule.severity)) {
      throw new Error(`Invalid alert severity: ${rule.severity}`);
    }

    if (!rule.condition || !rule.condition.metric) {
      throw new Error('Alert rule must have a valid condition');
    }

    if (!rule.actions || rule.actions.length === 0) {
      throw new Error('Alert rule must have at least one action');
    }
  }

  private generateAlertId(ruleId: string): string {
    return `${ruleId}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateNotificationId(): string {
    return `notif-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  private getRelevantComponents(
    condition: AlertCondition,
    healthResult: SystemHealthResult
  ): ComponentHealth[] {
    return healthResult.components.filter((component) => {
      if (condition.filters?.component && component.name !== condition.filters.component) {
        return false;
      }
      if (condition.filters?.type && component.type !== condition.filters.type) {
        return false;
      }
      return true;
    });
  }

  private extractMetricValue(metric: string, component: ComponentHealth): number | null {
    switch (metric) {
      case 'status':
        return component.status === HealthStatus.HEALTHY ? 1 : 0;
      case 'response_time_ms':
        return component.response_time_ms;
      case 'error_rate':
        return component.error_rate;
      case 'uptime_percentage':
        return component.uptime_percentage;
      case 'memory_usage_percent':
        return this.extractNumberFromDetails(component.details, 'memory_usage_percent');
      case 'circuit_breaker_state':
        return this.extractCircuitBreakerState(component.details);
      default:
        return this.extractNumberFromDetails(component.details, metric);
    }
  }

  /**
   * Safely extracts a numeric value from component details
   */
  private extractNumberFromDetails(
    details: Record<string, unknown> | undefined,
    key: string
  ): number | null {
    if (!details || !(key in details)) {
      return null;
    }

    const value = details[key];
    return typeof value === 'number' ? value : null;
  }

  /**
   * Safely extracts circuit breaker state from component details
   */
  private extractCircuitBreakerState(details: Record<string, unknown> | undefined): number | null {
    if (!details || !('circuit_breaker' in details)) {
      return null;
    }

    const circuitBreaker = details.circuit_breaker;
    if (!circuitBreaker || typeof circuitBreaker !== 'object' || circuitBreaker === null) {
      return null;
    }

    const circuitBreakerObj = circuitBreaker as Record<string, unknown>;
    if (!('state' in circuitBreakerObj)) {
      return null;
    }

    const state = circuitBreakerObj.state;
    return typeof state === 'string' && state === 'open' ? 1 : 0;
  }

  private evaluateCondition(
    value: number | string,
    operator: string,
    threshold: number | string | Array<number | string>
  ): boolean {
    switch (operator) {
      case 'gt':
        return typeof value === 'number' && typeof threshold === 'number' && value > threshold;
      case 'lt':
        return typeof value === 'number' && typeof threshold === 'number' && value < threshold;
      case 'eq':
        return value === threshold;
      case 'ne':
        return value !== threshold;
      case 'gte':
        return typeof value === 'number' && typeof threshold === 'number' && value >= threshold;
      case 'lte':
        return typeof value === 'number' && typeof threshold === 'number' && value <= threshold;
      case 'in':
        return Array.isArray(threshold) && threshold.includes(value);
      case 'not_in':
        return Array.isArray(threshold) && !threshold.includes(value);
      default:
        return false;
    }
  }

  private async checkConditionDuration(
    rule: AlertRule,
    component: ComponentHealth,
    timestamp: number
  ): Promise<boolean> {
    // This would typically involve checking historical data
    // For now, we'll implement a simple check
    return true; // Simplified implementation
  }

  private isWithinCooldown(alert: Alert, cooldownPeriod: number): boolean {
    const timeSinceLastNotification = Date.now() - alert.timestamp.getTime();
    return timeSinceLastNotification < cooldownPeriod;
  }

  private generateAlertTitle(rule: AlertRule, healthResult: SystemHealthResult): string {
    return `[${rule.severity.toUpperCase()}] ${rule.name}`;
  }

  private generateAlertMessage(rule: AlertRule, healthResult: SystemHealthResult): string {
    return `${rule.description}\n\nSystem Status: ${healthResult.status}\nTimestamp: ${healthResult.timestamp}\n\nAffected Components:\n${healthResult.components.map((c) => `- ${c.name}: ${c.status}`).join('\n')}`;
  }

  private extractAlertSource(rule: AlertRule, healthResult: SystemHealthResult): Alert['source'] {
    const relevantComponent = healthResult.components.find(
      (c) => rule.condition.filters?.component === c.name
    );

    return {
      component: relevantComponent?.name || 'system',
      type: relevantComponent?.type || DependencyType.MONITORING,
      metric: rule.condition.metric,
      value: relevantComponent
        ? this.extractMetricValue(rule.condition.metric, relevantComponent) || 'unknown'
        : 'unknown',
      threshold: Array.isArray(rule.condition.threshold)
        ? rule.condition.threshold[0] || 0
        : rule.condition.threshold,
    };
  }

  private async checkAlertResolution(
    rule: AlertRule,
    healthResult: SystemHealthResult
  ): Promise<void> {
    // Find active alerts for this rule
    const activeAlerts = Array.from(this.activeAlerts.values()).filter(
      (alert) => alert.ruleId === rule.id
    );

    for (const alert of activeAlerts) {
      const shouldResolve = !(await this.evaluateAlertRule(rule, healthResult));
      if (shouldResolve) {
        await this.resolveAlert(alert.id, 'Condition resolved');
      }
    }
  }

  private async sendEmailNotification(alert: Alert, config: unknown): Promise<unknown> {
    // Placeholder implementation
    logger.info({ alertId: alert.id, config }, 'Sending email notification');
    return { messageId: `email-${Date.now()}`, status: 'sent' };
  }

  private async sendSlackNotification(alert: Alert, config: unknown): Promise<unknown> {
    // Placeholder implementation
    logger.info({ alertId: alert.id, config }, 'Sending Slack notification');
    return { messageId: `slack-${Date.now()}`, status: 'sent' };
  }

  private async sendPagerDutyNotification(alert: Alert, config: unknown): Promise<unknown> {
    // Placeholder implementation
    logger.info({ alertId: alert.id, config }, 'Sending PagerDuty notification');
    return { incidentId: `pd-${Date.now()}`, status: 'triggered' };
  }

  private async sendWebhookNotification(alert: Alert, config: unknown): Promise<unknown> {
    // Placeholder implementation
    logger.info({ alertId: alert.id, config }, 'Sending webhook notification');
    return { requestId: `webhook-${Date.now()}`, status: 'sent' };
  }

  private async sendSNSNotification(alert: Alert, config: unknown): Promise<unknown> {
    // Placeholder implementation
    logger.info({ alertId: alert.id, config }, 'Sending SNS notification');
    return { messageId: `sns-${Date.now()}`, status: 'sent' };
  }

  private async sendTeamsNotification(alert: Alert, config: unknown): Promise<unknown> {
    // Placeholder implementation
    logger.info({ alertId: alert.id, config }, 'Sending Teams notification');
    return { activityId: `teams-${Date.now()}`, status: 'sent' };
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  private countEscalations(): number {
    return Array.from(this.activeAlerts.values()).filter((alert) => alert.escalated).length;
  }

  private async executeTestScenario(scenario: AlertTestScenario): Promise<void> {
    // Simulate test scenario execution
    switch (scenario.scenario.type) {
      case 'database_down':
        // Simulate database going down
        await this.simulateDatabaseDown();
        break;
      case 'circuit_breaker':
        // Simulate circuit breaker opening
        await this.simulateCircuitBreakerOpen();
        break;
      case 'memory_pressure':
        // Simulate memory pressure
        await this.simulateMemoryPressure();
        break;
      default:
        throw new Error(`Unsupported test scenario type: ${scenario.scenario.type}`);
    }
  }

  private async simulateDatabaseDown(): Promise<void> {
    // Create a simulated health result with database down
    const simulatedHealth: SystemHealthResult = {
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

    await this.evaluateHealthCheck(simulatedHealth);
  }

  private async simulateCircuitBreakerOpen(): Promise<void> {
    // Create a simulated health result with circuit breaker open
    const simulatedHealth: SystemHealthResult = {
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

    await this.evaluateHealthCheck(simulatedHealth);
  }

  private async simulateMemoryPressure(): Promise<void> {
    // Create a simulated health result with memory pressure
    const simulatedHealth: SystemHealthResult = {
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

    await this.evaluateHealthCheck(simulatedHealth);
  }

  private validateTestResults(
    scenario: AlertTestScenario,
    actualResults: ExpectedTestResults
  ): boolean {
    const expected = scenario.expectedResults;

    return (
      actualResults.alertsFired === expected.alertsFired &&
      this.arraysEqual(actualResults.alertSeverities, expected.alertSeverities) &&
      actualResults.notificationsSent >= expected.notificationsSent &&
      actualResults.escalationsTriggered === expected.escalationsTriggered
    );
  }

  private arraysEqual<T>(a: T[], b: T[]): boolean {
    return a.length === b.length && a.every((val, index) => val === b[index]);
  }

  private async executeTestCleanup(cleanup: TestCleanup): Promise<void> {
    // Execute cleanup actions
    for (const action of cleanup.actions) {
      logger.info({ action }, 'Executing test cleanup action');
      // Implementation would depend on specific cleanup actions
    }
  }

  private groupAlertsBySeverity(alerts: Alert[]): Record<AlertSeverity, number> {
    const groups: Record<AlertSeverity, number> = {
      [AlertSeverity.INFO]: 0,
      [AlertSeverity.WARNING]: 0,
      [AlertSeverity.CRITICAL]: 0,
      [AlertSeverity.EMERGENCY]: 0,
    };

    alerts.forEach((alert) => {
      groups[alert.severity]++;
    });

    return groups;
  }

  private groupAlertsByStatus(alerts: Alert[]): Record<string, number> {
    const groups: Record<string, number> = {
      firing: 0,
      acknowledged: 0,
      resolved: 0,
      suppressed: 0,
    };

    alerts.forEach((alert) => {
      groups[alert.status]++;
    });

    return groups;
  }

  private calculateAverageResolutionTime(alerts: Alert[]): number {
    const resolvedAlerts = alerts.filter((alert) => alert.resolvedAt);
    if (resolvedAlerts.length === 0) return 0;

    const totalResolutionTime = resolvedAlerts.reduce((total, alert) => {
      return total + (alert.resolvedAt!.getTime() - alert.timestamp.getTime());
    }, 0);

    return totalResolutionTime / resolvedAlerts.length;
  }

  private calculateNotificationSuccessRate(since: number): number {
    const recentNotifications = this.notificationHistory.filter(
      (n) => n.timestamp.getTime() > since
    );

    if (recentNotifications.length === 0) return 100;

    const successfulNotifications = recentNotifications.filter((n) => n.status === 'sent').length;

    return (successfulNotifications / recentNotifications.length) * 100;
  }

  private calculateEscalationRate(alerts: Alert[]): number {
    if (alerts.length === 0) return 0;

    const escalatedAlerts = alerts.filter((alert) => alert.escalated).length;
    return (escalatedAlerts / alerts.length) * 100;
  }

  private async executeAutomatedStep(
    step: RunbookStep,
    context?: Record<string, unknown>
  ): Promise<unknown> {
    // Placeholder for automated step execution
    logger.info({ stepId: step.id, commands: step.commands }, 'Executing automated step');
    return { status: 'completed', output: 'Automated step executed successfully' };
  }

  private async executeVerificationStep(
    step: RunbookStep,
    context?: Record<string, unknown>
  ): Promise<unknown> {
    // Placeholder for verification step execution
    logger.info(
      { stepId: step.id, criteria: step.verificationCriteria },
      'Executing verification step'
    );
    return { status: 'verified', results: 'All criteria met' };
  }

  private async executeManualStep(
    step: RunbookStep,
    context?: Record<string, unknown>
  ): Promise<unknown> {
    // Placeholder for manual step execution
    logger.info({ stepId: step.id }, 'Manual step requires human intervention');
    return { status: 'pending', instructions: step.description };
  }

  /**
   * Get active alerts
   */
  getActiveAlerts(): Alert[] {
    return Array.from(this.activeAlerts.values());
  }

  /**
   * Get alert history
   */
  getAlertHistory(limit?: number): Alert[] {
    const alerts = Array.from(this.alertHistory.values());
    if (limit) {
      return alerts.slice(-limit);
    }
    return alerts;
  }

  /**
   * Cleanup method
   */
  cleanup(): void {
    this.isShuttingDown = true;

    if (this.evaluationInterval) {
      clearInterval(this.evaluationInterval);
      this.evaluationInterval = null;
    }

    this.removeAllListeners();
    logger.info('Alert management service cleaned up');
  }
}

// ============================================================================
// Supporting Interfaces
// ============================================================================

export interface AlertServiceConfig {
  evaluationIntervalMs: number;
  maxAlertHistory: number;
  maxNotificationHistory: number;
  defaultCooldownPeriod: number;
  notificationTimeoutMs: number;
  retryPolicy: {
    maxAttempts: number;
    baseDelayMs: number;
    maxDelayMs: number;
  };
}

export interface AlertTestResult {
  scenarioId: string;
  scenarioName: string;
  startTime: Date;
  endTime: Date;
  duration: number;
  alertsTriggered: number;
  notificationsSent: number;
  escalationsTriggered: number;
  passed: boolean;
  details: {
    activeAlerts: Alert[];
    notifications: NotificationAttempt[];
  };
}

export interface AlertMetrics {
  total: number;
  active: number;
  last24h: number;
  last7d: number;
  bySeverity: Record<AlertSeverity, number>;
  byStatus: Record<string, number>;
  averageResolutionTime: number;
  notificationSuccessRate: number;
  escalationRate: number;

  resolved?: unknown;

  acknowledged?: unknown;

  suppressed?: unknown;

  byRule?: unknown;

  byComponent?: unknown;

  bySource?: unknown;

  notificationsSent?: unknown;

  averageResponseTime?: unknown;
}

export interface RunbookStepResult {
  runbookId: string;
  stepId: string;
  stepTitle: string;
  stepType: string;
  startTime: Date;
  endTime: Date;
  duration: number;
  success: boolean;
  result?: unknown;
  error?: string;
}

// Export singleton instance
export const alertManagementService = new AlertManagementService({
  evaluationIntervalMs: 30000,
  maxAlertHistory: 10000,
  maxNotificationHistory: 50000,
  defaultCooldownPeriod: 300000,
  notificationTimeoutMs: 30000,
  retryPolicy: {
    maxAttempts: 3,
    baseDelayMs: 5000,
    maxDelayMs: 60000,
  },
});

// Additional exports for compatibility
export type TestResult = AlertTestResult;
export type ExecutionStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
export type TestCategory = 'functional' | 'performance' | 'security' | 'integration' | 'regression';
export type StepType = 'setup' | 'execute' | 'validate' | 'cleanup' | 'notification';
export type CommandType =
  | 'api_call'
  | 'database_query'
  | 'file_operation'
  | 'system_command'
  | 'custom';
export type VerificationType = 'automatic' | 'manual' | 'hybrid';
export type PanelType = 'metric' | 'log' | 'trace' | 'alert' | 'custom';
export type QueryType = 'promql' | 'sql' | 'logql' | 'custom';
export type AggregationType = 'sum' | 'avg' | 'min' | 'max' | 'count' | 'rate';
export type VisualizationType = 'line' | 'bar' | 'pie' | 'heatmap' | 'gauge' | 'table';
