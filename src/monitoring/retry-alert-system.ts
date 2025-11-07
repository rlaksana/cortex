// @ts-nocheck
/**
 * Comprehensive Retry Budget Alert System
 *
 * Advanced alerting system for retry budget monitoring with intelligent threshold
 * detection, multi-channel notifications, escalation policies, and alert correlation
 * with circuit breaker events and SLO violations.
 *
 * @author Cortex Team
 * @version 2.0.1
 */

import { EventEmitter } from 'events';
import { logger } from '@/utils/logger.js';
import {
  retryBudgetMonitor,
  type RetryBudgetMetrics,
  type RetryBudgetConfig
} from './retry-budget-monitor.js';
import {
  circuitBreakerMonitor,
  type CircuitBreakerHealthStatus,
  type CircuitBreakerEvent
} from './circuit-breaker-monitor.js';

/**
 * Alert severity levels
 */
export enum AlertSeverity {
  INFO = 'info',
  WARNING = 'warning',
  CRITICAL = 'critical',
}

/**
 * Alert types
 */
export enum AlertType {
  BUDGET_WARNING = 'budget_warning',
  BUDGET_CRITICAL = 'budget_critical',
  BUDGET_EXHAUSTED = 'budget_exhausted',
  SLO_VIOLATION = 'slo_violation',
  SLO_IMMINENT_VIOLATION = 'slo_imminent_violation',
  CIRCUIT_CORRELATION = 'circuit_correlation',
  PREDICTIVE_FAILURE = 'predictive_failure',
  DEPENDENCY_IMPACT = 'dependency_impact',
  BURN_RATE_HIGH = 'burn_rate_high',
  ERROR_BUDGET_EXHAUSTION = 'error_budget_exhaustion',
}

/**
 * Alert channels
 */
export enum AlertChannel {
  EMAIL = 'email',
  SLACK = 'slack',
  PAGERDUTY = 'pagerduty',
  WEBHOOK = 'webhook',
  SMS = 'sms',
  DASHBOARD = 'dashboard',
  LOG = 'log',
}

/**
 * Alert rule configuration
 */
export interface AlertRule {
  id: string;
  name: string;
  description: string;
  type: AlertType;
  severity: AlertSeverity;
  enabled: boolean;

  // Conditions
  conditions: {
    metric: string;
    operator: '>' | '<' | '=' | '>=' | '<=';
    threshold: number;
    duration?: number; // seconds
    serviceFilter?: string[]; // specific services, empty = all
  }[];

  // Notification settings
  notifications: {
    channels: AlertChannel[];
    cooldownMinutes: number;
    escalationPolicy?: string;
    suppressOnRecovery?: boolean;
  };

  // SLO integration
  slo?: {
    targetName: string;
    windowMinutes: number;
    burnRateThreshold: number;
  };
}

/**
 * Alert instance
 */
export interface Alert {
  id: string;
  ruleId: string;
  type: AlertType;
  severity: AlertSeverity;
  serviceName: string;
  title: string;
  message: string;
  details: Record<string, any>;
  timestamp: Date;
  acknowledged: boolean;
  acknowledgedBy?: string;
  acknowledgedAt?: Date;
  resolved: boolean;
  resolvedAt?: Date;
  escalated: boolean;
  escalationLevel: number;
  notificationsSent: AlertChannel[];
  correlationId?: string;
}

/**
 * Alert escalation policy
 */
export interface EscalationPolicy {
  id: string;
  name: string;
  description: string;
  levels: Array<{
    level: number;
    delayMinutes: number;
    channels: AlertChannel[];
    recipients?: string[];
    message?: string;
  }>;
  maxEscalationLevel: number;
}

/**
 * Alert system configuration
 */
export interface RetryAlertSystemConfig {
  // Alert rules
  defaultRules: AlertRule[];
  customRules?: AlertRule[];

  // Escalation policies
  escalationPolicies: EscalationPolicy[];

  // Notification channels
  channels: {
    email?: {
      enabled: boolean;
      smtp: {
        host: string;
        port: number;
        secure: boolean;
        auth: {
          user: string;
          pass: string;
        };
      };
      from: string;
      recipients: string[];
    };
    slack?: {
      enabled: boolean;
      webhookUrl: string;
      channel: string;
      username: string;
      iconEmoji?: string;
    };
    pagerduty?: {
      enabled: boolean;
      integrationKey: string;
      severity?: 'info' | 'warning' | 'error' | 'critical';
    };
    webhook?: {
      enabled: boolean;
      url: string;
      headers?: Record<string, string>;
      timeoutMs: number;
    };
  };

  // Alert processing
  processing: {
    evaluationIntervalSeconds: number;
    batchSize: number;
    deduplicationWindowMinutes: number;
    maxActiveAlerts: number;
  };

  // Alert correlation
  correlation: {
    enabled: boolean;
    windowMinutes: number;
    patterns: Array<{
      name: string;
      triggers: AlertType[];
      correlationLogic: string;
    }>;
  };

  // SLO integration
  sloIntegration: {
    enabled: boolean;
    errorBudgetThresholds: {
      warning: number; // percentage
      critical: number; // percentage
    };
    burnRateThresholds: {
      warning: number;
      critical: number;
    };
  };
}

/**
 * Alert notification payload
 */
export interface AlertNotification {
  alert: Alert;
  channel: AlertChannel;
  recipient?: string;
  message: string;
  metadata: {
    timestamp: string;
    correlationId?: string;
    escalationLevel: number;
  };
}

/**
 * Comprehensive Retry Alert System
 */
export class RetryAlertSystem extends EventEmitter {
  private config: RetryAlertSystemConfig;
  private isRunning = false;
  private startTime: number;

  // Alert management
  private activeAlerts: Map<string, Alert> = new Map();
  private alertHistory: Map<string, Alert[]> = new Map();
  private alertRules: Map<string, AlertRule> = new Map();
  private escalationPolicies: Map<string, EscalationPolicy> = new Map();

  // Processing intervals
  private evaluationInterval: NodeJS.Timeout | null = null;
  private escalationInterval: NodeJS.Timeout | null = null;

  // Alert deduplication
  private recentAlerts: Map<string, Date> = new Map();
  private alertCorrelations: Map<string, string[]> = new Map();

  constructor(config?: Partial<RetryAlertSystemConfig>) {
    super();

    this.config = {
      defaultRules: this.getDefaultAlertRules(),
      escalationPolicies: this.getDefaultEscalationPolicies(),
      channels: {
        email: {
          enabled: false,
          smtp: {
            host: '',
            port: 587,
            secure: false,
            auth: { user: '', pass: '' },
          },
          from: 'alerts@mcp-cortex.com',
          recipients: [],
        },
        slack: {
          enabled: false,
          webhookUrl: '',
          channel: '#alerts',
          username: 'MCP Cortex',
        },
        pagerduty: {
          enabled: false,
          integrationKey: '',
        },
        webhook: {
          enabled: false,
          url: '',
          timeoutMs: 5000,
        },
      },
      processing: {
        evaluationIntervalSeconds: 30,
        batchSize: 50,
        deduplicationWindowMinutes: 15,
        maxActiveAlerts: 1000,
      },
      correlation: {
        enabled: true,
        windowMinutes: 30,
        patterns: this.getDefaultCorrelationPatterns(),
      },
      sloIntegration: {
        enabled: true,
        errorBudgetThresholds: {
          warning: 70,
          critical: 90,
        },
        burnRateThresholds: {
          warning: 2,
          critical: 5,
        },
      },
      ...config,
    };

    this.startTime = Date.now();
    this.initializeRules();
    this.setupEventListeners();
  }

  /**
   * Start the alert system
   */
  start(): void {
    if (this.isRunning) {
      logger.warn('Retry alert system is already running');
      return;
    }

    this.isRunning = true;

    // Start evaluation interval
    this.evaluationInterval = setInterval(
      () => this.evaluateAlertRules(),
      this.config.processing.evaluationIntervalSeconds * 1000
    );

    // Start escalation interval
    this.escalationInterval = setInterval(
      () => this.processEscalations(),
      60 * 1000 // Every minute
    );

    // Perform initial evaluation
    this.evaluateAlertRules();

    logger.info(
      {
        evaluationInterval: this.config.processing.evaluationIntervalSeconds,
        rulesCount: this.alertRules.size,
        escalationPoliciesCount: this.escalationPolicies.size,
      },
      'Retry alert system started'
    );

    this.emit('started');
  }

  /**
   * Stop the alert system
   */
  stop(): void {
    if (!this.isRunning) {
      logger.warn('Retry alert system is not running');
      return;
    }

    this.isRunning = false;

    if (this.evaluationInterval) {
      clearInterval(this.evaluationInterval);
      this.evaluationInterval = null;
    }

    if (this.escalationInterval) {
      clearInterval(this.escalationInterval);
      this.escalationInterval = null;
    }

    logger.info('Retry alert system stopped');
    this.emit('stopped');
  }

  /**
   * Add custom alert rule
   */
  addAlertRule(rule: AlertRule): void {
    this.alertRules.set(rule.id, rule);
    logger.info({ ruleId: rule.id, ruleName: rule.name }, 'Alert rule added');
    this.emit('rule_added', rule);
  }

  /**
   * Update alert rule
   */
  updateAlertRule(ruleId: string, updates: Partial<AlertRule>): boolean {
    const existing = this.alertRules.get(ruleId);
    if (!existing) return false;

    const updated = { ...existing, ...updates };
    this.alertRules.set(ruleId, updated);
    logger.info({ ruleId, ruleName: updated.name }, 'Alert rule updated');
    this.emit('rule_updated', updated);
    return true;
  }

  /**
   * Delete alert rule
   */
  deleteAlertRule(ruleId: string): boolean {
    const deleted = this.alertRules.delete(ruleId);
    if (deleted) {
      logger.info({ ruleId }, 'Alert rule deleted');
      this.emit('rule_deleted', { ruleId });
    }
    return deleted;
  }

  /**
   * Get all alert rules
   */
  getAlertRules(): AlertRule[] {
    return Array.from(this.alertRules.values());
  }

  /**
   * Get active alerts
   */
  getActiveAlerts(): Alert[] {
    return Array.from(this.activeAlerts.values())
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  }

  /**
   * Get alert history for a service
   */
  getAlertHistory(serviceName: string, hours: number = 24): Alert[] {
    const history = this.alertHistory.get(serviceName) || [];
    const cutoff = Date.now() - (hours * 60 * 60 * 1000);

    return history
      .filter(alert => alert.timestamp.getTime() >= cutoff)
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  }

  /**
   * Acknowledge alert
   */
  acknowledgeAlert(alertId: string, acknowledgedBy?: string): boolean {
    const alert = this.activeAlerts.get(alertId);
    if (!alert) return false;

    alert.acknowledged = true;
    alert.acknowledgedBy = acknowledgedBy;
    alert.acknowledgedAt = new Date();

    logger.info({ alertId, acknowledgedBy }, 'Alert acknowledged');
    this.emit('alert_acknowledged', alert);
    return true;
  }

  /**
   * Resolve alert
   */
  resolveAlert(alertId: string): boolean {
    const alert = this.activeAlerts.get(alertId);
    if (!alert) return false;

    alert.resolved = true;
    alert.resolvedAt = new Date();

    // Move to history
    this.moveAlertToHistory(alert);
    this.activeAlerts.delete(alertId);

    logger.info({ alertId }, 'Alert resolved');
    this.emit('alert_resolved', alert);
    return true;
  }

  /**
   * Add escalation policy
   */
  addEscalationPolicy(policy: EscalationPolicy): void {
    this.escalationPolicies.set(policy.id, policy);
    logger.info({ policyId: policy.id, policyName: policy.name }, 'Escalation policy added');
    this.emit('escalation_policy_added', policy);
  }

  /**
   * Manually trigger alert for testing
   */
  async triggerTestAlert(serviceName: string, type: AlertType, severity: AlertSeverity): Promise<void> {
    const alert: Alert = {
      id: `test_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      ruleId: 'test_rule',
      type,
      severity,
      serviceName,
      title: `Test Alert: ${type}`,
      message: `This is a test alert for ${serviceName}`,
      details: { test: true },
      timestamp: new Date(),
      acknowledged: false,
      resolved: false,
      escalated: false,
      escalationLevel: 0,
      notificationsSent: [],
    };

    await this.processAlert(alert);
    logger.info({ alertId: alert.id, serviceName, type }, 'Test alert triggered');
  }

  /**
   * Evaluate all alert rules
   */
  private async evaluateAlertRules(): Promise<void> {
    if (!this.isRunning) return;

    try {
      const retryBudgetMetrics = retryBudgetMonitor.getAllMetrics();
      const circuitBreakerMetrics = circuitBreakerMonitor.getAllHealthStatuses();

      for (const [serviceName, retryMetrics] of retryBudgetMetrics) {
        await this.evaluateRulesForService(serviceName, retryMetrics, circuitBreakerMetrics.get(serviceName));
      }

      // Clean up old alerts
      this.cleanupOldAlerts();

      // Process alert correlations
      if (this.config.correlation.enabled) {
        this.processAlertCorrelations();
      }

    } catch (error) {
      logger.error({ error }, 'Failed to evaluate alert rules');
    }
  }

  /**
   * Evaluate rules for a specific service
   */
  private async evaluateRulesForService(
    serviceName: string,
    retryMetrics: RetryBudgetMetrics,
    circuitMetrics?: CircuitBreakerHealthStatus
  ): Promise<void> {
    for (const rule of this.alertRules.values()) {
      if (!rule.enabled) continue;
      const svcFilter = (rule.conditions as any[]).find(c => 'serviceFilter' in c)?.serviceFilter as string[] | undefined;
      if (svcFilter && !svcFilter.includes(serviceName)) continue;

      const shouldAlert = await this.evaluateRuleConditions(rule, serviceName, retryMetrics, circuitMetrics);
      if (shouldAlert) {
        await this.createAlert(rule, serviceName, retryMetrics, circuitMetrics);
      }
    }
  }

  /**
   * Evaluate rule conditions
   */
  private async evaluateRuleConditions(
    rule: AlertRule,
    serviceName: string,
    retryMetrics: RetryBudgetMetrics,
    circuitMetrics?: CircuitBreakerHealthStatus
  ): Promise<boolean> {
    for (const condition of rule.conditions) {
      const value = this.getMetricValue(condition.metric, serviceName, retryMetrics, circuitMetrics);
      if (value === null) continue;

      let conditionMet = false;
      switch (condition.operator) {
        case '>':
          conditionMet = value > condition.threshold;
          break;
        case '<':
          conditionMet = value < condition.threshold;
          break;
        case '>=':
          conditionMet = value >= condition.threshold;
          break;
        case '<=':
          conditionMet = value <= condition.threshold;
          break;
        case '=':
          conditionMet = value === condition.threshold;
          break;
      }

      if (conditionMet) {
        // Check duration if specified
        if (condition.duration) {
          const recentAlertKey = `${rule.id}:${serviceName}:${condition.metric}`;
          const lastAlert = this.recentAlerts.get(recentAlertKey);
          if (!lastAlert || Date.now() - lastAlert.getTime() < condition.duration * 1000) {
            if (lastAlert) {
              this.recentAlerts.set(recentAlertKey, new Date());
            }
            continue; // Duration not met yet
          }
        }

        return true;
      }
    }

    return false;
  }

  /**
   * Get metric value for evaluation
   */
  private getMetricValue(
    metric: string,
    serviceName: string,
    retryMetrics: RetryBudgetMetrics,
    circuitMetrics?: CircuitBreakerHealthStatus
  ): number | null {
    switch (metric) {
      case 'budget_utilization_percent':
        return retryMetrics.current.budgetUtilizationPercent;
      case 'retry_rate_percent':
        return retryMetrics.current.retryRatePercent;
      case 'remaining_retries_hour':
        return retryMetrics.current.budgetRemainingHour;
      case 'slo_compliance':
        return retryMetrics.slo.overallCompliance ? 1 : 0;
      case 'circuit_failure_rate':
        return circuitMetrics?.metrics.failureRate || 0;
      case 'circuit_consecutive_failures':
        return circuitMetrics?.metrics.consecutiveFailures || 0;
      case 'success_rate_variance':
        return retryMetrics.slo.successRateVariance;
      case 'response_time_p95':
        return retryMetrics.performance.p95ResponseTime;
      case 'error_budget_consumed_percent':
        return this.calculateErrorBudgetConsumption(retryMetrics);
      case 'burn_rate':
        return this.calculateBurnRate(retryMetrics);
      default:
        logger.warn({ metric }, 'Unknown metric for alert evaluation');
        return null;
    }
  }

  /**
   * Create alert from rule
   */
  private async createAlert(
    rule: AlertRule,
    serviceName: string,
    retryMetrics: RetryBudgetMetrics,
    circuitMetrics?: CircuitBreakerHealthStatus
  ): Promise<void> {
    const alertId = `${rule.id}_${serviceName}_${Date.now()}`;

    // Check for deduplication
    const dedupKey = `${rule.type}:${serviceName}`;
    const recentAlert = this.recentAlerts.get(dedupKey);
    if (recentAlert && Date.now() - recentAlert.getTime() < rule.notifications.cooldownMinutes * 60 * 1000) {
      return; // Skip due to cooldown
    }

    const alert: Alert = {
      id: alertId,
      ruleId: rule.id,
      type: rule.type,
      severity: rule.severity,
      serviceName,
      title: this.generateAlertTitle(rule, serviceName),
      message: this.generateAlertMessage(rule, serviceName, retryMetrics, circuitMetrics),
      details: {
        ruleName: rule.name,
        retryMetrics,
        circuitMetrics,
        timestamp: new Date().toISOString(),
      },
      timestamp: new Date(),
      acknowledged: false,
      resolved: false,
      escalated: false,
      escalationLevel: 0,
      notificationsSent: [],
    };

    await this.processAlert(alert);
    this.recentAlerts.set(dedupKey, new Date());
  }

  /**
   * Process alert (notifications, storage, etc.)
   */
  private async processAlert(alert: Alert): Promise<void> {
    // Store alert
    this.activeAlerts.set(alert.id, alert);

    // Send notifications
    const rule = this.alertRules.get(alert.ruleId);
    if (rule) {
      for (const channel of rule.notifications.channels) {
        await this.sendNotification(alert, channel);
        alert.notificationsSent.push(channel);
      }
    }

    // Emit alert event
    this.emit('alert_created', alert);

    logger.info(
      {
        alertId: alert.id,
        serviceName: alert.serviceName,
        type: alert.type,
        severity: alert.severity,
      },
      'Alert created and processed'
    );
  }

  /**
   * Send notification through specified channel
   */
  private async sendNotification(alert: Alert, channel: AlertChannel): Promise<void> {
    try {
      const notification: AlertNotification = {
        alert,
        channel,
        message: this.formatNotificationMessage(alert, channel),
        metadata: {
          timestamp: new Date().toISOString(),
          correlationId: alert.correlationId,
          escalationLevel: alert.escalationLevel,
        },
      };

      switch (channel) {
        case AlertChannel.EMAIL:
          await this.sendEmailNotification(notification);
          break;
        case AlertChannel.SLACK:
          await this.sendSlackNotification(notification);
          break;
        case AlertChannel.PAGERDUTY:
          await this.sendPagerDutyNotification(notification);
          break;
        case AlertChannel.WEBHOOK:
          await this.sendWebhookNotification(notification);
          break;
        case AlertChannel.DASHBOARD:
          this.emit('dashboard_alert', notification);
          break;
        case AlertChannel.LOG:
          logger[alert.severity === 'critical' ? 'error' : 'warn'](
            {
              alertId: alert.id,
              serviceName: alert.serviceName,
              type: alert.type,
              message: alert.message,
            },
            `Alert: ${alert.title}`
          );
          break;
      }

      logger.debug({ alertId: alert.id, channel }, 'Alert notification sent');
    } catch (error) {
      logger.error({ alertId: alert.id, channel, error }, 'Failed to send alert notification');
    }
  }

  /**
   * Process escalations
   */
  private async processEscalations(): Promise<void> {
    const now = Date.now();

    for (const alert of this.activeAlerts.values()) {
      if (alert.acknowledged || alert.resolved) continue;

      const rule = this.alertRules.get(alert.ruleId);
      if (!rule?.notifications.escalationPolicy) continue;

      const policy = this.escalationPolicies.get(rule.notifications.escalationPolicy);
      if (!policy) continue;

      // Check if escalation is needed
      const timeSinceAlert = now - alert.timestamp.getTime();
      const currentLevel = policy.levels.find(level =>
        timeSinceAlert >= level.delayMinutes * 60 * 1000 && level.level > alert.escalationLevel
      );

      if (currentLevel && !alert.escalated) {
        await this.escalateAlert(alert, currentLevel, policy);
      }
    }
  }

  /**
   * Escalate alert
   */
  private async escalateAlert(alert: Alert, level: any, policy: EscalationPolicy): Promise<void> {
    alert.escalated = true;
    alert.escalationLevel = level.level;

    // Send escalation notifications
    for (const channel of level.channels) {
      await this.sendNotification(alert, channel);
    }

    logger.info(
      {
        alertId: alert.id,
        serviceName: alert.serviceName,
        escalationLevel: level.level,
        policy: policy.name,
      },
      'Alert escalated'
    );

    this.emit('alert_escalated', { alert, level, policy });
  }

  /**
   * Process alert correlations
   */
  private processAlertCorrelations(): void {
    const recentAlerts = Array.from(this.activeAlerts.values())
      .filter(alert => Date.now() - alert.timestamp.getTime() < this.config.correlation.windowMinutes * 60 * 1000);

    for (const pattern of this.config.correlation.patterns) {
      const matchingAlerts = recentAlerts.filter(alert => pattern.triggers.includes(alert.type));

      if (matchingAlerts.length >= 2) {
        const correlationId = `corr_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

        for (const alert of matchingAlerts) {
          alert.correlationId = correlationId;
        }

        this.alertCorrelations.set(correlationId, matchingAlerts.map(a => a.id));

        logger.info(
          {
            correlationId,
            pattern: pattern.name,
            alertCount: matchingAlerts.length,
          },
          'Alert correlation detected'
        );

        this.emit('alert_correlation', { correlationId, pattern, alerts: matchingAlerts });
      }
    }
  }

  /**
   * Clean up old alerts and data
   */
  private cleanupOldAlerts(): void {
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours

    // Clean up recent alerts for deduplication
    for (const [key, timestamp] of this.recentAlerts) {
      if (now - timestamp.getTime() > this.config.processing.deduplicationWindowMinutes * 60 * 1000) {
        this.recentAlerts.delete(key);
      }
    }

    // Clean up resolved alerts from history
    for (const [serviceName, history] of this.alertHistory) {
      const filtered = history.filter(alert => now - alert.timestamp.getTime() < maxAge);
      this.alertHistory.set(serviceName, filtered);
    }

    // Ensure we don't exceed max active alerts
    if (this.activeAlerts.size > this.config.processing.maxActiveAlerts) {
      const sorted = Array.from(this.activeAlerts.values())
        .sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

      const toRemove = sorted.slice(0, this.activeAlerts.size - this.config.processing.maxActiveAlerts);
      for (const alert of toRemove) {
        this.moveAlertToHistory(alert);
        this.activeAlerts.delete(alert.id);
      }
    }
  }

  /**
   * Move alert to history
   */
  private moveAlertToHistory(alert: Alert): void {
    if (!this.alertHistory.has(alert.serviceName)) {
      this.alertHistory.set(alert.serviceName, []);
    }

    const history = this.alertHistory.get(alert.serviceName)!;
    history.push(alert);

    // Keep only recent history
    const maxSize = 1000;
    if (history.length > maxSize) {
      history.splice(0, history.length - maxSize);
    }
  }

  /**
   * Generate alert title
   */
  private generateAlertTitle(rule: AlertRule, serviceName: string): string {
    switch (rule.type) {
      case AlertType.BUDGET_WARNING:
        return `Retry Budget Warning: ${serviceName}`;
      case AlertType.BUDGET_CRITICAL:
        return `Retry Budget Critical: ${serviceName}`;
      case AlertType.SLO_VIOLATION:
        return `SLO Violation: ${serviceName}`;
      case AlertType.CIRCUIT_CORRELATION:
        return `Circuit Breaker Impact: ${serviceName}`;
      case AlertType.PREDICTIVE_FAILURE:
        return `Predicted Failure: ${serviceName}`;
      default:
        return `Alert: ${serviceName}`;
    }
  }

  /**
   * Generate alert message
   */
  private generateAlertMessage(
    rule: AlertRule,
    serviceName: string,
    retryMetrics: RetryBudgetMetrics,
    circuitMetrics?: CircuitBreakerHealthStatus
  ): string {
    switch (rule.type) {
      case AlertType.BUDGET_WARNING:
      case AlertType.BUDGET_CRITICAL:
        return `Retry budget utilization is ${retryMetrics.current.budgetUtilizationPercent.toFixed(1)}% for ${serviceName}. Threshold: ${rule.conditions[0].threshold}%.`;
      case AlertType.SLO_VIOLATION:
        return `SLO violation detected for ${serviceName}. Success Rate: ${retryMetrics.slo.successRateVariance.toFixed(1)}%, P95 Latency: ${retryMetrics.performance.p95ResponseTime}ms`;
      case AlertType.CIRCUIT_CORRELATION:
        return `Circuit breaker state (${circuitMetrics?.state}) detected for ${serviceName}. This may impact retry patterns.`;
      case AlertType.PREDICTIVE_FAILURE:
        return `Predictive analysis indicates potential failure for ${serviceName}. Risk level: ${retryMetrics.predictions.riskLevel}`;
      default:
        return rule.description;
    }
  }

  /**
   * Format notification message for channel
   */
  private formatNotificationMessage(alert: Alert, channel: AlertChannel): string {
    const baseMessage = `${alert.title}\n\n${alert.message}\n\nService: ${alert.serviceName}\nSeverity: ${alert.severity}\nTime: ${alert.timestamp.toISOString()}`;

    switch (channel) {
      case AlertChannel.SLACK:
        return `🚨 *${alert.title}*\n\n${alert.message}\n\n*Service:* ${alert.serviceName}\n*Severity:* ${alert.severity}\n*Time:* ${alert.timestamp.toISOString()}`;
      default:
        return baseMessage;
    }
  }

  /**
   * Calculate error budget consumption
   */
  private calculateErrorBudgetConsumption(metrics: RetryBudgetMetrics): number {
    const targetAvailability = 99.9; // SLO target
    const currentAvailability = metrics.slo.successRateVariance || 100;
    const errorBudget = 100 - targetAvailability;
    const consumed = Math.max(0, targetAvailability - currentAvailability);
    return errorBudget > 0 ? (consumed / errorBudget) * 100 : 0;
  }

  /**
   * Calculate burn rate
   */
  private calculateBurnRate(metrics: RetryBudgetMetrics): number {
    const currentErrorRate = metrics.current.retryRatePercent;
    const targetErrorRate = 0.1; // SLO target
    return currentErrorRate / Math.max(targetErrorRate, 0.01);
  }

  /**
   * Initialize default rules
   */
  private initializeRules(): void {
    for (const rule of this.config.defaultRules) {
      this.alertRules.set(rule.id, rule);
    }

    for (const policy of this.config.escalationPolicies) {
      this.escalationPolicies.set(policy.id, policy);
    }
  }

  /**
   * Set up event listeners
   */
  private setupEventListeners(): void {
    // Listen to circuit breaker events
    circuitBreakerMonitor.on('alert', (alert: any) => {
      // Create correlation alert if circuit breaker impacts retry budget
      const correlationRule = this.alertRules.get('circuit_correlation');
      if (correlationRule && correlationRule.enabled) {
        // This will be handled in the next evaluation cycle
      }
    });

    // Listen to retry budget events
    retryBudgetMonitor.on('alert', (alert: any) => {
      // Direct alert creation for immediate critical events
      if (alert.severity === 'critical') {
        // This will be handled in the next evaluation cycle
      }
    });
  }

  /**
   * Get default alert rules
   */
  private getDefaultAlertRules(): AlertRule[] {
    return [
      {
        id: 'budget_warning',
        name: 'Retry Budget Warning',
        description: 'Alert when retry budget utilization exceeds warning threshold',
        type: AlertType.BUDGET_WARNING,
        severity: AlertSeverity.WARNING,
        enabled: true,
        conditions: [
          {
            metric: 'budget_utilization_percent',
            operator: '>=',
            threshold: 75,
            duration: 300, // 5 minutes
          },
        ],
        notifications: {
          channels: [AlertChannel.DASHBOARD, AlertChannel.LOG],
          cooldownMinutes: 15,
        },
      },
      {
        id: 'budget_critical',
        name: 'Retry Budget Critical',
        description: 'Alert when retry budget utilization exceeds critical threshold',
        type: AlertType.BUDGET_CRITICAL,
        severity: AlertSeverity.CRITICAL,
        enabled: true,
        conditions: [
          {
            metric: 'budget_utilization_percent',
            operator: '>=',
            threshold: 90,
            duration: 60, // 1 minute
          },
        ],
        notifications: {
          channels: [AlertChannel.EMAIL, AlertChannel.SLACK, AlertChannel.DASHBOARD, AlertChannel.LOG],
          cooldownMinutes: 5,
          escalationPolicy: 'default_escalation',
        },
      },
      {
        id: 'slo_violation',
        name: 'SLO Violation',
        description: 'Alert when SLO targets are not met',
        type: AlertType.SLO_VIOLATION,
        severity: AlertSeverity.CRITICAL,
        enabled: true,
        conditions: [
          {
            metric: 'slo_compliance',
            operator: '=',
            threshold: 0,
            duration: 300, // 5 minutes
          },
        ],
        notifications: {
          channels: [AlertChannel.EMAIL, AlertChannel.SLACK, AlertChannel.DASHBOARD, AlertChannel.LOG],
          cooldownMinutes: 10,
          escalationPolicy: 'default_escalation',
        },
      },
      {
        id: 'circuit_correlation',
        name: 'Circuit Breaker Correlation',
        description: 'Alert when circuit breaker state may impact retry patterns',
        type: AlertType.CIRCUIT_CORRELATION,
        severity: AlertSeverity.WARNING,
        enabled: true,
        conditions: [
          {
            metric: 'circuit_failure_rate',
            operator: '>',
            threshold: 50,
            duration: 120, // 2 minutes
          },
        ],
        notifications: {
          channels: [AlertChannel.DASHBOARD, AlertChannel.LOG],
          cooldownMinutes: 20,
        },
      },
      {
        id: 'burn_rate_high',
        name: 'High Burn Rate',
        description: 'Alert when error budget burn rate is too high',
        type: AlertType.BURN_RATE_HIGH,
        severity: AlertSeverity.WARNING,
        enabled: true,
        conditions: [
          {
            metric: 'burn_rate',
            operator: '>',
            threshold: 2,
            duration: 600, // 10 minutes
          },
        ],
        notifications: {
          channels: [AlertChannel.EMAIL, AlertChannel.DASHBOARD, AlertChannel.LOG],
          cooldownMinutes: 30,
        },
      },
    ];
  }

  /**
   * Get default escalation policies
   */
  private getDefaultEscalationPolicies(): EscalationPolicy[] {
    return [
      {
        id: 'default_escalation',
        name: 'Default Escalation Policy',
        description: 'Standard escalation policy for critical alerts',
        levels: [
          {
            level: 1,
            delayMinutes: 0,
            channels: [AlertChannel.EMAIL, AlertChannel.SLACK],
          },
          {
            level: 2,
            delayMinutes: 15,
            channels: [AlertChannel.PAGERDUTY, AlertChannel.EMAIL],
          },
          {
            level: 3,
            delayMinutes: 30,
            channels: [AlertChannel.PAGERDUTY, AlertChannel.SMS],
          },
        ],
        maxEscalationLevel: 3,
      },
    ];
  }

  /**
   * Get default correlation patterns
   */
  private getDefaultCorrelationPatterns(): Array<{
    name: string;
    triggers: AlertType[];
    correlationLogic: string;
  }> {
    return [
      {
        name: 'Circuit Breaker Impact on Retry Budget',
        triggers: [AlertType.CIRCUIT_CORRELATION, AlertType.BUDGET_WARNING],
        correlationLogic: 'circuit_state_change AND budget_utilization_increase',
      },
      {
        name: 'Multiple SLO Violations',
        triggers: [AlertType.SLO_VIOLATION, AlertType.SLO_IMMINENT_VIOLATION],
        correlationLogic: 'multiple_slo_violations_same_service',
      },
    ];
  }

  /**
   * Send email notification (placeholder)
   */
  private async sendEmailNotification(notification: AlertNotification): Promise<void> {
    // In a real implementation, this would send email via SMTP
    logger.debug({ alertId: notification.alert.id }, 'Email notification would be sent');
    this.emit('email_notification_sent', notification);
  }

  /**
   * Send Slack notification (placeholder)
   */
  private async sendSlackNotification(notification: AlertNotification): Promise<void> {
    // In a real implementation, this would send Slack webhook
    logger.debug({ alertId: notification.alert.id }, 'Slack notification would be sent');
    this.emit('slack_notification_sent', notification);
  }

  /**
   * Send PagerDuty notification (placeholder)
   */
  private async sendPagerDutyNotification(notification: AlertNotification): Promise<void> {
    // In a real implementation, this would send PagerDuty alert
    logger.debug({ alertId: notification.alert.id }, 'PagerDuty notification would be sent');
    this.emit('pagerduty_notification_sent', notification);
  }

  /**
   * Send webhook notification (placeholder)
   */
  private async sendWebhookNotification(notification: AlertNotification): Promise<void> {
    // In a real implementation, this would send HTTP webhook
    logger.debug({ alertId: notification.alert.id }, 'Webhook notification would be sent');
    this.emit('webhook_notification_sent', notification);
  }
}

// Export singleton instance
export const retryAlertSystem = new RetryAlertSystem();
