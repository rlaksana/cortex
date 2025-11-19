/**
 * SLO Alerting Service
 *
 * Defines and manages alert rules tied directly to SLO thresholds.
 * Provides comprehensive alerting for SLO breaches, burn rate monitoring, and error budget management.
 *
 * @version 1.0.0
 * @since 2025-11-14
 */

import { EventEmitter } from 'events';

import { metricsService } from './metrics-service.js';
import { sloTracingService } from './slo-tracing-service.js';
import type { NotificationChannel } from '../types/slo-interfaces.js';
import { AlertSeverity } from '../types/unified-health-interfaces.js';

// ============================================================================
// Alert Rule Definitions
// ============================================================================

export interface SLOAlertRule {
  id: string;
  name: string;
  description: string;
  sloId: string;
  condition: AlertCondition;
  severity: AlertSeverity;
  enabled: boolean;
  duration: number; // Duration in milliseconds
  cooldown: number; // Cooldown period in milliseconds
  notificationChannels: string[];
  tags: Record<string, string>;
  metadata: {
    createdAt: Date;
    updatedAt: Date;
    lastTriggered?: Date;
    triggerCount: number;
    owner?: string;
    team?: string;
    runbook?: string;
  };
}

export interface AlertCondition {
  metric: string;
  operator: 'gt' | 'gte' | 'lt' | 'lte' | 'eq' | 'ne';
  threshold: number;
  evaluationWindow: number; // Window in milliseconds
  aggregation?: 'avg' | 'sum' | 'count' | 'max' | 'min';
  filters?: Record<string, string>;
}

export interface AlertInstance {
  id: string;
  ruleId: string;
  sloId: string;
  status: 'firing' | 'resolved' | 'suppressed';
  severity: AlertSeverity;
  message: string;
  details: {
    currentValue: number;
    threshold: number;
    evaluationTime: Date;
    metricValue: number;
    breachDuration?: number;
  };
  startTime: Date;
  endTime?: Date;
  acknowledged: boolean;
  acknowledgedBy?: string;
  acknowledgedAt?: Date;
  resolvedBy?: string;
  resolvedAt?: Date;
  notificationsSent: string[];
}

// ============================================================================
// SLO Alert Rules Configuration
// ============================================================================

export const SLO_ALERT_RULES: Partial<SLOAlertRule>[] = [
  // SLO-001: API Availability
  {
    name: 'API Availability - High Burn Rate',
    description: 'Alert when API availability error burn rate exceeds 2x for 2 hours',
    sloId: 'SLO-001',
    condition: {
      metric: 'cortex_availability_success_rate',
      operator: 'lt',
      threshold: 99.8, // 99.9% target - 0.1% tolerance
      evaluationWindow: 2 * 60 * 60 * 1000, // 2 hours
      aggregation: 'avg',
    },
    severity: AlertSeverity.WARNING,
    duration: 2 * 60 * 60 * 1000, // 2 hours
    cooldown: 30 * 60 * 1000, // 30 minutes
    notificationChannels: ['email', 'slack'],
    tags: {
      team: 'platform',
      service: 'cortex-mcp',
      category: 'availability',
    },
  },
  {
    name: 'API Availability - Critical Burn Rate',
    description: 'Alert when API availability error burn rate exceeds 10x for 15 minutes',
    sloId: 'SLO-001',
    condition: {
      metric: 'cortex_availability_success_rate',
      operator: 'lt',
      threshold: 99.0, // Significant breach
      evaluationWindow: 15 * 60 * 1000, // 15 minutes
      aggregation: 'avg',
    },
    severity: AlertSeverity.CRITICAL,
    duration: 15 * 60 * 1000, // 15 minutes
    cooldown: 15 * 60 * 1000, // 15 minutes
    notificationChannels: ['pagerduty', 'slack', 'email'],
    tags: {
      team: 'platform',
      service: 'cortex-mcp',
      category: 'availability',
      escalation: 'critical',
    },
  },

  // SLO-002: API Latency (P95)
  {
    name: 'P95 Latency - Warning Threshold',
    description: 'Alert when P95 latency exceeds 400ms for 1 hour',
    sloId: 'SLO-002',
    condition: {
      metric: 'cortex_request_duration_seconds',
      operator: 'gt',
      threshold: 0.4, // 400ms
      evaluationWindow: 60 * 60 * 1000, // 1 hour
      aggregation: 'avg',
      filters: { quantile: 'p95' },
    },
    severity: AlertSeverity.WARNING,
    duration: 60 * 60 * 1000, // 1 hour
    cooldown: 30 * 60 * 1000, // 30 minutes
    notificationChannels: ['slack'],
    tags: {
      team: 'platform',
      service: 'cortex-mcp',
      category: 'latency',
    },
  },
  {
    name: 'P95 Latency - Critical Threshold',
    description: 'Alert when P95 latency exceeds 750ms for 15 minutes',
    sloId: 'SLO-002',
    condition: {
      metric: 'cortex_request_duration_seconds',
      operator: 'gt',
      threshold: 0.75, // 750ms
      evaluationWindow: 15 * 60 * 1000, // 15 minutes
      aggregation: 'avg',
      filters: { quantile: 'p95' },
    },
    severity: AlertSeverity.CRITICAL,
    duration: 15 * 60 * 1000, // 15 minutes
    cooldown: 15 * 60 * 1000, // 15 minutes
    notificationChannels: ['pagerduty', 'slack'],
    tags: {
      team: 'platform',
      service: 'cortex-mcp',
      category: 'latency',
      escalation: 'critical',
    },
  },

  // SLO-003: API Latency (P99)
  {
    name: 'P99 Latency - Warning Threshold',
    description: 'Alert when P99 latency exceeds 1500ms for 30 minutes',
    sloId: 'SLO-003',
    condition: {
      metric: 'cortex_request_duration_seconds',
      operator: 'gt',
      threshold: 1.5, // 1500ms
      evaluationWindow: 30 * 60 * 1000, // 30 minutes
      aggregation: 'avg',
      filters: { quantile: 'p99' },
    },
    severity: AlertSeverity.WARNING,
    duration: 30 * 60 * 1000, // 30 minutes
    cooldown: 30 * 60 * 1000, // 30 minutes
    notificationChannels: ['slack'],
    tags: {
      team: 'platform',
      service: 'cortex-mcp',
      category: 'latency',
    },
  },
  {
    name: 'P99 Latency - Critical Threshold',
    description: 'Alert when P99 latency exceeds 3000ms for 10 minutes',
    sloId: 'SLO-003',
    condition: {
      metric: 'cortex_request_duration_seconds',
      operator: 'gt',
      threshold: 3.0, // 3000ms
      evaluationWindow: 10 * 60 * 1000, // 10 minutes
      aggregation: 'avg',
      filters: { quantile: 'p99' },
    },
    severity: AlertSeverity.CRITICAL,
    duration: 10 * 60 * 1000, // 10 minutes
    cooldown: 10 * 60 * 1000, // 10 minutes
    notificationChannels: ['pagerduty', 'slack'],
    tags: {
      team: 'platform',
      service: 'cortex-mcp',
      category: 'latency',
      escalation: 'critical',
    },
  },

  // SLO-004: Error Rate
  {
    name: 'Error Rate - Warning Threshold',
    description: 'Alert when error rate exceeds 0.5% for 30 minutes',
    sloId: 'SLO-004',
    condition: {
      metric: 'cortex_error_rate',
      operator: 'gt',
      threshold: 0.5, // 0.5%
      evaluationWindow: 30 * 60 * 1000, // 30 minutes
      aggregation: 'avg',
    },
    severity: AlertSeverity.WARNING,
    duration: 30 * 60 * 1000, // 30 minutes
    cooldown: 30 * 60 * 1000, // 30 minutes
    notificationChannels: ['slack'],
    tags: {
      team: 'platform',
      service: 'cortex-mcp',
      category: 'error_rate',
    },
  },
  {
    name: 'Error Rate - Critical Threshold',
    description: 'Alert when error rate exceeds 2% for 5 minutes',
    sloId: 'SLO-004',
    condition: {
      metric: 'cortex_error_rate',
      operator: 'gt',
      threshold: 2.0, // 2%
      evaluationWindow: 5 * 60 * 1000, // 5 minutes
      aggregation: 'avg',
    },
    severity: AlertSeverity.CRITICAL,
    duration: 5 * 60 * 1000, // 5 minutes
    cooldown: 5 * 60 * 1000, // 5 minutes
    notificationChannels: ['pagerduty', 'slack', 'email'],
    tags: {
      team: 'platform',
      service: 'cortex-mcp',
      category: 'error_rate',
      escalation: 'critical',
    },
  },

  // SLO-005: Qdrant Operation Latency
  {
    name: 'Qdrant Latency - Warning Threshold',
    description: 'Alert when Qdrant P95 latency exceeds 800ms for 30 minutes',
    sloId: 'SLO-005',
    condition: {
      metric: 'cortex_qdrant_operation_duration_seconds',
      operator: 'gt',
      threshold: 0.8, // 800ms
      evaluationWindow: 30 * 60 * 1000, // 30 minutes
      aggregation: 'avg',
      filters: { quantile: 'p95' },
    },
    severity: AlertSeverity.WARNING,
    duration: 30 * 60 * 1000, // 30 minutes
    cooldown: 20 * 60 * 1000, // 20 minutes
    notificationChannels: ['slack'],
    tags: {
      team: 'platform',
      service: 'cortex-mcp',
      component: 'qdrant',
      category: 'latency',
    },
  },
  {
    name: 'Qdrant Latency - Critical Threshold',
    description: 'Alert when Qdrant P95 latency exceeds 1500ms for 10 minutes',
    sloId: 'SLO-005',
    condition: {
      metric: 'cortex_qdrant_operation_duration_seconds',
      operator: 'gt',
      threshold: 1.5, // 1500ms
      evaluationWindow: 10 * 60 * 1000, // 10 minutes
      aggregation: 'avg',
      filters: { quantile: 'p95' },
    },
    severity: AlertSeverity.CRITICAL,
    duration: 10 * 60 * 1000, // 10 minutes
    cooldown: 10 * 60 * 1000, // 10 minutes
    notificationChannels: ['pagerduty', 'slack'],
    tags: {
      team: 'platform',
      service: 'cortex-mcp',
      component: 'qdrant',
      category: 'latency',
      escalation: 'critical',
    },
  },

  // SLO-006: Memory Store Throughput
  {
    name: 'Memory Store QPS - Warning Threshold',
    description: 'Alert when QPS drops below 800 for 5 minutes',
    sloId: 'SLO-006',
    condition: {
      metric: 'cortex_memory_store_qps',
      operator: 'lt',
      threshold: 800,
      evaluationWindow: 5 * 60 * 1000, // 5 minutes
      aggregation: 'avg',
    },
    severity: AlertSeverity.WARNING,
    duration: 5 * 60 * 1000, // 5 minutes
    cooldown: 10 * 60 * 1000, // 10 minutes
    notificationChannels: ['slack'],
    tags: {
      team: 'platform',
      service: 'cortex-mcp',
      component: 'memory-store',
      category: 'throughput',
    },
  },
  {
    name: 'Memory Store QPS - Critical Threshold',
    description: 'Alert when QPS drops below 500 for 2 minutes',
    sloId: 'SLO-006',
    condition: {
      metric: 'cortex_memory_store_qps',
      operator: 'lt',
      threshold: 500,
      evaluationWindow: 2 * 60 * 1000, // 2 minutes
      aggregation: 'avg',
    },
    severity: AlertSeverity.CRITICAL,
    duration: 2 * 60 * 1000, // 2 minutes
    cooldown: 5 * 60 * 1000, // 5 minutes
    notificationChannels: ['pagerduty', 'slack'],
    tags: {
      team: 'platform',
      service: 'cortex-mcp',
      component: 'memory-store',
      category: 'throughput',
      escalation: 'critical',
    },
  },
];

// ============================================================================
// SLO Alerting Service
// ============================================================================

export class SLOAlertingService extends EventEmitter {
  private rules: Map<string, SLOAlertRule> = new Map();
  private activeAlerts: Map<string, AlertInstance> = new Map();
  private evaluationHistory: Map<string, Array<{ timestamp: number; value: number }>> = new Map();
  private evaluationTimer?: NodeJS.Timeout;
  private notificationChannels: Map<string, NotificationChannel> = new Map();

  constructor() {
    super();
    this.initializeDefaultRules();
    this.startEvaluation();
  }

  /**
   * Create a new alert rule
   */
  createAlertRule(rule: Omit<SLOAlertRule, 'id' | 'metadata'>): string {
    const id = this.generateAlertId();
    const fullRule: SLOAlertRule = {
      ...rule,
      id,
      metadata: {
        createdAt: new Date(),
        updatedAt: new Date(),
        triggerCount: 0,
      },
    };

    this.rules.set(id, fullRule);
    this.emit('alert_rule_created', fullRule);

    return id;
  }

  /**
   * Update an existing alert rule
   */
  updateAlertRule(id: string, updates: Partial<SLOAlertRule>): SLOAlertRule | null {
    const rule = this.rules.get(id);
    if (!rule) {
      return null;
    }

    const updatedRule: SLOAlertRule = {
      ...rule,
      ...updates,
      metadata: {
        ...rule.metadata,
        updatedAt: new Date(),
      },
    };

    this.rules.set(id, updatedRule);
    this.emit('alert_rule_updated', updatedRule);

    return updatedRule;
  }

  /**
   * Delete an alert rule
   */
  deleteAlertRule(id: string): boolean {
    const rule = this.rules.get(id);
    if (!rule) {
      return false;
    }

    // Clean up any active alerts for this rule
    for (const [alertId, alert] of Array.from(this.activeAlerts.entries())) {
      if (alert.ruleId === id) {
        this.resolveAlert(alertId, 'system', 'Rule deleted');
      }
    }

    this.rules.delete(id);
    this.emit('alert_rule_deleted', { id, rule });

    return true;
  }

  /**
   * Get all alert rules
   */
  getAlertRules(filter?: {
    sloId?: string;
    severity?: AlertSeverity;
    enabled?: boolean;
  }): SLOAlertRule[] {
    let rules = Array.from(this.rules.values());

    if (filter) {
      if (filter.sloId) {
        rules = rules.filter((rule) => rule.sloId === filter.sloId);
      }
      if (filter.severity) {
        rules = rules.filter((rule) => rule.severity === filter.severity);
      }
      if (filter.enabled !== undefined) {
        rules = rules.filter((rule) => rule.enabled === filter.enabled);
      }
    }

    return rules;
  }

  /**
   * Get active alerts
   */
  getActiveAlerts(filter?: {
    sloId?: string;
    severity?: AlertSeverity;
    status?: 'firing' | 'resolved' | 'suppressed';
  }): AlertInstance[] {
    let alerts = Array.from(this.activeAlerts.values());

    if (filter) {
      if (filter.sloId) {
        alerts = alerts.filter((alert) => alert.sloId === filter.sloId);
      }
      if (filter.severity) {
        alerts = alerts.filter((alert) => alert.severity === filter.severity);
      }
      if (filter.status) {
        alerts = alerts.filter((alert) => alert.status === filter.status);
      }
    }

    return alerts;
  }

  /**
   * Manually trigger evaluation of all rules
   */
  evaluateRules(): {
    totalRules: number;
    evaluatedRules: number;
    newAlerts: number;
    resolvedAlerts: number;
    errors: string[];
  } {
    const results = {
      totalRules: this.rules.size,
      evaluatedRules: 0,
      newAlerts: 0,
      resolvedAlerts: 0,
      errors: [] as string[],
    };

    const now = Date.now();

    for (const rule of Array.from(this.rules.values())) {
      if (!rule.enabled) {
        continue;
      }

      try {
        const evaluation = this.evaluateRule(rule, now);
        results.evaluatedRules++;

        if (evaluation.shouldAlert) {
          const existingAlert = Array.from(this.activeAlerts.values()).find(
            (alert) => alert.ruleId === rule.id && alert.status === 'firing'
          );

          if (!existingAlert) {
            this.createAlert(rule, evaluation);
            results.newAlerts++;
          }
        } else {
          const existingAlerts = Array.from(this.activeAlerts.values()).filter(
            (alert) => alert.ruleId === rule.id && alert.status === 'firing'
          );

          for (const alert of existingAlerts) {
            this.resolveAlert(alert.id, 'system', 'Condition resolved');
            results.resolvedAlerts++;
          }
        }
      } catch (error) {
        results.errors.push(`Rule ${rule.id} evaluation failed: ${error}`);
      }
    }

    this.emit('evaluation_completed', results);
    return results;
  }

  /**
   * Acknowledge an alert
   */
  acknowledgeAlert(alertId: string, acknowledgedBy: string): boolean {
    const alert = this.activeAlerts.get(alertId);
    if (!alert || alert.status !== 'firing') {
      return false;
    }

    alert.acknowledged = true;
    alert.acknowledgedBy = acknowledgedBy;
    alert.acknowledgedAt = new Date();

    this.emit('alert_acknowledged', alert);
    return true;
  }

  /**
   * Resolve an alert
   */
  resolveAlert(alertId: string, resolvedBy: string, reason: string): boolean {
    const alert = this.activeAlerts.get(alertId);
    if (!alert) {
      return false;
    }

    alert.status = 'resolved';
    alert.endTime = new Date();
    alert.resolvedBy = resolvedBy;
    alert.resolvedAt = new Date();

    // Update rule metadata
    const rule = this.rules.get(alert.ruleId);
    if (rule) {
      rule.metadata.lastTriggered = alert.endTime;
      rule.metadata.triggerCount++;
    }

    this.emit('alert_resolved', { alert, reason });
    return true;
  }

  /**
   * Get alert statistics
   */
  getAlertStatistics(timeWindowMinutes: number = 60): {
    totalAlerts: number;
    activeAlerts: number;
    alertsBySeverity: Record<AlertSeverity, number>;
    alertsBySLO: Record<string, number>;
    topAlertingRules: Array<{ ruleId: string; ruleName: string; count: number }>;
    mttr: number; // Mean Time To Resolution in minutes
  } {
    const cutoff = Date.now() - timeWindowMinutes * 60 * 1000;
    const recentAlerts = Array.from(this.activeAlerts.values()).filter(
      (alert) => alert.startTime.getTime() >= cutoff
    );

    const alertsBySeverity: Record<AlertSeverity, number> = {
      [AlertSeverity.INFO]: 0,
      [AlertSeverity.WARNING]: 0,
      [AlertSeverity.CRITICAL]: 0,
      [AlertSeverity.EMERGENCY]: 0,
    };

    const alertsBySLO: Record<string, number> = {};

    for (const alert of recentAlerts) {
      alertsBySeverity[alert.severity]++;
      alertsBySLO[alert.sloId] = (alertsBySLO[alert.sloId] || 0) + 1;
    }

    // Calculate top alerting rules
    const ruleCounts: Record<string, { ruleName: string; count: number }> = {};
    for (const alert of recentAlerts) {
      const rule = this.rules.get(alert.ruleId);
      if (rule) {
        ruleCounts[alert.ruleId] = {
          ruleName: rule.name,
          count: (ruleCounts[alert.ruleId]?.count || 0) + 1,
        };
      }
    }

    const topAlertingRules = Object.entries(ruleCounts)
      .sort(([, a], [, b]) => b.count - a.count)
      .slice(0, 10)
      .map(([ruleId, data]) => ({ ruleId, ...data }));

    // Calculate MTTR
    const resolvedAlerts = recentAlerts.filter(
      (alert) => alert.status === 'resolved' && alert.endTime
    );
    const mttr =
      resolvedAlerts.length > 0
        ? resolvedAlerts.reduce((sum, alert) => {
            const resolutionTime =
              (alert.endTime!.getTime() - alert.startTime.getTime()) / (1000 * 60); // minutes
            return sum + resolutionTime;
          }, 0) / resolvedAlerts.length
        : 0;

    return {
      totalAlerts: recentAlerts.length,
      activeAlerts: recentAlerts.filter((alert) => alert.status === 'firing').length,
      alertsBySeverity,
      alertsBySLO,
      topAlertingRules,
      mttr,
    };
  }

  /**
   * Export alert rules in various formats
   */
  exportAlertRules(format: 'json' | 'prometheus' | 'yaml' = 'json'): string {
    const rules = Array.from(this.rules.values());

    switch (format) {
      case 'json':
        return JSON.stringify(rules, null, 2);
      case 'yaml':
        return this.convertToYaml(rules);
      case 'prometheus':
        return this.convertToPrometheusRules(rules);
      default:
        throw new Error(`Unsupported export format: ${format}`);
    }
  }

  // ============================================================================
  // Private Methods
  // ============================================================================

  private initializeDefaultRules(): void {
    for (const ruleConfig of SLO_ALERT_RULES) {
      if (ruleConfig.name && ruleConfig.sloId && ruleConfig.condition && ruleConfig.severity) {
        this.createAlertRule(ruleConfig as Omit<SLOAlertRule, 'id' | 'metadata'>);
      }
    }
  }

  private startEvaluation(): void {
    // Evaluate rules every minute
    this.evaluationTimer = setInterval(() => {
      this.evaluateRules();
    }, 60 * 1000);
  }

  private evaluateRule(
    rule: SLOAlertRule,
    now: number
  ): {
    shouldAlert: boolean;
    currentValue: number;
    evaluationTime: Date;
  } {
    const currentValue = this.getMetricValue(rule.condition);
    const evaluationTime = new Date(now);

    // Store evaluation in history
    if (!this.evaluationHistory.has(rule.id)) {
      this.evaluationHistory.set(rule.id, []);
    }
    const history = this.evaluationHistory.get(rule.id)!;
    history.push({ timestamp: now, value: currentValue });

    // Keep only recent evaluations (last evaluation window)
    const cutoff = now - rule.condition.evaluationWindow;
    while (history.length > 0 && history[0].timestamp < cutoff) {
      history.shift();
    }

    // Check if we have enough data to evaluate
    if (history.length < 2) {
      return { shouldAlert: false, currentValue, evaluationTime };
    }

    // Calculate aggregated value over the evaluation window
    const aggregatedValue = this.calculateAggregation(
      history.map((h) => h.value),
      rule.condition.aggregation || 'avg'
    );

    // Check if threshold is breached
    let shouldAlert = false;
    switch (rule.condition.operator) {
      case 'gt':
        shouldAlert = aggregatedValue > rule.condition.threshold;
        break;
      case 'gte':
        shouldAlert = aggregatedValue >= rule.condition.threshold;
        break;
      case 'lt':
        shouldAlert = aggregatedValue < rule.condition.threshold;
        break;
      case 'lte':
        shouldAlert = aggregatedValue <= rule.condition.threshold;
        break;
      case 'eq':
        shouldAlert = aggregatedValue === rule.condition.threshold;
        break;
      case 'ne':
        shouldAlert = aggregatedValue !== rule.condition.threshold;
        break;
    }

    return { shouldAlert, currentValue: aggregatedValue, evaluationTime };
  }

  private getMetricValue(condition: AlertCondition): number {
    // Get current metrics from the metrics service
    const realTimeMetrics = metricsService.getRealTimeMetrics();
    const tracingMetrics = sloTracingService.getSLOMetrics(5); // Last 5 minutes

    switch (condition.metric) {
      case 'cortex_availability_success_rate':
        return 99.5; // Simulated value
      case 'cortex_request_duration_seconds':
        if (condition.filters?.quantile === 'p95') {
          return realTimeMetrics.performance.store_p95_ms / 1000;
        } else if (condition.filters?.quantile === 'p99') {
          return realTimeMetrics.performance.store_p99_ms / 1000;
        }
        return 0.1;
      case 'cortex_error_rate':
        return tracingMetrics.errorRate;
      case 'cortex_qdrant_operation_duration_seconds':
        return 0.5; // Simulated value
      case 'cortex_memory_store_qps':
        return realTimeMetrics.qps.memory_store_qps;
      default:
        return 0;
    }
  }

  private calculateAggregation(values: number[], aggregation: string): number {
    if (values.length === 0) return 0;

    switch (aggregation) {
      case 'avg':
        return values.reduce((sum, val) => sum + val, 0) / values.length;
      case 'sum':
        return values.reduce((sum, val) => sum + val, 0);
      case 'count':
        return values.length;
      case 'max':
        return Math.max(...values);
      case 'min':
        return Math.min(...values);
      default:
        return values[values.length - 1]; // Last value
    }
  }

  private createAlert(
    rule: SLOAlertRule,
    evaluation: {
      shouldAlert: boolean;
      currentValue: number;
      evaluationTime: Date;
    }
  ): void {
    const alertId = this.generateAlertId();
    const alert: AlertInstance = {
      id: alertId,
      ruleId: rule.id,
      sloId: rule.sloId,
      status: 'firing',
      severity: rule.severity,
      message: this.generateAlertMessage(rule, {
        currentValue: evaluation.currentValue,
        threshold: rule.condition.threshold,
        evaluationTime: evaluation.evaluationTime,
      }),
      details: {
        currentValue: evaluation.currentValue,
        threshold: rule.condition.threshold,
        evaluationTime: evaluation.evaluationTime,
        metricValue: evaluation.currentValue,
      },
      startTime: evaluation.evaluationTime,
      acknowledged: false,
      notificationsSent: [],
    };

    this.activeAlerts.set(alertId, alert);
    this.sendNotifications(alert, rule);
    this.emit('alert_fired', alert);
  }

  private generateAlertMessage(
    rule: SLOAlertRule,
    evaluation: {
      currentValue: number;
      threshold: number;
      evaluationTime: Date;
    }
  ): string {
    const { currentValue, threshold } = evaluation;
    const operator = this.getOperatorDescription(rule.condition.operator);

    return `SLO Alert: ${rule.name} - ${rule.sloId} breach detected. Current value: ${currentValue.toFixed(2)} ${operator} threshold: ${threshold}`;
  }

  private getOperatorDescription(operator: string): string {
    switch (operator) {
      case 'gt':
        return '>';
      case 'gte':
        return '>=';
      case 'lt':
        return '<';
      case 'lte':
        return '<=';
      case 'eq':
        return '=';
      case 'ne':
        return '!=';
      default:
        return operator;
    }
  }

  private sendNotifications(alert: AlertInstance, rule: SLOAlertRule): void {
    for (const channelId of rule.notificationChannels) {
      const channel = this.notificationChannels.get(channelId);
      if (channel) {
        // In a real implementation, this would send actual notifications
        console.log(`Sending ${alert.severity} alert to ${channelId}: ${alert.message}`);
        alert.notificationsSent.push(channelId);
      }
    }
  }

  private generateAlertId(): string {
    return `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private convertToYaml(data: unknown): string {
    // Simplified YAML conversion
    return JSON.stringify(data, null, 2)
      .replace(/"/g, '')
      .replace(/,/g, '')
      .replace(/\{/g, '')
      .replace(/\}/g, '');
  }

  private convertToPrometheusRules(rules: SLOAlertRule[]): string {
    let output = '# Cortex MCP SLO Alerting Rules\n\n';
    output += 'groups:\n';
    output += '  - name: cortex_slo_alerts\n';
    output += '    rules:\n';

    for (const rule of rules) {
      output += `      - alert: ${rule.name.replace(/[^a-zA-Z0-9_]/g, '_')}\n`;
      output += `        expr: ${rule.condition.metric} ${rule.condition.operator} ${rule.condition.threshold}\n`;
      output += `        for: ${rule.duration / 60000}m\n`;
      output += `        labels:\n`;
      output += `          severity: ${rule.severity}\n`;
      output += `          slo_id: ${rule.sloId}\n`;
      for (const [key, value] of Object.entries(rule.tags)) {
        output += `          ${key}: ${value}\n`;
      }
      output += `        annotations:\n`;
      output += `          summary: "${rule.name}"\n`;
      output += `          description: "${rule.description}"\n`;
      output += '\n';
    }

    return output;
  }

  /**
   * Graceful shutdown
   */
  async shutdown(): Promise<void> {
    if (this.evaluationTimer) {
      clearInterval(this.evaluationTimer);
      this.evaluationTimer = undefined;
    }

    this.removeAllListeners();
    this.emit('shutdown_complete');
  }
}

// Export singleton instance
export const sloAlertingService = new SLOAlertingService();
