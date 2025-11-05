/**
 * Comprehensive Retry Budget Monitor
 *
 * Advanced monitoring system for tracking retry budget consumption, circuit breaker
 * states, and service dependency health with real-time metrics, alerting, and
 * SLO compliance tracking.
 *
 * @author Cortex Team
 * @version 2.0.1
 */

import { EventEmitter } from 'events';
import { logger } from '../utils/logger.js';
import {
  circuitBreakerMonitor,
  type CircuitBreakerHealthStatus,
  type CircuitBreakerEvent
} from './circuit-breaker-monitor.js';
import { HealthStatus } from '../types/unified-health-interfaces.js';

/**
 * Retry budget configuration per service
 */
export interface RetryBudgetConfig {
  serviceName: string;
  // Retry limits
  maxRetriesPerMinute: number;
  maxRetriesPerHour: number;
  maxRetryRatePercent: number; // percentage of total calls

  // Budget reset periods
  resetIntervalMinutes: number;

  // Alerting thresholds
  warningThresholdPercent: number; // % of budget consumed
  criticalThresholdPercent: number; // % of budget consumed

  // SLO targets
  sloTargetSuccessRate: number; // percentage
  sloTargetResponseTime: number; // milliseconds

  // Circuit breaker integration
  circuitBreakerName: string;

  // Budget optimization
  adaptiveBudgeting: boolean;
  minBudgetRetries: number;
  maxBudgetRetries: number;
}

/**
 * Retry budget metrics snapshot
 */
export interface RetryBudgetMetrics {
  serviceName: string;
  timestamp: Date;

  // Current budget state
  current: {
    usedRetriesMinute: number;
    usedRetriesHour: number;
    retryRatePercent: number;
    budgetRemainingMinute: number;
    budgetRemainingHour: number;
    budgetUtilizationPercent: number;
  };

  // Historical data
  history: {
    retriesPerMinute: number[];
    retriesPerHour: number[];
    retryRateHistory: number[];
    successRateHistory: number[];
    responseTimeHistory: number[];
  };

  // Circuit breaker correlation
  circuitBreaker: {
    state: 'closed' | 'open' | 'half-open';
    healthStatus: HealthStatus;
    failureRate: number;
    consecutiveFailures: number;
    lastStateChange: Date;
  };

  // SLO compliance
  slo: {
    successRateCompliance: boolean;
    responseTimeCompliance: boolean;
    overallCompliance: boolean;
    successRateVariance: number;
    responseTimeVariance: number;
  };

  // Alerts
  alerts: Array<{
    type: 'budget_warning' | 'budget_critical' | 'slo_violation' | 'circuit_correlation';
    severity: 'warning' | 'critical';
    message: string;
    timestamp: Date;
    threshold: number;
    currentValue: number;
  }>;

  // Predictions
  predictions: {
    budgetExhaustionTime: Date | null;
    recommendedAdjustments: string[];
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
  };
}

/**
 * Retry budget monitoring configuration
 */
export interface RetryBudgetMonitorConfig {
  // Monitoring intervals
  collectionIntervalMs: number;
  predictionIntervalMinutes: number;
  historyRetentionHours: number;

  // Adaptive budgeting
  adaptiveBudgeting: {
    enabled: boolean;
    adjustmentThresholdPercent: number;
    maxAdjustmentPercent: number;
    learningWindowMinutes: number;
  };

  // SLO monitoring
  sloMonitoring: {
    enabled: boolean;
    evaluationWindowMinutes: number;
    varianceThresholdPercent: number;
  };

  // Alerting
  alerting: {
    enabled: boolean;
    cooldownMinutes: number;
    predictionAlerts: boolean;
    circuitCorrelationAlerts: boolean;
  };

  // Export settings
  export: {
    prometheusEnabled: boolean;
    grafanaEnabled: boolean;
    jsonExportEnabled: boolean;
    exportIntervalMinutes: number;
  };
}

/**
 * Retry consumption event
 */
export interface RetryConsumptionEvent {
  serviceName: string;
  timestamp: Date;
  retryCount: number;
  operationType: string;
  responseTime: number;
  success: boolean;
  error?: string;
  circuitBreakerState: string;
  metadata?: Record<string, any>;
}

/**
 * Comprehensive Retry Budget Monitor
 */
export class RetryBudgetMonitor extends EventEmitter {
  private config: RetryBudgetMonitorConfig;
  private isRunning = false;
  private startTime: number;

  // Service budgets and tracking
  private serviceBudgets: Map<string, RetryBudgetConfig> = new Map();
  private budgetMetrics: Map<string, RetryBudgetMetrics> = new Map();
  private retryHistory: Map<string, RetryConsumptionEvent[]> = new Map();
  private sloMetrics: Map<string, { successRates: number[]; responseTimes: number[] }> = new Map();

  // Monitoring intervals
  private collectionInterval: NodeJS.Timeout | null = null;
  private predictionInterval: NodeJS.Timeout | null = null;
  private exportInterval: NodeJS.Timeout | null = null;

  // Alert management
  private activeAlerts: Map<string, {
    type: string;
    severity: string;
    firstTriggered: Date;
    lastTriggered: Date;
    count: number;
  }> = new Map();

  // Metrics storage for export
  private metricsHistory: Map<string, RetryBudgetMetrics[]> = new Map();

  constructor(config?: Partial<RetryBudgetMonitorConfig>) {
    super();

    this.config = {
      collectionIntervalMs: 30000, // 30 seconds
      predictionIntervalMinutes: 5, // 5 minutes
      historyRetentionHours: 24, // 1 day
      adaptiveBudgeting: {
        enabled: true,
        adjustmentThresholdPercent: 20,
        maxAdjustmentPercent: 50,
        learningWindowMinutes: 60,
      },
      sloMonitoring: {
        enabled: true,
        evaluationWindowMinutes: 15,
        varianceThresholdPercent: 10,
      },
      alerting: {
        enabled: true,
        cooldownMinutes: 15,
        predictionAlerts: true,
        circuitCorrelationAlerts: true,
      },
      export: {
        prometheusEnabled: true,
        grafanaEnabled: true,
        jsonExportEnabled: true,
        exportIntervalMinutes: 5,
      },
      ...config,
    };

    this.startTime = Date.now();
    this.setupCircuitBreakerListeners();
  }

  /**
   * Start retry budget monitoring
   */
  start(): void {
    if (this.isRunning) {
      logger.warn('Retry budget monitor is already running');
      return;
    }

    this.isRunning = true;

    // Start collection interval
    this.collectionInterval = setInterval(
      () => this.collectMetrics(),
      this.config.collectionIntervalMs
    );

    // Start prediction interval
    this.predictionInterval = setInterval(
      () => this.updatePredictions(),
      this.config.predictionIntervalMinutes * 60 * 1000
    );

    // Start export interval
    this.exportInterval = setInterval(
      () => this.exportMetrics(),
      this.config.exportIntervalIntervalMinutes * 60 * 1000
    );

    // Perform initial collection
    this.collectMetrics();
    this.updatePredictions();

    logger.info(
      {
        collectionInterval: this.config.collectionIntervalMs,
        predictionInterval: this.config.predictionIntervalMinutes,
        exportInterval: this.config.export.exportIntervalMinutes,
      },
      'Retry budget monitor started'
    );

    this.emit('started');
  }

  /**
   * Stop retry budget monitoring
   */
  stop(): void {
    if (!this.isRunning) {
      logger.warn('Retry budget monitor is not running');
      return;
    }

    this.isRunning = false;

    if (this.collectionInterval) {
      clearInterval(this.collectionInterval);
      this.collectionInterval = null;
    }

    if (this.predictionInterval) {
      clearInterval(this.predictionInterval);
      this.predictionInterval = null;
    }

    if (this.exportInterval) {
      clearInterval(this.exportInterval);
      this.exportInterval = null;
    }

    logger.info('Retry budget monitor stopped');
    this.emit('stopped');
  }

  /**
   * Register a service for retry budget monitoring
   */
  registerService(config: RetryBudgetConfig): void {
    this.serviceBudgets.set(config.serviceName, config);

    // Initialize tracking data
    if (!this.retryHistory.has(config.serviceName)) {
      this.retryHistory.set(config.serviceName, []);
    }

    if (!this.sloMetrics.has(config.serviceName)) {
      this.sloMetrics.set(config.serviceName, { successRates: [], responseTimes: [] });
    }

    if (!this.metricsHistory.has(config.serviceName)) {
      this.metricsHistory.set(config.serviceName, []);
    }

    logger.info(
      { serviceName: config.serviceName, maxRetriesPerMinute: config.maxRetriesPerMinute },
      'Service registered for retry budget monitoring'
    );

    this.emit('service_registered', { serviceName: config.serviceName, config });
  }

  /**
   * Record retry consumption event
   */
  recordRetryConsumption(event: RetryConsumptionEvent): void {
    const budget = this.serviceBudgets.get(event.serviceName);
    if (!budget) {
      logger.warn({ serviceName: event.serviceName }, 'Retry consumption for unregistered service');
      return;
    }

    // Store event
    const history = this.retryHistory.get(event.serviceName)!;
    history.push(event);

    // Trim old events
    const retentionMs = this.config.historyRetentionHours * 60 * 60 * 1000;
    const cutoff = Date.now() - retentionMs;
    while (history.length > 0 && history[0].timestamp.getTime() < cutoff) {
      history.shift();
    }

    // Update SLO metrics
    this.updateSLOMetrics(event.serviceName, event);

    // Emit event
    this.emit('retry_consumed', event);
  }

  /**
   * Get retry budget metrics for all services
   */
  getAllMetrics(): Map<string, RetryBudgetMetrics> {
    return new Map(this.budgetMetrics);
  }

  /**
   * Get retry budget metrics for a specific service
   */
  getMetrics(serviceName: string): RetryBudgetMetrics | null {
    return this.budgetMetrics.get(serviceName) || null;
  }

  /**
   * Get retry budget configuration for a service
   */
  getBudgetConfig(serviceName: string): RetryBudgetConfig | null {
    return this.serviceBudgets.get(serviceName) || null;
  }

  /**
   * Update retry budget configuration
   */
  updateBudgetConfig(serviceName: string, config: Partial<RetryBudgetConfig>): boolean {
    const existing = this.serviceBudgets.get(serviceName);
    if (!existing) {
      return false;
    }

    const updated = { ...existing, ...config };
    this.serviceBudgets.set(serviceName, updated);

    logger.info(
      { serviceName, changes: Object.keys(config) },
      'Retry budget configuration updated'
    );

    this.emit('budget_config_updated', { serviceName, config: updated });
    return true;
  }

  /**
   * Get active alerts
   */
  getActiveAlerts(): Array<{
    serviceName: string;
    type: string;
    severity: string;
    count: number;
    firstTriggered: Date;
    lastTriggered: Date;
  }> {
    const alerts: Array<{
      serviceName: string;
      type: string;
      severity: string;
      count: number;
      firstTriggered: Date;
      lastTriggered: Date;
    }> = [];

    for (const [alertKey, alert] of this.activeAlerts) {
      const [serviceName] = alertKey.split(':');
      alerts.push({
        serviceName,
        ...alert,
      });
    }

    return alerts;
  }

  /**
   * Get historical metrics for trend analysis
   */
  getHistoricalMetrics(serviceName: string, hours: number = 24): RetryBudgetMetrics[] {
    const history = this.metricsHistory.get(serviceName) || [];
    const cutoff = Date.now() - (hours * 60 * 60 * 1000);

    return history.filter(metrics =>
      metrics.timestamp.getTime() >= cutoff
    ).sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  }

  /**
   * Generate comprehensive retry budget report
   */
  generateReport(): {
    timestamp: Date;
    summary: {
      totalServices: number;
      servicesWithinBudget: number;
      servicesOverBudget: number;
      servicesWithSLOViolations: number;
      overallBudgetHealth: HealthStatus;
      totalRetriesLastHour: number;
      averageBudgetUtilization: number;
    };
    services: RetryBudgetMetrics[];
    alerts: Array<{
      serviceName: string;
      type: string;
      severity: string;
      count: number;
    }>;
    recommendations: string[];
    trends: {
      budgetUtilizationTrend: 'increasing' | 'decreasing' | 'stable';
      retryRateTrend: 'increasing' | 'decreasing' | 'stable';
      sloComplianceTrend: 'improving' | 'degrading' | 'stable';
    };
  } {
    const metrics = Array.from(this.budgetMetrics.values());
    const alerts = this.getActiveAlerts();

    const totalServices = metrics.length;
    const servicesWithinBudget = metrics.filter(m => m.current.budgetUtilizationPercent < 80).length;
    const servicesOverBudget = metrics.filter(m => m.current.budgetUtilizationPercent >= 80).length;
    const servicesWithSLOViolations = metrics.filter(m => !m.slo.overallCompliance).length;

    const totalRetriesLastHour = metrics.reduce((sum, m) => sum + m.current.usedRetriesHour, 0);
    const averageBudgetUtilization = metrics.length > 0
      ? metrics.reduce((sum, m) => sum + m.current.budgetUtilizationPercent, 0) / metrics.length
      : 0;

    let overallBudgetHealth = HealthStatus.HEALTHY;
    if (servicesWithSLOViolations > 0 || servicesOverBudget > totalServices * 0.3) {
      overallBudgetHealth = HealthStatus.UNHEALTHY;
    } else if (servicesOverBudget > 0 || servicesWithSLOViolations > 0) {
      overallBudgetHealth = HealthStatus.DEGRADED;
    }

    const recommendations: string[] = [];

    // Generate recommendations
    for (const metric of metrics) {
      if (metric.current.budgetUtilizationPercent > 90) {
        recommendations.push(`Critical: ${metric.serviceName} retry budget nearly exhausted (${metric.current.budgetUtilizationPercent.toFixed(1)}%)`);
      } else if (metric.current.budgetUtilizationPercent > 80) {
        recommendations.push(`Warning: ${metric.serviceName} retry budget running low (${metric.current.budgetUtilizationPercent.toFixed(1)}%)`);
      }

      if (!metric.slo.overallCompliance) {
        recommendations.push(`SLO Violation: ${metric.serviceName} not meeting SLO targets`);
      }

      if (metric.predictions.riskLevel === 'critical' || metric.predictions.riskLevel === 'high') {
        recommendations.push(`Risk Alert: ${metric.serviceName} predicted to exhaust retry budget ${metric.predictions.budgetExhaustionTime ? `by ${metric.predictions.budgetExhaustionTime.toISOString()}` : 'soon'}`);
      }
    }

    // Calculate trends
    const trends = {
      budgetUtilizationTrend: this.calculateTrend(metrics, m => m.current.budgetUtilizationPercent),
      retryRateTrend: this.calculateTrend(metrics, m => m.current.retryRatePercent),
      sloComplianceTrend: this.calculateSLOTrend(metrics),
    };

    return {
      timestamp: new Date(),
      summary: {
        totalServices,
        servicesWithinBudget,
        servicesOverBudget,
        servicesWithSLOViolations,
        overallBudgetHealth,
        totalRetriesLastHour,
        averageBudgetUtilization,
      },
      services: metrics,
      alerts: alerts.map(a => ({
        serviceName: a.serviceName,
        type: a.type,
        severity: a.severity,
        count: a.count,
      })),
      recommendations,
      trends,
    };
  }

  /**
   * Collect metrics for all registered services
   */
  private collectMetrics(): void {
    try {
      const now = new Date();

      for (const [serviceName, budget] of this.serviceBudgets) {
        const metrics = this.calculateServiceMetrics(serviceName, budget, now);
        this.budgetMetrics.set(serviceName, metrics);

        // Store in history
        const history = this.metricsHistory.get(serviceName)!;
        history.push(metrics);

        // Trim history based on retention
        const maxSize = Math.floor(this.config.historyRetentionHours * 60 / (this.config.collectionIntervalMs / 60000));
        if (history.length > maxSize) {
          history.splice(0, history.length - maxSize);
        }

        // Check for alerts
        this.checkForAlerts(serviceName, metrics);

        // Emit metrics update
        this.emit('metrics_updated', { serviceName, metrics, timestamp: now });
      }

    } catch (error) {
      logger.error({ error }, 'Failed to collect retry budget metrics');
    }
  }

  /**
   * Calculate metrics for a specific service
   */
  private calculateServiceMetrics(serviceName: string, budget: RetryBudgetConfig, now: Date): RetryBudgetMetrics {
    const retryHistory = this.retryHistory.get(serviceName) || [];
    const sloMetrics = this.sloMetrics.get(serviceName) || { successRates: [], responseTimes: [] };

    // Calculate current usage
    const oneMinuteAgo = new Date(now.getTime() - 60 * 1000);
    const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);

    const retriesLastMinute = retryHistory.filter(e => e.timestamp >= oneMinuteAgo).reduce((sum, e) => sum + e.retryCount, 0);
    const retriesLastHour = retryHistory.filter(e => e.timestamp >= oneHourAgo).reduce((sum, e) => sum + e.retryCount, 0);

    const totalCallsLastHour = retryHistory.filter(e => e.timestamp >= oneHourAgo).length;
    const retryRatePercent = totalCallsLastHour > 0 ? (retriesLastHour / totalCallsLastHour) * 100 : 0;

    const budgetRemainingMinute = Math.max(0, budget.maxRetriesPerMinute - retriesLastMinute);
    const budgetRemainingHour = Math.max(0, budget.maxRetriesPerHour - retriesLastHour);
    const budgetUtilizationPercent = Math.min(100, (retriesLastHour / budget.maxRetriesPerHour) * 100);

    // Get circuit breaker status
    const circuitStatus = circuitBreakerMonitor.getHealthStatus(budget.circuitBreakerName);

    // Calculate SLO compliance
    const sloMetricsWindow = sloMetrics.successRates.slice(-10); // Last 10 data points
    const avgSuccessRate = sloMetricsWindow.length > 0
      ? sloMetricsWindow.reduce((sum, rate) => sum + rate, 0) / sloMetricsWindow.length
      : 100;
    const avgResponseTime = sloMetrics.responseTimes.length > 0
      ? sloMetrics.responseTimes.reduce((sum, time) => sum + time, 0) / sloMetrics.responseTimes.length
      : 0;

    const successRateCompliance = avgSuccessRate >= budget.sloTargetSuccessRate;
    const responseTimeCompliance = avgResponseTime <= budget.sloTargetResponseTime;
    const overallCompliance = successRateCompliance && responseTimeCompliance;

    // Generate alerts
    const alerts: RetryBudgetMetrics['alerts'] = [];

    if (budgetUtilizationPercent >= budget.criticalThresholdPercent) {
      alerts.push({
        type: 'budget_critical',
        severity: 'critical',
        message: `Critical retry budget consumption: ${budgetUtilizationPercent.toFixed(1)}%`,
        timestamp: now,
        threshold: budget.criticalThresholdPercent,
        currentValue: budgetUtilizationPercent,
      });
    } else if (budgetUtilizationPercent >= budget.warningThresholdPercent) {
      alerts.push({
        type: 'budget_warning',
        severity: 'warning',
        message: `High retry budget consumption: ${budgetUtilizationPercent.toFixed(1)}%`,
        timestamp: now,
        threshold: budget.warningThresholdPercent,
        currentValue: budgetUtilizationPercent,
      });
    }

    if (!overallCompliance) {
      alerts.push({
        type: 'slo_violation',
        severity: 'critical',
        message: `SLO violation - Success Rate: ${avgSuccessRate.toFixed(1)}%, Response Time: ${avgResponseTime.toFixed(0)}ms`,
        timestamp: now,
        threshold: budget.sloTargetSuccessRate,
        currentValue: avgSuccessRate,
      });
    }

    if (circuitStatus && (circuitStatus.isOpen || circuitStatus.isHalfOpen)) {
      alerts.push({
        type: 'circuit_correlation',
        severity: circuitStatus.isOpen ? 'critical' : 'warning',
        message: `Circuit breaker ${circuitStatus.state.toUpperCase()} - possible retry budget impact`,
        timestamp: now,
        threshold: 0,
        currentValue: circuitStatus.isOpen ? 1 : 0.5,
      });
    }

    // Calculate predictions
    const predictions = this.calculatePredictions(serviceName, budget, retriesLastHour, retryRatePercent);

    return {
      serviceName,
      timestamp: now,
      current: {
        usedRetriesMinute: retriesLastMinute,
        usedRetriesHour: retriesLastHour,
        retryRatePercent,
        budgetRemainingMinute,
        budgetRemainingHour,
        budgetUtilizationPercent,
      },
      history: {
        retriesPerMinute: this.getTimeSeriesData(retryHistory, 60, e => e.retryCount),
        retriesPerHour: this.getTimeSeriesData(retryHistory, 3600, e => e.retryCount),
        retryRateHistory: this.calculateRetryRateHistory(retryHistory),
        successRateHistory: sloMetrics.successRates.slice(-20),
        responseTimeHistory: sloMetrics.responseTimes.slice(-20),
      },
      circuitBreaker: circuitStatus ? {
        state: circuitStatus.state,
        healthStatus: circuitStatus.healthStatus,
        failureRate: circuitStatus.metrics.failureRate,
        consecutiveFailures: circuitStatus.metrics.consecutiveFailures,
        lastStateChange: new Date(Date.now() - circuitStatus.metrics.timeSinceStateChange),
      } : {
        state: 'closed',
        healthStatus: HealthStatus.HEALTHY,
        failureRate: 0,
        consecutiveFailures: 0,
        lastStateChange: now,
      },
      slo: {
        successRateCompliance,
        responseTimeCompliance,
        overallCompliance,
        successRateVariance: this.calculateVariance(sloMetrics.successRates.slice(-10)),
        responseTimeVariance: this.calculateVariance(sloMetrics.responseTimes.slice(-10)),
      },
      alerts,
      predictions,
    };
  }

  /**
   * Update SLO metrics based on retry event
   */
  private updateSLOMetrics(serviceName: string, event: RetryConsumptionEvent): void {
    const metrics = this.sloMetrics.get(serviceName);
    if (!metrics) return;

    // Update success rate (simplified - would need more sophisticated tracking)
    const currentSuccessRate = event.success ? 100 : 0;
    metrics.successRates.push(currentSuccessRate);
    if (metrics.successRates.length > 100) {
      metrics.successRates.shift();
    }

    // Update response time
    if (event.responseTime > 0) {
      metrics.responseTimes.push(event.responseTime);
      if (metrics.responseTimes.length > 100) {
        metrics.responseTimes.shift();
      }
    }
  }

  /**
   * Check for alerts and emit them
   */
  private checkForAlerts(serviceName: string, metrics: RetryBudgetMetrics): void {
    if (!this.config.alerting.enabled) return;

    for (const alert of metrics.alerts) {
      const alertKey = `${serviceName}:${alert.type}`;
      const existingAlert = this.activeAlerts.get(alertKey);
      const cooldownMs = this.config.alerting.cooldownMinutes * 60 * 1000;

      if (existingAlert) {
        // Update existing alert if cooldown has passed
        if (Date.now() - existingAlert.lastTriggered.getTime() >= cooldownMs) {
          existingAlert.count++;
          existingAlert.lastTriggered = alert.timestamp;

          // Re-emit alert
          this.emit('alert', {
            serviceName,
            ...alert,
          });
        }
      } else {
        // Create new alert
        this.activeAlerts.set(alertKey, {
          type: alert.type,
          severity: alert.severity,
          count: 1,
          firstTriggered: alert.timestamp,
          lastTriggered: alert.timestamp,
        });

        // Emit new alert
        this.emit('alert', {
          serviceName,
          ...alert,
        });

        logger[alert.severity === 'critical' ? 'error' : 'warn'](
          {
            serviceName,
            alertType: alert.type,
            message: alert.message,
            currentValue: alert.currentValue,
            threshold: alert.threshold,
          },
          `Retry budget alert: ${serviceName} - ${alert.message}`
        );
      }
    }
  }

  /**
   * Calculate predictions for budget exhaustion
   */
  private calculatePredictions(
    serviceName: string,
    budget: RetryBudgetConfig,
    currentHourlyRetries: number,
    retryRatePercent: number
  ): RetryBudgetMetrics['predictions'] {
    const predictions: RetryBudgetMetrics['predictions'] = {
      budgetExhaustionTime: null,
      recommendedAdjustments: [],
      riskLevel: 'low',
    };

    // Simple linear prediction (could be enhanced with ML models)
    if (currentHourlyRetries > 0) {
      const hourlyBudget = budget.maxRetriesPerHour;
      const hoursRemaining = hourlyBudget / currentHourlyRetries;

      if (hoursRemaining < 1) {
        predictions.budgetExhaustionTime = new Date(Date.now() + hoursRemaining * 60 * 60 * 1000);
        predictions.riskLevel = 'critical';
        predictions.recommendedAdjustments.push(`Increase retry budget for ${serviceName} or reduce retry rate`);
      } else if (hoursRemaining < 4) {
        predictions.budgetExhaustionTime = new Date(Date.now() + hoursRemaining * 60 * 60 * 1000);
        predictions.riskLevel = 'high';
        predictions.recommendedAdjustments.push(`Monitor ${serviceName} closely - budget may be exhausted soon`);
      } else if (hoursRemaining < 8) {
        predictions.riskLevel = 'medium';
        predictions.recommendedAdjustments.push(`Consider proactive adjustments for ${serviceName}`);
      }
    }

    // Circuit breaker correlation predictions
    const circuitStatus = circuitBreakerMonitor.getHealthStatus(budget.circuitBreakerName);
    if (circuitStatus && (circuitStatus.isOpen || circuitStatus.isHalfOpen)) {
      predictions.riskLevel = predictions.riskLevel === 'critical' ? 'critical' : 'high';
      predictions.recommendedAdjustments.push(`Circuit breaker ${circuitStatus.state} for ${budget.circuitBreakerName} may impact retry patterns`);
    }

    // SLO violation predictions
    const metrics = this.budgetMetrics.get(serviceName);
    if (metrics && !metrics.slo.overallCompliance) {
      predictions.recommendedAdjustments.push(`Address SLO violations for ${serviceName} to prevent service degradation`);
    }

    return predictions;
  }

  /**
   * Update predictions for all services
   */
  private updatePredictions(): void {
    try {
      for (const [serviceName, budget] of this.serviceBudgets) {
        const metrics = this.budgetMetrics.get(serviceName);
        if (metrics) {
          const updatedPredictions = this.calculatePredictions(
            serviceName,
            budget,
            metrics.current.usedRetriesHour,
            metrics.current.retryRatePercent
          );

          // Update existing metrics with new predictions
          metrics.predictions = updatedPredictions;

          // Emit prediction update if significant
          if (updatedPredictions.riskLevel === 'critical' || updatedPredictions.riskLevel === 'high') {
            this.emit('prediction_alert', {
              serviceName,
              predictions: updatedPredictions,
              timestamp: new Date(),
            });
          }
        }
      }
    } catch (error) {
      logger.error({ error }, 'Failed to update retry budget predictions');
    }
  }

  /**
   * Export metrics for external monitoring systems
   */
  private exportMetrics(): void {
    try {
      if (this.config.export.prometheusEnabled) {
        this.exportToPrometheus();
      }

      if (this.config.export.grafanaEnabled) {
        this.exportToGrafana();
      }

      if (this.config.export.jsonExportEnabled) {
        this.exportToJSON();
      }

      this.emit('metrics_exported', { timestamp: new Date() });
    } catch (error) {
      logger.error({ error }, 'Failed to export retry budget metrics');
    }
  }

  /**
   * Export metrics in Prometheus format
   */
  private exportToPrometheus(): void {
    const prometheusMetrics: string[] = [];

    for (const [serviceName, metrics] of this.budgetMetrics) {
      const labels = `service="${serviceName}"`;

      prometheusMetrics.push(
        `# HELP retry_budget_utilization_percent Retry budget utilization percentage`,
        `# TYPE retry_budget_utilization_percent gauge`,
        `retry_budget_utilization_percent{${labels}} ${metrics.current.budgetUtilizationPercent}`,
        '',
        `# HELP retry_budget_remaining_retries_minute Remaining retries in current minute`,
        `# TYPE retry_budget_remaining_retries_minute gauge`,
        `retry_budget_remaining_retries_minute{${labels}} ${metrics.current.budgetRemainingMinute}`,
        '',
        `# HELP retry_budget_remaining_retries_hour Remaining retries in current hour`,
        `# TYPE retry_budget_remaining_retries_hour gauge`,
        `retry_budget_remaining_retries_hour{${labels}} ${metrics.current.budgetRemainingHour}`,
        '',
        `# HELP retry_rate_percent Current retry rate percentage`,
        `# TYPE retry_rate_percent gauge`,
        `retry_rate_percent{${labels}} ${metrics.current.retryRatePercent}`,
        '',
        `# HELP slo_success_rate_compliance SLO success rate compliance (1 for compliant, 0 for non-compliant)`,
        `# TYPE slo_success_rate_compliance gauge`,
        `slo_success_rate_compliance{${labels}} ${metrics.slo.successRateCompliance ? 1 : 0}`,
        '',
        `# HELP slo_response_time_compliance SLO response time compliance (1 for compliant, 0 for non-compliant)`,
        `# TYPE slo_response_time_compliance gauge`,
        `slo_response_time_compliance{${labels}} ${metrics.slo.responseTimeCompliance ? 1 : 0}`,
        ''
      );
    }

    // In a real implementation, this would be exposed via a metrics endpoint
    // For now, we'll emit it as an event
    this.emit('prometheus_metrics_exported', { metrics: prometheusMetrics.join('\n') });
  }

  /**
   * Export metrics for Grafana consumption
   */
  private exportToGrafana(): void {
    const grafanaData = {
      timestamp: new Date().toISOString(),
      services: Array.from(this.budgetMetrics.entries()).map(([serviceName, metrics]) => ({
        name: serviceName,
        utilization: metrics.current.budgetUtilizationPercent,
        retryRate: metrics.current.retryRatePercent,
        remainingMinute: metrics.current.budgetRemainingMinute,
        remainingHour: metrics.current.budgetRemainingHour,
        sloCompliance: metrics.slo.overallCompliance ? 1 : 0,
        riskLevel: metrics.predictions.riskLevel,
        circuitBreakerState: metrics.circuitBreaker.state,
      })),
      summary: this.generateReport().summary,
    };

    this.emit('grafana_metrics_exported', { data: grafanaData });
  }

  /**
   * Export metrics to JSON format
   */
  private exportToJSON(): void {
    const jsonData = {
      timestamp: new Date().toISOString(),
      version: '2.0.1',
      metrics: Object.fromEntries(this.budgetMetrics),
      summary: this.generateReport().summary,
    };

    this.emit('json_metrics_exported', { data: jsonData });
  }

  /**
   * Set up circuit breaker event listeners
   */
  private setupCircuitBreakerListeners(): void {
    circuitBreakerMonitor.on('circuit_state_change', (event: CircuitBreakerEvent) => {
      // Find services that use this circuit breaker
      for (const [serviceName, budget] of this.serviceBudgets) {
        if (budget.circuitBreakerName === event.serviceName) {
          this.emit('circuit_breaker_impact', {
            serviceName,
            circuitBreakerName: event.serviceName,
            event,
            timestamp: new Date(),
          });
        }
      }
    });

    circuitBreakerMonitor.on('alert', (alert: any) => {
      // Correlate circuit breaker alerts with retry budget
      for (const [serviceName, budget] of this.serviceBudgets) {
        if (budget.circuitBreakerName === alert.serviceName) {
          const metrics = this.budgetMetrics.get(serviceName);
          if (metrics && this.config.alerting.circuitCorrelationAlerts) {
            this.emit('alert', {
              serviceName,
              type: 'circuit_correlation',
              severity: alert.severity,
              message: `Circuit breaker alert for ${alert.serviceName}: ${alert.message}`,
              timestamp: new Date(),
              threshold: 0,
              currentValue: 1,
            });
          }
        }
      }
    });
  }

  /**
   * Get time series data from history
   */
  private getTimeSeriesData<T>(history: Array<{ timestamp: Date } & Record<string, T>>, windowSeconds: number, extractor: (item: any) => T): T[] {
    const cutoff = new Date(Date.now() - windowSeconds * 1000);
    return history
      .filter(item => item.timestamp >= cutoff)
      .map(extractor);
  }

  /**
   * Calculate retry rate history
   */
  private calculateRetryRateHistory(history: RetryConsumptionEvent[]): number[] {
    const windows: number[] = [];
    const windowSizeMs = 5 * 60 * 1000; // 5 minutes

    const now = Date.now();
    for (let i = 0; i < 12; i++) { // Last hour in 5-minute windows
      const windowStart = now - (i + 1) * windowSizeMs;
      const windowEnd = now - i * windowSizeMs;

      const windowRetries = history
        .filter(e => e.timestamp.getTime() >= windowStart && e.timestamp.getTime() < windowEnd)
        .reduce((sum, e) => sum + e.retryCount, 0);

      const totalCalls = history
        .filter(e => e.timestamp.getTime() >= windowStart && e.timestamp.getTime() < windowEnd)
        .length;

      const retryRate = totalCalls > 0 ? (windowRetries / totalCalls) * 100 : 0;
      windows.unshift(retryRate);
    }

    return windows;
  }

  /**
   * Calculate variance for a set of numbers
   */
  private calculateVariance(values: number[]): number {
    if (values.length === 0) return 0;

    const mean = values.reduce((sum, val) => sum + val, 0) / values.length;
    const squaredDiffs = values.map(val => Math.pow(val - mean, 2));
    return squaredDiffs.reduce((sum, val) => sum + val, 0) / values.length;
  }

  /**
   * Calculate trend direction from metrics
   */
  private calculateTrend<T>(metrics: RetryBudgetMetrics[], extractor: (m: RetryBudgetMetrics) => T): 'increasing' | 'decreasing' | 'stable' {
    if (metrics.length < 3) return 'stable';

    const recent = metrics.slice(-3).map(extractor);
    if (typeof recent[0] !== 'number') return 'stable';

    const trend = recent[2] - recent[0];
    const threshold = Math.abs(recent[0] * 0.05); // 5% threshold

    if (trend > threshold) return 'increasing';
    if (trend < -threshold) return 'decreasing';
    return 'stable';
  }

  /**
   * Calculate SLO compliance trend
   */
  private calculateSLOTrend(metrics: RetryBudgetMetrics[]): 'improving' | 'degrading' | 'stable' {
    if (metrics.length < 3) return 'stable';

    const recent = metrics.slice(-3);
    const complianceRates = recent.map(m => m.slo.overallCompliance ? 1 : 0);

    const trend = complianceRates[2] - complianceRates[0];
    if (trend > 0.2) return 'improving';
    if (trend < -0.2) return 'degrading';
    return 'stable';
  }
}

// Export singleton instance
export const retryBudgetMonitor = new RetryBudgetMonitor();