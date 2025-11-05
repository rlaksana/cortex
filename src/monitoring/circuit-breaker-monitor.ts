/**
 * Enhanced Circuit Breaker Monitor
 *
 * Comprehensive monitoring system for circuit breakers with detailed state tracking,
 * performance analysis, and proactive alerting. Provides visibility into circuit
 * breaker health, failure patterns, and recovery detection.
 *
 * @author Cortex Team
 * @version 2.0.1
 */

import { EventEmitter } from 'events';
import {
  circuitBreakerManager,
  CircuitBreaker,
  CircuitBreakerStats,
  type CircuitBreakerConfig
} from '../services/circuit-breaker.service.js';
import { HealthStatus, DependencyType } from '../types/unified-health-interfaces.js';
import { logger } from '../utils/logger.js';

/**
 * Circuit breaker monitoring event types
 */
export enum CircuitBreakerEventType {
  STATE_CHANGE = 'state_change',
  FAILURE = 'failure',
  SUCCESS = 'success',
  TIMEOUT = 'timeout',
  RECOVERY = 'recovery',
  THRESHOLD_EXCEEDED = 'threshold_exceeded',
}

/**
 * Circuit breaker event data
 */
export interface CircuitBreakerEvent {
  serviceName: string;
  eventType: CircuitBreakerEventType;
  timestamp: Date;
  previousState?: string;
  currentState?: string;
  error?: string;
  responseTime?: number;
  failureRate?: number;
  consecutiveFailures?: number;
  metadata?: Record<string, any>;
}

/**
 * Circuit breaker health status
 */
export interface CircuitBreakerHealthStatus {
  serviceName: string;
  healthStatus: HealthStatus;
  state: 'closed' | 'open' | 'half_open';
  isOpen: boolean;
  isHalfOpen: boolean;
  metrics: {
    failures: number;
    successes: number;
    totalCalls: number;
    failureRate: number;
    successRate: number;
    averageResponseTime: number;
    timeSinceLastFailure: number;
    timeSinceStateChange: number;
    consecutiveFailures: number;
    consecutiveSuccesses: number;
  };
  performance: {
    responseTimeP50: number;
    responseTimeP95: number;
    responseTimeP99: number;
    throughputPerSecond: number;
    errorTrend: 'improving' | 'degrading' | 'stable';
  };
  configuration: {
    failureThreshold: number;
    recoveryTimeoutMs: number;
    monitoringWindowMs: number;
    minimumCalls: number;
    failureRateThreshold: number;
  };
  alerts: Array<{
    type: string;
    severity: 'info' | 'warning' | 'critical';
    message: string;
    timestamp: Date;
    count: number;
  }>;
  lastEvent?: CircuitBreakerEvent;
}

/**
 * Circuit breaker monitoring configuration
 */
export interface CircuitBreakerMonitorConfig {
  // Monitoring intervals
  healthCheckIntervalMs: number;
  metricsCollectionIntervalMs: number;
  eventRetentionMinutes: number;

  // Alerting thresholds
  alerts: {
    enabled: boolean;
    failureRateWarning: number;      // percentage
    failureRateCritical: number;     // percentage
    consecutiveFailuresWarning: number;
    consecutiveFailuresCritical: number;
    responseTimeWarning: number;     // milliseconds
    responseTimeCritical: number;    // milliseconds
    openCircuitAlert: boolean;
    recoveryAlert: boolean;
  };

  // Performance monitoring
  performance: {
    enabled: boolean;
    responseTimeHistorySize: number;
    throughputWindowSeconds: number;
    trendAnalysisWindowMinutes: number;
  };

  // Reporting
  reporting: {
    enabled: boolean;
    generateHealthReports: boolean;
    healthReportIntervalMinutes: number;
    includeEventHistory: boolean;
  };
}

/**
 * Enhanced Circuit Breaker Monitor
 */
export class CircuitBreakerMonitor extends EventEmitter {
  private config: CircuitBreakerMonitorConfig;
  private isRunning = false;
  private startTime: number;

  // Monitoring intervals
  private healthCheckInterval: NodeJS.Timeout | null = null;
  private metricsCollectionInterval: NodeJS.Timeout | null = null;

  // State tracking
  private circuitHealthStatuses: Map<string, CircuitBreakerHealthStatus> = new Map();
  private eventHistory: Map<string, CircuitBreakerEvent[]> = new Map();
  private performanceHistory: Map<string, number[]> = new Map();

  // Alert tracking
  private activeAlerts: Map<string, {
    type: string;
    severity: string;
    count: number;
    firstTriggered: Date;
    lastTriggered: Date;
  }> = new Map();

  constructor(config?: Partial<CircuitBreakerMonitorConfig>) {
    super();

    this.config = {
      healthCheckIntervalMs: 15000,        // 15 seconds
      metricsCollectionIntervalMs: 10000,  // 10 seconds
      eventRetentionMinutes: 60,           // 1 hour
      alerts: {
        enabled: true,
        failureRateWarning: 10,            // 10%
        failureRateCritical: 25,           // 25%
        consecutiveFailuresWarning: 3,
        consecutiveFailuresCritical: 5,
        responseTimeWarning: 2000,         // 2 seconds
        responseTimeCritical: 5000,        // 5 seconds
        openCircuitAlert: true,
        recoveryAlert: true,
      },
      performance: {
        enabled: true,
        responseTimeHistorySize: 100,
        throughputWindowSeconds: 60,
        trendAnalysisWindowMinutes: 10,
      },
      reporting: {
        enabled: true,
        generateHealthReports: true,
        healthReportIntervalMinutes: 5,
        includeEventHistory: true,
      },
      ...config,
    };

    this.startTime = Date.now();

    // Set up event listeners on circuit breaker manager
    this.setupCircuitBreakerListeners();
  }

  /**
   * Start circuit breaker monitoring
   */
  start(): void {
    if (this.isRunning) {
      logger.warn('Circuit breaker monitor is already running');
      return;
    }

    this.isRunning = true;

    // Start health check interval
    this.healthCheckInterval = setInterval(
      () => this.performHealthCheck(),
      this.config.healthCheckIntervalMs
    );

    // Start metrics collection interval
    this.metricsCollectionInterval = setInterval(
      () => this.collectMetrics(),
      this.config.metricsCollectionIntervalMs
    );

    // Perform initial health check and metrics collection
    this.performHealthCheck();
    this.collectMetrics();

    logger.info(
      {
        healthCheckInterval: this.config.healthCheckIntervalMs,
        metricsCollectionInterval: this.config.metricsCollectionIntervalMs,
      },
      'Circuit breaker monitor started'
    );

    this.emit('started');
  }

  /**
   * Stop circuit breaker monitoring
   */
  stop(): void {
    if (!this.isRunning) {
      logger.warn('Circuit breaker monitor is not running');
      return;
    }

    this.isRunning = false;

    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
      this.healthCheckInterval = null;
    }

    if (this.metricsCollectionInterval) {
      clearInterval(this.metricsCollectionInterval);
      this.metricsCollectionInterval = null;
    }

    logger.info('Circuit breaker monitor stopped');
    this.emit('stopped');
  }

  /**
   * Get health status for all circuit breakers
   */
  getAllHealthStatuses(): Map<string, CircuitBreakerHealthStatus> {
    return new Map(this.circuitHealthStatuses);
  }

  /**
   * Get health status for a specific circuit breaker
   */
  getHealthStatus(serviceName: string): CircuitBreakerHealthStatus | null {
    return this.circuitHealthStatuses.get(serviceName) || null;
  }

  /**
   * Get event history for a circuit breaker
   */
  getEventHistory(serviceName: string, limit?: number): CircuitBreakerEvent[] {
    const history = this.eventHistory.get(serviceName) || [];
    const sorted = [...history].sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
    return limit ? sorted.slice(0, limit) : sorted;
  }

  /**
   * Get performance metrics for a circuit breaker
   */
  getPerformanceMetrics(serviceName: string): {
    responseTimeHistory: number[];
    throughputPerSecond: number;
    errorTrend: 'improving' | 'degrading' | 'stable';
  } {
    const history = this.performanceHistory.get(serviceName) || [];
    const now = Date.now();
    const windowStart = now - (this.config.performance.throughputWindowSeconds * 1000);

    const recentCalls = history.filter(time => time >= windowStart);
    const throughputPerSecond = recentCalls.length / this.config.performance.throughputWindowSeconds;

    return {
      responseTimeHistory: [...history].slice(-this.config.performance.responseTimeHistorySize),
      throughputPerSecond,
      errorTrend: this.calculateErrorTrend(serviceName),
    };
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
   * Generate comprehensive health report
   */
  generateHealthReport(): {
    timestamp: Date;
    overall: {
      totalCircuits: number;
      healthyCircuits: number;
      degradedCircuits: number;
      failingCircuits: number;
      openCircuits: number;
      overallHealth: HealthStatus;
    };
    circuitBreakers: CircuitBreakerHealthStatus[];
    activeAlerts: Array<{
      serviceName: string;
      type: string;
      severity: string;
      count: number;
    }>;
    summary: {
      criticalIssues: string[];
      warnings: string[];
      recommendations: string[];
    };
  } {
    const statuses = Array.from(this.circuitHealthStatuses.values());
    const alerts = this.getActiveAlerts();

    const totalCircuits = statuses.length;
    const healthyCircuits = statuses.filter(s => s.healthStatus === HealthStatus.HEALTHY).length;
    const degradedCircuits = statuses.filter(s => s.healthStatus === HealthStatus.DEGRADED).length;
    const failingCircuits = statuses.filter(s => s.healthStatus === HealthStatus.UNHEALTHY).length;
    const openCircuits = statuses.filter(s => s.isOpen).length;

    let overallHealth = HealthStatus.HEALTHY;
    if (failingCircuits > 0) {
      overallHealth = HealthStatus.UNHEALTHY;
    } else if (degradedCircuits > 0 || openCircuits > 0) {
      overallHealth = HealthStatus.DEGRADED;
    }

    const criticalIssues: string[] = [];
    const warnings: string[] = [];
    const recommendations: string[] = [];

    // Analyze issues and generate recommendations
    for (const status of statuses) {
      if (status.isOpen) {
        criticalIssues.push(`Circuit breaker for ${status.serviceName} is OPEN`);
        recommendations.push(`Investigate ${status.serviceName} service health and connectivity`);
      }

      if (status.metrics.failureRate > this.config.alerts.failureRateCritical) {
        criticalIssues.push(`${status.serviceName} has critical failure rate: ${status.metrics.failureRate.toFixed(2)}%`);
        recommendations.push(`Review ${status.serviceName} error handling and retry logic`);
      } else if (status.metrics.failureRate > this.config.alerts.failureRateWarning) {
        warnings.push(`${status.serviceName} has high failure rate: ${status.metrics.failureRate.toFixed(2)}%`);
      }

      if (status.metrics.consecutiveFailures >= this.config.alerts.consecutiveFailuresCritical) {
        criticalIssues.push(`${status.serviceName} has ${status.metrics.consecutiveFailures} consecutive failures`);
        recommendations.push(`Check ${status.serviceName} service availability and configuration`);
      }
    }

    return {
      timestamp: new Date(),
      overall: {
        totalCircuits,
        healthyCircuits,
        degradedCircuits,
        failingCircuits,
        openCircuits,
        overallHealth,
      },
      circuitBreakers: statuses,
      activeAlerts: alerts.map(a => ({
        serviceName: a.serviceName,
        type: a.type,
        severity: a.severity,
        count: a.count,
      })),
      summary: {
        criticalIssues,
        warnings,
        recommendations,
      },
    };
  }

  /**
   * Perform health check for all circuit breakers
   */
  private performHealthCheck(): void {
    try {
      const allStats = circuitBreakerManager.getAllStats();
      const now = Date.now();

      for (const [serviceName, stats] of Object.entries(allStats)) {
        const healthStatus = this.calculateHealthStatus(serviceName, stats);
        this.circuitHealthStatuses.set(serviceName, healthStatus);

        // Check for alerts
        this.checkForAlerts(serviceName, healthStatus);

        // Emit health status update
        this.emit('health_status_update', {
          serviceName,
          healthStatus,
          timestamp: new Date(),
        });
      }

      // Remove health statuses for circuits that no longer exist
      for (const [serviceName] of this.circuitHealthStatuses) {
        if (!allStats[serviceName]) {
          this.circuitHealthStatuses.delete(serviceName);
          this.eventHistory.delete(serviceName);
          this.performanceHistory.delete(serviceName);
        }
      }

    } catch (error) {
      logger.error({ error }, 'Failed to perform circuit breaker health check');
    }
  }

  /**
   * Collect performance metrics
   */
  private collectMetrics(): void {
    try {
      const allStats = circuitBreakerManager.getAllStats();

      for (const [serviceName, stats] of Object.entries(allStats)) {
        // Record response time for performance tracking
        if (this.config.performance.enabled) {
          this.recordResponseTime(serviceName, stats.averageResponseTime);
        }

        // Emit metrics event
        this.emit('metrics_collected', {
          serviceName,
          stats,
          timestamp: new Date(),
        });
      }

    } catch (error) {
      logger.error({ error }, 'Failed to collect circuit breaker metrics');
    }
  }

  /**
   * Set up event listeners on circuit breakers
   */
  private setupCircuitBreakerListeners(): void {
    // This would require extending the CircuitBreaker class to emit events
    // For now, we'll monitor through periodic checks

    // Listen to circuit breaker manager events if available
    if ((circuitBreakerManager as any).on) {
      (circuitBreakerManager as any).on('circuitStateChanged', (event: any) => {
        this.handleCircuitStateChange(event);
      });

      (circuitBreakerManager as any).on('circuitFailure', (event: any) => {
        this.handleCircuitFailure(event);
      });

      (circuitBreakerManager as any).on('circuitRecovery', (event: any) => {
        this.handleCircuitRecovery(event);
      });
    }
  }

  /**
   * Calculate health status for a circuit breaker
   */
  private calculateHealthStatus(serviceName: string, stats: CircuitBreakerStats): CircuitBreakerHealthStatus {
    const now = Date.now();
    let healthStatus = HealthStatus.HEALTHY;
    const alerts: Array<{
      type: string;
      severity: 'info' | 'warning' | 'critical';
      message: string;
      timestamp: Date;
      count: number;
    }> = [];

    // Determine health status based on state and metrics
    if (stats.isOpen) {
      healthStatus = HealthStatus.UNHEALTHY;
      alerts.push({
        type: 'circuit_open',
        severity: 'critical',
        message: `Circuit breaker is OPEN`,
        timestamp: new Date(),
        count: 1,
      });
    } else if (stats.state === 'half-open') {
      healthStatus = HealthStatus.DEGRADED;
      alerts.push({
        type: 'circuit_half_open',
        severity: 'warning',
        message: `Circuit breaker is HALF-OPEN`,
        timestamp: new Date(),
        count: 1,
      });
    }

    // Check failure rate
    if (stats.failureRate > this.config.alerts.failureRateCritical) {
      healthStatus = HealthStatus.UNHEALTHY;
      alerts.push({
        type: 'high_failure_rate',
        severity: 'critical',
        message: `Critical failure rate: ${(stats.failureRate * 100).toFixed(2)}%`,
        timestamp: new Date(),
        count: 1,
      });
    } else if (stats.failureRate > this.config.alerts.failureRateWarning) {
      if (healthStatus === HealthStatus.HEALTHY) healthStatus = HealthStatus.DEGRADED;
      alerts.push({
        type: 'elevated_failure_rate',
        severity: 'warning',
        message: `High failure rate: ${(stats.failureRate * 100).toFixed(2)}%`,
        timestamp: new Date(),
        count: 1,
      });
    }

    // Check response time
    if (stats.averageResponseTime > this.config.alerts.responseTimeCritical) {
      healthStatus = HealthStatus.UNHEALTHY;
      alerts.push({
        type: 'slow_response_time',
        severity: 'critical',
        message: `Critical response time: ${stats.averageResponseTime}ms`,
        timestamp: new Date(),
        count: 1,
      });
    } else if (stats.averageResponseTime > this.config.alerts.responseTimeWarning) {
      if (healthStatus === HealthStatus.HEALTHY) healthStatus = HealthStatus.DEGRADED;
      alerts.push({
        type: 'elevated_response_time',
        severity: 'warning',
        message: `High response time: ${stats.averageResponseTime}ms`,
        timestamp: new Date(),
        count: 1,
      });
    }

    // Get performance metrics
    const performanceMetrics = this.getPerformanceMetrics(serviceName);

    return {
      serviceName,
      healthStatus,
      state: stats.state === 'half-open' ? 'half_open' : stats.state as 'closed' | 'open' | 'half_open',
      isOpen: stats.isOpen,
      isHalfOpen: stats.state === 'half-open',
      metrics: {
        failures: stats.failures,
        successes: stats.successes,
        totalCalls: stats.totalCalls,
        failureRate: stats.failureRate * 100,
        successRate: stats.successRate * 100,
        averageResponseTime: stats.averageResponseTime,
        timeSinceLastFailure: stats.timeSinceLastFailure,
        timeSinceStateChange: stats.timeSinceStateChange,
        consecutiveFailures: stats.failures, // Simplified
        consecutiveSuccesses: stats.successes, // Simplified
      },
      performance: {
        responseTimeP50: this.calculatePercentile(performanceMetrics.responseTimeHistory, 0.5),
        responseTimeP95: this.calculatePercentile(performanceMetrics.responseTimeHistory, 0.95),
        responseTimeP99: this.calculatePercentile(performanceMetrics.responseTimeHistory, 0.99),
        throughputPerSecond: performanceMetrics.throughputPerSecond,
        errorTrend: performanceMetrics.errorTrend,
      },
      configuration: {
        failureThreshold: 5, // Would need to get from actual circuit breaker config
        recoveryTimeoutMs: 60000,
        monitoringWindowMs: 300000,
        minimumCalls: 10,
        failureRateThreshold: 0.5,
      },
      alerts,
      lastEvent: this.getLastEvent(serviceName),
    };
  }

  /**
   * Check for alerts and emit them
   */
  private checkForAlerts(serviceName: string, healthStatus: CircuitBreakerHealthStatus): void {
    if (!this.config.alerts.enabled) return;

    for (const alert of healthStatus.alerts) {
      const alertKey = `${serviceName}:${alert.type}`;
      const existingAlert = this.activeAlerts.get(alertKey);

      if (existingAlert) {
        existingAlert.count++;
        existingAlert.lastTriggered = alert.timestamp;
      } else {
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
            healthStatus: healthStatus.healthStatus,
          },
          `Circuit breaker alert: ${serviceName} - ${alert.message}`
        );
      }
    }
  }

  /**
   * Record response time for performance tracking
   */
  private recordResponseTime(serviceName: string, responseTime: number): void {
    if (!this.performanceHistory.has(serviceName)) {
      this.performanceHistory.set(serviceName, []);
    }

    const history = this.performanceHistory.get(serviceName)!;
    history.push(responseTime);

    // Keep only recent history
    const maxSize = this.config.performance.responseTimeHistorySize;
    if (history.length > maxSize) {
      history.splice(0, history.length - maxSize);
    }
  }

  /**
   * Calculate error trend for a service
   */
  private calculateErrorTrend(serviceName: string): 'improving' | 'degrading' | 'stable' {
    const history = this.getEventHistory(serviceName, 20);
    if (history.length < 10) return 'stable';

    const recentFailures = history.slice(0, 10).filter(e => e.eventType === CircuitBreakerEventType.FAILURE).length;
    const olderFailures = history.slice(10, 20).filter(e => e.eventType === CircuitBreakerEventType.FAILURE).length;

    if (recentFailures < olderFailures * 0.8) return 'improving';
    if (recentFailures > olderFailures * 1.2) return 'degrading';
    return 'stable';
  }

  /**
   * Calculate percentile from array of numbers
   */
  private calculatePercentile(values: number[], percentile: number): number {
    if (values.length === 0) return 0;

    const sorted = [...values].sort((a, b) => a - b);
    const index = Math.ceil(sorted.length * percentile) - 1;
    return sorted[Math.max(0, Math.min(index, sorted.length - 1))];
  }

  /**
   * Get last event for a service
   */
  private getLastEvent(serviceName: string): CircuitBreakerEvent | undefined {
    const history = this.eventHistory.get(serviceName);
    if (!history || history.length === 0) return undefined;

    return history.reduce((latest, event) =>
      event.timestamp > latest.timestamp ? event : latest
    );
  }

  /**
   * Handle circuit state change event
   */
  private handleCircuitStateChange(event: any): void {
    const { serviceName, previousState, currentState } = event;

    const circuitEvent: CircuitBreakerEvent = {
      serviceName,
      eventType: CircuitBreakerEventType.STATE_CHANGE,
      timestamp: new Date(),
      previousState,
      currentState,
    };

    this.recordEvent(circuitEvent);
    this.emit('circuit_state_change', circuitEvent);
  }

  /**
   * Handle circuit failure event
   */
  private handleCircuitFailure(event: any): void {
    const { serviceName, error, responseTime } = event;

    const circuitEvent: CircuitBreakerEvent = {
      serviceName,
      eventType: CircuitBreakerEventType.FAILURE,
      timestamp: new Date(),
      error,
      responseTime,
    };

    this.recordEvent(circuitEvent);
    this.emit('circuit_failure', circuitEvent);
  }

  /**
   * Handle circuit recovery event
   */
  private handleCircuitRecovery(event: any): void {
    const { serviceName } = event;

    const circuitEvent: CircuitBreakerEvent = {
      serviceName,
      eventType: CircuitBreakerEventType.RECOVERY,
      timestamp: new Date(),
    };

    this.recordEvent(circuitEvent);
    this.emit('circuit_recovery', circuitEvent);
  }

  /**
   * Record circuit breaker event
   */
  private recordEvent(event: CircuitBreakerEvent): void {
    if (!this.eventHistory.has(event.serviceName)) {
      this.eventHistory.set(event.serviceName, []);
    }

    const history = this.eventHistory.get(event.serviceName)!;
    history.push(event);

    // Trim old events based on retention policy
    const maxAge = this.config.eventRetentionMinutes * 60 * 1000;
    const cutoff = Date.now() - maxAge;

    while (history.length > 0 && history[0].timestamp.getTime() < cutoff) {
      history.shift();
    }
  }

  /**
   * Clean up old alerts
   */
  private cleanupOldAlerts(): void {
    const now = Date.now();
    const maxAge = 30 * 60 * 1000; // 30 minutes

    for (const [alertKey, alert] of this.activeAlerts) {
      if (now - alert.lastTriggered.getTime() > maxAge) {
        this.activeAlerts.delete(alertKey);
      }
    }
  }

  /**
   * Force circuit breaker to a specific state (for testing)
   */
  forceCircuitState(serviceName: string, state: 'closed' | 'open' | 'half-open'): boolean {
    return circuitBreakerManager.forceCircuitState(serviceName, state);
  }

  /**
   * Simulate service failure
   */
  simulateServiceFailure(serviceName: string): boolean {
    return circuitBreakerManager.simulateServiceFailure(serviceName);
  }

  /**
   * Simulate service recovery
   */
  simulateServiceRecovery(serviceName: string): boolean {
    return circuitBreakerManager.simulateServiceRecovery(serviceName);
  }

  /**
   * Reset all circuit breakers
   */
  resetAllCircuits(): void {
    circuitBreakerManager.resetAll();
    this.circuitHealthStatuses.clear();
    this.eventHistory.clear();
    this.performanceHistory.clear();
    this.activeAlerts.clear();

    logger.info('All circuit breakers have been reset');
    this.emit('all_circuits_reset');
  }
}

// Export singleton instance
export const circuitBreakerMonitor = new CircuitBreakerMonitor();