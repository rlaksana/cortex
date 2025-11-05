/**
 * Qdrant Error Budget Tracker
 *
 * Tracks and manages error budgets for Qdrant operations, providing visibility
 * into service reliability and degradation costs. Implements SRE-style error
 * budget management with detailed reporting and alerting.
 *
 * @author Cortex Team
 * @version 2.0.1
 */

import { EventEmitter } from 'events';
import { logger } from '../utils/logger.js';
import { DegradationLevel, DegradationEvent } from './degradation-detector.js';
import { HealthStatus } from '../types/unified-health-interfaces.js';

/**
 * Error budget configuration
 */
export interface ErrorBudgetConfig {
  // Service level objectives (SLO)
  slo: {
    availabilityTarget: number;        // percentage (e.g., 99.9)
    latencyTarget: number;            // milliseconds (e.g., 1000)
    errorRateTarget: number;          // percentage (e.g., 0.1)
    timeWindowMs: number;             // SLO time window (e.g., 30 days)
  };

  // Error budget calculation
  budget: {
    burnRateWarningThreshold: number;  // percentage of budget burned
    burnRateCriticalThreshold: number; // percentage of budget burned
    rapidBurnThreshold: number;        // burn rate multiplier for rapid detection
    minimumSampleSize: number;         // minimum operations for reliable calculation
  };

  // Reporting and alerting
  reporting: {
    intervalMs: number;               // reporting interval
    includeDegradedOperations: boolean; // count degraded ops in budget
    includeCircuitBreakerEvents: boolean;
    enableHistoricalTrends: boolean;
    trendWindowDays: number;
  };

  // Budget actions
  actions: {
    haltDeploymentThreshold: number;  // percentage burned - halt deployments
    requireApprovalThreshold: number; // percentage burned - require approval
    emergencyModeThreshold: number;   // percentage burned - emergency mode
  };
}

/**
 * Operation metrics for error budget calculation
 */
export interface OperationMetrics {
  timestamp: number;
  operationType: 'read' | 'write' | 'search' | 'health_check' | 'other';
  success: boolean;
  responseTime: number;
  degraded: boolean;
  errorType?: string;
  fallbackUsed: boolean;
}

/**
 * Error budget status
 */
export interface ErrorBudgetStatus {
  // Current status
  availability: number;
  errorRate: number;
  averageResponseTime: number;
  budgetBurned: number;              // percentage
  budgetRemaining: number;           // percentage
  burnRate: number;                  // percentage per hour

  // Time-based calculations
  timeWindowStart: Date;
  timeWindowEnd: Date;
  totalOperations: number;
  successfulOperations: number;
  failedOperations: number;
  degradedOperations: number;
  fallbackOperations: number;

  // Budget consumption
  projectedBurnTime: Date | null;    // when budget will be exhausted
  burnRateVelocity: 'normal' | 'increasing' | 'rapid' | 'critical';
  recommendedActions: string[];
}

/**
 * Error budget report
 */
export interface ErrorBudgetReport {
  period: {
    start: Date;
    end: Date;
    duration: number; // milliseconds
  };

  // SLO compliance
  sloCompliance: {
    availability: number;
    latency: number;
    errorRate: number;
    availabilityTarget: number;
    latencyTarget: number;
    errorRateTarget: number;
    passed: boolean;
  };

  // Error budget details
  errorBudget: {
    totalBudget: number;           // percentage
    consumed: number;              // percentage
    remaining: number;             // percentage
    burnRate: number;              // percentage per hour
  };

  // Operational metrics
  operations: {
    total: number;
    successful: number;
    failed: number;
    degraded: number;
    fallback: number;
    averageResponseTime: number;
    p95ResponseTime: number;
    p99ResponseTime: number;
  };

  // Degradation impact
  degradationImpact: {
    totalDegradationTime: number;   // milliseconds
    degradationEvents: number;
    averageDegradationDuration: number;
    criticalEvents: number;
    unavailableEvents: number;
  };

  // Recommendations
  recommendations: string[];
  alerts: Array<{
    severity: 'info' | 'warning' | 'critical';
    message: string;
    threshold: number;
    currentValue: number;
  }>;
}

/**
 * Qdrant Error Budget Tracker
 */
export class QdrantErrorBudgetTracker extends EventEmitter {
  private config: ErrorBudgetConfig;
  private operationHistory: OperationMetrics[] = [];
  private degradationEvents: DegradationEvent[] = [];
  private currentReport: ErrorBudgetReport | null = null;
  private isTracking = false;
  private reportingInterval: NodeJS.Timeout | null = null;

  // State tracking
  private startTime = Date.now();
  private lastReportTime = 0;
  private cumulativeOperations = 0;
  private cumulativeFailures = 0;
  private cumulativeDegraded = 0;

  constructor(config?: Partial<ErrorBudgetConfig>) {
    super();

    this.config = {
      slo: {
        availabilityTarget: 99.9,
        latencyTarget: 1000,
        errorRateTarget: 0.1,
        timeWindowMs: 30 * 24 * 60 * 60 * 1000, // 30 days
      },
      budget: {
        burnRateWarningThreshold: 50,   // 50% of budget burned
        burnRateCriticalThreshold: 80,  // 80% of budget burned
        rapidBurnThreshold: 2,          // 2x normal burn rate
        minimumSampleSize: 100,
      },
      reporting: {
        intervalMs: 5 * 60 * 1000,      // 5 minutes
        includeDegradedOperations: true,
        includeCircuitBreakerEvents: true,
        enableHistoricalTrends: true,
        trendWindowDays: 7,
      },
      actions: {
        haltDeploymentThreshold: 90,
        requireApprovalThreshold: 70,
        emergencyModeThreshold: 95,
      },
      ...config,
    };

    logger.info('Error budget tracker initialized', {
      availabilityTarget: this.config.slo.availabilityTarget,
      latencyTarget: this.config.slo.latencyTarget,
      errorRateTarget: this.config.slo.errorRateTarget,
    });
  }

  /**
   * Start error budget tracking
   */
  start(): void {
    if (this.isTracking) {
      logger.warn('Error budget tracking is already running');
      return;
    }

    this.isTracking = true;
    this.startTime = Date.now();

    // Start reporting interval
    this.reportingInterval = setInterval(
      () => this.generateReport(),
      this.config.reporting.intervalMs
    );

    // Generate initial report
    this.generateReport();

    logger.info(
      {
        trackingStarted: new Date().toISOString(),
        reportingInterval: this.config.reporting.intervalMs,
        timeWindow: this.config.slo.timeWindowMs,
      },
      'Error budget tracking started'
    );

    this.emit('started');
  }

  /**
   * Stop error budget tracking
   */
  stop(): void {
    if (!this.isTracking) {
      logger.warn('Error budget tracking is not running');
      return;
    }

    this.isTracking = false;

    if (this.reportingInterval) {
      clearInterval(this.reportingInterval);
      this.reportingInterval = null;
    }

    // Generate final report
    this.generateReport();

    logger.info('Error budget tracking stopped');
    this.emit('stopped');
  }

  /**
   * Record operation metrics
   */
  recordOperation(metrics: OperationMetrics): void {
    if (!this.isTracking) {
      return;
    }

    this.operationHistory.push(metrics);
    this.cumulativeOperations++;

    if (!metrics.success) {
      this.cumulativeFailures++;
    }

    if (metrics.degraded) {
      this.cumulativeDegraded++;
    }

    // Keep history within SLO time window
    const cutoff = Date.now() - this.config.slo.timeWindowMs;
    this.operationHistory = this.operationHistory.filter(m => m.timestamp > cutoff);

    // Check for immediate alerts
    this.checkImmediateAlerts();

    this.emit('operation_recorded', metrics);
  }

  /**
   * Record degradation event
   */
  recordDegradationEvent(event: DegradationEvent): void {
    if (!this.isTracking) {
      return;
    }

    this.degradationEvents.push(event);

    // Keep recent events
    const cutoff = Date.now() - this.config.slo.timeWindowMs;
    this.degradationEvents = this.degradationEvents.filter(e => e.timestamp.getTime() > cutoff);

    this.emit('degradation_recorded', event);

    // Generate report immediately for critical events
    if (event.level === DegradationLevel.CRITICAL || event.level === DegradationLevel.UNAVAILABLE) {
      this.generateReport();
    }
  }

  /**
   * Get current error budget status
   */
  getCurrentStatus(): ErrorBudgetStatus {
    const now = Date.now();
    const windowStart = now - this.config.slo.timeWindowMs;

    // Filter operations within SLO window
    const windowOperations = this.operationHistory.filter(m => m.timestamp > windowStart);

    if (windowOperations.length < this.config.budget.minimumSampleSize) {
      return {
        availability: 100,
        errorRate: 0,
        averageResponseTime: 0,
        budgetBurned: 0,
        budgetRemaining: 100,
        burnRate: 0,
        timeWindowStart: new Date(windowStart),
        timeWindowEnd: new Date(now),
        totalOperations: windowOperations.length,
        successfulOperations: 0,
        failedOperations: 0,
        degradedOperations: 0,
        fallbackOperations: 0,
        projectedBurnTime: null,
        burnRateVelocity: 'normal',
        recommendedActions: ['Insufficient data for error budget calculation'],
      };
    }

    // Calculate metrics
    const successful = windowOperations.filter(m => m.success).length;
    const failed = windowOperations.filter(m => !m.success).length;
    const degraded = windowOperations.filter(m => m.degraded).length;
    const fallback = windowOperations.filter(m => m.fallbackUsed).length;

    const availability = (successful / windowOperations.length) * 100;
    const errorRate = (failed / windowOperations.length) * 100;

    const responseTimes = windowOperations.map(m => m.responseTime);
    const averageResponseTime = responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length;

    // Calculate error budget
    const availabilityTarget = this.config.slo.availabilityTarget;
    const availabilityBudget = 100 - availabilityTarget; // Total error budget percentage
    const availabilityBurned = Math.max(0, availabilityTarget - availability);
    const budgetBurned = (availabilityBurned / availabilityBudget) * 100;

    // Calculate burn rate (per hour)
    const timeWindowHours = this.config.slo.timeWindowMs / (1000 * 60 * 60);
    const burnRate = budgetBurned / timeWindowHours;

    // Project burn time
    let projectedBurnTime: Date | null = null;
    if (burnRate > 0) {
      const timeToExhaustion = (100 - budgetBurned) / burnRate;
      if (timeToExhaustion > 0 && timeToExhaustion < 24 * 7) { // Only project if less than a week
        projectedBurnTime = new Date(now + (timeToExhaustion * 60 * 60 * 1000));
      }
    }

    // Determine burn rate velocity
    let burnRateVelocity: 'normal' | 'increasing' | 'rapid' | 'critical' = 'normal';
    if (burnRate > this.config.budget.rapidBurnThreshold * (availabilityBudget / timeWindowHours)) {
      burnRateVelocity = 'rapid';
    }
    if (burnRate > this.config.budget.rapidBurnThreshold * 2 * (availabilityBudget / timeWindowHours)) {
      burnRateVelocity = 'critical';
    } else if (burnRate > (availabilityBudget / timeWindowHours) * 1.5) {
      burnRateVelocity = 'increasing';
    }

    // Generate recommendations
    const recommendations = this.generateRecommendations(
      availability,
      errorRate,
      budgetBurned,
      burnRate,
      burnRateVelocity
    );

    return {
      availability,
      errorRate,
      averageResponseTime,
      budgetBurned,
      budgetRemaining: Math.max(0, 100 - budgetBurned),
      burnRate,
      timeWindowStart: new Date(windowStart),
      timeWindowEnd: new Date(now),
      totalOperations: windowOperations.length,
      successfulOperations: successful,
      failedOperations: failed,
      degradedOperations: degraded,
      fallbackOperations: fallback,
      projectedBurnTime,
      burnRateVelocity,
      recommendedActions: recommendations,
    };
  }

  /**
   * Get latest error budget report
   */
  getLatestReport(): ErrorBudgetReport | null {
    return this.currentReport;
  }

  /**
   * Generate error budget report
   */
  generateReport(): ErrorBudgetReport {
    const now = Date.now();
    const windowStart = now - this.config.slo.timeWindowMs;

    // Get operations within window
    const windowOperations = this.operationHistory.filter(m => m.timestamp > windowStart);
    const windowDegradations = this.degradationEvents.filter(e => e.timestamp.getTime() > windowStart);

    // Calculate basic metrics
    const total = windowOperations.length;
    const successful = windowOperations.filter(m => m.success).length;
    const failed = windowOperations.filter(m => !m.success).length;
    const degraded = windowOperations.filter(m => m.degraded).length;
    const fallback = windowOperations.filter(m => m.fallbackUsed).length;

    const availability = total > 0 ? (successful / total) * 100 : 100;
    const errorRate = total > 0 ? (failed / total) * 100 : 0;

    // Calculate response time metrics
    const responseTimes = windowOperations.map(m => m.responseTime);
    const averageResponseTime = responseTimes.length > 0
      ? responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length
      : 0;

    const sortedTimes = responseTimes.sort((a, b) => a - b);
    const p95ResponseTime = this.calculatePercentile(sortedTimes, 0.95);
    const p99ResponseTime = this.calculatePercentile(sortedTimes, 0.99);

    // Calculate SLO compliance
    const availabilityTarget = this.config.slo.availabilityTarget;
    const latencyTarget = this.config.slo.latencyTarget;
    const errorRateTarget = this.config.slo.errorRate;

    const sloPassed = availability >= availabilityTarget &&
                     averageResponseTime <= latencyTarget &&
                     errorRate <= errorRateTarget;

    // Calculate error budget
    const availabilityBudget = 100 - availabilityTarget;
    const availabilityBurned = Math.max(0, availabilityTarget - availability);
    const budgetConsumed = (availabilityBurned / availabilityBudget) * 100;

    const timeWindowHours = this.config.slo.timeWindowMs / (1000 * 60 * 60);
    const burnRate = timeWindowHours > 0 ? budgetConsumed / timeWindowHours : 0;

    // Calculate degradation impact
    const totalDegradationTime = this.calculateTotalDegradationTime(windowDegradations);
    const averageDegradationDuration = windowDegradations.length > 0
      ? totalDegradationTime / windowDegradations.length
      : 0;

    const criticalEvents = windowDegradations.filter(e => e.level === DegradationLevel.CRITICAL).length;
    const unavailableEvents = windowDegradations.filter(e => e.level === DegradationLevel.UNAVAILABLE).length;

    // Generate recommendations and alerts
    const recommendations = this.generateRecommendations(
      availability,
      errorRate,
      budgetConsumed,
      burnRate,
      'normal' // Simplified for report
    );

    const alerts = this.generateAlerts(availability, errorRate, budgetConsumed, burnRate);

    const report: ErrorBudgetReport = {
      period: {
        start: new Date(windowStart),
        end: new Date(now),
        duration: this.config.slo.timeWindowMs,
      },
      sloCompliance: {
        availability,
        latency: averageResponseTime,
        errorRate,
        availabilityTarget,
        latencyTarget,
        errorRateTarget,
        passed: sloPassed,
      },
      errorBudget: {
        totalBudget: availabilityBudget,
        consumed: budgetConsumed,
        remaining: Math.max(0, availabilityBudget - availabilityBurned),
        burnRate,
      },
      operations: {
        total,
        successful,
        failed,
        degraded,
        fallback,
        averageResponseTime,
        p95ResponseTime,
        p99ResponseTime,
      },
      degradationImpact: {
        totalDegradationTime,
        degradationEvents: windowDegradations.length,
        averageDegradationDuration,
        criticalEvents,
        unavailableEvents,
      },
      recommendations,
      alerts,
    };

    this.currentReport = report;
    this.lastReportTime = now;

    this.emit('report_generated', report);

    return report;
  }

  // === Private Methods ===

  /**
   * Check for immediate alerts
   */
  private checkImmediateAlerts(): void {
    const status = this.getCurrentStatus();

    // Check critical thresholds
    if (status.budgetBurned >= this.config.budget.burnRateCriticalThreshold) {
      this.emit('critical_alert', {
        type: 'budget_exhaustion_critical',
        message: `Error budget critically depleted: ${status.budgetBurned.toFixed(2)}% burned`,
        budgetBurned: status.budgetBurned,
        burnRate: status.burnRate,
        recommendedActions: status.recommendedActions,
      });
    }

    if (status.burnRateVelocity === 'critical') {
      this.emit('critical_alert', {
        type: 'rapid_burn_rate',
        message: `Critical error budget burn rate detected: ${status.burnRate.toFixed(2)}%/hour`,
        burnRate: status.burnRate,
        burnRateVelocity: status.burnRateVelocity,
        projectedBurnTime: status.projectedBurnTime,
      });
    }
  }

  /**
   * Generate recommendations
   */
  private generateRecommendations(
    availability: number,
    errorRate: number,
    budgetBurned: number,
    burnRate: number,
    burnRateVelocity: 'normal' | 'increasing' | 'rapid' | 'critical'
  ): string[] {
    const recommendations: string[] = [];

    if (availability < this.config.slo.availabilityTarget) {
      recommendations.push('Investigate availability issues immediately');
      recommendations.push('Review recent failures and root causes');
    }

    if (errorRate > this.config.slo.errorRateTarget) {
      recommendations.push('Address high error rates');
      recommendations.push('Review error logs and fix recurring issues');
    }

    if (budgetBurned >= this.config.actions.emergencyModeThreshold) {
      recommendations.push('EMERGENCY: Halt all non-essential deployments');
      recommendations.push('Engage incident response team');
      recommendations.push('Prepare rollback procedures');
    } else if (budgetBurned >= this.config.actions.haltDeploymentThreshold) {
      recommendations.push('HALT: Stop all deployments until error budget recovers');
      recommendations.push('Require manual approval for any changes');
    } else if (budgetBurned >= this.config.actions.requireApprovalThreshold) {
      recommendations.push('REVIEW: Require approval for new deployments');
      recommendations.push('Increase monitoring and alerting');
    }

    if (burnRateVelocity === 'critical') {
      recommendations.push('CRITICAL: Error budget burning at dangerous rate');
      recommendations.push('Investigate immediate cause of rapid degradation');
      recommendations.push('Consider emergency failover procedures');
    } else if (burnRateVelocity === 'rapid') {
      recommendations.push('WARNING: Error budget burn rate is elevated');
      recommendations.push('Monitor closely for continued degradation');
    }

    if (recommendations.length === 0) {
      recommendations.push('Continue normal operations');
      recommendations.push('Maintain current monitoring and alerting');
    }

    return recommendations;
  }

  /**
   * Generate alerts
   */
  private generateAlerts(
    availability: number,
    errorRate: number,
    budgetBurned: number,
    burnRate: number
  ): Array<{
    severity: 'info' | 'warning' | 'critical';
    message: string;
    threshold: number;
    currentValue: number;
  }> {
    const alerts: Array<{
      severity: 'info' | 'warning' | 'critical';
      message: string;
      threshold: number;
      currentValue: number;
    }> = [];

    // Availability alerts
    if (availability < this.config.slo.availabilityTarget) {
      alerts.push({
        severity: availability < this.config.slo.availabilityTarget * 0.95 ? 'critical' : 'warning',
        message: `Availability below SLO target`,
        threshold: this.config.slo.availabilityTarget,
        currentValue: availability,
      });
    }

    // Error rate alerts
    if (errorRate > this.config.slo.errorRateTarget) {
      alerts.push({
        severity: errorRate > this.config.slo.errorRateTarget * 2 ? 'critical' : 'warning',
        message: `Error rate above SLO target`,
        threshold: this.config.slo.errorRateTarget,
        currentValue: errorRate,
      });
    }

    // Error budget alerts
    if (budgetBurned >= this.config.budget.burnRateCriticalThreshold) {
      alerts.push({
        severity: 'critical',
        message: `Error budget critically depleted`,
        threshold: this.config.budget.burnRateCriticalThreshold,
        currentValue: budgetBurned,
      });
    } else if (budgetBurned >= this.config.budget.burnRateWarningThreshold) {
      alerts.push({
        severity: 'warning',
        message: `Error budget significantly consumed`,
        threshold: this.config.budget.burnRateWarningThreshold,
        currentValue: budgetBurned,
      });
    }

    return alerts;
  }

  /**
   * Calculate total degradation time
   */
  private calculateTotalDegradationTime(events: DegradationEvent[]): number {
    let totalTime = 0;

    for (const event of events) {
      if (event.estimatedRecoveryTime) {
        totalTime += event.estimatedRecoveryTime;
      } else {
        // Default estimate based on severity
        const defaultDurations = {
          [DegradationLevel.WARNING]: 10 * 60 * 1000,      // 10 minutes
          [DegradationLevel.DEGRADED]: 30 * 60 * 1000,    // 30 minutes
          [DegradationLevel.CRITICAL]: 60 * 60 * 1000,    // 1 hour
          [DegradationLevel.UNAVAILABLE]: 2 * 60 * 60 * 1000, // 2 hours
        };

        totalTime += defaultDurations[event.level] || 30 * 60 * 1000;
      }
    }

    return totalTime;
  }

  /**
   * Calculate percentile from sorted array
   */
  private calculatePercentile(sortedArray: number[], percentile: number): number {
    if (sortedArray.length === 0) return 0;

    const index = Math.ceil(sortedArray.length * percentile) - 1;
    return sortedArray[Math.max(0, Math.min(index, sortedArray.length - 1))];
  }
}

export default QdrantErrorBudgetTracker;