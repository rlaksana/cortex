
/**
 * Health Aggregation Service
 *
 * Advanced health monitoring and aggregation system that collects health data from
 * multiple dependencies, computes weighted health scores, and provides comprehensive
 * system health insights with SLA monitoring and alerting capabilities.
 *
 * Features:
 * - Multi-dimensional health scoring with weighted metrics
 * - SLA monitoring and compliance tracking
 * - Advanced alerting with threshold-based triggers
 * - Health trend analysis and prediction
 * - Dependency impact analysis and critical path tracking
 * - Historical health data analysis and reporting
 * - Health degradation detection and early warning
 * - Custom health metrics and KPIs
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { EventEmitter } from 'node:events';
import { createHash } from 'crypto';

import { logger } from '@/utils/logger.js';

import {
  AggregatedHealthStatus,
  type DependencyConfig,
  type DependencyRegistry,
  type DependencyState,
  DependencyStatus,
  HealthCheckResult as DependencyHealthResult,
} from './deps-registry.js';
import {
  AlertSeverity,
  dependencyStatusToHealthStatus,
  type HealthAggregationConfig,
  type HealthAlert,
  type HealthAnalysis,
  type HealthSnapshot,
  HealthTrend,
  isDependencyHealthResult,
  type SLACompliance,
  type SLADefinition,
  SLAStatus,
  ValidationPerformanceMonitor,
} from '../types/unified-health-interfaces.js';

// Note: All health-related interfaces (AlertSeverity, HealthTrend, SLAStatus, HealthAlert,
// SLADefinition, SLACompliance, HealthAnalysis, HealthAggregationConfig, HealthSnapshot)
// are now imported from unified-health-interfaces.ts to maintain consistency

/**
 * Health Aggregation Service
 *
 * Provides comprehensive health monitoring, analysis, and alerting capabilities
 * for all registered dependencies with advanced SLA monitoring and trend analysis.
 */
export class HealthAggregationService extends EventEmitter {
  private dependencyRegistry: DependencyRegistry;
  private config: HealthAggregationConfig;
  private healthHistory: HealthSnapshot[] = [];
  private alerts = new Map<string, HealthAlert>();
  private slaDefinitions = new Map<string, SLADefinition>();
  private slaCompliance = new Map<string, SLACompliance>();
  private lastAlertTimes = new Map<string, number>();
  private evaluationInterval?: NodeJS.Timeout;

  constructor(
    dependencyRegistry: DependencyRegistry,
    config: Partial<HealthAggregationConfig> = {}
  ) {
    super();

    this.dependencyRegistry = dependencyRegistry;
    this.config = {
      healthScoreWeights: {
        availability: 0.4,
        responseTime: 0.3,
        errorRate: 0.2,
        trend: 0.1,
      },
      alertThresholds: {
        responseTimeWarning: 1000,
        responseTimeCritical: 5000,
        errorRateWarning: 5,
        errorRateCritical: 15,
        availabilityWarning: 99,
        availabilityCritical: 95,
      },
      trendAnalysis: {
        windowSize: 10,
        minDataPoints: 5,
        threshold: 0.1,
      },
      slaMonitoring: {
        enabled: true,
        evaluationInterval: 60000, // 1 minute
        violationGracePeriod: 300000, // 5 minutes
      },
      alerting: {
        enabled: true,
        cooldownPeriod: 300000, // 5 minutes
        escalationPolicy: {
          warningDelay: 0,
          criticalDelay: 300000, // 5 minutes
          emergencyDelay: 900000, // 15 minutes
        },
      },
      ...config,
    };

    this.setupEventListeners();
  }

  /**
   * Start the health aggregation service
   */
  async start(): Promise<void> {
    try {
      logger.info('Starting Health Aggregation Service...');

      // Start SLA evaluation if enabled
      if (this.config.slaMonitoring.enabled) {
        this.startSLAEvaluation();
      }

      // Perform initial health collection
      await this.collectHealthSnapshot();

      // Set up periodic health collection
      this.evaluationInterval = setInterval(async () => {
        try {
          await this.collectHealthSnapshot();
          await this.evaluateHealthConditions();
        } catch (error) {
          logger.error({ error }, 'Error during health evaluation');
        }
      }, this.config.slaMonitoring.evaluationInterval);

      this.emit('started');
      logger.info('Health Aggregation Service started successfully');
    } catch (error) {
      logger.error({ error }, 'Failed to start Health Aggregation Service');
      throw error;
    }
  }

  /**
   * Stop the health aggregation service
   */
  async stop(): Promise<void> {
    try {
      logger.info('Stopping Health Aggregation Service...');

      if (this.evaluationInterval) {
        clearInterval(this.evaluationInterval);
        this.evaluationInterval = undefined;
      }

      this.emit('stopped');
      logger.info('Health Aggregation Service stopped');
    } catch (error) {
      logger.error({ error }, 'Failed to stop Health Aggregation Service');
      throw error;
    }
  }

  /**
   * Register an SLA definition
   */
  registerSLA(sla: SLADefinition): void {
    logger.info({ sla: sla.name }, 'Registering SLA definition');
    this.slaDefinitions.set(sla.name, sla);
    this.emit('slaRegistered', sla.name, sla);
  }

  /**
   * Get current health status with comprehensive analysis
   */
  async getHealthStatus(): Promise<HealthAnalysis> {
    try {
      const snapshot = await this.collectHealthSnapshot();
      const analysis = this.analyzeHealth(snapshot);

      return analysis;
    } catch (error) {
      logger.error({ error }, 'Failed to get health status');
      throw error;
    }
  }

  /**
   * Get SLA compliance status
   */
  getSLACompliance(slaName?: string): Map<string, SLACompliance> {
    if (slaName) {
      const compliance = this.slaCompliance.get(slaName);
      return compliance ? new Map([[slaName, compliance]]) : new Map();
    }
    return new Map(this.slaCompliance);
  }

  /**
   * Get active alerts
   */
  getActiveAlerts(severity?: AlertSeverity): HealthAlert[] {
    const alerts = Array.from(this.alerts.values()).filter(
      (alert) => !alert.resolved && !alert.acknowledged
    );

    if (severity) {
      return alerts.filter((alert) => alert.severity === severity);
    }

    return alerts.sort((a, b) => {
      const severityOrder = [
        AlertSeverity.EMERGENCY,
        AlertSeverity.CRITICAL,
        AlertSeverity.WARNING,
        AlertSeverity.INFO,
      ];
      return severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity);
    });
  }

  /**
   * Acknowledge an alert
   */
  acknowledgeAlert(alertId: string, acknowledgedBy: string): void {
    const alert = this.alerts.get(alertId);
    if (alert && !alert.acknowledged && !alert.resolved) {
      alert.acknowledged = true;
      alert.acknowledgedBy = acknowledgedBy;
      alert.acknowledgedAt = new Date();
      this.emit('alertAcknowledged', alertId, alert);
      logger.info({ alertId, acknowledgedBy }, 'Alert acknowledged');
    }
  }

  /**
   * Resolve an alert
   */
  resolveAlert(alertId: string): void {
    const alert = this.alerts.get(alertId);
    if (alert && !alert.resolved) {
      alert.resolved = true;
      alert.resolvedAt = new Date();
      this.emit('alertResolved', alertId, alert);
      logger.info({ alertId }, 'Alert resolved');
    }
  }

  /**
   * Get health history
   */
  getHealthHistory(limit: number = 100): HealthSnapshot[] {
    return this.healthHistory.slice(-limit);
  }

  /**
   * Perform comprehensive health analysis
   */
  performDetailedAnalysis(): Promise<{
    current: HealthAnalysis;
    trends: {
      status: HealthTrend;
      score: number;
      confidence: number;
      prediction: DependencyStatus;
    };
    risks: Array<{
      type: string;
      probability: number;
      impact: number;
      description: string;
      mitigation: string;
    }>;
    recommendations: Array<{
      priority: string;
      category: string;
      title: string;
      description: string;
      estimatedImpact: number;
    }>;
  }> {
    throw new Error('Method not implemented');
  }

  /**
   * Set up event listeners for dependency registry events
   */
  private setupEventListeners(): void {
    this.dependencyRegistry.on('statusChanged', (name, previousStatus, newStatus) => {
      this.handleDependencyStatusChange(name, previousStatus, newStatus);
    });

    this.dependencyRegistry.on('dependencyRegistered', (name) => {
      logger.debug({ dependency: name }, 'Dependency registered in health aggregation');
    });

    this.dependencyRegistry.on('dependencyUnregistered', (name) => {
      // Clean up any alerts for this dependency
      this.cleanupDependencyAlerts(name);
    });
  }

  /**
   * Collect current health snapshot from all dependencies
   */
  private async collectHealthSnapshot(): Promise<HealthSnapshot> {
    const dependencies = this.dependencyRegistry.getAllDependencies();
    const snapshot: HealthSnapshot = {
      timestamp: new Date(),
      dependencies: {},
      overall: {
        status: DependencyStatus.HEALTHY,
        score: 100,
      },
    };

    let totalScore = 0;
    let totalWeight = 0;
    let criticalCount = 0;

    for (const [name, state] of Object.entries(dependencies)) {
      const score = this.calculateDependencyHealthScore(state);
      const trend = this.calculateDependencyTrend(name);

      snapshot.dependencies[name] = {
        status: state.status,
        score,
        responseTime: state.metrics.responseTime.current,
        errorRate: state.metrics.error.rate * 100,
        availability: this.calculateAvailability(state),
      };

      // Calculate weighted average for overall score
      const weight = this.getDependencyWeight(state.config.priority);
      totalScore += score * weight;
      totalWeight += weight;

      if (state.status === DependencyStatus.CRITICAL) {
        criticalCount++;
      }
    }

    // Calculate overall status and score
    if (totalWeight > 0) {
      snapshot.overall.score = Math.round(totalScore / totalWeight);
    }

    if (criticalCount > 0) {
      snapshot.overall.status = DependencyStatus.CRITICAL;
    } else if (snapshot.overall.score < 70) {
      snapshot.overall.status = DependencyStatus.WARNING;
    } else {
      snapshot.overall.status = DependencyStatus.HEALTHY;
    }

    // Store in history
    this.healthHistory.push(snapshot);
    if (this.healthHistory.length > 1000) {
      this.healthHistory.splice(0, this.healthHistory.length - 1000);
    }

    this.emit('healthSnapshotCollected', snapshot);
    return snapshot;
  }

  /**
   * Calculate health score for a dependency
   */
  private calculateDependencyHealthScore(state: DependencyState): number {
    const weights = this.config.healthScoreWeights;

    // Availability score (0-100)
    const availabilityScore = this.calculateAvailability(state);

    // Response time score (0-100)
    const responseTimeScore = this.calculateResponseTimeScore(state.metrics.responseTime.current);

    // Error rate score (0-100)
    const errorRateScore = this.calculateErrorRateScore(state.metrics.error.rate);

    // Trend score (0-100)
    const trendScore = this.calculateTrendScore(state);

    // Calculate weighted score
    const weightedScore =
      availabilityScore * weights.availability +
      responseTimeScore * weights.responseTime +
      errorRateScore * weights.errorRate +
      trendScore * weights.trend;

    return Math.round(Math.max(0, Math.min(100, weightedScore)));
  }

  /**
   * Calculate availability percentage
   */
  private calculateAvailability(state: DependencyState): number {
    const { uptime, downtime } = state.metrics.availability;
    const totalTime = uptime + downtime;

    if (totalTime === 0) {
      // If no data, use status-based availability
      switch (state.status) {
        case DependencyStatus.HEALTHY:
          return 100;
        case DependencyStatus.WARNING:
          return 95;
        case DependencyStatus.CRITICAL:
          return 80;
        case DependencyStatus.UNKNOWN:
          return 50;
        default:
          return 0;
      }
    }

    return Math.round((uptime / totalTime) * 100);
  }

  /**
   * Calculate response time score
   */
  private calculateResponseTimeScore(responseTime: number): number {
    const thresholds = this.config.alertThresholds;

    if (responseTime <= thresholds.responseTimeWarning) {
      return 100;
    } else if (responseTime <= thresholds.responseTimeCritical) {
      // Linear interpolation between warning and critical
      const ratio =
        (responseTime - thresholds.responseTimeWarning) /
        (thresholds.responseTimeCritical - thresholds.responseTimeWarning);
      return Math.round(100 - ratio * 50); // Scale from 100 to 50
    } else {
      // Exponential decay for very slow responses
      return Math.max(0, 50 - Math.log10(responseTime / thresholds.responseTimeCritical) * 10);
    }
  }

  /**
   * Calculate error rate score
   */
  private calculateErrorRateScore(errorRate: number): number {
    const errorRatePercentage = errorRate * 100;
    const thresholds = this.config.alertThresholds;

    if (errorRatePercentage <= thresholds.errorRateWarning) {
      return 100;
    } else if (errorRatePercentage <= thresholds.errorRateCritical) {
      // Linear interpolation
      const ratio =
        (errorRatePercentage - thresholds.errorRateWarning) /
        (thresholds.errorRateCritical - thresholds.errorRateWarning);
      return Math.round(100 - ratio * 50);
    } else {
      return Math.max(0, 50 - errorRatePercentage);
    }
  }

  /**
   * Calculate trend score
   */
  private calculateTrendScore(state: DependencyState): number {
    const trend = this.calculateDependencyTrend(state.config.name);

    switch (trend) {
      case HealthTrend.IMPROVING:
        return 100;
      case HealthTrend.STABLE:
        return 80;
      case HealthTrend.FLUCTUATING:
        return 60;
      case HealthTrend.DEGRADING:
        return 20;
      default:
        return 50;
    }
  }

  /**
   * Calculate dependency trend based on historical data
   */
  private calculateDependencyTrend(dependencyName: string): HealthTrend {
    const history = this.healthHistory.slice(-this.config.trendAnalysis.windowSize);

    if (history.length < this.config.trendAnalysis.minDataPoints) {
      return HealthTrend.STABLE;
    }

    const scores = history
      .map((snapshot) => snapshot.dependencies[dependencyName]?.score)
      .filter((score) => score !== undefined);

    if (scores.length < this.config.trendAnalysis.minDataPoints) {
      return HealthTrend.STABLE;
    }

    // Calculate trend using linear regression
    const n = scores.length;
    const x = Array.from({ length: n }, (_, i) => i);
    const y = scores;

    const sumX = x.reduce((a, b) => a + b, 0);
    const sumY = y.reduce((a, b) => a + b, 0);
    const sumXY = x.reduce((total, xi, i) => total + xi * y[i], 0);
    const sumXX = x.reduce((total, xi) => total + xi * xi, 0);

    const slope = (n * sumXY - sumX * sumY) / (n * sumXX - sumX * sumX);
    const threshold = this.config.trendAnalysis.threshold;

    if (Math.abs(slope) < threshold) {
      return HealthTrend.STABLE;
    } else if (slope > threshold) {
      return HealthTrend.IMPROVING;
    } else if (slope < -threshold) {
      return HealthTrend.DEGRADING;
    } else {
      // Check for fluctuation pattern
      const variance = this.calculateVariance(scores);
      const meanVariance =
        scores.reduce((sum, score) => sum + Math.pow(score - sumY / n, 2), 0) / n;

      if (variance > meanVariance * 2) {
        return HealthTrend.FLUCTUATING;
      }

      return slope > 0 ? HealthTrend.IMPROVING : HealthTrend.DEGRADING;
    }
  }

  /**
   * Calculate variance of an array of numbers
   */
  private calculateVariance(values: number[]): number {
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const squaredDiffs = values.map((value) => Math.pow(value - mean, 2));
    return squaredDiffs.reduce((a, b) => a + b, 0) / values.length;
  }

  /**
   * Get dependency weight based on priority
   */
  private getDependencyWeight(priority: string): number {
    switch (priority) {
      case 'critical':
        return 4;
      case 'high':
        return 3;
      case 'medium':
        return 2;
      case 'low':
        return 1;
      default:
        return 1;
    }
  }

  /**
   * Analyze comprehensive health status
   */
  private analyzeHealth(snapshot: HealthSnapshot): HealthAnalysis {
    const dependencies = this.dependencyRegistry.getAllDependencies();

    const analysis: HealthAnalysis = {
      overall: {
        status: snapshot.overall.status,
        score: snapshot.overall.score,
        trend: this.calculateOverallTrend(),
        confidence: this.calculateConfidenceScore(),
      },
      dependencies: {},
      risks: [],
      recommendations: [],
      timestamp: new Date(),
    };

    // Analyze individual dependencies
    for (const [name, state] of Object.entries(dependencies)) {
      const depData = snapshot.dependencies[name];
      if (!depData) continue;

      const trend = this.calculateDependencyTrend(name);
      const impact = this.calculateDependencyImpact(name, state);
      const risk = this.assessDependencyRisk(depData, trend);

      analysis.dependencies[name] = {
        status: depData.status,
        score: depData.score,
        trend,
        impact,
        risk,
      };

      // Add risks if any
      if (risk !== 'low') {
        analysis.risks.push(this.createDependencyRisk(name, depData, risk));
      }

      // Add recommendations
      this.addDependencyRecommendations(analysis, name, depData, trend);
    }

    // Sort recommendations by priority
    analysis.recommendations.sort((a, b) => {
      const priorityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
      return priorityOrder[b.priority] - priorityOrder[a.priority];
    });

    // Sort risks by level
    analysis.risks.sort((a, b) => {
      const levelOrder = { critical: 4, high: 3, medium: 2, low: 1 };
      return levelOrder[b.level] - levelOrder[a.level];
    });

    return analysis;
  }

  /**
   * Calculate overall health trend
   */
  private calculateOverallTrend(): HealthTrend {
    if (this.healthHistory.length < this.config.trendAnalysis.minDataPoints) {
      return HealthTrend.STABLE;
    }

    const overallScores = this.healthHistory.map((snapshot) => snapshot.overall.score);
    const variance = this.calculateVariance(overallScores);

    if (variance > 25) {
      return HealthTrend.FLUCTUATING;
    }

    const recentScores = overallScores.slice(-5);
    const olderScores = overallScores.slice(-10, -5);

    if (recentScores.length === 0 || olderScores.length === 0) {
      return HealthTrend.STABLE;
    }

    const recentAvg = recentScores.reduce((a, b) => a + b, 0) / recentScores.length;
    const olderAvg = olderScores.reduce((a, b) => a + b, 0) / olderScores.length;

    const difference = recentAvg - olderAvg;
    const threshold = this.config.trendAnalysis.threshold * 10;

    if (Math.abs(difference) < threshold) {
      return HealthTrend.STABLE;
    } else if (difference > threshold) {
      return HealthTrend.IMPROVING;
    } else {
      return HealthTrend.DEGRADING;
    }
  }

  /**
   * Calculate confidence score for health analysis
   */
  private calculateConfidenceScore(): number {
    const dataPoints = this.healthHistory.length;
    const maxDataPoints = 100;

    // Base confidence on amount of data
    let confidence = Math.min(100, (dataPoints / maxDataPoints) * 100);

    // Reduce confidence if data is too recent
    if (dataPoints < 10) {
      confidence *= 0.5;
    } else if (dataPoints < 20) {
      confidence *= 0.7;
    }

    return Math.round(confidence);
  }

  /**
   * Calculate dependency impact on overall system
   */
  private calculateDependencyImpact(name: string, state: DependencyState): number {
    const baseImpact = this.getDependencyWeight(state.config.priority) * 25;

    // Adjust impact based on number of dependent services
    const dependentCount = this.countDependentServices(name);
    const dependencyMultiplier = Math.min(2, 1 + dependentCount * 0.1);

    return Math.round(baseImpact * dependencyMultiplier);
  }

  /**
   * Count services that depend on a given dependency
   */
  private countDependentServices(dependencyName: string): number {
    // This is a simplified implementation
    // In a real system, this would analyze the dependency graph
    return 1;
  }

  /**
   * Assess dependency risk level
   */
  private assessDependencyRisk(
    dependencyData: HealthSnapshot['dependencies'][string],
    trend: HealthTrend
  ): 'low' | 'medium' | 'high' | 'critical' {
    const { status, score, responseTime, errorRate, availability } = dependencyData;

    // Critical risks
    if (status === DependencyStatus.CRITICAL || score < 30) {
      return 'critical';
    }

    // High risks
    if (status === DependencyStatus.WARNING || score < 60) {
      if (trend === HealthTrend.DEGRADING) {
        return 'critical';
      }
      return 'high';
    }

    // Medium risks
    if (trend === HealthTrend.DEGRADING || trend === HealthTrend.FLUCTUATING) {
      return 'medium';
    }

    // Performance-based risks
    if (
      responseTime > this.config.alertThresholds.responseTimeCritical ||
      errorRate > this.config.alertThresholds.errorRateCritical ||
      availability < this.config.alertThresholds.availabilityCritical
    ) {
      return 'high';
    }

    if (
      responseTime > this.config.alertThresholds.responseTimeWarning ||
      errorRate > this.config.alertThresholds.errorRateWarning ||
      availability < this.config.alertThresholds.availabilityWarning
    ) {
      return 'medium';
    }

    return 'low';
  }

  /**
   * Create dependency risk object
   */
  private createDependencyRisk(
    name: string,
    dependencyData: HealthSnapshot['dependencies'][string],
    risk: 'low' | 'medium' | 'high' | 'critical'
  ): HealthAnalysis['risks'][0] {
    const issues: string[] = [];

    if (dependencyData.responseTime > this.config.alertThresholds.responseTimeCritical) {
      issues.push('critical response time');
    } else if (dependencyData.responseTime > this.config.alertThresholds.responseTimeWarning) {
      issues.push('elevated response time');
    }

    if (dependencyData.errorRate > this.config.alertThresholds.errorRateCritical) {
      issues.push('critical error rate');
    } else if (dependencyData.errorRate > this.config.alertThresholds.errorRateWarning) {
      issues.push('elevated error rate');
    }

    if (dependencyData.availability < this.config.alertThresholds.availabilityCritical) {
      issues.push('critical availability');
    } else if (dependencyData.availability < this.config.alertThresholds.availabilityWarning) {
      issues.push('reduced availability');
    }

    let type: HealthAnalysis['risks'][0]['type'] = 'performance';
    let description = `Performance degradation detected`;

    if (issues.some((issue) => issue.includes('error rate'))) {
      type = 'error_rate';
      description = `High error rate affecting service reliability`;
    } else if (issues.some((issue) => issue.includes('availability'))) {
      type = 'availability';
      description = `Service availability below acceptable thresholds`;
    }

    return {
      dependency: name,
      type,
      level: risk,
      description: `${description}: ${issues.join(', ')}`,
      probability: this.calculateRiskProbability(dependencyData, risk),
      impact: this.calculateRiskImpact(dependencyData, risk),
      mitigation: this.generateMitigationStrategy(type, risk),
    };
  }

  /**
   * Calculate risk probability
   */
  private calculateRiskProbability(
    dependencyData: HealthSnapshot['dependencies'][string],
    risk: 'low' | 'medium' | 'high' | 'critical'
  ): number {
    switch (risk) {
      case 'critical':
        return 0.9;
      case 'high':
        return 0.7;
      case 'medium':
        return 0.5;
      case 'low':
        return 0.2;
      default:
        return 0.3;
    }
  }

  /**
   * Calculate risk impact
   */
  private calculateRiskImpact(
    dependencyData: HealthSnapshot['dependencies'][string],
    risk: 'low' | 'medium' | 'high' | 'critical'
  ): number {
    const baseImpact = (100 - dependencyData.score) / 100;

    switch (risk) {
      case 'critical':
        return baseImpact * 1.0;
      case 'high':
        return baseImpact * 0.7;
      case 'medium':
        return baseImpact * 0.4;
      case 'low':
        return baseImpact * 0.2;
      default:
        return baseImpact * 0.3;
    }
  }

  /**
   * Generate mitigation strategy
   */
  private generateMitigationStrategy(
    type: HealthAnalysis['risks'][0]['type'],
    risk: 'low' | 'medium' | 'high' | 'critical'
  ): string {
    const strategies = {
      performance: 'Implement caching, optimize queries, or scale resources',
      availability: 'Enable failover mechanisms, health checks, and circuit breakers',
      error_rate: 'Implement retry logic, improve error handling, and monitoring',
      dependency_chain: 'Reduce dependencies, implement async patterns, and timeouts',
    };

    return strategies[type] || 'Review dependency configuration and monitoring';
  }

  /**
   * Add dependency recommendations to analysis
   */
  private addDependencyRecommendations(
    analysis: HealthAnalysis,
    name: string,
    dependencyData: HealthSnapshot['dependencies'][string],
    trend: HealthTrend
  ): void {
    // Performance recommendations
    if (dependencyData.responseTime > this.config.alertThresholds.responseTimeWarning) {
      analysis.recommendations.push({
        priority:
          dependencyData.responseTime > this.config.alertThresholds.responseTimeCritical
            ? 'high'
            : 'medium',
        category: 'performance',
        title: 'Optimize response time',
        description: `Dependency ${name} has elevated response time of ${dependencyData.responseTime}ms`,
        estimatedImpact:
          dependencyData.responseTime > this.config.alertThresholds.responseTimeCritical ? 80 : 50,
      });
    }

    // Reliability recommendations
    if (dependencyData.availability < this.config.alertThresholds.availabilityWarning) {
      analysis.recommendations.push({
        priority:
          dependencyData.availability < this.config.alertThresholds.availabilityCritical
            ? 'critical'
            : 'high',
        category: 'reliability',
        title: 'Improve service availability',
        description: `Dependency ${name} availability is at ${dependencyData.availability}%`,
        estimatedImpact:
          dependencyData.availability < this.config.alertThresholds.availabilityCritical ? 90 : 60,
      });
    }

    // Monitoring recommendations
    if (trend === HealthTrend.FLUCTUATING) {
      analysis.recommendations.push({
        priority: 'medium',
        category: 'monitoring',
        title: 'Investigate performance fluctuations',
        description: `Dependency ${name} shows unstable performance patterns`,
        estimatedImpact: 40,
      });
    }

    // Trend-based recommendations
    if (trend === HealthTrend.DEGRADING) {
      analysis.recommendations.push({
        priority: 'high',
        category: 'performance',
        title: 'Address performance degradation',
        description: `Dependency ${name} shows declining performance trend`,
        estimatedImpact: 70,
      });
    }
  }

  /**
   * Handle dependency status changes
   */
  private handleDependencyStatusChange(
    name: string,
    previousStatus: DependencyStatus,
    newStatus: DependencyStatus
  ): void {
    // Check if we need to generate alerts
    this.evaluateStatusChangeAlerts(name, previousStatus, newStatus);
  }

  /**
   * Evaluate status change and generate alerts if needed
   */
  private evaluateStatusChangeAlerts(
    name: string,
    previousStatus: DependencyStatus,
    newStatus: DependencyStatus
  ): void {
    const alertKey = `${name}_${newStatus}`;
    const now = Date.now();
    const lastAlert = this.lastAlertTimes.get(alertKey);

    // Check cooldown period
    if (lastAlert && now - lastAlert < this.config.alerting.cooldownPeriod) {
      return;
    }

    let severity: AlertSeverity;
    let title: string;
    let message: string;

    switch (newStatus) {
      case DependencyStatus.CRITICAL:
        severity = AlertSeverity.CRITICAL;
        title = `Critical: ${name} is down`;
        message = `Dependency ${name} has entered critical status and may be unavailable`;
        break;
      case DependencyStatus.WARNING:
        severity = AlertSeverity.WARNING;
        title = `Warning: ${name} performance issues`;
        message = `Dependency ${name} is experiencing performance degradation`;
        break;
      case DependencyStatus.HEALTHY:
        if (previousStatus !== DependencyStatus.HEALTHY) {
          severity = AlertSeverity.INFO;
          title = `Resolved: ${name} is healthy`;
          message = `Dependency ${name} has recovered and is now healthy`;
        } else {
          return; // No alert for staying healthy
        }
        break;
      default:
        return; // No alert for unknown or disabled status
    }

    this.createAlert(name, severity, title, message);
    this.lastAlertTimes.set(alertKey, now);
  }

  /**
   * Create a new alert
   */
  private createAlert(
    dependency: string,
    severity: AlertSeverity,
    title: string,
    message: string,
    metadata?: Record<string, any>
  ): void {
    const alertId = createHash('md5')
      .update(`${dependency}_${severity}_${Date.now()}`)
      .digest('hex');

    const alert: HealthAlert = {
      id: alertId,
      dependency,
      severity,
      title,
      message,
      timestamp: new Date(),
      acknowledged: false,
      resolved: false,
      metadata,
    };

    this.alerts.set(alertId, alert);
    this.emit('alertCreated', alert);
    logger.warn({ alertId, dependency, severity, title }, 'Health alert created');
  }

  /**
   * Evaluate health conditions and generate alerts
   */
  private async evaluateHealthConditions(): Promise<void> {
    const snapshot = await this.collectHealthSnapshot();

    for (const [name, dependencyData] of Object.entries(snapshot.dependencies)) {
      // Check threshold-based alerts
      this.evaluateThresholdAlerts(name, dependencyData);
    }

    // Evaluate SLA compliance
    if (this.config.slaMonitoring.enabled) {
      await this.evaluateSLACompliance();
    }
  }

  /**
   * Evaluate threshold-based alerts
   */
  private evaluateThresholdAlerts(
    name: string,
    dependencyData: HealthSnapshot['dependencies'][string]
  ): void {
    const thresholds = this.config.alertThresholds;

    // Response time alerts
    if (dependencyData.responseTime > thresholds.responseTimeCritical) {
      this.createAlert(
        name,
        AlertSeverity.CRITICAL,
        `Critical Response Time: ${name}`,
        `Response time of ${dependencyData.responseTime}ms exceeds critical threshold of ${thresholds.responseTimeCritical}ms`
      );
    } else if (dependencyData.responseTime > thresholds.responseTimeWarning) {
      this.createAlert(
        name,
        AlertSeverity.WARNING,
        `High Response Time: ${name}`,
        `Response time of ${dependencyData.responseTime}ms exceeds warning threshold of ${thresholds.responseTimeWarning}ms`
      );
    }

    // Error rate alerts
    if (dependencyData.errorRate > thresholds.errorRateCritical) {
      this.createAlert(
        name,
        AlertSeverity.CRITICAL,
        `Critical Error Rate: ${name}`,
        `Error rate of ${dependencyData.errorRate}% exceeds critical threshold of ${thresholds.errorRateCritical}%`
      );
    } else if (dependencyData.errorRate > thresholds.errorRateWarning) {
      this.createAlert(
        name,
        AlertSeverity.WARNING,
        `High Error Rate: ${name}`,
        `Error rate of ${dependencyData.errorRate}% exceeds warning threshold of ${thresholds.errorRateWarning}%`
      );
    }

    // Availability alerts
    if (dependencyData.availability < thresholds.availabilityCritical) {
      this.createAlert(
        name,
        AlertSeverity.CRITICAL,
        `Critical Availability: ${name}`,
        `Availability of ${dependencyData.availability}% below critical threshold of ${thresholds.availabilityCritical}%`
      );
    } else if (dependencyData.availability < thresholds.availabilityWarning) {
      this.createAlert(
        name,
        AlertSeverity.WARNING,
        `Low Availability: ${name}`,
        `Availability of ${dependencyData.availability}% below warning threshold of ${thresholds.availabilityWarning}%`
      );
    }
  }

  /**
   * Start SLA evaluation
   */
  private startSLAEvaluation(): void {
    // Perform initial evaluation
    this.evaluateSLACompliance().catch((error) =>
      logger.error({ error }, 'Initial SLA evaluation failed')
    );

    // Set up periodic evaluation
    setInterval(() => {
      this.evaluateSLACompliance().catch((error) =>
        logger.error({ error }, 'SLA evaluation failed')
      );
    }, this.config.slaMonitoring.evaluationInterval);
  }

  /**
   * Evaluate SLA compliance for all defined SLAs
   */
  private async evaluateSLACompliance(): Promise<void> {
    for (const [slaName, sla] of this.slaDefinitions) {
      try {
        const compliance = await this.calculateSLACompliance(sla);
        this.slaCompliance.set(slaName, compliance);

        // Check for SLA violations
        if (compliance.status === SLAStatus.VIOLATION) {
          this.createSLAViolationAlert(slaName, compliance);
        }
      } catch (error) {
        logger.error({ sla: slaName, error }, 'SLA evaluation failed');
      }
    }
  }

  /**
   * Calculate SLA compliance for a specific SLA
   */
  private async calculateSLACompliance(sla: SLADefinition): Promise<SLACompliance> {
    const now = new Date();
    const periodEnd = new Date(now);
    const periodStart = new Date(now);

    // Set period start based on SLA period type
    switch (sla.period.type) {
      case 'daily':
        periodStart.setDate(periodStart.getDate() - sla.period.duration);
        break;
      case 'weekly':
        periodStart.setDate(periodStart.getDate() - sla.period.duration * 7);
        break;
      case 'monthly':
        periodStart.setMonth(periodStart.getMonth() - sla.period.duration);
        break;
    }

    // Get relevant health snapshots for the period
    const relevantSnapshots = this.healthHistory.filter(
      (snapshot) => snapshot.timestamp >= periodStart && snapshot.timestamp <= periodEnd
    );

    if (relevantSnapshots.length === 0) {
      return {
        sla: sla.name,
        status: SLAStatus.UNKNOWN,
        period: { start: periodStart, end: periodEnd },
        metrics: {
          availability: { current: 0, target: sla.targets.availability, compliance: 0 },
          responseTime: { current: 0, target: sla.targets.responseTime, compliance: 0 },
          errorRate: { current: 0, target: sla.targets.errorRate, compliance: 0 },
        },
        violations: [],
        score: 0,
      };
    }

    // Calculate metrics for SLA dependencies
    const slaDependencies = sla.dependencies;
    let totalAvailability = 0;
    let totalResponseTime = 0;
    let totalErrorRate = 0;
    let dependencyCount = 0;

    const violations: SLACompliance['violations'] = [];

    for (const snapshot of relevantSnapshots) {
      for (const depName of slaDependencies) {
        const depData = snapshot.dependencies[depName];
        if (!depData) continue;

        totalAvailability += depData.availability;
        totalResponseTime += depData.responseTime;
        totalErrorRate += depData.errorRate;
        dependencyCount++;

        // Check for violations
        if (depData.availability < sla.targets.availability) {
          violations.push({
            metric: 'availability',
            value: depData.availability,
            target: sla.targets.availability,
            timestamp: snapshot.timestamp,
          });
        }

        if (depData.responseTime > sla.targets.responseTime) {
          violations.push({
            metric: 'responseTime',
            value: depData.responseTime,
            target: sla.targets.responseTime,
            timestamp: snapshot.timestamp,
          });
        }

        if (depData.errorRate > sla.targets.errorRate) {
          violations.push({
            metric: 'errorRate',
            value: depData.errorRate,
            target: sla.targets.errorRate,
            timestamp: snapshot.timestamp,
          });
        }
      }
    }

    if (dependencyCount === 0) {
      return {
        sla: sla.name,
        status: SLAStatus.UNKNOWN,
        period: { start: periodStart, end: periodEnd },
        metrics: {
          availability: { current: 0, target: sla.targets.availability, compliance: 0 },
          responseTime: { current: 0, target: sla.targets.responseTime, compliance: 0 },
          errorRate: { current: 0, target: sla.targets.errorRate, compliance: 0 },
        },
        violations: [],
        score: 0,
      };
    }

    // Calculate averages
    const avgAvailability = totalAvailability / dependencyCount;
    const avgResponseTime = totalResponseTime / dependencyCount;
    const avgErrorRate = totalErrorRate / dependencyCount;

    // Calculate compliance percentages
    const availabilityCompliance = Math.min(
      100,
      (avgAvailability / sla.targets.availability) * 100
    );
    const responseTimeCompliance = Math.min(
      100,
      (sla.targets.responseTime / avgResponseTime) * 100
    );
    const errorRateCompliance = Math.min(100, (sla.targets.errorRate / avgErrorRate) * 100);

    // Determine overall SLA status
    let status: SLAStatus = SLAStatus.COMPLIANT;
    if (violations.length > 0) {
      const criticalViolations = violations.filter(
        (v) => v.metric === 'availability' && v.value < 95
      );
      status = criticalViolations.length > 0 ? SLAStatus.VIOLATION : SLAStatus.WARNING;
    }

    // Calculate overall score
    const overallScore =
      (availabilityCompliance + responseTimeCompliance + errorRateCompliance) / 3;

    return {
      sla: sla.name,
      status,
      period: { start: periodStart, end: periodEnd },
      metrics: {
        availability: {
          current: Math.round(avgAvailability),
          target: sla.targets.availability,
          compliance: Math.round(availabilityCompliance),
        },
        responseTime: {
          current: Math.round(avgResponseTime),
          target: sla.targets.responseTime,
          compliance: Math.round(responseTimeCompliance),
        },
        errorRate: {
          current: Math.round(avgErrorRate),
          target: sla.targets.errorRate,
          compliance: Math.round(errorRateCompliance),
        },
      },
      violations,
      score: Math.round(overallScore),
    };
  }

  /**
   * Create SLA violation alert
   */
  private createSLAViolationAlert(slaName: string, compliance: SLACompliance): void {
    const alertKey = `sla_violation_${slaName}`;
    const now = Date.now();
    const lastAlert = this.lastAlertTimes.get(alertKey);

    // Check grace period
    if (lastAlert && now - lastAlert < this.config.slaMonitoring.violationGracePeriod) {
      return;
    }

    const criticalViolations = compliance.violations.filter(
      (v) => v.metric === 'availability' && v.value < 95
    );

    const severity = criticalViolations.length > 0 ? AlertSeverity.CRITICAL : AlertSeverity.WARNING;

    this.createAlert(
      slaName,
      severity,
      `SLA Violation: ${slaName}`,
      `SLA ${slaName} has ${compliance.violations.length} violations with an overall score of ${compliance.score}`,
      { sla: slaName, violations: compliance.violations, score: compliance.score }
    );

    this.lastAlertTimes.set(alertKey, now);
  }

  /**
   * Clean up alerts for unregistered dependencies
   */
  private cleanupDependencyAlerts(dependencyName: string): void {
    for (const [alertId, alert] of this.alerts) {
      if (alert.dependency === dependencyName && !alert.resolved) {
        alert.resolved = true;
        alert.resolvedAt = new Date();
        this.emit('alertResolved', alertId, alert);
      }
    }
  }
}

// Export types and service
export { HealthAggregationService as default };

// Re-export required enums for isolatedModules compliance
export { AlertSeverity, HealthTrend,SLAStatus } from '../types/unified-health-interfaces.js';
