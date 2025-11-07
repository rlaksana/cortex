// @ts-nocheck
/**
 * Enhanced Circuit Breaker Dashboard with SLO Overlays
 *
 * Advanced dashboard system for visualizing circuit breaker health, retry budget
 * consumption, and SLO compliance with real-time updates, interactive visualizations,
 * and comprehensive service dependency mapping.
 *
 * @author Cortex Team
 * @version 2.0.1
 */

import { EventEmitter } from 'events';
import { Request, Response } from 'express';
import { logger } from '@/utils/logger.js';
import {
  circuitBreakerMonitor,
  type CircuitBreakerHealthStatus
} from './circuit-breaker-monitor.js';
import {
  retryBudgetMonitor,
  type RetryBudgetMetrics,
  type RetryBudgetConfig
} from './retry-budget-monitor.js';
import {
  retryMetricsExporter,
  type GrafanaDashboardData
} from './retry-metrics-exporter.js';
import { HealthStatus } from '../types/unified-health-interfaces.js';

type Risk = 'low' | 'medium' | 'high' | 'critical';
const toRisk = (v: unknown): Risk => {
  const k = String(v || '').toLowerCase();
  return (k === 'critical' || k === 'high' || k === 'medium' || k === 'low' ? (k as Risk) : 'low');
};

/**
 * Dashboard configuration
 */
export interface EnhancedCircuitDashboardConfig {
  // Real-time updates
  realTime: {
    enabled: boolean;
    updateIntervalMs: number;
    bufferSize: number;
  };

  // SLO configuration
  slo: {
    enabled: boolean;
    targets: {
      availability: number; // percentage
      latency: number; // milliseconds
      errorRate: number; // percentage
    };
    windows: {
      shortTerm: number; // minutes
      mediumTerm: number; // hours
      longTerm: number; // days
    };
  };

  // Visualization settings
  visualization: {
    maxServices: number;
    chartHistoryPoints: number;
    colorScheme: 'default' | 'dark' | 'high-contrast';
    enableAnimations: boolean;
  };

  // Features
  features: {
    serviceDependencyMap: boolean;
    predictiveAlerts: boolean;
    historicalTrends: boolean;
    comparativeAnalysis: boolean;
    exportCapabilities: boolean;
  };

  // Performance
  performance: {
    cachingEnabled: boolean;
    cacheTtlSeconds: number;
    compressionEnabled: boolean;
  };
}

/**
 * Service dependency information
 */
export interface ServiceDependency {
  serviceName: string;
  dependsOn: string[];
  impactLevel: 'critical' | 'high' | 'medium' | 'low';
  healthImpact: {
    ifDown: number; // percentage impact on overall system
    cascadeRisk: number; // 0-1 risk of cascade failure
  };
}

/**
 * Dashboard data snapshot
 */
export interface DashboardSnapshot {
  timestamp: Date;
  overall: {
    totalServices: number;
    healthyServices: number;
    degradedServices: number;
    unhealthyServices: number;
    overallHealth: HealthStatus;
    sloComplianceRate: number;
  };
  services: Array<{
    name: string;
    circuitBreaker: CircuitBreakerHealthStatus;
    retryBudget: RetryBudgetMetrics;
    slo: {
      compliance: boolean;
      availability: number;
      latency: number;
      errorRate: number;
      trend: 'improving' | 'degrading' | 'stable';
    };
    dependencies: ServiceDependency;
    alerts: Array<{
      type: string;
      severity: 'warning' | 'critical';
      message: string;
      timestamp: Date;
    }>;
    predictions: {
      riskLevel: 'low' | 'medium' | 'high' | 'critical';
      predictedFailure: Date | null;
      recommendations: string[];
    };
  }>;
  trends: {
    healthTrend: 'improving' | 'degrading' | 'stable';
    performanceTrend: 'improving' | 'degrading' | 'stable';
    sloTrend: 'improving' | 'degrading' | 'stable';
  };
  alerts: Array<{
    id: string;
    serviceName: string;
    type: string;
    severity: 'info' | 'warning' | 'critical';
    message: string;
    timestamp: Date;
    acknowledged: boolean;
  }>;
}

/**
 * SLO overlay data
 */
export interface SLOOverlayData {
  serviceName: string;
  sloTargets: {
    availability: { target: number; current: number; compliant: boolean };
    latency: { target: number; current: number; compliant: boolean };
    errorRate: { target: number; current: number; compliant: boolean };
  };
  burnRate: {
    current: number;
    remaining: number;
    period: 'short' | 'medium' | 'long';
  };
  errorBudget: {
    total: number;
    consumed: number;
    remaining: number;
    burnRate: number;
  };
  predictions: {
    willMeetSLO: boolean;
    projectedCompliance: number;
    riskFactors: string[];
  };
}

/**
 * Chart data point
 */
export interface ChartDataPoint {
  timestamp: Date;
  value: number;
  metadata?: Record<string, any>;
}

/**
 * Enhanced Circuit Breaker Dashboard
 */
export class EnhancedCircuitDashboard extends EventEmitter {
  private config: EnhancedCircuitDashboardConfig;
  private isRunning = false;
  private startTime: number;

  // Data storage
  private dashboardCache: DashboardSnapshot | null = null;
  private historicalData: Map<string, ChartDataPoint[]> = new Map();
  private serviceDependencies: Map<string, ServiceDependency> = new Map();

  // Real-time updates
  private updateInterval: NodeJS.Timeout | null = null;
  private subscribers: Map<string, Response> = new Map();

  // Alert management
  private activeAlerts: Map<string, {
    id: string;
    serviceName: string;
    type: string;
    severity: 'info' | 'warning' | 'critical';
    message: string;
    timestamp: Date;
    acknowledged: boolean;
  }> = new Map();

  constructor(config?: Partial<EnhancedCircuitDashboardConfig>) {
    super();

    this.config = {
      realTime: {
        enabled: true,
        updateIntervalMs: 5000, // 5 seconds
        bufferSize: 100,
      },
      slo: {
        enabled: true,
        targets: {
          availability: 99.9,
          latency: 500,
          errorRate: 0.1,
        },
        windows: {
          shortTerm: 5, // 5 minutes
          mediumTerm: 60, // 1 hour
          longTerm: 1440, // 1 day
        },
      },
      visualization: {
        maxServices: 50,
        chartHistoryPoints: 100,
        colorScheme: 'default',
        enableAnimations: true,
      },
      features: {
        serviceDependencyMap: true,
        predictiveAlerts: true,
        historicalTrends: true,
        comparativeAnalysis: true,
        exportCapabilities: true,
      },
      performance: {
        cachingEnabled: true,
        cacheTtlSeconds: 30,
        compressionEnabled: true,
      },
      ...config,
    };

    this.startTime = Date.now();
    this.setupEventListeners();
  }

  /**
   * Start the dashboard
   */
  start(): void {
    if (this.isRunning) {
      logger.warn('Enhanced circuit dashboard is already running');
      return;
    }

    this.isRunning = true;

    // Start real-time updates
    if (this.config.realTime.enabled) {
      this.updateInterval = setInterval(
        () => this.updateDashboard(),
        this.config.realTime.updateIntervalMs
      );
    }

    // Perform initial update
    this.updateDashboard();

    logger.info(
      {
        updateInterval: this.config.realTime.updateIntervalMs,
        features: this.config.features,
      },
      'Enhanced circuit dashboard started'
    );

    this.emit('started');
  }

  /**
   * Stop the dashboard
   */
  stop(): void {
    if (!this.isRunning) {
      logger.warn('Enhanced circuit dashboard is not running');
      return;
    }

    this.isRunning = false;

    if (this.updateInterval) {
      clearInterval(this.updateInterval);
      this.updateInterval = null;
    }

    // Close all subscriber connections
    for (const [id, response] of this.subscribers) {
      try {
        response.end();
      } catch (error) {
        logger.warn({ subscriberId: id, error }, 'Failed to close subscriber connection');
      }
    }
    this.subscribers.clear();

    logger.info('Enhanced circuit dashboard stopped');
    this.emit('stopped');
  }

  /**
   * Get current dashboard snapshot
   */
  async getDashboardSnapshot(): Promise<DashboardSnapshot> {
    if (this.config.performance.cachingEnabled && this.dashboardCache) {
      const age = Date.now() - this.dashboardCache.timestamp.getTime();
      if (age < this.config.performance.cacheTtlSeconds * 1000) {
        return this.dashboardCache;
      }
    }

    return this.generateDashboardSnapshot();
  }

  /**
   * Get SLO overlay data for all services
   */
  getSLOOverlayData(): SLOOverlayData[] {
    const retryBudgetMetrics = retryBudgetMonitor.getAllMetrics();
    const sloData: SLOOverlayData[] = [];

    for (const [serviceName, metrics] of retryBudgetMetrics) {
      const sloOverlay = this.calculateSLOOverlay(serviceName, metrics);
      sloData.push(sloOverlay);
    }

    return sloData;
  }

  /**
   * Get historical chart data for a metric
   */
  getHistoricalData(serviceName: string, metric: string, hours: number = 24): ChartDataPoint[] {
    const key = `${serviceName}:${metric}`;
    const data = this.historicalData.get(key) || [];
    const cutoff = Date.now() - (hours * 60 * 60 * 1000);

    return data
      .filter(point => point.timestamp.getTime() >= cutoff)
      .sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  }

  /**
   * Get service dependency map
   */
  getServiceDependencyMap(): Map<string, ServiceDependency> {
    return new Map(this.serviceDependencies);
  }

  /**
   * Register service dependency
   */
  registerServiceDependency(dependency: ServiceDependency): void {
    this.serviceDependencies.set(dependency.serviceName, dependency);

    // Calculate impact on other services
    this.updateDependencyImpact(dependency);

    logger.info(
      { serviceName: dependency.serviceName, dependsOn: dependency.dependsOn },
      'Service dependency registered'
    );

    this.emit('dependency_registered', dependency);
  }

  /**
   * Acknowledge alert
   */
  acknowledgeAlert(alertId: string): boolean {
    const alert = this.activeAlerts.get(alertId);
    if (alert) {
      alert.acknowledged = true;
      this.emit('alert_acknowledged', { alertId, alert });
      return true;
    }
    return false;
  }

  /**
   * Get active alerts
   */
  getActiveAlerts(): Array<{
    id: string;
    serviceName: string;
    type: string;
    severity: 'info' | 'warning' | 'critical';
    message: string;
    timestamp: Date;
    acknowledged: boolean;
  }> {
    return Array.from(this.activeAlerts.values())
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  }

  /**
   * Export dashboard data
   */
  async exportDashboard(format: 'json' | 'csv' | 'pdf'): Promise<string> {
    const snapshot = await this.getDashboardSnapshot();

    switch (format) {
      case 'json':
        return JSON.stringify(snapshot, null, 2);
      case 'csv':
        return this.exportToCSV(snapshot);
      case 'pdf':
        // In a real implementation, this would generate PDF
        return 'PDF export not implemented in this version';
      default:
        throw new Error(`Unsupported export format: ${format}`);
    }
  }

  /**
   * Subscribe to real-time updates (Server-Sent Events)
   */
  subscribeToUpdates(request: Request, response: Response): void {
    const subscriberId = this.generateSubscriberId();

    // Set up SSE headers
    response.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
    });

    // Store subscriber
    this.subscribers.set(subscriberId, response);

    // Send initial data
    this.sendUpdateToSubscriber(subscriberId);

    // Handle disconnect
    request.on('close', () => {
      this.subscribers.delete(subscriberId);
    });

    logger.debug({ subscriberId }, 'Dashboard update subscription created');
  }

  /**
   * Generate Grafana dashboard configuration
   */
  generateGrafanaDashboard(): GrafanaDashboardData {
    const baseDashboard = retryMetricsExporter.generateGrafanaDashboard();

    // Add enhanced panels for SLO overlays and dependencies
    baseDashboard.panels.push(
      {
        title: 'SLO Compliance Overview',
        type: 'stat',
        targets: [
          {
            expr: 'slo_compliance_ratio',
            legendFormat: '{{service}}',
            refId: 'A',
          },
        ],
        gridPos: { x: 0, y: 24, w: 12, h: 8 },
      },
      {
        title: 'Error Budget Consumption',
        type: 'timeseries',
        targets: [
          {
            expr: 'error_budget_consumption_percent',
            legendFormat: '{{service}}',
            refId: 'B',
          },
        ],
        gridPos: { x: 12, y: 24, w: 12, h: 8 },
      },
      {
        title: 'Service Dependency Impact',
        type: 'graph',
        targets: [
          {
            expr: 'dependency_impact_score',
            legendFormat: '{{service}} -> {{dependency}}',
            refId: 'C',
          },
        ],
        gridPos: { x: 0, y: 32, w: 24, h: 8 },
      },
      {
        title: 'Circuit Breaker State Transitions',
        type: 'heatmap',
        targets: [
          {
            expr: 'circuit_breaker_state_transitions',
            legendFormat: '{{service}}',
            refId: 'D',
          },
        ],
        gridPos: { x: 0, y: 40, w: 24, h: 8 },
      }
    );

    return baseDashboard;
  }

  /**
   * Update dashboard data
   */
  private async updateDashboard(): Promise<void> {
    try {
      const snapshot = await this.generateDashboardSnapshot();
      this.dashboardCache = snapshot;

      // Store historical data
      this.storeHistoricalData(snapshot);

      // Send updates to subscribers
      this.broadcastUpdate(snapshot);

      // Emit update event
      this.emit('dashboard_updated', snapshot);
    } catch (error) {
      logger.error({ error }, 'Failed to update dashboard');
    }
  }

  /**
   * Generate dashboard snapshot
   */
  private async generateDashboardSnapshot(): Promise<DashboardSnapshot> {
    const circuitBreakerMetrics = circuitBreakerMonitor.getAllHealthStatuses();
    const retryBudgetMetrics = retryBudgetMonitor.getAllMetrics();
    const timestamp = new Date();

    // Calculate overall statistics
    const totalServices = Math.max(circuitBreakerMetrics.size, retryBudgetMetrics.size);
    const healthyServices = Array.from(circuitBreakerMetrics.values())
      .filter(cb => cb.healthStatus === HealthStatus.HEALTHY).length;
    const degradedServices = Array.from(circuitBreakerMetrics.values())
      .filter(cb => cb.healthStatus === HealthStatus.DEGRADED).length;
    const unhealthyServices = Array.from(circuitBreakerMetrics.values())
      .filter(cb => cb.healthStatus === HealthStatus.UNHEALTHY).length;

    let overallHealth = HealthStatus.HEALTHY;
    if (unhealthyServices > 0) {
      overallHealth = HealthStatus.UNHEALTHY;
    } else if (degradedServices > 0) {
      overallHealth = HealthStatus.DEGRADED;
    }

    const sloComplianceRate = this.calculateOverallSLOCompliance(retryBudgetMetrics);

    // Generate service data
    const services: DashboardSnapshot['services'] = [];

    for (const [serviceName] of circuitBreakerMetrics) {
      const circuitBreaker = circuitBreakerMetrics.get(serviceName)!;
      const retryBudget = retryBudgetMetrics.get(serviceName);
      const dependencies = this.serviceDependencies.get(serviceName) || {
        serviceName,
        dependsOn: [],
        impactLevel: 'medium',
        healthImpact: { ifDown: 0, cascadeRisk: 0 },
      };

      const slo = retryBudget ? this.calculateSLOMetrics(serviceName, retryBudget) : {
        compliance: true,
        availability: 100,
        latency: 0,
        errorRate: 0,
        trend: 'stable' as const,
      };

      const alerts = this.generateServiceAlerts(serviceName, circuitBreaker, retryBudget);
      const predictions = this.generatePredictions(serviceName, circuitBreaker, retryBudget);

      services.push({
        name: serviceName,
        circuitBreaker,
        retryBudget: retryBudget || this.getEmptyRetryBudgetMetrics(serviceName),
        slo,
        dependencies,
        alerts,
        predictions,
      });
    }

    // Calculate trends
    const trends = this.calculateTrends();

    // Get active alerts
    const alerts = this.getActiveAlerts();

    return {
      timestamp,
      overall: {
        totalServices,
        healthyServices,
        degradedServices,
        unhealthyServices,
        overallHealth,
        sloComplianceRate,
      },
      services,
      trends,
      alerts,
    };
  }

  /**
   * Calculate SLO overlay for a service
   */
  private calculateSLOOverlay(serviceName: string, metrics: RetryBudgetMetrics): SLOOverlayData {
    const targets = this.config.slo.targets;

    // Current SLO status
    const availability = metrics.slo.successRateCompliance ? metrics.slo.successRateVariance : 95;
    const latency = metrics.performance.p95ResponseTime;
    const errorRate = metrics.current.retryRatePercent;

    const sloTargets = {
      availability: {
        target: targets.availability,
        current: availability,
        compliant: availability >= targets.availability,
      },
      latency: {
        target: targets.latency,
        current: latency,
        compliant: latency <= targets.latency,
      },
      errorRate: {
        target: targets.errorRate,
        current: errorRate,
        compliant: errorRate <= targets.errorRate,
      },
    };

    // Calculate burn rate
    const burnRate = this.calculateBurnRate(metrics);
    const errorBudget = this.calculateErrorBudget(metrics, targets);

    // Predictions
    const predictions = this.calculateSLOPredictions(metrics, sloTargets);

    return {
      serviceName,
      sloTargets,
      burnRate,
      errorBudget,
      predictions,
    };
  }

  /**
   * Calculate SLO metrics for a service
   */
  private calculateSLOMetrics(serviceName: string, metrics: RetryBudgetMetrics): DashboardSnapshot['services'][0]['slo'] {
    const targets = this.config.slo.targets;

    const availability = metrics.slo.successRateVariance || 100;
    const latency = metrics.performance.p95ResponseTime;
    const errorRate = metrics.current.retryRatePercent;

    const compliance = availability >= targets.availability &&
                      latency <= targets.latency &&
                      errorRate <= targets.errorRate;

    const trend = this.calculateSLOTrend(serviceName);

    return {
      compliance,
      availability,
      latency,
      errorRate,
      trend,
    };
  }

  /**
   * Generate service alerts
   */
  private generateServiceAlerts(
    serviceName: string,
    circuitBreaker: CircuitBreakerHealthStatus,
    retryBudget?: RetryBudgetMetrics
  ): DashboardSnapshot['services'][0]['alerts'] {
    const alerts: DashboardSnapshot['services'][0]['alerts'] = [];

    // Circuit breaker alerts
    if (circuitBreaker.isOpen) {
      alerts.push({
        type: 'circuit_open',
        severity: 'critical',
        message: `Circuit breaker is OPEN for ${serviceName}`,
        timestamp: new Date(),
      });
    } else if (circuitBreaker.isHalfOpen) {
      alerts.push({
        type: 'circuit_half_open',
        severity: 'warning',
        message: `Circuit breaker is HALF-OPEN for ${serviceName}`,
        timestamp: new Date(),
      });
    }

    // Retry budget alerts
    if (retryBudget) {
      if (retryBudget.current.budgetUtilizationPercent >= 90) {
        alerts.push({
          type: 'budget_critical',
          severity: 'critical',
          message: `Retry budget critically high: ${retryBudget.current.budgetUtilizationPercent.toFixed(1)}%`,
          timestamp: new Date(),
        });
      } else if (retryBudget.current.budgetUtilizationPercent >= 75) {
        alerts.push({
          type: 'budget_warning',
          severity: 'warning',
          message: `Retry budget high: ${retryBudget.current.budgetUtilizationPercent.toFixed(1)}%`,
          timestamp: new Date(),
        });
      }

      // SLO violation alerts
      if (!retryBudget.slo.overallCompliance) {
        alerts.push({
          type: 'slo_violation',
          severity: 'critical',
          message: `SLO violations detected for ${serviceName}`,
          timestamp: new Date(),
        });
      }
    }

    return alerts;
  }

  /**
   * Generate predictions for a service
   */
  private generatePredictions(
    serviceName: string,
    circuitBreaker: CircuitBreakerHealthStatus,
    retryBudget?: RetryBudgetMetrics
  ): DashboardSnapshot['services'][0]['predictions'] {
    const predictions = {
      riskLevel: 'low' as Risk,
      predictedFailure: null as Date | null,
      recommendations: [] as string[],
    };

    // Analyze circuit breaker state
    if (circuitBreaker.isOpen) {
      predictions.riskLevel = 'critical';
      predictions.predictedFailure = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes
      predictions.recommendations.push('Investigate service connectivity immediately');
    } else if (circuitBreaker.metrics.failureRate > 20) {
      predictions.riskLevel = 'high';
      predictions.predictedFailure = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
      predictions.recommendations.push('Monitor service closely - high failure rate');
    }

    // Analyze retry budget
    if (retryBudget) {
      if (retryBudget.current.budgetUtilizationPercent > 80) {
        predictions.riskLevel = predictions.riskLevel === 'critical' ? 'critical' : 'high';
        predictions.recommendations.push('Retry budget running low - consider adjustments');
      }

      if (retryBudget.predictions.budgetExhaustionTime) {
        predictions.predictedFailure = retryBudget.predictions.budgetExhaustionTime;
        predictions.recommendations.push(...retryBudget.predictions.recommendedAdjustments);
      }
    }

    // Dependency impact analysis
    const dependencies = this.serviceDependencies.get(serviceName);
    if (dependencies && dependencies.healthImpact.cascadeRisk > 0.7) {
      predictions.recommendations.push('High cascade risk - review dependencies');
    }

    return predictions;
  }

  /**
   * Calculate overall trends
   */
  private calculateTrends(): DashboardSnapshot['trends'] {
    // This would analyze historical data to determine trends
    // For now, return stable trends
    return {
      healthTrend: 'stable',
      performanceTrend: 'stable',
      sloTrend: 'stable',
    };
  }

  /**
   * Calculate overall SLO compliance rate
   */
  private calculateOverallSLOCompliance(retryBudgetMetrics: Map<string, RetryBudgetMetrics>): number {
    if (retryBudgetMetrics.size === 0) return 100;

    const compliantServices = Array.from(retryBudgetMetrics.values())
      .filter(metrics => metrics.slo.overallCompliance).length;

    return (compliantServices / retryBudgetMetrics.size) * 100;
  }

  /**
   * Store historical data
   */
  private storeHistoricalData(snapshot: DashboardSnapshot): void {
    for (const service of snapshot.services) {
      const metrics = [
        { key: 'utilization', value: service.retryBudget.current.budgetUtilizationPercent },
        { key: 'retryRate', value: service.retryBudget.current.retryRatePercent },
        { key: 'availability', value: service.slo.availability },
        { key: 'latency', value: service.slo.latency },
        { key: 'failureRate', value: service.circuitBreaker.metrics.failureRate },
      ];

      for (const metric of metrics) {
        const dataKey = `${service.name}:${metric.key}`;
        if (!this.historicalData.has(dataKey)) {
          this.historicalData.set(dataKey, []);
        }

        const data = this.historicalData.get(dataKey)!;
        data.push({
          timestamp: snapshot.timestamp,
          value: metric.value,
        });

        // Keep only recent data points
        const maxPoints = this.config.visualization.chartHistoryPoints;
        if (data.length > maxPoints) {
          data.splice(0, data.length - maxPoints);
        }
      }
    }
  }

  /**
   * Broadcast update to all subscribers
   */
  private broadcastUpdate(snapshot: DashboardSnapshot): void {
    const data = `data: ${JSON.stringify(snapshot)}\n\n`;

    for (const [id, response] of this.subscribers) {
      try {
        response.write(data);
      } catch (error) {
        logger.warn({ subscriberId: id, error }, 'Failed to send update to subscriber');
        this.subscribers.delete(id);
      }
    }
  }

  /**
   * Send update to specific subscriber
   */
  private sendUpdateToSubscriber(subscriberId: string): void {
    const response = this.subscribers.get(subscriberId);
    if (!response || !this.dashboardCache) return;

    try {
      const data = `data: ${JSON.stringify(this.dashboardCache)}\n\n`;
      response.write(data);
    } catch (error) {
      logger.warn({ subscriberId, error }, 'Failed to send update to subscriber');
      this.subscribers.delete(subscriberId);
    }
  }

  /**
   * Calculate burn rate for SLO
   */
  private calculateBurnRate(metrics: RetryBudgetMetrics): SLOOverlayData['burnRate'] {
    const currentRate = metrics.current.retryRatePercent;
    const targetRate = this.config.slo.targets.errorRate;

    let burnRate = 0;
    let remaining = 100;
    let period: 'short' | 'medium' | 'long' = 'long';

    if (currentRate > targetRate) {
      burnRate = currentRate / targetRate;
      remaining = Math.max(0, 100 - (currentRate - targetRate) * 10);
      period = burnRate > 10 ? 'short' : burnRate > 2 ? 'medium' : 'long';
    }

    return { current: burnRate, remaining, period };
  }

  /**
   * Calculate error budget
   */
  private calculateErrorBudget(metrics: RetryBudgetMetrics, targets: any): SLOOverlayData['errorBudget'] {
    const totalBudget = 100 - targets.availability;
    const consumed = Math.max(0, 100 - metrics.slo.successRateVariance);
    const remaining = Math.max(0, totalBudget - consumed);
    const burnRate = remaining > 0 ? consumed / remaining : 999;

    return { total: totalBudget, consumed, remaining, burnRate };
  }

  /**
   * Calculate SLO predictions
   */
  private calculateSLOPredictions(metrics: RetryBudgetMetrics, sloTargets: any): SLOOverlayData['predictions'] {
    const willMeetSLO = sloTargets.availability.compliant &&
                       sloTargets.latency.compliant &&
                       sloTargets.errorRate.compliant;

    const projectedCompliance = willMeetSLO ? 95 : 85; // Simplified projection

    const riskFactors: string[] = [];
    if (!sloTargets.availability.compliant) riskFactors.push('Low availability');
    if (!sloTargets.latency.compliant) riskFactors.push('High latency');
    if (!sloTargets.errorRate.compliant) riskFactors.push('High error rate');
    if (metrics.current.budgetUtilizationPercent > 80) riskFactors.push('High retry budget usage');

    return {
      willMeetSLO,
      projectedCompliance,
      riskFactors,
    };
  }

  /**
   * Calculate SLO trend
   */
  private calculateSLOTrend(serviceName: string): 'improving' | 'degrading' | 'stable' {
    // This would analyze historical SLO compliance data
    // For now, return stable
    return 'stable';
  }

  /**
   * Update dependency impact
   */
  private updateDependencyImpact(dependency: ServiceDependency): void {
    // Calculate cascade risk and impact on other services
    for (const [serviceName, existingDep] of this.serviceDependencies) {
      if (existingDep.dependsOn.includes(dependency.serviceName)) {
        // Update cascade risk
        existingDep.healthImpact.cascadeRisk = Math.min(1,
          existingDep.healthImpact.cascadeRisk + 0.1);
      }
    }
  }

  /**
   * Get empty retry budget metrics
   */
  private getEmptyRetryBudgetMetrics(serviceName: string): RetryBudgetMetrics {
    return {
      serviceName,
      timestamp: new Date(),
      performance: { averageResponseTime: 0, p95ResponseTime: 0, p99ResponseTime: 0, throughput: 0, errorRate: 0 },
      current: {
        usedRetriesMinute: 0,
        usedRetriesHour: 0,
        retryRatePercent: 0,
        budgetRemainingMinute: 100,
        budgetRemainingHour: 100,
        budgetUtilizationPercent: 0,
      },
      history: {
        retriesPerMinute: [],
        retriesPerHour: [],
        retryRateHistory: [],
        successRateHistory: [],
        responseTimeHistory: [],
      },
      circuitBreaker: {
        state: 'closed',
        healthStatus: HealthStatus.HEALTHY,
        failureRate: 0,
        consecutiveFailures: 0,
        lastStateChange: new Date(),
      },
      slo: {
        successRateCompliance: true,
        responseTimeCompliance: true,
        overallCompliance: true,
        successRateVariance: 0,
        responseTimeVariance: 0,
      },
      alerts: [],
      predictions: {
        budgetExhaustionTime: null,
        recommendedAdjustments: [],
        riskLevel: 'low',
      },
    };
  }

  /**
   * Export to CSV format
   */
  private exportToCSV(snapshot: DashboardSnapshot): string {
    const headers = [
      'timestamp',
      'service_name',
      'health_status',
      'circuit_state',
      'retry_budget_utilization',
      'retry_rate',
      'slo_compliance',
      'availability',
      'latency_p95',
      'error_rate',
    ];

    const rows = [headers.join(',')];

    for (const service of snapshot.services) {
      rows.push([
        snapshot.timestamp.toISOString(),
        service.name,
        service.circuitBreaker.healthStatus,
        service.circuitBreaker.state,
        service.retryBudget.current.budgetUtilizationPercent.toFixed(2),
        service.retryBudget.current.retryRatePercent.toFixed(2),
        service.slo.compliance ? '1' : '0',
        service.slo.availability.toFixed(2),
        service.slo.latency.toFixed(0),
        service.slo.errorRate.toFixed(2),
      ].join(','));
    }

    return rows.join('\n');
  }

  /**
   * Set up event listeners
   */
  private setupEventListeners(): void {
    // Listen to circuit breaker events
    circuitBreakerMonitor.on('alert', (alert: any) => {
      this.createOrUpdateAlert({
        id: `cb_${Date.now()}_${Math.random()}`,
        serviceName: alert.serviceName,
        type: alert.type,
        severity: alert.severity,
        message: alert.message,
        timestamp: alert.timestamp,
        acknowledged: false,
      });
    });

    // Listen to retry budget events
    retryBudgetMonitor.on('alert', (alert: any) => {
      this.createOrUpdateAlert({
        id: `rb_${Date.now()}_${Math.random()}`,
        serviceName: alert.serviceName,
        type: alert.type,
        severity: alert.severity,
        message: alert.message,
        timestamp: alert.timestamp,
        acknowledged: false,
      });
    });
  }

  /**
   * Create or update alert
   */
  private createOrUpdateAlert(alert: DashboardSnapshot['alerts'][0]): void {
    this.activeAlerts.set(alert.id, alert);
    this.emit('alert_created', alert);
  }

  /**
   * Generate subscriber ID
   */
  private generateSubscriberId(): string {
    return `sub_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

// Export singleton instance
export const enhancedCircuitDashboard = new EnhancedCircuitDashboard();
