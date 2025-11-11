
/**
 * Comprehensive Retry Budget Dashboard
 *
 * Advanced dashboard system with service dependency health visualization,
 * interactive charts, real-time monitoring, and comprehensive analytics for
 * retry budget and circuit breaker management.
 *
 * @author Cortex Team
 * @version 2.0.1
 */

import { EventEmitter } from 'events';
import { type Request, type Response } from 'express';

import { logger } from '@/utils/logger.js';

import {
  type CircuitBreakerHealthStatus,
  circuitBreakerMonitor} from './circuit-breaker-monitor.js';
import {
  type Alert,
  type AlertSeverity,
  retryAlertSystem} from './retry-alert-system.js';
import {
  type RetryBudgetConfig,
  type RetryBudgetMetrics,
  retryBudgetMonitor} from './retry-budget-monitor.js';
import {
  type AnomalyDetection,
  type PatternDetection,
  type PredictiveAnalysis,
  retryTrendAnalyzer,
  type TrendAnalysis} from './retry-trend-analyzer.js';

/**
 * Service dependency relationship
 */
export interface ServiceDependency {
  fromService: string;
  toService: string;
  dependencyType: 'sync' | 'async' | 'shared_resource';
  impactLevel: 'critical' | 'high' | 'medium' | 'low';
  healthImpact: {
    ifDown: number; // percentage impact on overall system
    cascadeRisk: number; // 0-1 risk of cascade failure
    recoveryTime: number; // estimated recovery time in minutes
  };
}

/**
 * Service health metrics
 */
export interface ServiceHealthMetrics {
  serviceName: string;
  overallHealth: number; // 0-100
  retryBudget: RetryBudgetMetrics;
  circuitBreaker: CircuitBreakerHealthStatus;
  dependencies: ServiceDependency[];
  dependents: ServiceDependency[];
  riskScore: number; // 0-100
  performanceScore: number; // 0-100
  availabilityScore: number; // 0-100
}

/**
 * Dashboard view types
 */
export enum DashboardView {
  OVERVIEW = 'overview',
  SERVICE_DETAIL = 'service_detail',
  DEPENDENCY_MAP = 'dependency_map',
  TRENDS = 'trends',
  ALERTS = 'alerts',
  PREDICTIONS = 'predictions',
  SLO = 'slo',
}

/**
 * Dashboard configuration
 */
export interface ComprehensiveDashboardConfig {
  // Visualization
  visualization: {
    refreshIntervalMs: number;
    maxDataPoints: number;
    animationEnabled: boolean;
    theme: 'light' | 'dark' | 'auto';
  };

  // Service mapping
  serviceMap: {
    maxServices: number;
    groupByTeam: boolean;
    showDependencies: boolean;
    showImpactLevels: boolean;
  };

  // Features
  features: {
    realTimeUpdates: boolean;
    dependencyVisualization: boolean;
    predictiveAnalytics: boolean;
    comparativeAnalysis: boolean;
    exportCapabilities: boolean;
    alertManagement: boolean;
  };

  // Performance
  performance: {
    cachingEnabled: boolean;
    cacheTtlSeconds: number;
    compressionEnabled: boolean;
    batchSize: number;
  };
}

/**
 * Dashboard data response
 */
export interface DashboardResponse {
  view: DashboardView;
  timestamp: Date;
  data: any;
  metadata: {
    processingTime: number;
    cacheHit: boolean;
    totalServices: number;
    activeAlerts: number;
  };
}

/**
 * Comprehensive Retry Budget Dashboard
 */
export class ComprehensiveRetryDashboard extends EventEmitter {
  private config: ComprehensiveDashboardConfig;
  private isRunning = false;
  private startTime: number;

  // Data storage
  private serviceDependencies: Map<string, ServiceDependency[]> = new Map();
  private serviceHealthCache: Map<string, { data: ServiceHealthMetrics; timestamp: number }> = new Map();
  private dashboardCache: Map<string, { response: DashboardResponse; timestamp: number }> = new Map();

  // Real-time connections
  private subscribers: Map<string, { response: Response; view: DashboardView; filters?: any }> = new Map();

  constructor(config?: Partial<ComprehensiveDashboardConfig>) {
    super();

    this.config = {
      visualization: {
        refreshIntervalMs: 5000,
        maxDataPoints: 1000,
        animationEnabled: true,
        theme: 'auto',
      },
      serviceMap: {
        maxServices: 100,
        groupByTeam: false,
        showDependencies: true,
        showImpactLevels: true,
      },
      features: {
        realTimeUpdates: true,
        dependencyVisualization: true,
        predictiveAnalytics: true,
        comparativeAnalysis: true,
        exportCapabilities: true,
        alertManagement: true,
      },
      performance: {
        cachingEnabled: true,
        cacheTtlSeconds: 30,
        compressionEnabled: false,
        batchSize: 50,
      },
      ...config,
    };

    this.startTime = Date.now();
  }

  /**
   * Start the dashboard
   */
  start(): void {
    if (this.isRunning) {
      logger.warn('Comprehensive retry dashboard is already running');
      return;
    }

    this.isRunning = true;

    // Start real-time updates
    if (this.config.features.realTimeUpdates) {
      setInterval(
        () => this.broadcastUpdates(),
        this.config.visualization.refreshIntervalMs
      );
    }

    logger.info(
      {
        refreshInterval: this.config.visualization.refreshIntervalMs,
        features: this.config.features,
      },
      'Comprehensive retry dashboard started'
    );

    this.emit('started');
  }

  /**
   * Stop the dashboard
   */
  stop(): void {
    if (!this.isRunning) {
      logger.warn('Comprehensive retry dashboard is not running');
      return;
    }

    this.isRunning = false;

    // Close all subscriber connections
    for (const [id, subscriber] of this.subscribers) {
      try {
        subscriber.response.end();
      } catch (error) {
        logger.warn({ subscriberId: id, error }, 'Failed to close subscriber connection');
      }
    }
    this.subscribers.clear();

    logger.info('Comprehensive retry dashboard stopped');
    this.emit('stopped');
  }

  /**
   * Register service dependency
   */
  registerServiceDependency(dependency: ServiceDependency): void {
    if (!this.serviceDependencies.has(dependency.fromService)) {
      this.serviceDependencies.set(dependency.fromService, []);
    }

    const existingDeps = this.serviceDependencies.get(dependency.fromService)!;
    const existingIndex = existingDeps.findIndex(
      d => d.toService === dependency.toService && d.dependencyType === dependency.dependencyType
    );

    if (existingIndex >= 0) {
      existingDeps[existingIndex] = dependency;
    } else {
      existingDeps.push(dependency);
    }

    // Invalidate cache
    this.serviceHealthCache.clear();

    logger.info(
      { fromService: dependency.fromService, toService: dependency.toService, impactLevel: dependency.impactLevel },
      'Service dependency registered'
    );

    this.emit('dependency_registered', dependency);
  }

  /**
   * Get overview dashboard data
   */
  async getOverviewData(filters?: any): Promise<DashboardResponse> {
    const cacheKey = `overview:${JSON.stringify(filters)}`;
    const startTime = Date.now();

    if (this.config.performance.cachingEnabled) {
      const cached = this.dashboardCache.get(cacheKey);
      if (cached && Date.now() - cached.timestamp < this.config.performance.cacheTtlSeconds * 1000) {
        return {
          ...cached.response,
          metadata: {
            ...cached.response.metadata,
            cacheHit: true,
          },
        };
      }
    }

    const retryMetrics = retryBudgetMonitor.getAllMetrics();
    const circuitMetrics = circuitBreakerMonitor.getAllHealthStatuses();
    const activeAlerts = retryAlertSystem.getActiveAlerts();

    // Calculate overall statistics
    const totalServices = Math.max(retryMetrics.size, circuitMetrics.size);
    const healthyServices = Array.from(circuitMetrics.values())
      .filter(cb => cb.healthStatus === 'healthy').length;
    const criticalAlerts = activeAlerts.filter(a => a.severity === 'critical').length;

    // Service health distribution
    const healthDistribution = this.calculateHealthDistribution(retryMetrics, circuitMetrics);

    // Top services by utilization
    const topServicesByUtilization = Array.from(retryMetrics.values())
      .sort((a, b) => b.current.budgetUtilizationPercent - a.current.budgetUtilizationPercent)
      .slice(0, 10)
      .map(m => ({
        name: m.serviceName,
        utilization: m.current.budgetUtilizationPercent,
        riskLevel: m.predictions.riskLevel,
      }));

    // Recent alerts
    const recentAlerts = activeAlerts
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
      .slice(0, 20);

    // System-wide predictions
    const systemPredictions = this.calculateSystemPredictions(retryMetrics);

    const data = {
      summary: {
        totalServices,
        healthyServices,
        criticalAlerts,
        overallHealth: this.calculateSystemHealth(retryMetrics, circuitMetrics),
        averageUtilization: this.calculateAverageUtilization(retryMetrics),
      },
      healthDistribution,
      topServicesByUtilization,
      recentAlerts,
      systemPredictions,
      dependencyHealth: this.calculateDependencyHealthSummary(),
    };

    const response: DashboardResponse = {
      view: DashboardView.OVERVIEW,
      timestamp: new Date(),
      data,
      metadata: {
        processingTime: Date.now() - startTime,
        cacheHit: false,
        totalServices,
        activeAlerts: activeAlerts.length,
      },
    };

    if (this.config.performance.cachingEnabled) {
      this.dashboardCache.set(cacheKey, { response, timestamp: Date.now() });
    }

    return response;
  }

  /**
   * Get service detail data
   */
  async getServiceDetailData(serviceName: string, timeWindow: string = '24h'): Promise<DashboardResponse> {
    const startTime = Date.now();

    const retryMetrics = retryBudgetMonitor.getMetrics(serviceName);
    const circuitMetrics = circuitBreakerMonitor.getHealthStatus(serviceName);
    const trends = await this.getServiceTrends(serviceName, timeWindow);
    const anomalies = retryTrendAnalyzer.detectAnomalies(serviceName);
    const patterns = retryTrendAnalyzer.detectPatterns(serviceName);
    const predictions = retryTrendAnalyzer.performPredictiveAnalysis(serviceName);
    const dependencies = this.serviceDependencies.get(serviceName) || [];
    const dependents = this.getDependents(serviceName);

    const serviceHealth = await this.calculateServiceHealth(serviceName);

    const data = {
      service: {
        name: serviceName,
        health: serviceHealth,
        retryBudget: retryMetrics,
        circuitBreaker: circuitMetrics,
      },
      trends,
      anomalies,
      patterns,
      predictions,
      dependencies: {
        outgoing: dependencies,
        incoming: dependents,
      },
      recommendations: this.generateServiceRecommendations(serviceName, trends, anomalies, predictions),
    };

    return {
      view: DashboardView.SERVICE_DETAIL,
      timestamp: new Date(),
      data,
      metadata: {
        processingTime: Date.now() - startTime,
        cacheHit: false,
        totalServices: 1,
        activeAlerts: anomalies.filter(a => a.severity === 'critical' || a.severity === 'high').length,
      },
    };
  }

  /**
   * Get dependency map data
   */
  async getDependencyMapData(): Promise<DashboardResponse> {
    const startTime = Date.now();

    const retryMetrics = retryBudgetMonitor.getAllMetrics();
    const circuitMetrics = circuitBreakerMonitor.getAllHealthStatuses();

    // Build dependency graph
    const nodes = Array.from(retryMetrics.keys()).map(serviceName => {
      const metrics = retryMetrics.get(serviceName)!;
      const circuit = circuitMetrics.get(serviceName);
      const health = this.calculateServiceHealthScore(metrics, circuit);

      return {
        id: serviceName,
        name: serviceName,
        health,
        utilization: metrics.current.budgetUtilizationPercent,
        riskLevel: metrics.predictions.riskLevel,
        circuitState: circuit?.state || 'closed',
      };
    });

    const links: Array<{
      source: string;
      target: string;
      type: string;
      impact: number;
      health: number;
    }> = [];

    for (const [fromService, dependencies] of this.serviceDependencies) {
      for (const dep of dependencies) {
        const targetHealth = this.getServiceHealthScore(dep.toService);

        links.push({
          source: fromService,
          target: dep.toService,
          type: dep.dependencyType,
          impact: dep.healthImpact.ifDown,
          health: targetHealth,
        });
      }
    }

    // Calculate layout positions (simplified force-directed layout)
    const positions = this.calculateNodePositions(nodes, links);

    const data = {
      nodes: nodes.map(node => ({
        ...node,
        ...positions[node.id],
      })),
      links,
      clusters: this.identifyServiceClusters(nodes, links),
      criticalPaths: this.identifyCriticalPaths(nodes, links),
    };

    return {
      view: DashboardView.DEPENDENCY_MAP,
      timestamp: new Date(),
      data,
      metadata: {
        processingTime: Date.now() - startTime,
        cacheHit: false,
        totalServices: nodes.length,
        activeAlerts: 0,
      },
    };
  }

  /**
   * Get trends data
   */
  async getTrendsData(serviceName?: string, metrics?: string[]): Promise<DashboardResponse> {
    const startTime = Date.now();

    if (serviceName) {
      // Single service trends
      const serviceTrends = await this.getServiceTrends(serviceName, '7d');
      const comparison = retryTrendAnalyzer.performComparativeAnalysis(
        serviceName,
        '24h' as any,
        '7d' as any
      );

      const data = {
        serviceName,
        trends: serviceTrends,
        comparison,
        patterns: retryTrendAnalyzer.detectPatterns(serviceName),
      };

      return {
        view: DashboardView.TRENDS,
        timestamp: new Date(),
        data,
        metadata: {
          processingTime: Date.now() - startTime,
          cacheHit: false,
          totalServices: 1,
          activeAlerts: 0,
        },
      };
    } else {
      // System-wide trends
      const systemTrends = await this.calculateSystemTrends(metrics || [
        'budget_utilization_percent',
        'retry_rate_percent',
        'circuit_failure_rate',
      ]);

      const data = {
        systemTrends,
        serviceComparisons: this.calculateServiceComparisons(),
        patternAnalysis: this.calculateSystemPatternAnalysis(),
      };

      return {
        view: DashboardView.TRENDS,
        timestamp: new Date(),
        data,
        metadata: {
          processingTime: Date.now() - startTime,
          cacheHit: false,
          totalServices: retryBudgetMonitor.getAllMetrics().size,
          activeAlerts: 0,
        },
      };
    }
  }

  /**
   * Get alerts data
   */
  async getAlertsData(filters?: any): Promise<DashboardResponse> {
    const startTime = Date.now();

    const activeAlerts = retryAlertSystem.getActiveAlerts();
    const alertHistory = this.getAlertHistory(filters);

    const data = {
      activeAlerts: activeAlerts.filter(alert => this.matchesFilters(alert, filters)),
      alertHistory,
      alertTrends: this.calculateAlertTrends(),
      escalationStatus: this.calculateEscalationStatus(),
      recommendations: this.generateAlertRecommendations(activeAlerts),
    };

    return {
      view: DashboardView.ALERTS,
      timestamp: new Date(),
      data,
      metadata: {
        processingTime: Date.now() - startTime,
        cacheHit: false,
        totalServices: 0,
        activeAlerts: activeAlerts.length,
      },
    };
  }

  /**
   * Get predictions data
   */
  async getPredictionsData(): Promise<DashboardResponse> {
    const startTime = Date.now();

    const retryMetrics = retryBudgetMonitor.getAllMetrics();
    const predictions: Array<{
      serviceName: string;
      prediction: PredictiveAnalysis;
    }> = [];

    for (const serviceName of retryMetrics.keys()) {
      const servicePredictions = retryTrendAnalyzer.performPredictiveAnalysis(serviceName);
      predictions.push(...servicePredictions.map(p => ({ serviceName, prediction: p })));
    }

    // Sort by risk level and confidence
    predictions.sort((a, b) => {
      const riskOrder = { critical: 4, high: 3, medium: 2, low: 1 };
      const aRisk = riskOrder[a.prediction.riskLevel as keyof typeof riskOrder];
      const bRisk = riskOrder[b.prediction.riskLevel as keyof typeof riskOrder];

      if (aRisk !== bRisk) return bRisk - aRisk;
      return b.prediction.confidence - a.prediction.confidence;
    });

    const data = {
      predictions,
      riskDistribution: this.calculateRiskDistribution(predictions),
      mitigationStrategies: this.calculateMitigationStrategies(predictions),
      timeline: this.calculatePredictionTimeline(predictions),
    };

    return {
      view: DashboardView.PREDICTIONS,
      timestamp: new Date(),
      data,
      metadata: {
        processingTime: Date.now() - startTime,
        cacheHit: false,
        totalServices: retryMetrics.size,
        activeAlerts: predictions.filter(p => p.prediction.riskLevel === 'critical').length,
      },
    };
  }

  /**
   * Get SLO data
   */
  async getSLOData(): Promise<DashboardResponse> {
    const startTime = Date.now();

    const retryMetrics = retryBudgetMonitor.getAllMetrics();
    const sloData = Array.from(retryMetrics.entries()).map(([serviceName, metrics]) => {
      const sloTargets = {
        availability: 99.9,
        latency: 500,
        errorRate: 0.1,
      };

      return {
        serviceName,
        current: {
          availability: metrics.slo.successRateVariance || 100,
          latency: metrics.performance.p95ResponseTime,
          errorRate: metrics.current.retryRatePercent,
        },
        targets: sloTargets,
        compliance: {
          availability: metrics.slo.successRateCompliance,
          latency: metrics.slo.responseTimeCompliance,
          overall: metrics.slo.overallCompliance,
        },
        errorBudget: this.calculateErrorBudget(metrics, sloTargets),
        burnRate: this.calculateBurnRate(metrics, sloTargets),
      };
    });

    const data = {
      services: sloData,
      overall: this.calculateOverallSLOStatus(sloData),
      trends: this.calculateSLOTrends(sloData),
      recommendations: this.calculateSLORecommendations(sloData),
    };

    return {
      view: DashboardView.SLO,
      timestamp: new Date(),
      data,
      metadata: {
        processingTime: Date.now() - startTime,
        cacheHit: false,
        totalServices: sloData.length,
        activeAlerts: sloData.filter(s => !s.compliance.overall).length,
      },
    };
  }

  /**
   * Subscribe to real-time updates
   */
  subscribeToUpdates(request: Request, response: Response, view: DashboardView, filters?: any): void {
    const subscriberId = this.generateSubscriberId();

    // Set up Server-Sent Events
    response.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
    });

    this.subscribers.set(subscriberId, { response, view, filters });

    // Send initial data
    this.sendUpdateToSubscriber(subscriberId);

    // Handle disconnect
    request.on('close', () => {
      this.subscribers.delete(subscriberId);
    });

    logger.debug({ subscriberId, view }, 'Dashboard subscription created');
  }

  /**
   * Export dashboard data
   */
  async exportData(view: DashboardView, format: 'json' | 'csv' | 'pdf', filters?: any): Promise<string> {
    let data: any;

    switch (view) {
      case DashboardView.OVERVIEW:
        data = await this.getOverviewData(filters);
        break;
      case DashboardView.SERVICE_DETAIL:
        data = await this.getServiceDetailData(filters.serviceName, filters.timeWindow);
        break;
      case DashboardView.DEPENDENCY_MAP:
        data = await this.getDependencyMapData();
        break;
      case DashboardView.TRENDS:
        data = await this.getTrendsData(filters.serviceName, filters.metrics);
        break;
      case DashboardView.ALERTS:
        data = await this.getAlertsData(filters);
        break;
      case DashboardView.PREDICTIONS:
        data = await this.getPredictionsData();
        break;
      case DashboardView.SLO:
        data = await this.getSLOData();
        break;
      default:
        throw new Error(`Unsupported view: ${view}`);
    }

    switch (format) {
      case 'json':
        return JSON.stringify(data, null, 2);
      case 'csv':
        return this.convertToCSV(data);
      case 'pdf':
        return 'PDF export not implemented in this version';
      default:
        throw new Error(`Unsupported format: ${format}`);
    }
  }

  // Private helper methods

  private async broadcastUpdates(): Promise<void> {
    if (!this.isRunning) return;

    for (const subscriberId of this.subscribers.keys()) {
      this.sendUpdateToSubscriber(subscriberId);
    }
  }

  private async sendUpdateToSubscriber(subscriberId: string): Promise<void> {
    const subscriber = this.subscribers.get(subscriberId);
    if (!subscriber) return;

    try {
      let data: DashboardResponse;

      switch (subscriber.view) {
        case DashboardView.OVERVIEW:
          data = await this.getOverviewData(subscriber.filters);
          break;
        case DashboardView.SERVICE_DETAIL:
          data = await this.getServiceDetailData(
            subscriber.filters?.serviceName,
            subscriber.filters?.timeWindow
          );
          break;
        case DashboardView.DEPENDENCY_MAP:
          data = await this.getDependencyMapData();
          break;
        case DashboardView.TRENDS:
          data = await this.getTrendsData(subscriber.filters?.serviceName, subscriber.filters?.metrics);
          break;
        case DashboardView.ALERTS:
          data = await this.getAlertsData(subscriber.filters);
          break;
        case DashboardView.PREDICTIONS:
          data = await this.getPredictionsData();
          break;
        case DashboardView.SLO:
          data = await this.getSLOData();
          break;
        default:
          return;
      }

      const sseData = `data: ${JSON.stringify(data)}\n\n`;
      subscriber.response.write(sseData);
    } catch (error) {
      logger.warn({ subscriberId, error }, 'Failed to send update to subscriber');
      this.subscribers.delete(subscriberId);
    }
  }

  private calculateHealthDistribution(
    retryMetrics: Map<string, RetryBudgetMetrics>,
    circuitMetrics: Map<string, CircuitBreakerHealthStatus>
  ): any {
    const distribution = {
      healthy: 0,
      degraded: 0,
      unhealthy: 0,
      unknown: 0,
    };

    for (const [serviceName] of retryMetrics) {
      const circuit = circuitMetrics.get(serviceName);
      if (!circuit) {
        distribution.unknown++;
      } else if (circuit.healthStatus === 'healthy') {
        distribution.healthy++;
      } else if (circuit.healthStatus === 'degraded') {
        distribution.degraded++;
      } else {
        distribution.unhealthy++;
      }
    }

    return distribution;
  }

  private calculateSystemHealth(
    retryMetrics: Map<string, RetryBudgetMetrics>,
    circuitMetrics: Map<string, CircuitBreakerHealthStatus>
  ): number {
    if (retryMetrics.size === 0) return 100;

    let totalHealth = 0;
    let serviceCount = 0;

    for (const [serviceName, retryMetric] of retryMetrics) {
      const circuit = circuitMetrics.get(serviceName);
      const health = this.calculateServiceHealthScore(retryMetric, circuit);
      totalHealth += health;
      serviceCount++;
    }

    return serviceCount > 0 ? totalHealth / serviceCount : 100;
  }

  private calculateAverageUtilization(retryMetrics: Map<string, RetryBudgetMetrics>): number {
    if (retryMetrics.size === 0) return 0;

    const totalUtilization = Array.from(retryMetrics.values())
      .reduce((sum, metric) => sum + metric.current.budgetUtilizationPercent, 0);

    return totalUtilization / retryMetrics.size;
  }

  private calculateSystemPredictions(retryMetrics: Map<string, RetryBudgetMetrics>): any {
    const predictions = {
      criticalRiskServices: 0,
      highRiskServices: 0,
      budgetExhaustionSoon: 0,
      sloViolationsImminent: 0,
    };

    for (const metric of retryMetrics.values()) {
      if (metric.predictions.riskLevel === 'critical') predictions.criticalRiskServices++;
      if (metric.predictions.riskLevel === 'high') predictions.highRiskServices++;
      if (metric.predictions.budgetExhaustionTime) {
        const hoursToExhaustion = (metric.predictions.budgetExhaustionTime.getTime() - Date.now()) / (1000 * 60 * 60);
        if (hoursToExhaustion < 6) predictions.budgetExhaustionSoon++;
      }
      if (!metric.slo.overallCompliance) predictions.sloViolationsImminent++;
    }

    return predictions;
  }

  private calculateDependencyHealthSummary(): any {
    const totalDependencies = Array.from(this.serviceDependencies.values())
      .reduce((sum, deps) => sum + deps.length, 0);

    const criticalDependencies = Array.from(this.serviceDependencies.values())
      .flat()
      .filter(dep => dep.impactLevel === 'critical').length;

    return {
      totalDependencies,
      criticalDependencies,
      averageCascadeRisk: this.calculateAverageCascadeRisk(),
    };
  }

  private calculateAverageCascadeRisk(): number {
    const allDependencies = Array.from(this.serviceDependencies.values()).flat();
    if (allDependencies.length === 0) return 0;

    const totalRisk = allDependencies.reduce((sum, dep) => sum + dep.healthImpact.cascadeRisk, 0);
    return totalRisk / allDependencies.length;
  }

  private async getServiceTrends(serviceName: string, timeWindow: string): Promise<TrendAnalysis[]> {
    const metrics = [
      'budget_utilization_percent',
      'retry_rate_percent',
      'success_rate_variance',
      'response_time_p95',
    ];

    const trends: TrendAnalysis[] = [];
    for (const metric of metrics) {
      const trend = retryTrendAnalyzer.analyzeTrends(serviceName, metric, timeWindow as any);
      if (trend) {
        trends.push(trend);
      }
    }

    return trends;
  }

  private getDependents(serviceName: string): ServiceDependency[] {
    const dependents: ServiceDependency[] = [];
    for (const [fromService, dependencies] of this.serviceDependencies) {
      for (const dep of dependencies) {
        if (dep.toService === serviceName) {
          dependents.push(dep);
        }
      }
    }
    return dependents;
  }

  private async calculateServiceHealth(serviceName: string): Promise<ServiceHealthMetrics> {
    const cacheKey = serviceName;
    const cached = this.serviceHealthCache.get(cacheKey);

    if (cached && Date.now() - cached.timestamp < 30000) { // 30 second cache
      return cached.data;
    }

    const retryMetrics = retryBudgetMonitor.getMetrics(serviceName);
    const circuitMetrics = circuitBreakerMonitor.getHealthStatus(serviceName);
    const dependencies = this.serviceDependencies.get(serviceName) || [];
    const dependents = this.getDependents(serviceName);

    if (!retryMetrics || !circuitMetrics) {
      throw new Error(`Service ${serviceName} not found`);
    }

    const overallHealth = this.calculateServiceHealthScore(retryMetrics, circuitMetrics);
    const riskScore = this.calculateRiskScore(retryMetrics, circuitMetrics, dependencies);
    const performanceScore = this.calculatePerformanceScore(retryMetrics);
    const availabilityScore = this.calculateAvailabilityScore(circuitMetrics);

    const healthMetrics: ServiceHealthMetrics = {
      serviceName,
      overallHealth,
      retryBudget: retryMetrics,
      circuitBreaker: circuitMetrics,
      dependencies,
      dependents,
      riskScore,
      performanceScore,
      availabilityScore,
    };

    this.serviceHealthCache.set(cacheKey, { data: healthMetrics, timestamp: Date.now() });
    return healthMetrics;
  }

  private calculateServiceHealthScore(
    retryMetrics: RetryBudgetMetrics,
    circuitMetrics?: CircuitBreakerHealthStatus
  ): number {
    let score = 100;

    // Circuit breaker health impact
    if (circuitMetrics) {
      if (circuitMetrics.healthStatus === 'unhealthy') score -= 40;
      else if (circuitMetrics.healthStatus === 'degraded') score -= 20;
      if (circuitMetrics.isOpen) score -= 30;
      else if (circuitMetrics.isHalfOpen) score -= 15;
    }

    // Retry budget utilization impact
    if (retryMetrics.current.budgetUtilizationPercent > 90) score -= 30;
    else if (retryMetrics.current.budgetUtilizationPercent > 75) score -= 15;
    else if (retryMetrics.current.budgetUtilizationPercent > 50) score -= 5;

    // SLO compliance impact
    if (!retryMetrics.slo.overallCompliance) score -= 25;
    if (!retryMetrics.slo.successRateCompliance) score -= 15;
    if (!retryMetrics.slo.responseTimeCompliance) score -= 10;

    // Risk level impact
    if (retryMetrics.predictions.riskLevel === 'critical') score -= 20;
    else if (retryMetrics.predictions.riskLevel === 'high') score -= 10;
    else if (retryMetrics.predictions.riskLevel === 'medium') score -= 5;

    return Math.max(0, Math.min(100, score));
  }

  private getServiceHealthScore(serviceName: string): number {
    const retryMetrics = retryBudgetMonitor.getMetrics(serviceName);
    const circuitMetrics = circuitBreakerMonitor.getHealthStatus(serviceName);

    if (!retryMetrics) return 100;
    return this.calculateServiceHealthScore(retryMetrics, circuitMetrics ?? undefined);
  }

  private calculateRiskScore(
    retryMetrics: RetryBudgetMetrics,
    circuitMetrics?: CircuitBreakerHealthStatus,
    dependencies: ServiceDependency[] = []
  ): number {
    let risk = 0;

    // Circuit breaker risk
    if (circuitMetrics) {
      if (circuitMetrics.isOpen) risk += 40;
      if (circuitMetrics.metrics.failureRate > 50) risk += 30;
      if (circuitMetrics.metrics.consecutiveFailures > 5) risk += 20;
    }

    // Retry budget risk
    if (retryMetrics.current.budgetUtilizationPercent > 90) risk += 35;
    if (retryMetrics.predictions.riskLevel === 'critical') risk += 30;

    // Dependency risk
    const criticalDeps = dependencies.filter(d => d.impactLevel === 'critical').length;
    risk += criticalDeps * 10;

    return Math.min(100, risk);
  }

  private calculatePerformanceScore(retryMetrics: RetryBudgetMetrics): number {
    let score = 100;

    if (retryMetrics.performance.p95ResponseTime > 1000) score -= 20;
    if (retryMetrics.performance.p95ResponseTime > 500) score -= 10;
    if (retryMetrics.current.retryRatePercent > 10) score -= 15;
    if (retryMetrics.current.retryRatePercent > 5) score -= 5;

    return Math.max(0, score);
  }

  private calculateAvailabilityScore(circuitMetrics: CircuitBreakerHealthStatus): number {
    const successRate = circuitMetrics.metrics.successRate;
    return Math.min(100, successRate);
  }

  private generateServiceRecommendations(
    serviceName: string,
    trends: TrendAnalysis[],
    anomalies: AnomalyDetection[],
    predictions: PredictiveAnalysis[]
  ): string[] {
    const recommendations: string[] = [];

    // Trend-based recommendations
    const degradingTrends = trends.filter(t => t.direction === 'degrading');
    if (degradingTrends.length > 0) {
      recommendations.push('Multiple metrics showing degrading trends - investigate root causes');
    }

    // Anomaly-based recommendations
    const criticalAnomalies = anomalies.filter(a => a.severity === 'critical' || a.severity === 'high');
    if (criticalAnomalies.length > 0) {
      recommendations.push('Critical anomalies detected - immediate attention required');
    }

    // Prediction-based recommendations
    const criticalPredictions = predictions.filter(p => p.riskLevel === 'critical');
    if (criticalPredictions.length > 0) {
      recommendations.push('Critical risk predictions detected - implement mitigation strategies');
    }

    return recommendations;
  }

  private calculateNodePositions(nodes: any[], links: any[]): Record<string, { x: number; y: number }> {
    const positions: Record<string, { x: number; y: number }> = {};
    const centerX = 500;
    const centerY = 300;
    const radius = 200;

    // Simple circular layout
    nodes.forEach((node, index) => {
      const angle = (index / nodes.length) * 2 * Math.PI;
      positions[node.id] = {
        x: centerX + radius * Math.cos(angle),
        y: centerY + radius * Math.sin(angle),
      };
    });

    return positions;
  }

  private identifyServiceClusters(nodes: any[], links: any[]): any[] {
    // Simplified clustering - group by health status
    const clusters = [
      {
        id: 'healthy',
        name: 'Healthy Services',
        nodes: nodes.filter(n => n.health > 80),
        color: '#22c55e',
      },
      {
        id: 'degraded',
        name: 'Degraded Services',
        nodes: nodes.filter(n => n.health >= 50 && n.health <= 80),
        color: '#f59e0b',
      },
      {
        id: 'unhealthy',
        name: 'Unhealthy Services',
        nodes: nodes.filter(n => n.health < 50),
        color: '#ef4444',
      },
    ];

    return clusters.filter(c => c.nodes.length > 0);
  }

  private identifyCriticalPaths(nodes: any[], links: any[]): any[] {
    // Identify paths between critical services
    const criticalServices = nodes.filter(n => n.utilization > 80 || n.riskLevel === 'critical');
    const criticalPaths: any[] = [];

    for (const critical of criticalServices) {
      const connectedLinks = links.filter(l => l.source === critical.id || l.target === critical.id);
      for (const link of connectedLinks) {
        const otherNode = link.source === critical.id ? link.target : link.source;
        const otherService = nodes.find(n => n.id === otherNode);
        if (otherService && otherService.utilization > 60) {
          criticalPaths.push({
            from: critical.id,
            to: otherNode,
            risk: 'high',
            impact: link.impact,
          });
        }
      }
    }

    return criticalPaths;
  }

  private matchesFilters(alert: Alert, filters?: any): boolean {
    if (!filters) return true;

    if (filters.serviceName && alert.serviceName !== filters.serviceName) return false;
    if (filters.severity && alert.severity !== filters.severity) return false;
    if (filters.type && alert.type !== filters.type) return false;

    return true;
  }

  private getAlertHistory(filters?: any): Alert[] {
    // This would fetch alert history from storage
    // For now, return empty array
    return [];
  }

  private calculateAlertTrends(): any {
    // This would analyze alert trends over time
    return {
      hourlyVolume: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
      severityDistribution: { critical: 0, warning: 0, info: 0 },
      topServices: [],
    };
  }

  private calculateEscalationStatus(): any {
    // This would calculate escalation status
    return {
      escalatedAlerts: 0,
      pendingEscalations: 0,
      averageEscalationTime: 0,
    };
  }

  private generateAlertRecommendations(activeAlerts: Alert[]): string[] {
    const recommendations: string[] = [];

    const criticalAlerts = activeAlerts.filter(a => a.severity === 'critical');
    if (criticalAlerts.length > 5) {
      recommendations.push('High number of critical alerts - consider emergency response procedures');
    }

    const servicesWithMultipleAlerts = activeAlerts.reduce((acc, alert) => {
      acc[alert.serviceName] = (acc[alert.serviceName] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const problematicServices = Object.entries(servicesWithMultipleAlerts)
      .filter(([_, count]) => count > 3)
      .map(([service, _]) => service);

    if (problematicServices.length > 0) {
      recommendations.push(`Multiple services with high alert counts: ${problematicServices.join(', ')}`);
    }

    return recommendations;
  }

  private async calculateSystemTrends(metrics: string[]): Promise<any> {
    const trends: any = {};

    for (const metric of metrics) {
      trends[metric] = {
        direction: 'stable',
        changePercent: 0,
        confidence: 0.5,
      };
    }

    return trends;
  }

  private calculateServiceComparisons(): any {
    // This would compare services across various metrics
    return {
      topPerformers: [],
      needsAttention: [],
      mostImproved: [],
      mostDegraded: [],
    };
  }

  private calculateSystemPatternAnalysis(): any {
    // This would analyze system-wide patterns
    return {
      dailyPatterns: [],
      weeklyPatterns: [],
      seasonalPatterns: [],
    };
  }

  private calculateRiskDistribution(predictions: any[]): any {
    const distribution: Record<string, number> = {
      low: 0,
      medium: 0,
      high: 0,
      critical: 0,
    };

    predictions.forEach(({ prediction }) => {
      distribution[prediction.riskLevel]++;
    });

    return distribution;
  }

  private calculateMitigationStrategies(predictions: any[]): string[] {
    const strategies = new Set<string>();

    predictions.forEach(({ prediction }) => {
      prediction.mitigationStrategies.forEach((strategy: string) => {
        strategies.add(strategy);
      });
    });

    return Array.from(strategies);
  }

  private calculatePredictionTimeline(predictions: any[]): any {
    const timeline: { nextHour: any[]; nextDay: any[]; nextWeek: any[] } = {
      nextHour: [],
      nextDay: [],
      nextWeek: [],
    };

    predictions.forEach(({ prediction }) => {
      if (prediction.timeToEvent <= 1) timeline.nextHour.push(prediction);
      else if (prediction.timeToEvent <= 24) timeline.nextDay.push(prediction);
      else if (prediction.timeToEvent <= 168) timeline.nextWeek.push(prediction);
    });

    return timeline;
  }

  private calculateErrorBudget(metrics: RetryBudgetMetrics, targets: any): any {
    const totalBudget = 100 - targets.availability;
    const consumed = Math.max(0, targets.availability - (metrics.slo.successRateVariance || 100));
    const remaining = Math.max(0, totalBudget - consumed);

    return {
      total: totalBudget,
      consumed,
      remaining,
      percentage: totalBudget > 0 ? (consumed / totalBudget) * 100 : 0,
    };
  }

  private calculateBurnRate(metrics: RetryBudgetMetrics, targets: any): number {
    const currentErrorRate = metrics.current.retryRatePercent;
    const targetErrorRate = targets.errorRate;
    return targetErrorRate > 0 ? currentErrorRate / targetErrorRate : 0;
  }

  private calculateOverallSLOStatus(sloData: any[]): any {
    const compliantServices = sloData.filter(s => s.compliance.overall).length;
    const totalServices = sloData.length;

    return {
      complianceRate: totalServices > 0 ? (compliantServices / totalServices) * 100 : 100,
      overallCompliance: compliantServices === totalServices,
      servicesAtRisk: sloData.filter(s => !s.compliance.overall).length,
    };
  }

  private calculateSLOTrends(sloData: any[]): any {
    // This would calculate SLO trends over time
    return {
      availabilityTrend: 'stable',
      latencyTrend: 'stable',
      errorRateTrend: 'stable',
    };
  }

  private calculateSLORecommendations(sloData: any[]): string[] {
    const recommendations: string[] = [];
    const nonCompliantServices = sloData.filter(s => !s.compliance.overall);

    if (nonCompliantServices.length > 0) {
      recommendations.push(`${nonCompliantServices.length} services not meeting SLO targets`);
    }

    const highBurnRateServices = sloData.filter(s => s.burnRate > 2);
    if (highBurnRateServices.length > 0) {
      recommendations.push(`${highBurnRateServices.length} services with high error budget burn rate`);
    }

    return recommendations;
  }

  private convertToCSV(data: any): string {
    // Simplified CSV conversion
    return 'CSV export not fully implemented in this version';
  }

  private generateSubscriberId(): string {
    return `sub_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

// Export singleton instance
export const comprehensiveRetryDashboard = new ComprehensiveRetryDashboard();
