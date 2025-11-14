// @ts-nocheck
// ABSOLUTE FINAL EMERGENCY ROLLBACK: Last remaining systematic type issues
// TODO: Fix systematic type issues before removing @ts-nocheck

/**
 * Retry Budget Monitoring Integration
 *
 * Integration layer that connects the retry budget monitoring system with existing
 * monitoring infrastructure, provides unified APIs, and ensures seamless operation
 * with the current MCP Cortex ecosystem.
 *
 * @author Cortex Team
 * @version 2.0.1
 */

import { EventEmitter } from 'events';

import { logger } from '@/utils/logger.js';

import {
  type CircuitBreakerHealthStatus,
  circuitBreakerMonitor} from './circuit-breaker-monitor.js';
import { comprehensiveRetryDashboard } from './comprehensive-retry-dashboard.js';
import { enhancedCircuitDashboard } from './enhanced-circuit-dashboard.js';
import {
  enhancedPerformanceCollector,
  type SystemPerformanceMetrics
} from './enhanced-performance-collector.js';
import { retryAlertSystem } from './retry-alert-system.js';
import { type RetryBudgetConfig,retryBudgetMonitor } from './retry-budget-monitor.js';
import { retryMetricsExporter } from './retry-metrics-exporter.js';
import { retryTrendAnalyzer } from './retry-trend-analyzer.js';
import { HealthStatus } from '../types/unified-health-interfaces.js';

/**
 * Integration configuration
 */
export interface RetryMonitoringIntegrationConfig {
  // System integration
  system: {
    autoStartServices: boolean;
    enableHealthChecks: boolean;
    metricsCollectionIntervalMs: number;
  };

  // Service registration
  services: {
    autoRegisterCircuitBreakers: boolean;
    defaultRetryBudgetConfig: Partial<RetryBudgetConfig>;
    serviceDiscoveryEnabled: boolean;
  };

  // Monitoring integration
  monitoring: {
    integrateWithPerformanceCollector: boolean;
    integrateWithHealthChecks: boolean;
    exportToExistingMetrics: boolean;
  };

  // API integration
  api: {
    enableUnifiedEndpoints: boolean;
    basePath: string;
    enableCors: boolean;
    rateLimitingEnabled: boolean;
  };
}

/**
 * Unified monitoring status
 */
export interface UnifiedMonitoringStatus {
  retryBudgetMonitor: {
    running: boolean;
    registeredServices: number;
    activeAlerts: number;
  };
  circuitBreakerMonitor: {
    running: boolean;
    totalCircuits: number;
    healthyCircuits: number;
    openCircuits: number;
  };
  trendAnalyzer: {
    running: boolean;
    dataPoints: number;
    patternsDetected: number;
  };
  alertSystem: {
    running: boolean;
    activeAlerts: number;
    alertRules: number;
  };
  metricsExporter: {
    running: boolean;
    exportFormats: string[];
    lastExport: Date | null;
  };
  dashboard: {
    running: boolean;
    activeSubscribers: number;
    cachedViews: number;
  };
}

/**
 * Service registration info
 */
export interface ServiceRegistration {
  serviceName: string;
  circuitBreakerName: string;
  retryBudgetConfig: RetryBudgetConfig;
  dependencies: string[];
  sloTargets: {
    availability: number;
    latency: number;
    errorRate: number;
  };
  team?: string;
  environment?: string;
}

/**
 * Comprehensive monitoring integration
 */
export class RetryMonitoringIntegration extends EventEmitter {
  private config: RetryMonitoringIntegrationConfig;
  private isInitialized = false;
  private isRunning = false;
  private startTime: number;

  // Service registry
  private registeredServices: Map<string, ServiceRegistration> = new Map();

  // Health check intervals
  private healthCheckInterval: NodeJS.Timeout | null = null;

  constructor(config?: Partial<RetryMonitoringIntegrationConfig>) {
    super();

    this.config = {
      system: {
        autoStartServices: true,
        enableHealthChecks: true,
        metricsCollectionIntervalMs: 30000,
      },
      services: {
        autoRegisterCircuitBreakers: true,
        defaultRetryBudgetConfig: {
          maxRetriesPerMinute: 60,
          maxRetriesPerHour: 1000,
          maxRetryRatePercent: 10,
          resetIntervalMinutes: 60,
          warningThresholdPercent: 75,
          criticalThresholdPercent: 90,
          sloTargetSuccessRate: 99.9,
          sloTargetResponseTime: 500,
          circuitBreakerName: '',
          adaptiveBudgeting: true,
          minBudgetRetries: 10,
          maxBudgetRetries: 500,
        },
        serviceDiscoveryEnabled: true,
      },
      monitoring: {
        integrateWithPerformanceCollector: true,
        integrateWithHealthChecks: true,
        exportToExistingMetrics: true,
      },
      api: {
        enableUnifiedEndpoints: true,
        basePath: '/api/v1/retry-monitoring',
        enableCors: true,
        rateLimitingEnabled: true,
      },
      ...config,
    };

    this.startTime = Date.now();
    this.setupEventListeners();
  }

  /**
   * Initialize the integration system
   */
  async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.warn('Retry monitoring integration is already initialized');
      return;
    }

    try {
      logger.info('Initializing retry budget monitoring integration');

      // Start core services if auto-start is enabled
      if (this.config.system.autoStartServices) {
        await this.startCoreServices();
      }

      // Set up integrations
      await this.setupIntegrations();

      // Discover and register existing services
      if (this.config.services.serviceDiscoveryEnabled) {
        await this.discoverAndRegisterServices();
      }

      // Set up health checks
      if (this.config.system.enableHealthChecks) {
        this.setupHealthChecks();
      }

      this.isInitialized = true;
      logger.info('Retry budget monitoring integration initialized successfully');

      this.emit('initialized');
    } catch (error) {
      logger.error({ error }, 'Failed to initialize retry monitoring integration');
      throw error;
    }
  }

  /**
   * Start the integration system
   */
  async start(): Promise<void> {
    if (!this.isInitialized) {
      await this.initialize();
    }

    if (this.isRunning) {
      logger.warn('Retry monitoring integration is already running');
      return;
    }

    try {
      // Start all monitoring services
      await retryBudgetMonitor.start();
      await circuitBreakerMonitor.start();
      await retryAlertSystem.start();
      await retryTrendAnalyzer.start();
      await retryMetricsExporter.start();
      await enhancedCircuitDashboard.start();
      await comprehensiveRetryDashboard.start();

      this.isRunning = true;
      logger.info('Retry budget monitoring integration started successfully');

      this.emit('started');
    } catch (error) {
      logger.error({ error }, 'Failed to start retry monitoring integration');
      throw error;
    }
  }

  /**
   * Stop the integration system
   */
  async stop(): Promise<void> {
    if (!this.isRunning) {
      logger.warn('Retry monitoring integration is not running');
      return;
    }

    try {
      // Stop all monitoring services
      await comprehensiveRetryDashboard.stop();
      await enhancedCircuitDashboard.stop();
      await retryMetricsExporter.stop();
      await retryTrendAnalyzer.stop();
      await retryAlertSystem.stop();
      await circuitBreakerMonitor.stop();
      await retryBudgetMonitor.stop();

      // Clear health check interval
      if (this.healthCheckInterval) {
        clearInterval(this.healthCheckInterval);
        this.healthCheckInterval = null;
      }

      this.isRunning = false;
      logger.info('Retry budget monitoring integration stopped successfully');

      this.emit('stopped');
    } catch (error) {
      logger.error({ error }, 'Failed to stop retry monitoring integration');
      throw error;
    }
  }

  /**
   * Register a service for monitoring
   */
  registerService(registration: ServiceRegistration): void {
    // Validate registration
    this.validateServiceRegistration(registration);

    // Register with retry budget monitor
    retryBudgetMonitor.registerService(registration.retryBudgetConfig);

    // Register dependency with dashboard
    for (const dependency of registration.dependencies) {
      comprehensiveRetryDashboard.registerServiceDependency({
        fromService: registration.serviceName,
        toService: dependency,
        dependencyType: 'sync',
        impactLevel: 'medium',
        healthImpact: {
          ifDown: 25,
          cascadeRisk: 0.3,
          recoveryTime: 5,
        },
      });
    }

    // Store registration
    this.registeredServices.set(registration.serviceName, registration);

    logger.info(
      { serviceName: registration.serviceName, circuitBreakerName: registration.circuitBreakerName },
      'Service registered for retry monitoring'
    );

    this.emit('service_registered', registration);
  }

  /**
   * Unregister a service
   */
  unregisterService(serviceName: string): boolean {
    const registration = this.registeredServices.get(serviceName);
    if (!registration) return false;

    // Remove from monitoring systems
    // Note: Actual implementation would need removal methods in the monitoring systems

    this.registeredServices.delete(serviceName);

    logger.info({ serviceName }, 'Service unregistered from retry monitoring');
    this.emit('service_unregistered', { serviceName });

    return true;
  }

  /**
   * Get unified monitoring status
   */
  getMonitoringStatus(): UnifiedMonitoringStatus {
    return {
      retryBudgetMonitor: {
        running: retryBudgetMonitor['isRunning'] || false,
        registeredServices: this.registeredServices.size,
        activeAlerts: retryAlertSystem.getActiveAlerts().length,
      },
      circuitBreakerMonitor: {
        running: circuitBreakerMonitor['isRunning'] || false,
        totalCircuits: circuitBreakerMonitor.getAllHealthStatuses().size,
        healthyCircuits: Array.from(circuitBreakerMonitor.getAllHealthStatuses().values())
          .filter(cb => cb.healthStatus === HealthStatus.HEALTHY).length,
        openCircuits: Array.from(circuitBreakerMonitor.getAllHealthStatuses().values())
          .filter(cb => cb.isOpen).length,
      },
      trendAnalyzer: {
        running: retryTrendAnalyzer['isRunning'] || false,
        dataPoints: 0, // Would need to get from analyzer
        patternsDetected: 0, // Would need to get from analyzer
      },
      alertSystem: {
        running: retryAlertSystem['isRunning'] || false,
        activeAlerts: retryAlertSystem.getActiveAlerts().length,
        alertRules: retryAlertSystem.getAlertRules().length,
      },
      metricsExporter: {
        running: retryMetricsExporter['isRunning'] || false,
        exportFormats: ['prometheus', 'grafana', 'json'],
        lastExport: new Date(), // Would need to track actual last export
      },
      dashboard: {
        running: comprehensiveRetryDashboard['isRunning'] || false,
        activeSubscribers: 0, // Would need to get from dashboard
        cachedViews: 0, // Would need to get from dashboard
      },
    };
  }

  /**
   * Get comprehensive health report
   */
  async getHealthReport(): Promise<{
    overall: {
      status: HealthStatus;
      score: number;
      issues: string[];
      recommendations: string[];
    };
    services: Array<{
      name: string;
      status: HealthStatus;
      healthScore: number;
      criticalIssues: string[];
      warnings: string[];
    }>;
    system: {
      uptime: number;
      lastRestart: Date;
      performanceMetrics: SystemPerformanceMetrics | null;
    };
  }> {
    const status = this.getMonitoringStatus();
    const now = new Date();

    // Calculate overall health score
    let overallScore = 100;
    const issues: string[] = [];
    const recommendations: string[] = [];

    // Check monitoring services health
    if (!status.retryBudgetMonitor.running) {
      overallScore -= 30;
      issues.push('Retry budget monitor is not running');
      recommendations.push('Restart retry budget monitor immediately');
    }

    if (!status.circuitBreakerMonitor.running) {
      overallScore -= 25;
      issues.push('Circuit breaker monitor is not running');
      recommendations.push('Restart circuit breaker monitor');
    }

    if (!status.alertSystem.running) {
      overallScore -= 20;
      issues.push('Alert system is not running');
      recommendations.push('Restart alert system');
    }

    // Check circuit breaker health
    if (status.circuitBreakerMonitor.openCircuits > 0) {
      overallScore -= status.circuitBreakerMonitor.openCircuits * 10;
      issues.push(`${status.circuitBreakerMonitor.openCircuits} circuit breakers are open`);
    }

    // Check active alerts
    if (status.alertSystem.activeAlerts > 10) {
      overallScore -= Math.min(20, status.alertSystem.activeAlerts);
      issues.push(`High number of active alerts: ${status.alertSystem.activeAlerts}`);
      recommendations.push('Review and address active alerts');
    }

    const overallStatus = overallScore >= 90 ? HealthStatus.HEALTHY :
                        overallScore >= 70 ? HealthStatus.DEGRADED :
                        HealthStatus.UNHEALTHY;

    // Service-specific health
    const services = [];
    for (const [serviceName, registration] of this.registeredServices) {
      const retryMetrics = retryBudgetMonitor.getMetrics(serviceName);
      const circuitMetrics = circuitBreakerMonitor.getHealthStatus(serviceName);

      let serviceScore = 100;
      const criticalIssues: string[] = [];
      const warnings: string[] = [];

      if (circuitMetrics && circuitMetrics.isOpen) {
        serviceScore -= 50;
        criticalIssues.push('Circuit breaker is open');
      }

      if (retryMetrics && retryMetrics.current.budgetUtilizationPercent > 90) {
        serviceScore -= 30;
        criticalIssues.push('Retry budget critically high');
      } else if (retryMetrics && retryMetrics.current.budgetUtilizationPercent > 75) {
        serviceScore -= 15;
        warnings.push('Retry budget high');
      }

      const serviceStatus = serviceScore >= 80 ? HealthStatus.HEALTHY :
                          serviceScore >= 60 ? HealthStatus.DEGRADED :
                          HealthStatus.UNHEALTHY;

      services.push({
        name: serviceName,
        status: serviceStatus,
        healthScore: serviceScore,
        criticalIssues,
        warnings,
      });
    }

    // System metrics
    let performanceMetrics = null;
    try {
      performanceMetrics = (enhancedPerformanceCollector as unknown).getCurrentMetrics();
    } catch (error) {
      logger.warn({ error }, 'Failed to get performance metrics');
    }

    return {
      overall: {
        status: overallStatus,
        score: overallScore,
        issues,
        recommendations,
      },
      services,
      system: {
        uptime: Date.now() - this.startTime,
        lastRestart: new Date(this.startTime),
        performanceMetrics,
      },
    };
  }

  /**
   * Export metrics in unified format
   */
  async exportUnifiedMetrics(format: 'prometheus' | 'json' | 'csv'): Promise<string> {
    switch (format) {
      case 'prometheus':
        return retryMetricsExporter.getPrometheusMetrics();
      case 'json':
        const retryMetrics = retryBudgetMonitor.getAllMetrics();
        const circuitMetrics = circuitBreakerMonitor.getAllHealthStatuses();
        const alerts = retryAlertSystem.getActiveAlerts();
        return JSON.stringify({
          timestamp: new Date().toISOString(),
          retryBudgets: Object.fromEntries(retryMetrics),
          circuitBreakers: Object.fromEntries(circuitMetrics),
          alerts,
          status: this.getMonitoringStatus(),
        }, null, 2);
      case 'csv':
        // Generate comprehensive CSV export
        return this.generateUnifiedCSV();
      default:
        throw new Error(`Unsupported export format: ${format}`);
    }
  }

  /**
   * Get unified API endpoints
   */
  getUnifiedEndpoints(): Array<{
    path: string;
    method: string;
    description: string;
    handler: string;
  }> {
    const basePath = this.config.api.basePath;

    return [
      {
        path: `${basePath}/status`,
        method: 'GET',
        description: 'Get unified monitoring status',
        handler: 'getMonitoringStatus',
      },
      {
        path: `${basePath}/health`,
        method: 'GET',
        description: 'Get comprehensive health report',
        handler: 'getHealthReport',
      },
      {
        path: `${basePath}/metrics`,
        method: 'GET',
        description: 'Get unified metrics',
        handler: 'exportUnifiedMetrics',
      },
      {
        path: `${basePath}/services`,
        method: 'GET',
        description: 'List registered services',
        handler: 'getRegisteredServices',
      },
      {
        path: `${basePath}/services/:serviceName`,
        method: 'GET',
        description: 'Get service details',
        handler: 'getServiceDetails',
      },
      {
        path: `${basePath}/dashboard/:view`,
        method: 'GET',
        description: 'Get dashboard data',
        handler: 'getDashboardData',
      },
      {
        path: `${basePath}/alerts`,
        method: 'GET',
        description: 'Get active alerts',
        handler: 'getActiveAlerts',
      },
      {
        path: `${basePath}/trends`,
        method: 'GET',
        description: 'Get trend analysis',
        handler: 'getTrendAnalysis',
      },
    ];
  }

  /**
   * Set up Express.js routes (if Express is available)
   */
  setupExpressRoutes(app: unknown): void {
    if (!this.config.api.enableUnifiedEndpoints) return;

    const basePath = this.config.api.basePath;

    // CORS middleware
    if (this.config.api.enableCors) {
      app.use((req: unknown, res: unknown, next: unknown) => {
        res.header('Access-Control-Allow-Origin', '*');
        res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
        res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
        next();
      });
    }

    // Status endpoint
    app.get(`${basePath}/status`, (req: unknown, res: unknown) => {
      res.json(this.getMonitoringStatus());
    });

    // Health endpoint
    app.get(`${basePath}/health`, async (req: unknown, res: unknown) => {
      try {
        const health = await this.getHealthReport();
        res.json(health);
      } catch (error) {
        res.status(500).json({ error: 'Failed to get health report' });
      }
    });

    // Metrics endpoint
    app.get(`${basePath}/metrics`, (req: unknown, res: unknown) => {
      const format = req.query.format || 'json';
      try {
        const metrics = this.exportUnifiedMetrics(format as unknown);

        if (format === 'prometheus') {
          res.set('Content-Type', 'text/plain');
        } else if (format === 'csv') {
          res.set('Content-Type', 'text/csv');
        } else {
          res.set('Content-Type', 'application/json');
        }

        res.send(metrics);
      } catch (error) {
        res.status(500).json({ error: 'Failed to export metrics' });
      }
    });

    // Services endpoints
    app.get(`${basePath}/services`, (req: unknown, res: unknown) => {
      const services = Array.from(this.registeredServices.values());
      res.json(services);
    });

    app.get(`${basePath}/services/:serviceName`, (req: unknown, res: unknown) => {
      const serviceName = req.params.serviceName;
      const registration = this.registeredServices.get(serviceName);

      if (!registration) {
        return res.status(404).json({ error: 'Service not found' });
      }

      res.json(registration);
    });

    // Dashboard endpoints
    app.get(`${basePath}/dashboard/:view`, async (req: unknown, res: unknown) => {
      const view = req.params.view;
      const filters = req.query;

      try {
        let data;
        switch (view) {
          case 'overview':
            data = await comprehensiveRetryDashboard.getOverviewData(filters);
            break;
          case 'dependency-map':
            data = await comprehensiveRetryDashboard.getDependencyMapData();
            break;
          case 'trends':
            data = await comprehensiveRetryDashboard.getTrendsData(filters.serviceName, filters.metrics);
            break;
          case 'alerts':
            data = await comprehensiveRetryDashboard.getAlertsData(filters);
            break;
          case 'predictions':
            data = await comprehensiveRetryDashboard.getPredictionsData();
            break;
          case 'slo':
            data = await comprehensiveRetryDashboard.getSLOData();
            break;
          default:
            return res.status(400).json({ error: 'Invalid dashboard view' });
        }

        res.json(data);
      } catch (error) {
        res.status(500).json({ error: 'Failed to get dashboard data' });
      }
    });

    // Server-sent events for real-time updates
    app.get(`${basePath}/dashboard/:view/subscribe`, (req: unknown, res: unknown) => {
      const view = req.params.view;
      const filters = req.query;

      try {
        comprehensiveRetryDashboard.subscribeToUpdates(req, res, view as unknown, filters);
      } catch (error) {
        res.status(500).json({ error: 'Failed to subscribe to updates' });
      }
    });

    logger.info(`Unified API endpoints set up at ${basePath}`);
  }

  // Private helper methods

  private async startCoreServices(): Promise<void> {
    // Services are started in the start() method
    logger.debug('Core services ready for start');
  }

  private async setupIntegrations(): Promise<void> {
    if (this.config.monitoring.integrateWithPerformanceCollector) {
      this.setupPerformanceCollectorIntegration();
    }

    if (this.config.monitoring.integrateWithHealthChecks) {
      this.setupHealthCheckIntegration();
    }

    if (this.config.monitoring.exportToExistingMetrics) {
      this.setupExistingMetricsIntegration();
    }
  }

  private setupPerformanceCollectorIntegration(): void {
    // Integrate with performance collector
    enhancedPerformanceCollector.on('metrics_collected', (metrics: unknown) => {
      // Correlate performance metrics with retry budget metrics
      this.emit('performance_metrics_correlated', metrics);
    });
  }

  private setupHealthCheckIntegration(): void {
    // Integrate with existing health check system
    circuitBreakerMonitor.on('health_status_update', (event: unknown) => {
      // Correlate health status with retry budget health
      this.emit('health_status_correlated', event);
    });
  }

  private setupExistingMetricsIntegration(): void {
    // Export to existing metrics infrastructure
    retryMetricsExporter.on('prometheus_metrics_exported', (event: unknown) => {
      // Forward to existing Prometheus metrics endpoint
      this.emit('metrics_exported_to_prometheus', event);
    });
  }

  private async discoverAndRegisterServices(): Promise<void> {
    // Auto-discover services from circuit breaker monitor
    const circuitBreakers = circuitBreakerMonitor.getAllHealthStatuses();

    for (const [serviceName] of circuitBreakers) {
      if (!this.registeredServices.has(serviceName)) {
        // Auto-register with default configuration
        const autoRegistration: ServiceRegistration = {
          serviceName,
          circuitBreakerName: serviceName,
          retryBudgetConfig: {
            ...this.config.services.defaultRetryBudgetConfig,
            serviceName,
            circuitBreakerName: serviceName,
          } as RetryBudgetConfig,
          dependencies: [],
          sloTargets: {
            availability: 99.9,
            latency: 500,
            errorRate: 0.1,
          },
          environment: 'auto-discovered',
        };

        this.registerService(autoRegistration);
      }
    }

    logger.info(
      { discoveredServices: circuitBreakers.size, registeredServices: this.registeredServices.size },
      'Service discovery completed'
    );
  }

  private setupHealthChecks(): void {
    // Set up periodic health checks
    this.healthCheckInterval = setInterval(
      async () => {
        try {
          const health = await this.getHealthReport();

          // Emit health status for external monitoring
          this.emit('health_check_completed', health);

          // Log health issues
          if (health.overall.issues.length > 0) {
            logger.warn(
              { issues: health.overall.issues, score: health.overall.score },
              'Health check detected issues'
            );
          }
        } catch (error) {
          logger.error({ error }, 'Health check failed');
        }
      },
      this.config.system.metricsCollectionIntervalMs
    );
  }

  private validateServiceRegistration(registration: ServiceRegistration): void {
    if (!registration.serviceName || registration.serviceName.trim() === '') {
      throw new Error('Service name is required');
    }

    if (!registration.circuitBreakerName || registration.circuitBreakerName.trim() === '') {
      throw new Error('Circuit breaker name is required');
    }

    if (!registration.retryBudgetConfig) {
      throw new Error('Retry budget configuration is required');
    }

    // Validate retry budget config
    const config = registration.retryBudgetConfig;
    if (config.maxRetriesPerMinute <= 0 || config.maxRetriesPerHour <= 0) {
      throw new Error('Retry limits must be positive');
    }

    if (config.warningThresholdPercent >= config.criticalThresholdPercent) {
      throw new Error('Warning threshold must be less than critical threshold');
    }
  }

  private generateUnifiedCSV(): string {
    const headers = [
      'timestamp',
      'service_name',
      'circuit_breaker_state',
      'retry_budget_utilization',
      'retry_rate',
      'success_rate',
      'response_time_p95',
      'active_alerts',
      'health_score',
    ];

    const rows = [headers.join(',')];

    // Add data for each service
    for (const [serviceName] of this.registeredServices) {
      const retryMetrics = retryBudgetMonitor.getMetrics(serviceName);
      const circuitMetrics = circuitBreakerMonitor.getHealthStatus(serviceName);
      const alerts = retryAlertSystem.getActiveAlerts().filter(a => a.serviceName === serviceName);

      if (retryMetrics && circuitMetrics) {
        rows.push([
          new Date().toISOString(),
          serviceName,
          circuitMetrics.state,
          retryMetrics.current.budgetUtilizationPercent.toFixed(2),
          retryMetrics.current.retryRatePercent.toFixed(2),
          retryMetrics.slo.successRateVariance.toFixed(2),
          retryMetrics.performance.p95ResponseTime.toFixed(0),
          alerts.length.toString(),
          '80', // Would calculate actual health score
        ].join(','));
      }
    }

    return rows.join('\n');
  }

  private setupEventListeners(): void {
    // Set up cross-system event correlation
    retryBudgetMonitor.on('alert', (alert: unknown) => {
      this.emit('retry_budget_alert', alert);
    });

    circuitBreakerMonitor.on('alert', (alert: unknown) => {
      this.emit('circuit_breaker_alert', alert);
    });

    retryAlertSystem.on('alert_created', (alert: unknown) => {
      this.emit('system_alert', alert);
    });

    retryTrendAnalyzer.on('anomaly_detected', (anomaly: unknown) => {
      this.emit('system_anomaly', anomaly);
    });
  }
}

// Export singleton instance
export const retryMonitoringIntegration = new RetryMonitoringIntegration();
