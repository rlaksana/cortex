/**
 * SLO Integration Service
 *
 * Central integration service that orchestrates all SLO components including
 * monitoring, reporting, breach detection, and error budget tracking with unified
 * configuration and lifecycle management.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { EventEmitter } from 'events';

import { ErrorBudgetService } from './error-budget-service.js';
import { SLOBreachDetectionService } from './slo-breach-detection-service.js';
import { SLOReportingService } from './slo-reporting-service.js';
import { SLOService } from './slo-service.js';
import { SLODashboardService } from '../monitoring/slo-dashboard-service.js';
import {
  type BurnRateAnalysis,
  type ErrorBudget,
  type SLO,
  type SLOAlert,
  type SLOBreachIncident,
  type SLOEvaluation,
  type SLOFrameworkConfig,
  type SLOTrendAnalysis,
} from '../types/slo-interfaces.js';

/**
 * SLO Integration Service - Main orchestrator for all SLO functionality
 */
export class SLOIntegrationService extends EventEmitter {
  private config: SLOFrameworkConfig;
  private services: {
    sloService: SLOService;
    dashboardService: SLODashboardService;
    reportingService: SLOReportingService;
    breachDetectionService: SLOBreachDetectionService;
    errorBudgetService: ErrorBudgetService;
  };
  private isStarted = false;
  private healthStatus: 'healthy' | 'degraded' | 'unhealthy' = 'healthy';
  private metrics: {
    totalSLOs: number;
    activeSLOs: number;
    evaluations: number;
    alerts: number;
    incidents: number;
    lastHealthCheck: Date;
  };

  constructor(config: Partial<SLOFrameworkConfig> = {}) {
    super();
    this.config = this.mergeConfig(config);
    this.metrics = {
      totalSLOs: 0,
      activeSLOs: 0,
      evaluations: 0,
      alerts: 0,
      incidents: 0,
      lastHealthCheck: new Date(),
    };

    // Initialize services (will be properly injected in start method)
    this.services = {
      sloService: null as unknown,
      dashboardService: null as unknown,
      reportingService: null as unknown,
      breachDetectionService: null as unknown,
      errorBudgetService: null as unknown,
    };
  }

  /**
   * Start the SLO integration service
   */
  async start(): Promise<void> {
    if (this.isStarted) {
      this.emit('warning', 'SLO Integration Service is already started');
      return;
    }

    try {
      console.log('🚀 Starting SLO Integration Service...');

      // Initialize and start services in dependency order
      await this.initializeServices();
      await this.startServices();
      await this.setupServiceIntegration();
      await this.startHealthMonitoring();

      this.isStarted = true;
      this.healthStatus = 'healthy';
      this.metrics.lastHealthCheck = new Date();

      this.emit('started', 'SLO Integration Service started successfully');
      console.log('✅ SLO Integration Service started successfully');
    } catch (error) {
      this.healthStatus = 'unhealthy';
      this.emit('error', `Failed to start SLO Integration Service: ${error}`);
      console.error('❌ Failed to start SLO Integration Service:', error);
      throw error;
    }
  }

  /**
   * Stop the SLO integration service
   */
  async stop(): Promise<void> {
    if (!this.isStarted) {
      this.emit('warning', 'SLO Integration Service is not started');
      return;
    }

    try {
      console.log('🛑 Stopping SLO Integration Service...');

      // Stop services in reverse order
      await this.stopServices();

      this.isStarted = false;
      this.healthStatus = 'unhealthy';
      this.metrics.lastHealthCheck = new Date();

      this.emit('stopped', 'SLO Integration Service stopped successfully');
      console.log('✅ SLO Integration Service stopped successfully');
    } catch (error) {
      this.emit('error', `Error stopping SLO Integration Service: ${error}`);
      console.error('❌ Error stopping SLO Integration Service:', error);
      throw error;
    }
  }

  /**
   * Get service health status
   */
  getServiceHealth(): {
    overall: 'healthy' | 'degraded' | 'unhealthy';
    services: Record<
      string,
      {
        status: 'healthy' | 'degraded' | 'unhealthy';
        uptime: number;
        lastCheck: Date;
        issues: string[];
      }
    >;
    metrics: unknown;
    lastUpdate: Date;
  } {
    const serviceHealth = {} as unknown;

    // Check each service's health
    for (const [name, service] of Object.entries(this.services)) {
      try {
        if (service && typeof (service as unknown).getStatus === 'function') {
          serviceHealth[name] = (service as unknown).getStatus();
        } else {
          serviceHealth[name] = {
            status: 'healthy',
            uptime: Date.now(),
            lastCheck: new Date(),
            issues: [],
          };
        }
      } catch (error) {
        serviceHealth[name] = {
          status: 'unhealthy',
          uptime: 0,
          lastCheck: new Date(),
          issues: [error instanceof Error ? error.message : 'Unknown error'],
        };
      }
    }

    return {
      overall: this.healthStatus,
      services: serviceHealth,
      metrics: { ...this.metrics },
      lastUpdate: new Date(),
    };
  }

  // ============================================================================
  // SLO Management Operations
  // ============================================================================

  /**
   * Create a new SLO with full integration
   */
  async createSLO(slo: SLO): Promise<{
    slo: SLO;
    errorBudget: ErrorBudget;
    dashboard: unknown;
    status: string;
  }> {
    this.ensureStarted();

    try {
      // Create SLO in core service
      const createdSLO = await this.services.sloService.createSLO(slo);

      // Calculate initial error budget
      const errorBudget = await this.services.errorBudgetService.calculateErrorBudget(slo.id);

      // Create dashboard widget for the SLO
      const dashboard = await this.createDefaultDashboardWidget(slo);

      // Update metrics
      this.metrics.totalSLOs++;
      this.metrics.activeSLOs++;

      const result = {
        slo: createdSLO,
        errorBudget,
        dashboard,
        status: 'created',
      };

      this.emit('slo:created', result);
      return result;
    } catch (error) {
      this.emit('error', `Failed to create SLO: ${error}`);
      throw error;
    }
  }

  /**
   * Get comprehensive SLO overview
   */
  async getSLOOverview(sloId: string): Promise<{
    slo: SLO;
    evaluation: SLOEvaluation | undefined;
    errorBudget: ErrorBudget;
    burnRateAnalysis: BurnRateAnalysis;
    trendAnalysis: SLOTrendAnalysis;
    activeIncidents: SLOBreachIncident[];
    alerts: SLOAlert[];
    recommendations: string[];
  }> {
    this.ensureStarted();

    try {
      // Get basic SLO information
      const slo = this.services.sloService.getSLO(sloId);
      if (!slo) {
        throw new Error(`SLO ${sloId} not found`);
      }

      // Get evaluation
      const evaluation = this.services.sloService.getLatestEvaluation(sloId);

      // Get comprehensive analysis
      const [errorBudget, burnRateAnalysis, trendAnalysis] = await Promise.all([
        this.services.errorBudgetService.calculateErrorBudget(sloId),
        this.services.errorBudgetService.calculateBurnRateAnalysis(sloId),
        this.services.reportingService.performTrendAnalysis(sloId),
      ]);

      // Get incidents and alerts
      const extendedIncidents = this.services.breachDetectionService
        .getActiveIncidents()
        .filter((incident) => incident.sloId === sloId);

      // Convert ExtendedSLOBreachIncident to SLOBreachIncident
      // ExtendedSLOBreachIncident has additional properties: sloName, detectedAt, evaluation, etc.
      // We need to extract the base properties and convert/extend to match SLOBreachIncident interface
      const activeIncidents: SLOBreachIncident[] = extendedIncidents.map((incident) => {
        const {
          sloName,
          detectedAt,
          evaluation,
          impactAssessment,
          notifications,
          escalations,
          responses,
          resolution: extendedResolution,
          ...baseIncident
        } = incident;

        // Convert resolution structure to match base interface
        // ExtendedSLOBreachIncident.resolution has different structure than SLOBreachIncident.resolution
        const resolution = extendedResolution
          ? {
              timestamp: extendedResolution.resolvedBy ? new Date() : new Date(),
              actions: extendedResolution.actions || [],
              rootCause: extendedResolution.reason || '',
              preventiveMeasures: extendedResolution.preventRecurrence || [],
            }
          : undefined;

        // Map the extended properties to base interface structure
        return {
          ...baseIncident,
          escalation: incident.escalation as unknown, // Convert from any to EscalationLevel
          resolution,
          detectedAt: detectedAt,
          metadata: {
            sloName,
            evaluation,
            impactAssessment,
            notifications,
            escalations,
            responses,
          },
        } as SLOBreachIncident;
      });

      const alerts = this.services.sloService.getLatestEvaluation(sloId)?.alerts || [];

      // Generate recommendations
      const recommendations = this.generateRecommendations(
        slo,
        evaluation,
        errorBudget,
        burnRateAnalysis
      );

      return {
        slo,
        evaluation,
        errorBudget,
        burnRateAnalysis,
        trendAnalysis,
        activeIncidents,
        alerts,
        recommendations,
      };
    } catch (error) {
      this.emit('error', `Failed to get SLO overview: ${error}`);
      throw error;
    }
  }

  /**
   * Update SLO with cascading updates
   */
  async updateSLO(
    sloId: string,
    updates: Partial<SLO>
  ): Promise<{
    slo: SLO;
    affected: string[];
    status: string;
  }> {
    this.ensureStarted();

    try {
      // Update SLO
      const updatedSLO = await this.services.sloService.updateSLO(sloId, updates);

      // Recalculate dependent metrics
      await Promise.all([
        this.services.errorBudgetService.calculateErrorBudget(sloId),
        this.services.errorBudgetService.calculateBurnRateAnalysis(sloId),
      ]);

      const result = {
        slo: updatedSLO,
        affected: ['error_budget', 'burn_rate', 'evaluations'],
        status: 'updated',
      };

      this.emit('slo:updated', result);
      return result;
    } catch (error) {
      this.emit('error', `Failed to update SLO: ${error}`);
      throw error;
    }
  }

  /**
   * Delete SLO with cleanup
   */
  async deleteSLO(sloId: string): Promise<{
    deleted: boolean;
    cleaned: string[];
    status: string;
  }> {
    this.ensureStarted();

    try {
      // Delete SLO
      const deleted = await this.services.sloService.deleteSLO(sloId);

      // Clean up related data
      const cleaned: string[] = [];
      // Note: Cleanup would happen automatically in individual services

      // Update metrics
      if (deleted) {
        this.metrics.totalSLOs--;
        const slo = this.services.sloService.getSLO(sloId);
        if (slo?.status === 'active') {
          this.metrics.activeSLOs--;
        }
      }

      const result = {
        deleted,
        cleaned,
        status: deleted ? 'deleted' : 'not_found',
      };

      this.emit('slo:deleted', result);
      return result;
    } catch (error) {
      this.emit('error', `Failed to delete SLO: ${error}`);
      throw error;
    }
  }

  // ============================================================================
  // Bulk Operations
  // ============================================================================

  /**
   * Get all SLOs with comprehensive data
   */
  async getAllSLOsOverview(): Promise<
    Array<{
      slo: SLO;
      evaluation: SLOEvaluation | undefined;
      errorBudget: ErrorBudget;
      status: 'healthy' | 'warning' | 'critical';
    }>
  > {
    this.ensureStarted();

    try {
      const slos = this.services.sloService.getAllSLOs();
      const overviews = [];

      for (const slo of slos) {
        const evaluation = this.services.sloService.getLatestEvaluation(slo.id);
        const errorBudget = await this.services.errorBudgetService.calculateErrorBudget(slo.id);

        let status: 'healthy' | 'warning' | 'critical' = 'healthy';
        if (evaluation) {
          if (evaluation.status === 'violation') status = 'critical';
          else if (evaluation.status === 'warning') status = 'warning';
        }

        overviews.push({
          slo,
          evaluation,
          errorBudget,
          status,
        });
      }

      return overviews;
    } catch (error) {
      this.emit('error', `Failed to get all SLOs overview: ${error}`);
      throw error;
    }
  }

  /**
   * Generate comprehensive system report
   */
  async generateSystemReport(period?: { start: Date; end: Date }): Promise<{
    summary: {
      totalSLOs: number;
      activeSLOs: number;
      compliantSLOs: number;
      violatingSLOs: number;
      warningSLOs: number;
      totalErrorBudget: number;
      consumedErrorBudget: number;
      overallHealth: string;
    };
    details: {
      sloPerformances: unknown[];
      incidents: unknown[];
      alerts: unknown[];
      trends: unknown[];
    };
    recommendations: string[];
    generatedAt: Date;
  }> {
    this.ensureStarted();

    try {
      const slos = this.services.sloService.getAllSLOs();
      const overviews = await this.getAllSLOsOverview();

      // Calculate summary metrics
      const summary = {
        totalSLOs: slos.length,
        activeSLOs: slos.filter((slo) => slo.status === 'active').length,
        compliantSLOs: overviews.filter((o) => o.status === 'healthy').length,
        violatingSLOs: overviews.filter((o) => o.status === 'critical').length,
        warningSLOs: overviews.filter((o) => o.status === 'warning').length,
        totalErrorBudget: overviews.reduce((sum, o) => sum + o.errorBudget.total, 0),
        consumedErrorBudget: overviews.reduce((sum, o) => sum + o.errorBudget.consumed, 0),
        overallHealth: this.calculateOverallHealth(overviews),
      };

      // Get detailed information
      const [incidents, alerts, trends] = await Promise.all([
        this.services.breachDetectionService.getActiveIncidents(),
        this.getActiveAlerts(),
        this.getSystemTrends(),
      ]);

      const details = {
        sloPerformances: overviews,
        incidents,
        alerts,
        trends,
      };

      // Generate recommendations
      const recommendations = this.generateSystemRecommendations(summary, details);

      const report = {
        summary,
        details,
        recommendations,
        generatedAt: new Date(),
      };

      this.emit('report:generated', report);
      return report;
    } catch (error) {
      this.emit('error', `Failed to generate system report: ${error}`);
      throw error;
    }
  }

  // ============================================================================
  // Dashboard Operations
  // ============================================================================

  /**
   * Create default dashboard for SLO monitoring
   */
  async createDefaultDashboard(): Promise<{
    dashboardId: string;
    url: string;
    widgets: unknown[];
  }> {
    this.ensureStarted();

    try {
      // Create dashboard
      const dashboard = await this.services.dashboardService.createDashboard({
        name: 'SLO Overview Dashboard',
        description: 'Comprehensive SLO monitoring dashboard',
        owner: 'slo-team',
        refreshInterval: 30000,
      });

      // Add standard widgets
      const widgets = await Promise.all([
        this.addDashboardWidget(dashboard.id, 'slo_status', 'SLO Status Overview'),
        this.addDashboardWidget(dashboard.id, 'error_budget', 'Error Budget Status'),
        this.addDashboardWidget(dashboard.id, 'burn_rate', 'Burn Rate Analysis'),
        this.addDashboardWidget(dashboard.id, 'alerts', 'Active Alerts'),
      ]);

      const url = `http://localhost:3001/dashboards/${dashboard.id}`;

      return {
        dashboardId: dashboard.id,
        url,
        widgets,
      };
    } catch (error) {
      this.emit('error', `Failed to create default dashboard: ${error}`);
      throw error;
    }
  }

  /**
   * Add widget to dashboard
   */
  private async addDashboardWidget(
    dashboardId: string,
    type: string,
    title: string
  ): Promise<unknown> {
    return await this.services.dashboardService.addWidget(dashboardId, {
      type: type as unknown,
      title,
      position: { x: 0, y: 0, width: 4, height: 3 },
      config: {},
    });
  }

  /**
   * Create default dashboard widget for an SLO
   */
  private async createDefaultDashboardWidget(slo: SLO): Promise<unknown> {
    // This would create a specific widget for the SLO
    return {
      sloId: slo.id,
      widgetType: 'slo_status',
      title: `SLO: ${slo.name}`,
      created: true,
    };
  }

  // ============================================================================
  // Private Helper Methods
  // ============================================================================

  /**
   * Ensure service is started
   */
  private ensureStarted(): void {
    if (!this.isStarted) {
      throw new Error('SLO Integration Service is not started');
    }
  }

  /**
   * Merge configuration with defaults
   */
  private mergeConfig(config: Partial<SLOFrameworkConfig>): SLOFrameworkConfig {
    return {
      monitoring: {
        evaluationInterval: 60000,
        dataRetentionPeriod: 90 * 24 * 60 * 60 * 1000,
        batchSize: 1000,
        maxConcurrency: 10,
        ...config.monitoring,
      },
      storage: {
        type: 'influxdb',
        connection: {},
        retention: {
          raw: 7 * 24 * 60 * 60 * 1000,
          hourly: 30 * 24 * 60 * 60 * 1000,
          daily: 365 * 24 * 60 * 60 * 1000,
        },
        ...config.storage,
      },
      alerting: {
        enabled: true,
        defaultChannels: [],
        rateLimiting: {
          maxAlertsPerMinute: 10,
          maxAlertsPerHour: 100,
          ...config.alerting?.rateLimiting,
        },
        ...config.alerting,
      },
      dashboard: {
        enabled: true,
        defaultRefreshInterval: 30000,
        maxWidgets: 50,
        ...config.dashboard,
      },
      analytics: {
        enabled: true,
        predictionWindow: 24 * 60 * 60 * 1000,
        anomalyDetection: {
          enabled: true,
          sensitivity: 0.5,
          minConfidence: 0.8,
          ...config.analytics?.anomalyDetection,
        },
        ...config.analytics,
      },
      security: {
        authentication: {
          enabled: false,
          method: 'oauth',
          ...config.security?.authentication,
        },
        authorization: {
          enabled: false,
          roles: {},
          ...config.security?.authorization,
        },
        ...config.security,
      },
    };
  }

  /**
   * Initialize services
   */
  private async initializeServices(): Promise<void> {
    console.log('🔧 Initializing SLO services...');

    // Initialize core SLO service
    this.services.sloService = new SLOService(this.config);

    // Initialize other services with dependencies
    this.services.errorBudgetService = new ErrorBudgetService(this.services.sloService);
    this.services.breachDetectionService = new SLOBreachDetectionService(this.services.sloService);
    this.services.reportingService = new SLOReportingService(this.services.sloService);
    this.services.dashboardService = new SLODashboardService(this.services.sloService, {
      port: 3001,
      host: '0.0.0.0',
    });

    console.log('✅ SLO services initialized');
  }

  /**
   * Start services
   */
  private async startServices(): Promise<void> {
    console.log('🚀 Starting SLO services...');

    // Start services in dependency order
    await this.services.sloService.start();
    await this.services.errorBudgetService.start();
    await this.services.breachDetectionService.start();
    await this.services.reportingService.start();
    await this.services.dashboardService.start();

    console.log('✅ SLO services started');
  }

  /**
   * Stop services
   */
  private async stopServices(): Promise<void> {
    console.log('🛑 Stopping SLO services...');

    // Stop services in reverse order
    await this.services.dashboardService.stop();
    await this.services.reportingService.stop();
    await this.services.breachDetectionService.stop();
    await this.services.errorBudgetService.stop();
    await this.services.sloService.stop();

    console.log('✅ SLO services stopped');
  }

  /**
   * Setup service integration
   */
  private async setupServiceIntegration(): Promise<void> {
    console.log('🔗 Setting up service integration...');

    // Setup event listeners between services
    this.setupEventListeners();

    // Configure default policies and thresholds
    await this.configureDefaultPolicies();

    console.log('✅ Service integration configured');
  }

  /**
   * Setup event listeners between services
   */
  private setupEventListeners(): void {
    // SLO evaluations -> Error budget service
    this.services.sloService.on('slo:evaluated', async (evaluation: SLOEvaluation) => {
      this.metrics.evaluations++;

      // Trigger related calculations
      try {
        await Promise.all([
          this.services.errorBudgetService.calculateErrorBudget(evaluation.sloId),
          this.services.errorBudgetService.calculateBurnRateAnalysis(evaluation.sloId),
        ]);
      } catch (error) {
        this.emit('error', `Error in post-evaluation processing: ${error}`);
      }
    });

    // Alerts -> Metrics update
    this.services.sloService.on('alert:created', (alert: SLOAlert) => {
      this.metrics.alerts++;
    });

    // Incidents -> Metrics update
    this.services.breachDetectionService.on('incident:created', (incident: SLOBreachIncident) => {
      this.metrics.incidents++;
    });

    // Service health monitoring
    Object.entries(this.services).forEach(([name, service]) => {
      if (service && typeof (service as unknown).on === 'function') {
        (service as unknown).on('error', (error: unknown) => {
          this.emit('service:error', { service: name, error });
          this.updateHealthStatus();
        });
      }
    });
  }

  /**
   * Configure default policies
   */
  private async configureDefaultPolicies(): Promise<void> {
    // Configure default error budget policies
    const slos = this.services.sloService.getAllSLOs();
    for (const slo of slos) {
      if (slo.status === 'active') {
        const defaultPolicy = {
          id: `default-${slo.id}`,
          name: `Default Policy for ${slo.name}`,
          description: 'Default error budget policy',
          maxBurnRate: 2.0,
          alertThresholds: [
            { level: 'warning', threshold: 60, timeWindow: 24 * 60 * 60 * 1000 },
            { level: 'critical', threshold: 80, timeWindow: 24 * 60 * 60 * 1000 },
          ],
          automatedResponses: [
            { trigger: 'burn_rate_exceeded', action: 'scale_up', enabled: true },
            { trigger: 'budget_exhausted', action: 'incident_response', enabled: true },
          ],
        };

        this.services.errorBudgetService.configureBudgetPolicy(slo.id, defaultPolicy as unknown);
      }
    }
  }

  /**
   * Start health monitoring
   */
  private async startHealthMonitoring(): Promise<void> {
    // Schedule health checks every minute
    setInterval(() => {
      this.updateHealthStatus();
      this.metrics.lastHealthCheck = new Date();
    }, 60 * 1000);
  }

  /**
   * Update health status
   */
  private updateHealthStatus(): void {
    try {
      const serviceHealth = this.getServiceHealth();
      const unhealthyServices = Object.values(serviceHealth.services).filter(
        (s) => s.status === 'unhealthy'
      ).length;

      if (unhealthyServices > 0) {
        this.healthStatus = 'unhealthy';
      } else if (Object.values(serviceHealth.services).some((s) => s.status === 'degraded')) {
        this.healthStatus = 'degraded';
      } else {
        this.healthStatus = 'healthy';
      }
    } catch (error) {
      this.healthStatus = 'unhealthy';
      this.emit('error', `Health check failed: ${error}`);
    }
  }

  /**
   * Calculate overall health
   */
  private calculateOverallHealth(overviews: unknown[]): string {
    if (overviews.length === 0) return 'unknown';

    const criticalCount = overviews.filter((o) => o.status === 'critical').length;
    const warningCount = overviews.filter((o) => o.status === 'warning').length;

    if (criticalCount > 0) return 'critical';
    if (warningCount > overviews.length * 0.3) return 'warning';
    return 'healthy';
  }

  /**
   * Generate recommendations for an SLO
   */
  private generateRecommendations(
    slo: SLO,
    evaluation: SLOEvaluation | undefined,
    errorBudget: ErrorBudget,
    burnRateAnalysis: BurnRateAnalysis
  ): string[] {
    const recommendations: string[] = [];

    // Budget-based recommendations
    if (errorBudget.remaining < 20) {
      recommendations.push('Error budget critically low - immediate action required');
      recommendations.push('Consider implementing circuit breakers or rate limiting');
    }

    // Burn rate recommendations
    if (burnRateAnalysis.currentRate > 2) {
      recommendations.push('High burn rate detected - investigate root cause');
      recommendations.push('Review recent deployments and configuration changes');
    }

    // Trend-based recommendations
    if (burnRateAnalysis.trend === 'increasing' && (burnRateAnalysis as unknown).confidence > 0.7) {
      recommendations.push('Burn rate trending upward - prepare escalation procedures');
    }

    // Evaluation-based recommendations
    if (evaluation && evaluation.status === 'violation') {
      recommendations.push('SLO violation detected - implement immediate remediation');
    }

    if (recommendations.length === 0) {
      recommendations.push('SLO performance is within acceptable ranges');
    }

    return recommendations;
  }

  /**
   * Get active alerts
   */
  private async getActiveAlerts(): Promise<SLOAlert[]> {
    const slos = this.services.sloService.getAllSLOs();
    const allAlerts: SLOAlert[] = [];

    for (const slo of slos) {
      const evaluation = this.services.sloService.getLatestEvaluation(slo.id);
      if (evaluation) {
        allAlerts.push(...evaluation.alerts.filter((alert) => !alert.resolved));
      }
    }

    return allAlerts;
  }

  /**
   * Get system trends
   */
  private async getSystemTrends(): Promise<unknown[]> {
    const slos = this.services.sloService.getAllSLOs();
    const trends = [];

    for (const slo of slos) {
      try {
        const trendAnalysis = await this.services.reportingService.performTrendAnalysis(slo.id);
        trends.push({
          sloId: slo.id,
          sloName: slo.name,
          trend: trendAnalysis,
        });
      } catch (error) {
        // Skip SLOs with insufficient data
      }
    }

    return trends;
  }

  /**
   * Generate system recommendations
   */
  private generateSystemRecommendations(summary: unknown, details: unknown): string[] {
    const recommendations: string[] = [];

    // Overall health recommendations
    if (summary.overallHealth === 'critical') {
      recommendations.push('System health is critical - immediate attention required');
      recommendations.push('Review and prioritize incident response for all violating SLOs');
    }

    // Budget utilization recommendations
    const budgetUtilization = (summary.consumedErrorBudget / summary.totalErrorBudget) * 100;
    if (budgetUtilization > 80) {
      recommendations.push('Overall error budget utilization is high - review system reliability');
    }

    // Incident recommendations
    if (details.incidents.length > 0) {
      recommendations.push(
        `Resolve ${details.incidents.length} active incidents to restore service health`
      );
    }

    // Alert recommendations
    if (details.alerts.length > 10) {
      recommendations.push('High number of active alerts - consider tuning alert thresholds');
    }

    if (recommendations.length === 0) {
      recommendations.push('System is performing well - continue monitoring');
    }

    return recommendations;
  }

  /**
   * Update metrics
   */
  private updateMetrics(): void {
    const slos = this.services.sloService.getAllSLOs();
    this.metrics.totalSLOs = slos.length;
    this.metrics.activeSLOs = slos.filter((slo) => slo.status === 'active').length;
  }
}

// Export singleton instance
export const sloIntegrationService = new SLOIntegrationService();
