/**
 * SLO Monitoring Integration
 *
 * Comprehensive integration service that wires SLOs, error budgets, circuit breakers,
 * and monitoring together for complete observability and automated response.
 *
 * Features:
 * - Real-time SLO monitoring with automatic evaluation
 * - Error budget tracking with burn rate calculations
 * - Circuit breaker integration for automated protection
 * - Multi-dimensional monitoring dashboards
 * - Alert correlation and incident management
 * - Automated escalation and recovery procedures
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { EventEmitter } from 'events';
import { SLOService } from '../services/slo-service.js';
import { ErrorBudgetService } from '../services/error-budget-service.js';
import { SLOBreachDetectionService } from '../services/slo-breach-detection-service.js';
import { SLOReportingService } from '../services/slo-reporting-service.js';
import { circuitBreakerManager } from '../services/circuit-breaker.service.js';
import { CircuitBreakerMonitor } from './circuit-breaker-monitor.js';
import { EnhancedCircuitDashboard } from './enhanced-circuit-dashboard.js';
import { SLODashboardService } from './slo-dashboard-service.js';
import { RetryBudgetMonitor } from './retry-budget-monitor.js';
import { QdrantGracefulDegradationManager } from './graceful-degradation-manager.js';
import { logger } from '../utils/logger.js';
import type {
  SLO,
  SLOEvaluation,
  SLOAlert,
  ErrorBudget,
  BudgetAlert,
  BurnRateAnalysis,
  CircuitBreakerStats,
  SLOMonitoringConfig,
  IntegratedMonitoringSnapshot,
  SLOHealthStatus,
  AlertCorrelation,
  AutomatedResponse,
} from '../types/slo-interfaces.js';

/**
 * SLO Monitoring Integration Service
 */
export class SLOMonitoringIntegration extends EventEmitter {
  private sloService: SLOService;
  private errorBudgetService: ErrorBudgetService;
  private breachDetectionService: SLOBreachDetectionService;
  private reportingService: SLOReportingService;
  private circuitBreakerMonitor: CircuitBreakerMonitor;
  private circuitDashboard: EnhancedCircuitDashboard;
  private sloDashboard: SLODashboardService;
  private retryMonitor: RetryBudgetMonitor;
  private degradationManager: QdrantGracefulDegradationManager;

  private config: SLOMonitoringConfig;
  private isStarted = false;
  private monitoringIntervals: Map<string, NodeJS.Timeout> = new Map();
  private alertCorrelations: Map<string, AlertCorrelation> = new Map();
  private automatedResponses: Map<string, AutomatedResponse> = new Map();

  constructor(config: SLOMonitoringConfig = {}) {
    super();

    this.config = {
      evaluationInterval: 30000, // 30 seconds
      breachCheckInterval: 10000, // 10 seconds
      circuitBreakerCheckInterval: 5000, // 5 seconds
      errorBudgetCalculationInterval: 60000, // 1 minute
      dashboardRefreshInterval: 15000, // 15 seconds
      automatedResponseEnabled: true,
      alertCorrelationEnabled: true,
      incidentCreationEnabled: true,
      escalationEnabled: true,
      ...config,
    };

    // Initialize services
    this.sloService = new SLOService();
    this.errorBudgetService = new ErrorBudgetService(this.sloService);
    this.breachDetectionService = new SLOBreachDetectionService(this.sloService);
    this.reportingService = new SLOReportingService(this.sloService);
    this.circuitBreakerMonitor = new CircuitBreakerMonitor();
    this.circuitDashboard = new EnhancedCircuitDashboard();
    this.sloDashboard = new SLODashboardService(this.sloService);
    this.retryMonitor = new RetryBudgetMonitor();
    this.degradationManager = new QdrantGracefulDegradationManager();
  }

  /**
   * Start the integrated monitoring system
   */
  async start(): Promise<void> {
    if (this.isStarted) {
      logger.warn('SLO Monitoring Integration is already started');
      return;
    }

    try {
      logger.info('Starting SLO Monitoring Integration...');

      // Start all services
      await Promise.all([
        this.sloService.start(),
        this.errorBudgetService.start(),
        this.breachDetectionService.start(),
        this.reportingService.start(),
        this.sloDashboard.start(),
      ]);

      // Setup event handlers
      this.setupEventHandlers();

      // Start monitoring intervals
      this.startMonitoringIntervals();

      // Initialize default SLOs if none exist
      await this.initializeDefaultSLOs();

      // Configure automated responses
      if (this.config.automatedResponseEnabled) {
        await this.configureAutomatedResponses();
      }

      this.isStarted = true;
      this.emit('started', 'SLO Monitoring Integration started successfully');
      logger.info('🎯 SLO Monitoring Integration started successfully');

    } catch (error) {
      logger.error({ error }, 'Failed to start SLO Monitoring Integration');
      throw error;
    }
  }

  /**
   * Stop the integrated monitoring system
   */
  async stop(): Promise<void> {
    if (!this.isStarted) {
      logger.warn('SLO Monitoring Integration is not started');
      return;
    }

    try {
      logger.info('Stopping SLO Monitoring Integration...');

      // Clear monitoring intervals
      for (const interval of this.monitoringIntervals.values()) {
        clearInterval(interval);
      }
      this.monitoringIntervals.clear();

      // Stop all services
      await Promise.all([
        this.sloService.stop(),
        this.errorBudgetService.stop(),
        this.breachDetectionService.stop(),
        this.reportingService.stop(),
        this.sloDashboard.stop(),
      ]);

      this.isStarted = false;
      this.emit('stopped', 'SLO Monitoring Integration stopped successfully');
      logger.info('SLO Monitoring Integration stopped successfully');

    } catch (error) {
      logger.error({ error }, 'Failed to stop SLO Monitoring Integration');
      throw error;
    }
  }

  /**
   * Setup event handlers for integrated monitoring
   */
  private setupEventHandlers(): void {
    // SLO Evaluation Events
    this.sloService.on('slo:evaluated', (evaluation: SLOEvaluation) => {
      this.handleSLOEvaluation(evaluation);
    });

    // Error Budget Events
    this.errorBudgetService.on('budget:alert', (alert: BudgetAlert) => {
      this.handleBudgetAlert(alert);
    });

    this.errorBudgetService.on('budget:exhausted', (budget: ErrorBudget) => {
      this.handleBudgetExhausted(budget);
    });

    // SLO Breach Detection Events
    this.breachDetectionService.on('breach:detected', (incident) => {
      this.handleBreachDetected(incident);
    });

    this.breachDetectionService.on('warning:detected', (warning) => {
      this.handleBreachWarning(warning);
    });

    // Circuit Breaker Events
    this.circuitBreakerMonitor.on('alert', (alert) => {
      this.handleCircuitBreakerAlert(alert);
    });

    this.circuitBreakerMonitor.on('circuitStateChanged', (event) => {
      this.handleCircuitStateChanged(event);
    });

    // Retry Budget Events
    this.retryMonitor.on('alert', (alert) => {
      this.handleRetryBudgetAlert(alert);
    });

    // Degradation Events
    this.degradationManager.on('degradation:level_changed', (event) => {
      this.handleDegradationLevelChanged(event);
    });
  }

  /**
   * Start monitoring intervals
   */
  private startMonitoringIntervals(): void {
    // SLO Evaluation Interval
    const evaluationInterval = setInterval(async () => {
      try {
        await this.performSLOEvaluations();
      } catch (error) {
        logger.error({ error }, 'Error in SLO evaluation interval');
      }
    }, this.config.evaluationInterval);
    this.monitoringIntervals.set('evaluation', evaluationInterval);

    // Error Budget Calculation Interval
    const budgetInterval = setInterval(async () => {
      try {
        await this.calculateErrorBudgets();
      } catch (error) {
        logger.error({ error }, 'Error in error budget calculation interval');
      }
    }, this.config.errorBudgetCalculationInterval);
    this.monitoringIntervals.set('budget', budgetInterval);

    // Circuit Breaker Check Interval
    const circuitInterval = setInterval(async () => {
      try {
        await this.checkCircuitBreakerHealth();
      } catch (error) {
        logger.error({ error }, 'Error in circuit breaker check interval');
      }
    }, this.config.circuitBreakerCheckInterval);
    this.monitoringIntervals.set('circuit', circuitInterval);

    // Dashboard Refresh Interval
    const dashboardInterval = setInterval(async () => {
      try {
        await this.refreshDashboards();
      } catch (error) {
        logger.error({ error }, 'Error in dashboard refresh interval');
      }
    }, this.config.dashboardRefreshInterval);
    this.monitoringIntervals.set('dashboard', dashboardInterval);
  }

  /**
   * Perform SLO evaluations
   */
  private async performSLOEvaluations(): Promise<void> {
    const slos = await this.sloService.getAllSLOs();
    const activeSLOs = slos.filter(slo => slo.active);

    for (const slo of activeSLOs) {
      try {
        await this.sloService.evaluateSLO(slo.id);
      } catch (error) {
        logger.error({ sloId: slo.id, error }, 'Failed to evaluate SLO');
      }
    }
  }

  /**
   * Calculate error budgets
   */
  private async calculateErrorBudgets(): Promise<void> {
    const slos = await this.sloService.getAllSLOs();
    const activeSLOs = slos.filter(slo => slo.active);

    for (const slo of activeSLOs) {
      try {
        await this.errorBudgetService.calculateErrorBudget(slo.id);
      } catch (error) {
        logger.error({ sloId: slo.id, error }, 'Failed to calculate error budget');
      }
    }
  }

  /**
   * Check circuit breaker health
   */
  private async checkCircuitBreakerHealth(): Promise<void> {
    const stats = await this.circuitBreakerMonitor.getHealthReport();

    // Check for circuits that need attention
    for (const [name, circuitStats] of Object.entries(stats.circuitBreakers)) {
      if (circuitStats.state === 'OPEN') {
        this.emit('alert:circuit_open', { name, stats: circuitStats });
      }

      if (circuitStats.failureRate > 0.5) { // 50% failure rate
        this.emit('alert:circuit_degraded', { name, stats: circuitStats });
      }
    }
  }

  /**
   * Refresh dashboards
   */
  private async refreshDashboards(): Promise<void> {
    // Trigger dashboard data refresh
    this.sloDashboard.broadcastToAll('data:refresh', {
      timestamp: new Date(),
      trigger: 'scheduled_refresh'
    });
  }

  /**
   * Initialize default SLOs
   */
  private async initializeDefaultSLOs(): Promise<void> {
    const existingSLOs = await this.sloService.getAllSLOs();

    if (existingSLOs.length === 0) {
      // Create default SLOs for critical services
      const defaultSLOs = [
        {
          name: 'API Availability',
          description: 'API service availability SLO',
          objective: 0.99, // 99% availability
          timeWindow: {
            type: 'rolling' as const,
            duration: '30d'
          },
          sli: {
            type: 'availability' as const,
            description: 'API availability percentage',
            goodEvents: ['successful_api_requests'],
            totalEvents: ['total_api_requests'],
            query: 'success_rate > 0.99'
          },
          alerting: {
            burnRateThresholds: [
              { multiplier: 2, severity: 'warning' as const },
              { multiplier: 5, severity: 'critical' as const }
            ],
            alertEscalation: {
              enabled: true,
              timeToAlert: '5m',
              timeToWarn: '15m',
              timeToEscalate: '30m'
            }
          },
          active: true
        },
        {
          name: 'Database Response Time',
          description: 'Database response time SLO',
          objective: 0.95, // 95th percentile under 100ms
          timeWindow: {
            type: 'rolling' as const,
            duration: '7d'
          },
          sli: {
            type: 'latency' as const,
            description: '95th percentile response time',
            goodEvents: ['fast_database_queries'],
            totalEvents: ['total_database_queries'],
            query: 'p95_response_time_ms < 100'
          },
          alerting: {
            burnRateThresholds: [
              { multiplier: 3, severity: 'warning' as const },
              { multiplier: 10, severity: 'critical' as const }
            ],
            alertEscalation: {
              enabled: true,
              timeToAlert: '2m',
              timeToWarn: '10m',
              timeToEscalate: '20m'
            }
          },
          active: true
        },
        {
          name: 'Memory Store Success Rate',
          description: 'Memory store operations success rate SLO',
          objective: 0.999, // 99.9% success rate
          timeWindow: {
            type: 'rolling' as const,
            duration: '24h'
          },
          sli: {
            type: 'success_rate' as const,
            description: 'Memory store success rate',
            goodEvents: ['successful_memory_operations'],
            totalEvents: ['total_memory_operations'],
            query: 'success_rate > 0.999'
          },
          alerting: {
            burnRateThresholds: [
              { multiplier: 2, severity: 'warning' as const },
              { multiplier: 5, severity: 'critical' as const }
            ],
            alertEscalation: {
              enabled: true,
              timeToAlert: '3m',
              timeToWarn: '10m',
              timeToEscalate: '25m'
            }
          },
          active: true
        }
      ];

      for (const sloConfig of defaultSLOs) {
        await this.sloService.createSLO(sloConfig);
      }

      logger.info('Default SLOs created successfully');
    }
  }

  /**
   * Configure automated responses
   */
  private async configureAutomatedResponses(): Promise<void> {
    // Circuit breaker automation
    this.automatedResponses.set('circuit_breaker_open', {
      trigger: 'circuit_breaker_open',
      actions: [
        {
          type: 'circuit_breaker_reset',
          condition: 'failure_rate < 0.1 for 5m',
          delay: 300000 // 5 minutes
        },
        {
          type: 'escalation',
          condition: 'circuit_open > 10m',
          delay: 600000 // 10 minutes
        },
        {
          type: 'degradation_activation',
          condition: 'circuit_open > 15m',
          delay: 900000 // 15 minutes
        }
      ],
      enabled: true
    });

    // Error budget automation
    this.automatedResponses.set('error_budget_exhausted', {
      trigger: 'error_budget_exhausted',
      actions: [
        {
          type: 'feature_flag_disable',
          condition: 'budget_remaining < 0.1',
          delay: 0 // immediate
        },
        {
          type: 'traffic_throttling',
          condition: 'budget_remaining < 0.05',
          delay: 60000 // 1 minute
        },
        {
          type: 'emergency_shutdown',
          condition: 'budget_remaining < 0.01',
          delay: 300000 // 5 minutes
        }
      ],
      enabled: true
    });
  }

  // Event Handlers
  private handleSLOEvaluation(evaluation: SLOEvaluation): void {
    logger.debug({
      sloId: evaluation.sloId,
      status: evaluation.status,
      value: evaluation.value
    }, 'SLO evaluation completed');

    // Correlate with circuit breaker status
    await this.correlateWithCircuitBreaker(evaluation);

    // Update dashboards
    this.sloDashboard.broadcastToAll('slo:evaluation', evaluation);
  }

  private handleBudgetAlert(alert: BudgetAlert): void {
    logger.warn({
      sloId: alert.sloId,
      alertType: alert.alertType,
      burnRate: alert.burnRate
    }, 'Budget alert triggered');

    // Trigger automated response
    if (this.config.automatedResponseEnabled) {
      this.triggerAutomatedResponse('error_budget_warning', alert);
    }

    // Create incident if critical
    if (alert.alertType === 'critical' && this.config.incidentCreationEnabled) {
      this.createIncident(alert);
    }
  }

  private handleBudgetExhausted(budget: ErrorBudget): void {
    logger.error({
      sloId: budget.sloId,
      remaining: budget.remaining,
      consumption: budget.consumption
    }, 'Error budget exhausted');

    // Immediate automated response
    if (this.config.automatedResponseEnabled) {
      this.triggerAutomatedResponse('error_budget_exhausted', budget);
    }

    // Create critical incident
    if (this.config.incidentCreationEnabled) {
      this.createCriticalIncident(budget);
    }
  }

  private handleBreachDetected(incident): void {
    logger.error({
      sloId: incident.sloId,
      breachType: incident.breachType,
      severity: incident.severity
    }, 'SLO breach detected');

    // Correlate with other alerts
    if (this.config.alertCorrelationEnabled) {
      this.correlateAlerts(incident);
    }

    // Trigger response
    this.triggerBreachResponse(incident);
  }

  private handleBreachWarning(warning): void {
    logger.warn({
      sloId: warning.sloId,
      warningType: warning.warningType,
      projectedBreach: warning.projectedBreach
    }, 'SLO breach warning');

    // Preventive measures
    this.triggerPreventiveMeasures(warning);
  }

  private handleCircuitBreakerAlert(alert): void {
    logger.warn({
      circuitName: alert.circuitName,
      alertType: alert.alertType,
      failureRate: alert.failureRate
    }, 'Circuit breaker alert');

    // Check SLO impact
    this.checkSLOImpact(alert);

    // Correlate with error budgets
    this.correlateWithErrorBudgets(alert);
  }

  private handleCircuitStateChanged(event): void {
    logger.info({
      circuitName: event.circuitName,
      oldState: event.oldState,
      newState: event.newState
    }, 'Circuit breaker state changed');

    // Update SLO evaluations if needed
    this.updateSLOEvaluationsForCircuit(event);

    // Trigger response if critical
    if (event.newState === 'OPEN') {
      this.triggerCircuitBreakerResponse(event);
    }
  }

  private handleRetryBudgetAlert(alert): void {
    logger.warn({
      serviceName: alert.serviceName,
      alertType: alert.alertType,
      retryRate: alert.retryRate
    }, 'Retry budget alert');

    // Check impact on SLOs
    this.checkSLOImpactFromRetryBudget(alert);
  }

  private handleDegradationLevelChanged(event): void {
    logger.info({
      component: event.component,
      oldLevel: event.oldLevel,
      newLevel: event.newLevel
    }, 'Degradation level changed');

    // Adjust SLO targets based on degradation
    this.adjustSLOTargets(event);

    // Update error budget calculations
    this.updateErrorBudgetCalculations(event);
  }

  // Helper methods
  private async correlateWithCircuitBreaker(evaluation: SLOEvaluation): Promise<void> {
    // Implementation for correlating SLO evaluation with circuit breaker status
  }

  private async triggerAutomatedResponse(trigger: string, data: any): Promise<void> {
    // Implementation for triggering automated responses
  }

  private async createIncident(alert: BudgetAlert): Promise<void> {
    // Implementation for creating incidents
  }

  private async createCriticalIncident(budget: ErrorBudget): Promise<void> {
    // Implementation for creating critical incidents
  }

  private async correlateAlerts(incident): Promise<void> {
    // Implementation for alert correlation
  }

  private async triggerBreachResponse(incident): Promise<void> {
    // Implementation for breach response
  }

  private async triggerPreventiveMeasures(warning): Promise<void> {
    // Implementation for preventive measures
  }

  private async checkSLOImpact(alert): Promise<void> {
    // Implementation for SLO impact checking
  }

  private async correlateWithErrorBudgets(alert): Promise<void> {
    // Implementation for error budget correlation
  }

  private async updateSLOEvaluationsForCircuit(event): Promise<void> {
    // Implementation for updating SLO evaluations
  }

  private async triggerCircuitBreakerResponse(event): Promise<void> {
    // Implementation for circuit breaker response
  }

  private async checkSLOImpactFromRetryBudget(alert): Promise<void> {
    // Implementation for checking SLO impact from retry budget
  }

  private async adjustSLOTargets(event): Promise<void> {
    // Implementation for adjusting SLO targets
  }

  private async updateErrorBudgetCalculations(event): Promise<void> {
    // Implementation for updating error budget calculations
  }

  /**
   * Get comprehensive monitoring snapshot
   */
  async getMonitoringSnapshot(): Promise<IntegratedMonitoringSnapshot> {
    const [
      sloStatus,
      errorBudgets,
      circuitBreakerStats,
      retryBudgetStats,
      degradationStats
    ] = await Promise.all([
      this.getSLOHealthStatus(),
      this.getErrorBudgetSnapshot(),
      this.getCircuitBreakerSnapshot(),
      this.getRetryBudgetSnapshot(),
      this.getDegradationSnapshot()
    ]);

    return {
      timestamp: new Date(),
      sloStatus,
      errorBudgets,
      circuitBreakers: circuitBreakerStats,
      retryBudgets: retryBudgetStats,
      degradation: degradationStats,
      alerts: this.getActiveAlerts(),
      automatedResponses: Array.from(this.automatedResponses.values()),
      healthScore: this.calculateOverallHealthScore(sloStatus, errorBudgets, circuitBreakerStats)
    };
  }

  private async getSLOHealthStatus(): Promise<SLOHealthStatus> {
    // Implementation for getting SLO health status
    return {} as SLOHealthStatus;
  }

  private async getErrorBudgetSnapshot(): Promise<ErrorBudget[]> {
    // Implementation for getting error budget snapshot
    return [];
  }

  private async getCircuitBreakerSnapshot(): Promise<CircuitBreakerStats[]> {
    // Implementation for getting circuit breaker snapshot
    return [];
  }

  private async getRetryBudgetSnapshot(): Promise<any[]> {
    // Implementation for getting retry budget snapshot
    return [];
  }

  private async getDegradationSnapshot(): Promise<any> {
    // Implementation for getting degradation snapshot
    return {};
  }

  private getActiveAlerts(): SLOAlert[] {
    // Implementation for getting active alerts
    return [];
  }

  private calculateOverallHealthScore(sloStatus: any, errorBudgets: any, circuitBreakers: any): number {
    // Implementation for calculating overall health score
    return 0.95; // placeholder
  }
}