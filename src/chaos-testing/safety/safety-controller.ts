/**
 * Safety Controller and Blast Radius Management
 *
 * This module provides comprehensive safety mechanisms for chaos testing,
 * including blast radius control, emergency shutdown, and safety monitoring.
 */

import { EventEmitter } from 'events';
import {
  ChaosExperimentConfig,
  ChaosScenario,
  ExperimentExecutionContext,
  SafetyCheck,
  BlastRadiusControl,
  FailSafe,
  SafetyContext,
  SystemMetrics
} from '../types/chaos-testing-types';

export interface SafetyViolation {
  id: string;
  type: 'threshold_exceeded' | 'health_check_failed' | 'manual_abort' | 'system_limit_reached';
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  timestamp: Date;
  metrics?: SystemMetrics;
  component?: string;
  threshold?: number;
  actualValue?: number;
}

export interface SafetyState {
  enabled: boolean;
  emergencyShutdown: boolean;
  activeViolations: SafetyViolation[];
  blastRadiusContained: boolean;
  systemHealth: 'healthy' | 'degraded' | 'critical' | 'shutdown';
  lastSafetyCheck: Date;
}

export interface BlastRadiusMetrics {
  affectedComponents: string[];
  isolatedZones: string[];
  userImpact: {
    affectedUsers: number;
    totalUsers: number;
    impactPercentage: number;
  };
  businessImpact: {
    revenueImpact: number;
    customerSatisfactionImpact: number;
  };
  systemImpact: {
    availabilityImpact: number;
    performanceImpact: number;
    dataIntegrityRisk: number;
  };
}

export class SafetyController extends EventEmitter {
  private safetyState: SafetyState;
  private blastRadiusControl: BlastRadiusControl;
  private safetyContext: SafetyContext;
  private activeExperiments: Set<string> = new Set();
  private safetyCheckInterval?: NodeJS.Timeout;
  private blastRadiusMonitor?: NodeJS.Timeout;

  constructor() {
    super();
    this.initializeSafetyState();
    this.setupEventHandlers();
  }

  /**
   * Initialize safety controller for an experiment
   */
  async initializeForExperiment(
    experimentId: string,
    config: ChaosExperimentConfig,
    context: ExperimentExecutionContext
  ): Promise<void> {
    this.activeExperiments.add(experimentId);

    // Configure blast radius control
    this.blastRadiusControl = {
      maxAffectedComponents: this.calculateMaxAffectedComponents(config),
      isolationZones: this.defineIsolationZones(config),
      failSafes: this.configureFailSafes(config)
    };

    // Configure safety context
    this.safetyContext = {
      emergencyShutdown: false,
      maxAllowedDowntime: config.duration * 0.1, // 10% of experiment duration
      maxAllowedErrorRate: this.calculateMaxErrorRate(config),
      healthCheckEndpoints: this.getHealthCheckEndpoints(),
      rollbackProcedures: this.getRollbackProcedures()
    };

    // Reset safety state
    this.safetyState.enabled = true;
    this.safetyState.emergencyShutdown = false;
    this.safetyState.activeViolations = [];
    this.safetyState.blastRadiusContained = true;

    this.emit('safety:initialized', { experimentId, config });

    // Start safety monitoring
    this.startSafetyMonitoring(experimentId);
    this.startBlastRadiusMonitoring(experimentId);
  }

  /**
   * Validate experiment safety before execution
   */
  async validateExperimentSafety(
    experimentId: string,
    config: ChaosExperimentConfig,
    scenario: ChaosScenario,
    context: ExperimentExecutionContext
  ): Promise<{
    safe: boolean;
    violations: SafetyViolation[];
    recommendations: string[];
  }> {
    const violations: SafetyViolation[] = [];
    const recommendations: string[] = [];

    // Check basic safety constraints
    if (context.environment === 'production' && config.severity === 'critical') {
      violations.push(this.createViolation(
        'threshold_exceeded',
        'critical',
        'Critical severity experiments not allowed in production environment'
      ));
    }

    // Check concurrent experiment limits
    if (this.activeExperiments.size > 2) {
      violations.push(this.createViolation(
        'system_limit_reached',
        'high',
        'Too many concurrent experiments running'
      ));
      recommendations.push('Wait for other experiments to complete');
    }

    // Check blast radius constraints
    const blastRadiusCheck = await this.validateBlastRadius(scenario, config);
    if (!blastRadiusCheck.safe) {
      violations.push(...blastRadiusCheck.violations);
    }

    // Check system health before starting
    const healthCheck = await this.performSystemHealthCheck();
    if (!healthCheck.healthy) {
      violations.push(this.createViolation(
        'health_check_failed',
        'high',
        'System health check failed: ' + healthCheck.issues.join(', ')
      ));
      recommendations.push('Resolve system health issues before running experiment');
    }

    // Check resource availability
    const resourceCheck = await this.checkResourceAvailability(config);
    if (!resourceCheck.available) {
      violations.push(this.createViolation(
        'system_limit_reached',
        'medium',
        'Insufficient resources: ' + resourceCheck.constraints.join(', ')
      ));
      recommendations.push('Free up system resources or reduce experiment intensity');
    }

    // Validate against business hours and critical periods
    const businessCheck = await this.validateBusinessContext(context);
    if (!businessCheck.safe) {
      violations.push(this.createViolation(
        'threshold_exceeded',
        'medium',
        'Experiment not safe during current business period: ' + businessCheck.reason
      ));
      recommendations.push('Schedule experiment during off-peak hours');
    }

    return {
      safe: violations.length === 0,
      violations,
      recommendations
    };
  }

  /**
   * Monitor safety during experiment execution
   */
  async monitorExperimentSafety(experimentId: string): Promise<void> {
    if (!this.safetyState.enabled || this.safetyState.emergencyShutdown) {
      return;
    }

    try {
      // Check safety thresholds
      const thresholdViolations = await this.checkSafetyThresholds();
      for (const violation of thresholdViolations) {
        await this.handleSafetyViolation(experimentId, violation);
      }

      // Check system health
      const healthViolations = await this.checkSystemHealth();
      for (const violation of healthViolations) {
        await this.handleSafetyViolation(experimentId, violation);
      }

      // Check blast radius containment
      const blastRadiusViolations = await this.checkBlastRadiusContainment();
      for (const violation of blastRadiusViolations) {
        await this.handleSafetyViolation(experimentId, violation);
      }

      // Update safety state
      this.safetyState.lastSafetyCheck = new Date();
      this.safetyState.systemHealth = await this.calculateSystemHealth();

    } catch (error) {
      this.emit('safety:monitoring_error', { experimentId, error });
    }
  }

  /**
   * Handle safety violation
   */
  async handleSafetyViolation(
    experimentId: string,
    violation: SafetyViolation
  ): Promise<void> {
    this.safetyState.activeViolations.push(violation);
    this.emit('safety:violation_detected', { experimentId, violation });

    // Determine response based on severity
    switch (violation.severity) {
      case 'critical':
        await this.triggerEmergencyShutdown(experimentId, violation);
        break;
      case 'high':
        await this.triggerAbortSequence(experimentId, violation);
        break;
      case 'medium':
        await this.triggerMitigationSequence(experimentId, violation);
        break;
      case 'low':
        await this.logViolation(experimentId, violation);
        break;
    }
  }

  /**
   * Trigger emergency shutdown
   */
  async triggerEmergencyShutdown(
    experimentId: string,
    violation: SafetyViolation
  ): Promise<void> {
    this.safetyState.emergencyShutdown = true;
    this.safetyContext.emergencyShutdown = true;

    this.emit('safety:emergency_shutdown_triggered', { experimentId, violation });

    // Execute emergency shutdown procedures
    await this.executeEmergencyShutdownProcedures();

    // Execute rollback procedures
    await this.executeRollbackProcedures(experimentId);

    // Verify system stability
    await this.verifyPostShutdownStability();

    this.emit('safety:emergency_shutdown_completed', { experimentId });
  }

  /**
   * Trigger experiment abort sequence
   */
  async triggerAbortSequence(
    experimentId: string,
    violation: SafetyViolation
  ): Promise<void> {
    this.emit('safety:abort_triggered', { experimentId, violation });

    // Execute abort procedures
    await this.executeAbortProcedures(experimentId);

    this.emit('safety:abort_completed', { experimentId });
  }

  /**
   * Trigger mitigation sequence
   */
  async triggerMitigationSequence(
    experimentId: string,
    violation: SafetyViolation
  ): Promise<void> {
    this.emit('safety:mitigation_triggered', { experimentId, violation });

    // Execute mitigation procedures
    await this.executeMitigationProcedures(experimentId, violation);

    this.emit('safety:mitigation_completed', { experimentId });
  }

  /**
   * Monitor blast radius containment
   */
  async monitorBlastRadiusContainment(experimentId: string): Promise<void> {
    const blastRadiusMetrics = await this.calculateBlastRadiusMetrics();

    // Check if blast radius is contained
    const contained = await this.verifyBlastRadiusContainment(blastRadiusMetrics);
    this.safetyState.blastRadiusContained = contained;

    if (!contained) {
      const violation = this.createViolation(
        'threshold_exceeded',
        'high',
        `Blast radius containment failed. Affected components: ${blastRadiusMetrics.affectedComponents.join(', ')}`
      );

      await this.handleSafetyViolation(experimentId, violation);
    }

    this.emit('safety:blast_radius_checked', {
      experimentId,
      metrics: blastRadiusMetrics,
      contained
    });
  }

  /**
   * Calculate blast radius metrics
   */
  async calculateBlastRadiusMetrics(): Promise<BlastRadiusMetrics> {
    // Implementation would calculate actual blast radius metrics
    return {
      affectedComponents: ['qdrant', 'api-gateway'],
      isolatedZones: ['chaos-testing-zone'],
      userImpact: {
        affectedUsers: 100,
        totalUsers: 10000,
        impactPercentage: 1.0
      },
      businessImpact: {
        revenueImpact: 0.01,
        customerSatisfactionImpact: 0.05
      },
      systemImpact: {
        availabilityImpact: 2.0,
        performanceImpact: 15.0,
        dataIntegrityRisk: 0.1
      }
    };
  }

  /**
   * Verify blast radius containment
   */
  async verifyBlastRadiusContainment(metrics: BlastRadiusMetrics): Promise<boolean> {
    // Check against blast radius control limits
    if (metrics.affectedComponents.length > this.blastRadiusControl.maxAffectedComponents) {
      return false;
    }

    // Check user impact
    if (metrics.userImpact.impactPercentage > 5) { // 5% user impact threshold
      return false;
    }

    // Check business impact
    if (metrics.businessImpact.revenueImpact > 0.1) { // 10% revenue impact threshold
      return false;
    }

    return true;
  }

  /**
   * Clean up safety controller for experiment
   */
  async cleanupExperiment(experimentId: string): Promise<void> {
    this.activeExperiments.delete(experimentId);

    // Stop monitoring
    if (this.safetyCheckInterval) {
      clearInterval(this.safetyCheckInterval);
      this.safetyCheckInterval = undefined;
    }

    if (this.blastRadiusMonitor) {
      clearInterval(this.blastRadiusMonitor);
      this.blastRadiusMonitor = undefined;
    }

    // Reset safety state if no active experiments
    if (this.activeExperiments.size === 0) {
      this.safetyState.enabled = false;
      this.safetyState.emergencyShutdown = false;
      this.safetyState.activeViolations = [];
    }

    this.emit('safety:cleanup_completed', { experimentId });
  }

  /**
   * Get current safety state
   */
  getSafetyState(): SafetyState {
    return { ...this.safetyState };
  }

  /**
   * Get active safety violations
   */
  getActiveViolations(): SafetyViolation[] {
    return [...this.safetyState.activeViolations];
  }

  /**
   * Manual emergency shutdown trigger
   */
  async triggerManualEmergencyShutdown(reason: string): Promise<void> {
    const violation = this.createViolation(
      'manual_abort',
      'critical',
      `Manual emergency shutdown triggered: ${reason}`
    );

    for (const experimentId of this.activeExperiments) {
      await this.triggerEmergencyShutdown(experimentId, violation);
    }
  }

  // Private helper methods

  private initializeSafetyState(): void {
    this.safetyState = {
      enabled: false,
      emergencyShutdown: false,
      activeViolations: [],
      blastRadiusContained: true,
      systemHealth: 'healthy',
      lastSafetyCheck: new Date()
    };
  }

  private setupEventHandlers(): void {
    // Setup event handlers for safety-related events
  }

  private calculateMaxAffectedComponents(config: ChaosExperimentConfig): number {
    switch (config.blastRadius) {
      case 'component':
        return 1;
      case 'service':
        return 3;
      case 'cluster':
        return 10;
      default:
        return 1;
    }
  }

  private defineIsolationZones(config: ChaosExperimentConfig): string[] {
    return ['chaos-testing-zone', 'monitoring-zone'];
  }

  private configureFailSafes(config: ChaosExperimentConfig): FailSafe[] {
    return [
      {
        trigger: 'error_rate > 10%',
        action: 'abort_experiment',
        threshold: 10
      },
      {
        trigger: 'response_time > 5s',
        action: 'reduce_intensity',
        threshold: 5000
      },
      {
        trigger: 'availability < 95%',
        action: 'abort_experiment',
        threshold: 95
      }
    ];
  }

  private calculateMaxErrorRate(config: ChaosExperimentConfig): number {
    switch (config.severity) {
      case 'low':
        return 5; // 5%
      case 'medium':
        return 10; // 10%
      case 'high':
        return 20; // 20%
      case 'critical':
        return 30; // 30%
      default:
        return 10;
    }
  }

  private getHealthCheckEndpoints(): string[] {
    return [
      '/health',
      '/api/health',
      '/monitoring/health',
      '/qdrant/health'
    ];
  }

  private getRollbackProcedures(): string[] {
    return [
      'rollback-chaos-injection',
      'restore-configuration',
      'restart-services',
      'verify-system-health'
    ];
  }

  private startSafetyMonitoring(experimentId: string): void {
    this.safetyCheckInterval = setInterval(async () => {
      await this.monitorExperimentSafety(experimentId);
    }, 5000); // Check every 5 seconds
  }

  private startBlastRadiusMonitoring(experimentId: string): void {
    this.blastRadiusMonitor = setInterval(async () => {
      await this.monitorBlastRadiusContainment(experimentId);
    }, 10000); // Check every 10 seconds
  }

  private createViolation(
    type: SafetyViolation['type'],
    severity: SafetyViolation['severity'],
    message: string
  ): SafetyViolation {
    return {
      id: `violation_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      type,
      severity,
      message,
      timestamp: new Date()
    };
  }

  private async validateBlastRadius(
    scenario: ChaosScenario,
    config: ChaosExperimentConfig
  ): Promise<{ safe: boolean; violations: SafetyViolation[] }> {
    const violations: SafetyViolation[] = [];

    // Check if scenario affects critical components
    const criticalComponents = ['authentication', 'payment', 'user-data'];
    const affectedCritical = criticalComponents.filter(comp =>
      scenario.injectionPoint.component.includes(comp)
    );

    if (affectedCritical.length > 0) {
      violations.push(this.createViolation(
        'threshold_exceeded',
        'high',
        `Scenario affects critical components: ${affectedCritical.join(', ')}`
      ));
    }

    return {
      safe: violations.length === 0,
      violations
    };
  }

  private async performSystemHealthCheck(): Promise<{
    healthy: boolean;
    issues: string[];
  }> {
    // Implementation would perform actual health checks
    return {
      healthy: true,
      issues: []
    };
  }

  private async checkResourceAvailability(config: ChaosExperimentConfig): Promise<{
    available: boolean;
    constraints: string[];
  }> {
    // Implementation would check actual resource availability
    return {
      available: true,
      constraints: []
    };
  }

  private async validateBusinessContext(context: ExperimentExecutionContext): Promise<{
    safe: boolean;
    reason: string;
  }> {
    // Implementation would validate business hours, critical periods, etc.
    return {
      safe: true,
      reason: ''
    };
  }

  private async checkSafetyThresholds(): Promise<SafetyViolation[]> {
    const violations: SafetyViolation[] = [];

    // Check error rate
    const currentErrorRate = await this.getCurrentErrorRate();
    if (currentErrorRate > this.safetyContext.maxAllowedErrorRate) {
      violations.push(this.createViolation(
        'threshold_exceeded',
        'high',
        `Error rate exceeded threshold: ${currentErrorRate}% > ${this.safetyContext.maxAllowedErrorRate}%`
      ));
    }

    // Check downtime
    const currentDowntime = await this.getCurrentDowntime();
    if (currentDowntime > this.safetyContext.maxAllowedDowntime) {
      violations.push(this.createViolation(
        'threshold_exceeded',
        'high',
        `Downtime exceeded threshold: ${currentDowntime}ms > ${this.safetyContext.maxAllowedDowntime}ms`
      ));
    }

    return violations;
  }

  private async checkSystemHealth(): Promise<SafetyViolation[]> {
    const violations: SafetyViolation[] = [];

    // Check health endpoints
    for (const endpoint of this.safetyContext.healthCheckEndpoints) {
      const healthy = await this.checkHealthEndpoint(endpoint);
      if (!healthy) {
        violations.push(this.createViolation(
          'health_check_failed',
          'medium',
          `Health check failed for endpoint: ${endpoint}`
        ));
      }
    }

    return violations;
  }

  private async checkBlastRadiusContainment(): Promise<SafetyViolation[]> {
    const violations: SafetyViolation[] = [];

    const blastRadiusMetrics = await this.calculateBlastRadiusMetrics();
    const contained = await this.verifyBlastRadiusContainment(blastRadiusMetrics);

    if (!contained) {
      violations.push(this.createViolation(
        'threshold_exceeded',
        'high',
        'Blast radius containment failure'
      ));
    }

    return violations;
  }

  private async calculateSystemHealth(): Promise<SafetyState['systemHealth']> {
    const violations = this.safetyState.activeViolations;
    const criticalViolations = violations.filter(v => v.severity === 'critical');
    const highViolations = violations.filter(v => v.severity === 'high');

    if (criticalViolations.length > 0) {
      return 'shutdown';
    } else if (highViolations.length > 0) {
      return 'critical';
    } else if (violations.length > 0) {
      return 'degraded';
    } else {
      return 'healthy';
    }
  }

  private async executeEmergencyShutdownProcedures(): Promise<void> {
    // Implementation would execute emergency shutdown procedures
  }

  private async executeRollbackProcedures(experimentId: string): Promise<void> {
    // Implementation would execute rollback procedures
  }

  private async verifyPostShutdownStability(): Promise<void> {
    // Implementation would verify system stability after shutdown
  }

  private async executeAbortProcedures(experimentId: string): Promise<void> {
    // Implementation would execute abort procedures
  }

  private async executeMitigationProcedures(
    experimentId: string,
    violation: SafetyViolation
  ): Promise<void> {
    // Implementation would execute mitigation procedures based on violation type
  }

  private async logViolation(experimentId: string, violation: SafetyViolation): Promise<void> {
    // Implementation would log low-severity violations
  }

  private async getCurrentErrorRate(): Promise<number> {
    // Implementation would get current error rate from monitoring
    return 0;
  }

  private async getCurrentDowntime(): Promise<number> {
    // Implementation would calculate current downtime
    return 0;
  }

  private async checkHealthEndpoint(endpoint: string): Promise<boolean> {
    // Implementation would check specific health endpoint
    return true;
  }
}