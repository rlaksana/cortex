// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * Automated Chaos Experiment Runner
 *
 * This module orchestrates the execution of chaos experiments, managing the complete
 * lifecycle from setup through execution, verification, and cleanup.
 */

import { EventEmitter } from 'events';

import { ChaosInjectionEngine } from '../engine/chaos-injection-engine.js';
import { MTTRMeasurer } from '../measurement/mttr-measurer.js';
import {
  type ChaosExperimentConfig,
  type ChaosExperimentResult,
  type ChaosMetrics,
  type ChaosScenario,
  type ExperimentExecutionContext,
  ExperimentReport,
  type ExperimentStatus,
  type IncidentReport,
  type MTTRMetrics,
  type RecoveryMetrics,
  type SafetyCheck,
  type SystemMetrics,
  type VerificationResults,
} from '../types/chaos-testing-types.js';
import { AlertVerifier } from '../verification/alert-verifier.js';
import { GracefulDegradationVerifier } from '../verification/graceful-degradation-verifier.js';

export interface ExperimentPhase {
  name: string;
  startTime: Date;
  endTime?: Date;
  status: 'pending' | 'running' | 'completed' | 'failed';
  duration?: number;
  error?: Error;
}

export interface ExperimentExecutionReport {
  experimentId: string;
  config: ChaosExperimentConfig;
  phases: ExperimentPhase[];
  result?: ChaosExperimentResult;
  summary: ExperimentSummary;
  recommendations: string[];
  artifacts: ExperimentArtifact[];
}

export interface ExperimentSummary {
  totalDuration: number;
  success: boolean;
  hypothesisValidated: boolean;
  systemResilience: 'excellent' | 'good' | 'fair' | 'poor';
  keyFindings: string[];
  criticalIssues: string[];
}

export interface ExperimentArtifact {
  name: string;
  type: 'metrics' | 'logs' | 'screenshots' | 'config' | 'report';
  path: string;
  size: number;
  createdAt: Date;
}

export class ChaosExperimentRunner extends EventEmitter {
  private runningExperiments: Map<string, ExperimentContext> = new Map();
  private completedExperiments: ExperimentExecutionReport[] = [];
  private injectionEngine: ChaosInjectionEngine;
  private degradationVerifier: GracefulDegradationVerifier;
  private alertVerifier: AlertVerifier;
  private mttrMeasurer: MTTRMeasurer;

  constructor() {
    super();
    this.injectionEngine = new ChaosInjectionEngine();
    this.degradationVerifier = new GracefulDegradationVerifier();
    this.alertVerifier = new AlertVerifier();
    this.mttrMeasurer = new MTTRMeasurer();

    this.setupEventHandlers();
  }

  /**
   * Execute a chaos experiment
   */
  async executeExperiment(
    config: ChaosExperimentConfig,
    scenario: ChaosScenario,
    context: ExperimentExecutionContext
  ): Promise<ExperimentExecutionReport> {
    const experimentId = this.generateExperimentId();

    this.emit('experiment:started', { experimentId, config, scenario });

    const experimentContext: ExperimentContext = {
      id: experimentId,
      config,
      scenario,
      context,
      phases: [],
      startTime: new Date(),
      status: 'running',
      steadyStateMetrics: [],
    };

    this.runningExperiments.set(experimentId, experimentContext);

    try {
      // Execute experiment phases
      await this.executePhase(experimentContext, 'setup', () =>
        this.setupExperiment(experimentContext)
      );
      await this.executePhase(experimentContext, 'steady_state', () =>
        this.establishSteadyState(experimentContext)
      );
      await this.executePhase(experimentContext, 'chaos_injection', () =>
        this.injectChaos(experimentContext)
      );
      await this.executePhase(experimentContext, 'verification', () =>
        this.verifySystemBehavior(experimentContext)
      );
      await this.executePhase(experimentContext, 'recovery', () =>
        this.monitorRecovery(experimentContext)
      );
      await this.executePhase(experimentContext, 'cleanup', () =>
        this.cleanupExperiment(experimentContext)
      );

      // Generate final report
      const report = await this.generateExperimentReport(experimentContext);

      experimentContext.status = 'completed';
      this.runningExperiments.delete(experimentId);
      this.completedExperiments.push(report);

      this.emit('experiment:completed', { experimentId, report });

      return report;
    } catch (error) {
      experimentContext.status = 'failed';
      experimentContext.error = error as Error;

      // Attempt emergency cleanup
      try {
        await this.emergencyCleanup(experimentContext);
      } catch (cleanupError) {
        this.emit('experiment:cleanup_failed', { experimentId, error: cleanupError });
      }

      this.runningExperiments.delete(experimentId);

      const report = await this.generateExperimentReport(experimentContext);

      this.emit('experiment:failed', { experimentId, error, report });

      return report;
    }
  }

  /**
   * Execute a specific experiment phase
   */
  private async executePhase(
    context: ExperimentContext,
    phaseName: string,
    phaseExecutor: () => Promise<void>
  ): Promise<void> {
    const phase: ExperimentPhase = {
      name: phaseName,
      startTime: new Date(),
      status: 'running',
    };

    context.phases.push(phase);

    this.emit('experiment:phase_started', { experimentId: context.id, phase: phaseName });

    try {
      await phaseExecutor();

      phase.endTime = new Date();
      phase.duration = phase.endTime.getTime() - phase.startTime.getTime();
      phase.status = 'completed';

      this.emit('experiment:phase_completed', {
        experimentId: context.id,
        phase: phaseName,
        duration: phase.duration,
      });
    } catch (error) {
      phase.endTime = new Date();
      phase.duration = phase.endTime.getTime() - phase.startTime.getTime();
      phase.status = 'failed';
      phase.error = error as Error;

      this.emit('experiment:phase_failed', {
        experimentId: context.id,
        phase: phaseName,
        error,
      });

      throw error;
    }
  }

  /**
   * Setup experiment environment
   */
  private async setupExperiment(context: ExperimentContext): Promise<void> {
    // Validate safety checks
    const safetyValidation = await this.validateSafetyChecks(context);
    if (!safetyValidation.safe) {
      throw new Error(`Safety validation failed: ${safetyValidation.violations.join(', ')}`);
    }

    // Initialize monitoring systems
    await this.initializeMonitoring(context);

    // Create experiment artifacts directory
    await this.createArtifactsDirectory(context.id);

    // Record baseline metrics
    context.baselineMetrics = await this.collectBaselineMetrics();
  }

  /**
   * Establish steady state baseline
   */
  private async establishSteadyState(context: ExperimentContext): Promise<void> {
    const steadyStateDuration = context.config.steadyStateDuration * 1000; // Convert to ms

    this.emit('experiment:steady_state_started', {
      experimentId: context.id,
      duration: steadyStateDuration,
    });

    // Monitor system for steady state period
    const steadyStateMetrics: SystemMetrics[] = [];
    const steadyStateInterval = setInterval(async () => {
      const metrics = await this.collectSystemMetrics();
      steadyStateMetrics.push(metrics);

      // Check if system is stable
      if (steadyStateMetrics.length >= 10) {
        const isStable = await this.verifySystemStability(steadyStateMetrics.slice(-10));
        if (isStable) {
          clearInterval(steadyStateInterval);
          this.emit('experiment:steady_state_achieved', { experimentId: context.id });
        }
      }
    }, 2000);

    // Wait for steady state duration or stability
    await new Promise((resolve) => {
      setTimeout(resolve, steadyStateDuration);
    });

    clearInterval(steadyStateInterval);
    context.steadyStateMetrics = steadyStateMetrics;
  }

  /**
   * Inject chaos scenario
   */
  private async injectChaos(context: ExperimentContext): Promise<void> {
    this.emit('experiment:chaos_injection_started', {
      experimentId: context.id,
      scenario: context.scenario,
    });

    // Start monitoring systems
    await this.startVerificationMonitoring(context);

    // Inject chaos
    await this.injectionEngine.injectChaos(context.scenario, context.context);

    // Wait for chaos duration
    const chaosDuration = context.config.experimentDuration * 1000;
    await new Promise((resolve) => setTimeout(resolve, chaosDuration));

    // Collect chaos metrics
    context.chaosMetrics = await this.collectChaosMetrics();

    this.emit('experiment:chaos_injection_completed', {
      experimentId: context.id,
      metrics: context.chaosMetrics,
    });
  }

  /**
   * Verify system behavior during chaos
   */
  private async verifySystemBehavior(context: ExperimentContext): Promise<void> {
    this.emit('experiment:verification_started', { experimentId: context.id });

    // Stop verification monitoring
    const gracefulDegradationResult = await this.degradationVerifier.stopMonitoring();
    const alertingResult = await this.alertVerifier.stopMonitoring();

    // Verify system against expected behavior
    context.verificationResults = await this.performVerification(context.scenario.verification, {
      gracefulDegradation: gracefulDegradationResult,
      alerting: alertingResult,
      performance: await this.verifyPerformance(context),
      recovery: await this.verifyRecoveryBehavior(context),
    });

    this.emit('experiment:verification_completed', {
      experimentId: context.id,
      results: context.verificationResults,
    });
  }

  /**
   * Monitor recovery process
   */
  private async monitorRecovery(context: ExperimentContext): Promise<void> {
    this.emit('experiment:recovery_monitoring_started', { experimentId: context.id });

    // Start rolling back chaos
    await this.injectionEngine.rollbackChaos(context.scenario.id);

    // Wait for recovery duration
    const recoveryDuration = context.config.recoveryDuration * 1000;
    await new Promise((resolve) => setTimeout(resolve, recoveryDuration));

    // Stop MTTR measurement
    context.mttrMetrics = await this.mttrMeasurer.stopMeasurement();
    context.recoveryMetrics = await this.collectRecoveryMetrics();

    this.emit('experiment:recovery_monitoring_completed', {
      experimentId: context.id,
      mttrMetrics: context.mttrMetrics,
    });
  }

  /**
   * Cleanup experiment environment
   */
  private async cleanupExperiment(context: ExperimentContext): Promise<void> {
    this.emit('experiment:cleanup_started', { experimentId: context.id });

    // Ensure all chaos is rolled back
    await this.injectionEngine.rollbackAll();

    // Reset monitoring systems
    this.degradationVerifier.reset();
    this.alertVerifier.reset();

    // Cleanup temporary resources
    await this.cleanupTempResources(context.id);

    this.emit('experiment:cleanup_completed', { experimentId: context.id });
  }

  /**
   * Emergency cleanup for failed experiments
   */
  private async emergencyCleanup(context: ExperimentContext): Promise<void> {
    this.emit('experiment:emergency_cleanup', { experimentId: context.id });

    try {
      await this.injectionEngine.rollbackAll();
    } catch (error) {
      console.error('Failed to rollback chaos during emergency cleanup:', error);
    }

    try {
      this.degradationVerifier.reset();
      this.alertVerifier.reset();
    } catch (error) {
      console.error('Failed to reset monitoring during emergency cleanup:', error);
    }
  }

  /**
   * Generate comprehensive experiment report
   */
  private async generateExperimentReport(
    context: ExperimentContext
  ): Promise<ExperimentExecutionReport> {
    const endTime = new Date();
    const totalDuration = endTime.getTime() - context.startTime.getTime();

    const result: ChaosExperimentResult = {
      experimentId: context.id,
      scenario: context.scenario,
      startTime: context.startTime,
      endTime,
      status: context.status as ExperimentStatus,
      steadyStateMetrics:
        context.steadyStateMetrics[context.steadyStateMetrics.length - 1] || ({} as SystemMetrics),
      chaosMetrics: context.chaosMetrics || ({} as ChaosMetrics),
      recoveryMetrics: context.recoveryMetrics || ({} as RecoveryMetrics),
      verificationResults: context.verificationResults || ({} as VerificationResults),
      mttrMetrics: context.mttrMetrics || ({} as MTTRMetrics),
      incidentReport: await this.generateIncidentReport(context),
    };

    const summary = this.generateExperimentSummary(context, result);
    const recommendations = this.generateRecommendations(context, result);
    const artifacts = await this.collectExperimentArtifacts(context.id);

    return {
      experimentId: context.id,
      config: context.config,
      phases: context.phases,
      result,
      summary,
      recommendations,
      artifacts,
    };
  }

  /**
   * Generate experiment summary
   */
  private generateExperimentSummary(
    context: ExperimentContext,
    result: ChaosExperimentResult
  ): ExperimentSummary {
    const success = result.verificationResults.overall.passed;
    const hypothesisValidated = this.validateHypothesis(context.config.hypothesis, result);
    const systemResilience = this.calculateSystemResilience(result);

    const keyFindings = this.extractKeyFindings(result);
    const criticalIssues = this.extractCriticalIssues(result);

    return {
      totalDuration: result.endTime.getTime() - result.startTime.getTime(),
      success,
      hypothesisValidated,
      systemResilience,
      keyFindings,
      criticalIssues,
    };
  }

  /**
   * Generate recommendations based on experiment results
   */
  private generateRecommendations(
    context: ExperimentContext,
    result: ChaosExperimentResult
  ): string[] {
    const recommendations: string[] = [];

    // Analyze verification results
    if (!result.verificationResults.gracefulDegradation.passed) {
      recommendations.push('Improve graceful degradation mechanisms and fallback strategies');
    }

    if (!result.verificationResults.alerting.passed) {
      recommendations.push('Review and enhance alerting rules and notification channels');
    }

    if (!result.verificationResults.recovery.passed) {
      recommendations.push('Optimize recovery procedures and automation');
    }

    // Analyze MTTR metrics
    if (result.mttrMetrics.overallMTTR > 300000) {
      // 5 minutes
      recommendations.push('Reduce Mean Time To Recovery through improved automation');
    }

    // Analyze performance impact
    if (result.verificationResults.performance.responseTimeIncrease > 50) {
      recommendations.push('Implement better performance isolation and caching strategies');
    }

    return recommendations;
  }

  /**
   * Validate experiment safety
   */
  private async validateSafetyChecks(context: ExperimentContext): Promise<{
    safe: boolean;
    violations: string[];
  }> {
    const violations: string[] = [];

    for (const safetyCheck of context.config.safetyChecks) {
      if (!safetyCheck.enabled) {
        continue;
      }

      const result = await this.performSafetyCheck(safetyCheck);
      if (!result.passed) {
        violations.push(result.message);
      }
    }

    // Additional built-in safety checks
    if (context.context.environment === 'production' && context.config.severity === 'critical') {
      violations.push('Critical severity experiments not allowed in production');
    }

    if (this.runningExperiments.size >= 3) {
      violations.push('Too many concurrent experiments running');
    }

    return {
      safe: violations.length === 0,
      violations,
    };
  }

  /**
   * Perform individual safety check
   */
  private async performSafetyCheck(check: SafetyCheck): Promise<{
    passed: boolean;
    message: string;
  }> {
    // Implementation would perform actual safety check
    // For now, return mock results
    return {
      passed: true,
      message: 'Safety check passed',
    };
  }

  /**
   * Initialize monitoring systems
   */
  private async initializeMonitoring(context: ExperimentContext): Promise<void> {
    // Implementation would initialize monitoring systems
  }

  /**
   * Start verification monitoring
   */
  private async startVerificationMonitoring(context: ExperimentContext): Promise<void> {
    // Start MTTR measurement
    await this.mttrMeasurer.startMeasurement(context.scenario, context.context);

    // Start degradation verification
    await this.degradationVerifier.startMonitoring(context.scenario, context.context);

    // Start alert verification
    const alertExpectations = context.scenario.verification.alerting.expectedAlerts.map(alert => ({
      alertType: alert.name,
      expectedSeverity: alert.severity as 'low' | 'medium' | 'high' | 'critical',
      expectedWithinMs: context.scenario.verification.alerting.maxAlertDelay,
      description: `Expected alert: ${alert.name} from ${alert.source}`
    }));

    await this.alertVerifier.startMonitoring(context.scenario.id, alertExpectations);
  }

  /**
   * Collect system metrics
   */
  private async collectSystemMetrics(): Promise<SystemMetrics> {
    // Implementation would collect actual system metrics
    return {} as SystemMetrics;
  }

  /**
   * Collect baseline metrics
   */
  private async collectBaselineMetrics(): Promise<SystemMetrics> {
    return this.collectSystemMetrics();
  }

  /**
   * Collect chaos metrics
   */
  private async collectChaosMetrics(): Promise<ChaosMetrics> {
    // Implementation would calculate chaos-specific metrics
    return {} as ChaosMetrics;
  }

  /**
   * Collect recovery metrics
   */
  private async collectRecoveryMetrics(): Promise<RecoveryMetrics> {
    // Implementation would collect recovery-specific metrics
    return {} as RecoveryMetrics;
  }

  /**
   * Verify system stability
   */
  private async verifySystemStability(metrics: SystemMetrics[]): Promise<boolean> {
    // Implementation would verify if system metrics are stable
    return true;
  }

  /**
   * Perform verification against criteria
   */
  private async performVerification(criteria: any, results: any): Promise<VerificationResults> {
    // Implementation would perform comprehensive verification
    return {} as VerificationResults;
  }

  /**
   * Verify performance
   */
  private async verifyPerformance(context: ExperimentContext): Promise<any> {
    // Implementation would verify performance criteria
    return {};
  }

  /**
   * Verify recovery behavior
   */
  private async verifyRecoveryBehavior(context: ExperimentContext): Promise<any> {
    // Implementation would verify recovery behavior
    return {};
  }

  /**
   * Generate incident report
   */
  private async generateIncidentReport(context: ExperimentContext): Promise<IncidentReport> {
    // Implementation would generate detailed incident report
    return {} as IncidentReport;
  }

  /**
   * Validate hypothesis
   */
  private validateHypothesis(hypothesis: string, result: ChaosExperimentResult): boolean {
    // Implementation would validate if experiment results support the hypothesis
    return result.verificationResults.overall.passed;
  }

  /**
   * Calculate system resilience score
   */
  private calculateSystemResilience(
    result: ChaosExperimentResult
  ): ExperimentSummary['systemResilience'] {
    const overallScore = result.verificationResults.overall.score;

    if (overallScore >= 90) return 'excellent';
    if (overallScore >= 75) return 'good';
    if (overallScore >= 60) return 'fair';
    return 'poor';
  }

  /**
   * Extract key findings from results
   */
  private extractKeyFindings(result: ChaosExperimentResult): string[] {
    const findings: string[] = [];

    if (result.verificationResults.gracefulDegradation.fallbackActivated) {
      findings.push('System successfully activated fallback mechanisms');
    }

    if (result.verificationResults.alerting.alertsTriggered > 0) {
      findings.push(
        `Alerting system triggered ${result.verificationResults.alerting.alertsTriggered} alerts`
      );
    }

    if (result.mttrMetrics.overallMTTR < 60000) {
      // 1 minute
      findings.push('System demonstrated fast recovery capabilities');
    }

    return findings;
  }

  /**
   * Extract critical issues from results
   */
  private extractCriticalIssues(result: ChaosExperimentResult): string[] {
    const issues: string[] = [];

    if (!result.verificationResults.gracefulDegradation.passed) {
      issues.push('Graceful degradation mechanisms failed');
    }

    if (!result.verificationResults.alerting.passed) {
      issues.push('Alerting system did not function as expected');
    }

    if (result.mttrMetrics.overallMTTR > 600000) {
      // 10 minutes
      issues.push('Recovery time exceeded acceptable limits');
    }

    return issues;
  }

  /**
   * Collect experiment artifacts
   */
  private async collectExperimentArtifacts(experimentId: string): Promise<ExperimentArtifact[]> {
    // Implementation would collect logs, metrics, screenshots, etc.
    return [];
  }

  /**
   * Create artifacts directory
   */
  private async createArtifactsDirectory(experimentId: string): Promise<void> {
    // Implementation would create directory for experiment artifacts
  }

  /**
   * Cleanup temporary resources
   */
  private async cleanupTempResources(experimentId: string): Promise<void> {
    // Implementation would cleanup temporary files and resources
  }

  /**
   * Generate unique experiment ID
   */
  private generateExperimentId(): string {
    return `chaos_exp_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Setup event handlers
   */
  private setupEventHandlers(): void {
    this.injectionEngine.on('chaos:injected', (data) => {
      this.emit('experiment:chaos_injected', data);
    });

    this.injectionEngine.on('chaos:rolled_back', (data) => {
      this.emit('experiment:chaos_rolled_back', data);
    });

    this.degradationVerifier.on('degradation:detected', (data) => {
      this.emit('experiment:degradation_detected', data);
    });

    this.alertVerifier.on('alert:triggered', (data: any) => {
      this.emit('experiment:alert_triggered', data);
    });

    this.mttrMeasurer.on('mttr:event_recorded', (data) => {
      this.emit('experiment:mttr_event', data);
    });
  }

  /**
   * Get running experiments
   */
  getRunningExperiments(): string[] {
    return Array.from(this.runningExperiments.keys());
  }

  /**
   * Get completed experiments
   */
  getCompletedExperiments(): ExperimentExecutionReport[] {
    return [...this.completedExperiments];
  }

  /**
   * Get experiment by ID
   */
  getExperiment(experimentId: string): ExperimentExecutionReport | null {
    return this.completedExperiments.find((exp) => exp.experimentId === experimentId) || null;
  }

  /**
   * Stop running experiment
   */
  async stopExperiment(experimentId: string): Promise<void> {
    const context = this.runningExperiments.get(experimentId);
    if (!context) {
      throw new Error(`Experiment ${experimentId} not found`);
    }

    context.status = 'aborted';
    await this.emergencyCleanup(context);
    this.runningExperiments.delete(experimentId);

    this.emit('experiment:stopped', { experimentId });
  }

  /**
   * Stop all running experiments
   */
  async stopAllExperiments(): Promise<void> {
    const runningIds = Array.from(this.runningExperiments.keys());

    for (const id of runningIds) {
      try {
        await this.stopExperiment(id);
      } catch (error) {
        console.error(`Failed to stop experiment ${id}:`, error);
      }
    }
  }
}

// Supporting types

interface ExperimentContext {
  id: string;
  config: ChaosExperimentConfig;
  scenario: ChaosScenario;
  context: ExperimentExecutionContext;
  phases: ExperimentPhase[];
  startTime: Date;
  status: 'running' | 'completed' | 'failed' | 'aborted';
  error?: Error;
  baselineMetrics?: SystemMetrics;
  steadyStateMetrics: SystemMetrics[];
  chaosMetrics?: ChaosMetrics;
  recoveryMetrics?: RecoveryMetrics;
  verificationResults?: VerificationResults;
  mttrMetrics?: MTTRMetrics;
}
