/**
 * Chaos Testing Framework - Main Entry Point
 *
 * This module provides the main entry point for the chaos testing framework,
 * integrating all components and providing a simple API for chaos testing.
 */

import { ChaosExperimentRunner, type ExperimentExecutionReport } from './runner/chaos-experiment-runner';
import { SafetyController } from './safety/safety-controller';
import { ChaosInjectionEngine } from './engine/chaos-injection-engine';
import { GracefulDegradationVerifier } from './verification/graceful-degradation-verifier';
import { AlertVerifier } from './verification/alert-verifier';
import { MTTRMeasurer } from './measurement/mttr-measurer';
import {
  ChaosExperimentConfig,
  ChaosScenario,
  ExperimentExecutionContext
} from './types/chaos-testing-types';

export * from './types/chaos-testing-types';
export * from './engine/chaos-injection-engine';
export * from './verification/graceful-degradation-verifier';
export * from './verification/alert-verifier';
export * from './measurement/mttr-measurer';
export * from './runner/chaos-experiment-runner';
export * from './safety/safety-controller';

/**
 * Main Chaos Testing Framework class
 */
export class ChaosTestingFramework {
  private runner: ChaosExperimentRunner;
  private safetyController: SafetyController;

  constructor() {
    this.runner = new ChaosExperimentRunner();
    this.safetyController = new SafetyController();
  }

  /**
   * Execute a complete chaos experiment
   */
  async executeExperiment(
    config: ChaosExperimentConfig,
    scenario: ChaosScenario,
    context: ExperimentExecutionContext
  ): Promise<ExperimentExecutionReport> {
    // Validate safety before starting
    const safetyValidation = await this.safetyController.validateExperimentSafety(
      'temp-id',
      config,
      scenario,
      context
    );

    if (!safetyValidation.safe) {
      throw new Error(`Safety validation failed: ${safetyValidation.violations.map(v => v.message).join(', ')}`);
    }

    // Initialize safety for experiment
    const experimentId = this.generateExperimentId();
    await this.safetyController.initializeForExperiment(experimentId, config, context);

    try {
      // Execute the experiment
      const report = await this.runner.executeExperiment(config, scenario, context);
      return report;
    } finally {
      // Cleanup safety controller
      await this.safetyController.cleanupExperiment(experimentId);
    }
  }

  /**
   * Get framework status
   */
  getStatus() {
    return {
      runningExperiments: this.runner.getRunningExperiments(),
      safetyState: this.safetyController.getSafetyState(),
      activeViolations: this.safetyController.getActiveViolations()
    };
  }

  /**
   * Emergency stop all experiments
   */
  async emergencyStop(reason: string): Promise<void> {
    await this.safetyController.triggerManualEmergencyShutdown(reason);
    await this.runner.stopAllExperiments();
  }

  private generateExperimentId(): string {
    return `chaos_exp_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

// Export singleton instance
export const chaosFramework = new ChaosTestingFramework();