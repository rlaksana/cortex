/**
 * Chaos Testing Framework - Main Entry Point
 *
 * This module provides the main entry point for the chaos testing framework,
 * integrating all components and providing a simple API for chaos testing.
 */

import { ChaosInjectionEngine } from './engine/chaos-injection-engine.js';
import { MTTRMeasurer } from './measurement/mttr-measurer.js';
import { ChaosExperimentRunner, type ExperimentExecutionReport } from './runner/chaos-experiment-runner.js';
import { SafetyController } from './safety/safety-controller.js';
import {
  type ChaosExperimentConfig,
  type ChaosScenario,
  type ExperimentExecutionContext
} from './types/chaos-testing-types.js';
import { AlertVerifier } from './verification/alert-verifier.js';
import { GracefulDegradationVerifier } from './verification/graceful-degradation-verifier.js';

export * from './engine/chaos-injection-engine.js';
export * from './measurement/mttr-measurer.js';
export * from './runner/chaos-experiment-runner.js';
export * from './safety/safety-controller.js';
export * from './types/chaos-testing-types.js';
export * from './verification/alert-verifier.js';
export * from './verification/graceful-degradation-verifier.js';

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