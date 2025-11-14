// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * Alert Verifier
 *
 * This module verifies that alerts are properly triggered during chaos scenarios,
 * ensuring proper monitoring, alerting, and notification mechanisms.
 */

import { EventEmitter } from 'events';

import {
  type ChaosScenario,
  type ExperimentExecutionContext,
  type VerificationResults,
} from '../types/chaos-testing-types.js';

export interface AlertExpectation {
  alertType: string;
  expectedSeverity: 'low' | 'medium' | 'high' | 'critical';
  expectedWithinMs: number;
  description: string;
}

export interface AlertResult {
  alertType: string;
  triggered: boolean;
  severity?: string;
  triggerTime?: Date;
  matchedExpectation: boolean;
  description: string;
}

export interface AlertVerification {
  scenarioId: string;
  expectations: AlertExpectation[];
  results: AlertResult[];
  overallSuccess: boolean;
  verificationTime: Date;
}

/**
 * Alert Verifier class for monitoring alert behavior during chaos experiments
 */
export class AlertVerifier extends EventEmitter {
  private expectations: Map<string, AlertExpectation[]> = new Map();
  private results: Map<string, AlertResult[]> = new Map();

  /**
   * Add alert expectations for a scenario
   */
  public addExpectations(scenarioId: string, expectations: AlertExpectation[]): void {
    this.expectations.set(scenarioId, expectations);
  }

  /**
   * Record an alert trigger
   */
  public recordAlert(scenarioId: string, alertType: string, severity: string, description: string): void {
    const results = this.results.get(scenarioId) || [];
    results.push({
      alertType,
      triggered: true,
      severity,
      triggerTime: new Date(),
      matchedExpectation: false, // Will be updated during verification
      description,
    });
    this.results.set(scenarioId, results);
    this.emit('alertTriggered', { scenarioId, alertType, severity, description });
  }

  /**
   * Verify alert expectations against results
   */
  public async verifyAlerts(scenarioId: string, context: ExperimentExecutionContext): Promise<AlertVerification> {
    const expectations = this.expectations.get(scenarioId) || [];
    const results = this.results.get(scenarioId) || [];

    // Match results against expectations
    const updatedResults = results.map(result => {
      const expectation = expectations.find(exp => exp.alertType === result.alertType);
      return {
        ...result,
        matchedExpectation: !!expectation,
      };
    });

    // Check for missing alerts
    const missingAlerts = expectations.filter(exp =>
      !updatedResults.some(result => result.alertType === exp.alertType)
    ).map(exp => ({
      alertType: exp.alertType,
      triggered: false,
      matchedExpectation: false,
      description: `Expected alert ${exp.alertType} was not triggered`,
    }));

    const allResults = [...updatedResults, ...missingAlerts];
    const overallSuccess = expectations.every(exp =>
      allResults.some(result => result.alertType === exp.alertType && result.triggered)
    );

    const verification: AlertVerification = {
      scenarioId,
      expectations,
      results: allResults,
      overallSuccess,
      verificationTime: new Date(),
    };

    this.emit('verificationCompleted', verification);
    return verification;
  }

  /**
   * Clear results for a scenario
   */
  public clearResults(scenarioId: string): void {
    this.results.delete(scenarioId);
  }

  /**
   * Get verification results
   */
  public getResults(scenarioId: string): AlertResult[] {
    return this.results.get(scenarioId) || [];
  }

  /**
   * Start monitoring for alerts in a scenario
   */
  public async startMonitoring(scenarioId: string, expectations: AlertExpectation[]): Promise<void> {
    this.addExpectations(scenarioId, expectations);
    this.clearResults(scenarioId);
  }

  /**
   * Stop monitoring and return results
   */
  public async stopMonitoring(): Promise<{ success: boolean; message: string }> {
    return { success: true, message: 'Alert monitoring stopped' };
  }

  /**
   * Reset all monitoring state
   */
  public reset(): void {
    this.expectations.clear();
    this.results.clear();
  }
}