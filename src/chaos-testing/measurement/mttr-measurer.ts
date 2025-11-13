/**
 * MTTR (Mean Time To Recovery) Measurement Framework
 *
 * This module measures various recovery time metrics during chaos scenarios,
 * including detection time, response time, resolution time, and overall recovery time.
 */

import { EventEmitter } from 'events';

import {
  type ChaosScenario,
  type ComponentRecoverySequence,
  type DataConsistencyResult,
  type ExperimentExecutionContext,
  type MTTRMetrics,
  type RecoveryMetrics,
  type RecoveryPattern,
  type RecoveryStep,
  type SystemMetrics,
} from '../types/chaos-testing-types.js';

export interface IncidentTimeline {
  incidentStart: Date;
  firstDetection: Date;
  alertTriggered: Date;
  responseStarted: Date;
  mitigationApplied: Date;
  recoveryStarted: Date;
  fullRecovery: Date;
  verificationComplete: Date;
}

export interface RecoveryEvent {
  timestamp: Date;
  type:
    | 'detection'
    | 'alert'
    | 'response'
    | 'mitigation'
    | 'recovery_start'
    | 'recovery_complete'
    | 'verification';
  description: string;
  component?: string;
  automated: boolean;
  metadata: Record<string, any>;
}

export interface DetectionMetrics {
  timeToDetect: number; // ms
  detectionMethod: 'automated' | 'manual';
  detectionSource: string;
  confidence: number; // 0-1
  falsePositive: boolean;
}

export interface ResponseMetrics {
  timeToRespond: number; // ms
  responseMethod: 'automated' | 'manual';
  responder: string; // system/person name
  responseEffectiveness: number; // 0-1
  escalationOccurred: boolean;
}

export interface ResolutionMetrics {
  timeToResolve: number; // ms
  resolutionMethod: 'automated' | 'manual';
  rootCauseAddressed: boolean;
  permanentFix: boolean;
  temporaryFix: boolean;
}

export class MTTRMeasurer extends EventEmitter {
  private measuring = false;
  private timeline: IncidentTimeline | null = null;
  private recoveryEvents: RecoveryEvent[] = [];
  private systemMetrics: SystemMetrics[] = [];
  private componentStates: Map<string, ComponentState> = new Map();

  constructor() {
    super();
  }

  /**
   * Start MTTR measurement for a chaos scenario
   */
  async startMeasurement(
    scenario: ChaosScenario,
    context: ExperimentExecutionContext
  ): Promise<void> {
    this.measuring = true;
    this.recoveryEvents = [];
    this.systemMetrics = [];
    this.componentStates.clear();

    // Initialize incident timeline
    this.timeline = {
      incidentStart: new Date(),
      firstDetection: new Date(0),
      alertTriggered: new Date(0),
      responseStarted: new Date(0),
      mitigationApplied: new Date(0),
      recoveryStarted: new Date(0),
      fullRecovery: new Date(0),
      verificationComplete: new Date(0),
    };

    this.emit('mttr:measurement_started', { scenario, context });

    // Start continuous monitoring
    this.startContinuousMonitoring();
  }

  /**
   * Stop measurement and calculate MTTR metrics
   */
  async stopMeasurement(): Promise<MTTRMetrics> {
    this.measuring = false;

    if (!this.timeline) {
      throw new Error('Measurement not started');
    }

    this.timeline.verificationComplete = new Date();

    const metrics = await this.calculateMTTRMetrics();

    this.emit('mttr:measurement_completed', { metrics });

    return metrics;
  }

  /**
   * Record a recovery event
   */
  recordEvent(event: Omit<RecoveryEvent, 'timestamp'>): void {
    if (!this.measuring) {
      return;
    }

    const fullEvent: RecoveryEvent = {
      ...event,
      timestamp: new Date(),
    };

    this.recoveryEvents.push(fullEvent);
    this.updateTimeline(fullEvent);

    this.emit('mttr:event_recorded', { event: fullEvent });
  }

  /**
   * Record system metrics snapshot
   */
  recordSystemMetrics(metrics: SystemMetrics): void {
    if (!this.measuring) {
      return;
    }

    this.systemMetrics.push(metrics);
  }

  /**
   * Record component state change
   */
  recordComponentState(
    component: string,
    state: 'healthy' | 'degraded' | 'failed' | 'recovering',
    metadata?: Record<string, any>
  ): void {
    if (!this.measuring) {
      return;
    }

    const componentState: ComponentState = {
      component,
      state,
      timestamp: new Date(),
      metadata: metadata || {},
    };

    this.componentStates.set(component, componentState);

    this.emit('mttr:component_state_changed', { componentState });
  }

  /**
   * Calculate comprehensive MTTR metrics
   */
  private async calculateMTTRMetrics(): Promise<MTTRMetrics> {
    if (!this.timeline) {
      throw new Error('Timeline not initialized');
    }

    const detectionMetrics = await this.calculateDetectionMetrics();
    const responseMetrics = await this.calculateResponseMetrics();
    const resolutionMetrics = await this.calculateResolutionMetrics();
    const recoveryMetrics = await this.calculateRecoveryMetrics();

    return {
      meanTimeToDetect: detectionMetrics.timeToDetect,
      meanTimeToRespond: responseMetrics.timeToRespond,
      meanTimeToResolve: resolutionMetrics.timeToResolve,
      meanTimeToRecover: recoveryMetrics.recoveryTime,
      overallMTTR: this.calculateOverallMTTR(),
    };
  }

  /**
   * Calculate detection metrics
   */
  private async calculateDetectionMetrics(): Promise<DetectionMetrics> {
    if (!this.timeline) {
      throw new Error('Timeline not initialized');
    }

    const detectionEvent = this.recoveryEvents.find((e) => e.type === 'detection');
    const firstDetection = detectionEvent?.timestamp || this.timeline.firstDetection;

    const timeToDetect = firstDetection.getTime() - this.timeline.incidentStart.getTime();
    const detectionMethod = detectionEvent?.automated ? 'automated' : 'manual';
    const detectionSource = detectionEvent?.description || 'unknown';
    const confidence = this.calculateDetectionConfidence();
    const falsePositive = await this.evaluateFalsePositive();

    return {
      timeToDetect,
      detectionMethod,
      detectionSource,
      confidence,
      falsePositive,
    };
  }

  /**
   * Calculate response metrics
   */
  private async calculateResponseMetrics(): Promise<ResponseMetrics> {
    if (!this.timeline) {
      throw new Error('Timeline not initialized');
    }

    const responseEvent = this.recoveryEvents.find((e) => e.type === 'response');
    const responseStarted = responseEvent?.timestamp || this.timeline.responseStarted;

    const timeToRespond = responseStarted.getTime() - this.timeline.incidentStart.getTime();
    const responseMethod = responseEvent?.automated ? 'automated' : 'manual';
    const responder = responseEvent?.metadata?.responder || 'unknown';
    const responseEffectiveness = await this.evaluateResponseEffectiveness();
    const escalationOccurred = this.checkForEscalation();

    return {
      timeToRespond,
      responseMethod,
      responder,
      responseEffectiveness,
      escalationOccurred,
    };
  }

  /**
   * Calculate resolution metrics
   */
  private async calculateResolutionMetrics(): Promise<ResolutionMetrics> {
    if (!this.timeline) {
      throw new Error('Timeline not initialized');
    }

    const mitigationEvent = this.recoveryEvents.find((e) => e.type === 'mitigation');
    const mitigationApplied = mitigationEvent?.timestamp || this.timeline.mitigationApplied;

    const timeToResolve = mitigationApplied.getTime() - this.timeline.incidentStart.getTime();
    const resolutionMethod = mitigationEvent?.automated ? 'automated' : 'manual';
    const rootCauseAddressed = await this.evaluateRootCauseAddressed();
    const permanentFix = await this.evaluatePermanentFix();
    const temporaryFix = await this.evaluateTemporaryFix();

    return {
      timeToResolve,
      resolutionMethod,
      rootCauseAddressed,
      permanentFix,
      temporaryFix,
    };
  }

  /**
   * Calculate recovery metrics
   */
  private async calculateRecoveryMetrics(): Promise<RecoveryMetrics> {
    if (!this.timeline) {
      throw new Error('Timeline not initialized');
    }

    const recoveryStartEvent = this.recoveryEvents.find((e) => e.type === 'recovery_start');
    const recoveryCompleteEvent = this.recoveryEvents.find((e) => e.type === 'recovery_complete');

    const recoveryStarted = recoveryStartEvent?.timestamp || this.timeline.recoveryStarted;
    const fullRecovery = recoveryCompleteEvent?.timestamp || this.timeline.fullRecovery;

    const recoveryTime = fullRecovery.getTime() - recoveryStarted.getTime();

    const recoveryPattern = await this.analyzeRecoveryPattern();
    const dataConsistencyCheck = await this.performDataConsistencyCheck();
    const componentRecoveryOrder = this.analyzeComponentRecoverySequence();

    return {
      recoveryTime,
      recoveryPattern,
      dataConsistencyCheck,
      componentRecoveryOrder,
    };
  }

  /**
   * Calculate overall MTTR
   */
  private calculateOverallMTTR(): number {
    if (!this.timeline) {
      return 0;
    }

    return this.timeline.verificationComplete.getTime() - this.timeline.incidentStart.getTime();
  }

  /**
   * Update timeline based on recovery event
   */
  private updateTimeline(event: RecoveryEvent): void {
    if (!this.timeline) {
      return;
    }

    switch (event.type) {
      case 'detection':
        if (this.timeline.firstDetection.getTime() === 0) {
          this.timeline.firstDetection = event.timestamp;
        }
        break;
      case 'alert':
        if (this.timeline.alertTriggered.getTime() === 0) {
          this.timeline.alertTriggered = event.timestamp;
        }
        break;
      case 'response':
        if (this.timeline.responseStarted.getTime() === 0) {
          this.timeline.responseStarted = event.timestamp;
        }
        break;
      case 'mitigation':
        if (this.timeline.mitigationApplied.getTime() === 0) {
          this.timeline.mitigationApplied = event.timestamp;
        }
        break;
      case 'recovery_start':
        if (this.timeline.recoveryStarted.getTime() === 0) {
          this.timeline.recoveryStarted = event.timestamp;
        }
        break;
      case 'recovery_complete':
        if (this.timeline.fullRecovery.getTime() === 0) {
          this.timeline.fullRecovery = event.timestamp;
        }
        break;
    }
  }

  /**
   * Calculate detection confidence
   */
  private calculateDetectionConfidence(): number {
    const detectionEvents = this.recoveryEvents.filter((e) => e.type === 'detection');

    if (detectionEvents.length === 0) {
      return 0;
    }

    // Confidence based on multiple factors
    let confidence = 0.5; // Base confidence

    // Automated detection increases confidence
    const automatedDetections = detectionEvents.filter((e) => e.automated);
    confidence += (automatedDetections.length / detectionEvents.length) * 0.3;

    // Multiple detection sources increase confidence
    const uniqueSources = new Set(detectionEvents.map((e) => e.description));
    confidence += Math.min(uniqueSources.size * 0.1, 0.2);

    return Math.min(confidence, 1.0);
  }

  /**
   * Evaluate if detection was a false positive
   */
  private async evaluateFalsePositive(): Promise<boolean> {
    // Check if system actually experienced the issue
    const actualIssues = this.recoveryEvents.filter(
      (e) => e.type === 'mitigation' || e.type === 'recovery_start'
    );

    return actualIssues.length === 0;
  }

  /**
   * Evaluate response effectiveness
   */
  private async evaluateResponseEffectiveness(): Promise<number> {
    const responseEvents = this.recoveryEvents.filter((e) => e.type === 'response');
    const mitigationEvents = this.recoveryEvents.filter((e) => e.type === 'mitigation');

    if (responseEvents.length === 0) {
      return 0;
    }

    // Effectiveness based on time to mitigation and success rate
    const firstResponse = responseEvents[0];
    const firstMitigation = mitigationEvents[0];

    if (!firstMitigation) {
      return 0.3; // Response initiated but no mitigation yet
    }

    const responseToMitigationTime =
      firstMitigation.timestamp.getTime() - firstResponse.timestamp.getTime();
    const effectiveness = Math.max(0, 1 - responseToMitigationTime / 300000); // 5 minute max

    return Math.min(effectiveness, 1.0);
  }

  /**
   * Check if escalation occurred
   */
  private checkForEscalation(): boolean {
    const escalationEvents = this.recoveryEvents.filter(
      (e) => e.metadata?.escalated === true || e.description.includes('escalation')
    );

    return escalationEvents.length > 0;
  }

  /**
   * Evaluate if root cause was addressed
   */
  private async evaluateRootCauseAddressed(): Promise<boolean> {
    const mitigationEvents = this.recoveryEvents.filter((e) => e.type === 'mitigation');

    return mitigationEvents.some((e) => e.metadata?.rootCauseAddressed === true);
  }

  /**
   * Evaluate if permanent fix was applied
   */
  private async evaluatePermanentFix(): Promise<boolean> {
    const mitigationEvents = this.recoveryEvents.filter((e) => e.type === 'mitigation');

    return mitigationEvents.some((e) => e.metadata?.permanentFix === true);
  }

  /**
   * Evaluate if temporary fix was applied
   */
  private async evaluateTemporaryFix(): Promise<boolean> {
    const mitigationEvents = this.recoveryEvents.filter((e) => e.type === 'mitigation');

    return mitigationEvents.some((e) => e.metadata?.temporaryFix === true);
  }

  /**
   * Analyze recovery pattern
   */
  private async analyzeRecoveryPattern(): Promise<RecoveryPattern> {
    if (!this.timeline) {
      throw new Error('Timeline not initialized');
    }

    const recoveryEvents = this.recoveryEvents.filter(
      (e) => e.type === 'recovery_start' || e.type === 'recovery_complete'
    );

    if (recoveryEvents.length < 2) {
      return {
        type: 'gradual',
        timeToFirstSignOfRecovery: 0,
        timeToFullRecovery: 0,
        recoveryStability: 0,
      };
    }

    const recoveryStarted = recoveryEvents[0].timestamp;
    const fullRecovery = recoveryEvents[recoveryEvents.length - 1].timestamp;

    const timeToFirstSignOfRecovery =
      recoveryStarted.getTime() - this.timeline.incidentStart.getTime();
    const timeToFullRecovery = fullRecovery.getTime() - this.timeline.incidentStart.getTime();

    // Analyze recovery pattern from system metrics
    const pattern = this.determineRecoveryPattern();
    const stability = this.calculateRecoveryStability();

    return {
      type: pattern,
      timeToFirstSignOfRecovery,
      timeToFullRecovery,
      recoveryStability: stability,
    };
  }

  /**
   * Determine recovery pattern type
   */
  private determineRecoveryPattern(): RecoveryPattern['type'] {
    if (this.systemMetrics.length < 3) {
      return 'gradual';
    }

    const lastMetrics = this.systemMetrics.slice(-10);
    const responseTimeTrend = this.calculateTrend(lastMetrics.map((m) => m.responseTime.mean));
    const errorRateTrend = this.calculateTrend(lastMetrics.map((m) => m.errorRate.errorRate));

    if (Math.abs(responseTimeTrend) < 0.1 && Math.abs(errorRateTrend) < 0.1) {
      return 'immediate';
    } else if (responseTimeTrend > -0.5 && errorRateTrend > -0.5) {
      return 'gradual';
    } else if (this.hasOscillations(lastMetrics)) {
      return 'oscillating';
    } else {
      return 'step_function';
    }
  }

  /**
   * Calculate trend in data series
   */
  private calculateTrend(values: number[]): number {
    if (values.length < 2) {
      return 0;
    }

    const n = values.length;
    const sumX = (n * (n - 1)) / 2;
    const sumY = values.reduce((sum, val) => sum + val, 0);
    const sumXY = values.reduce((sum, val, index) => sum + val * index, 0);
    const sumX2 = (n * (n - 1) * (2 * n - 1)) / 6;

    const slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);

    return slope;
  }

  /**
   * Check for oscillations in metrics
   */
  private hasOscillations(metrics: SystemMetrics[]): boolean {
    if (metrics.length < 5) {
      return false;
    }

    const responseTimes = metrics.map((m) => m.responseTime.mean);
    let signChanges = 0;

    for (let i = 1; i < responseTimes.length - 1; i++) {
      const prevDiff = responseTimes[i] - responseTimes[i - 1];
      const nextDiff = responseTimes[i + 1] - responseTimes[i];

      if (prevDiff * nextDiff < 0) {
        signChanges++;
      }
    }

    return signChanges > responseTimes.length * 0.3;
  }

  /**
   * Calculate recovery stability
   */
  private calculateRecoveryStability(): number {
    if (this.systemMetrics.length < 5) {
      return 0;
    }

    const lastMetrics = this.systemMetrics.slice(-10);
    const responseTimes = lastMetrics.map((m) => m.responseTime.mean);
    const errorRates = lastMetrics.map((m) => m.errorRate.errorRate);

    const responseTimeVariance = this.calculateVariance(responseTimes);
    const errorRateVariance = this.calculateVariance(errorRates);

    // Lower variance indicates higher stability
    const responseTimeStability = Math.max(0, 1 - responseTimeVariance / 10000);
    const errorRateStability = Math.max(0, 1 - errorRateVariance);

    return (responseTimeStability + errorRateStability) / 2;
  }

  /**
   * Calculate variance of data series
   */
  private calculateVariance(values: number[]): number {
    if (values.length === 0) {
      return 0;
    }

    const mean = values.reduce((sum, val) => sum + val, 0) / values.length;
    const variance = values.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / values.length;

    return variance;
  }

  /**
   * Perform data consistency check
   */
  private async performDataConsistencyCheck(): Promise<DataConsistencyResult> {
    // This would implement actual data consistency checks
    // For now, return a mock result

    return {
      consistent: true,
      inconsistencies: [],
      verificationTime: 5000,
    };
  }

  /**
   * Analyze component recovery sequence
   */
  private analyzeComponentRecoverySequence(): ComponentRecoverySequence {
    const sequence: string[] = [];
    const timeline: RecoveryStep[] = [];

    // Sort component states by timestamp
    const sortedStates = Array.from(this.componentStates.values()).sort(
      (a, b) => a.timestamp.getTime() - b.timestamp.getTime()
    );

    let lastState: ComponentState | null = null;

    for (const state of sortedStates) {
      if (state.state === 'healthy' && lastState && lastState.state !== 'healthy') {
        sequence.push(state.component);

        timeline.push({
          component: state.component,
          recoveredAt: state.timestamp,
          recoveryTime: state.timestamp.getTime() - lastState.timestamp.getTime(),
          method: state.metadata?.recoveryMethod || 'auto',
        });
      }

      lastState = state;
    }

    return {
      sequence,
      timeline,
    };
  }

  /**
   * Start continuous monitoring
   */
  private startContinuousMonitoring(): void {
    const monitoringInterval = setInterval(async () => {
      if (!this.measuring) {
        clearInterval(monitoringInterval);
        return;
      }

      try {
        const metrics = await this.collectSystemMetrics();
        this.recordSystemMetrics(metrics);

        // Check for component state changes
        await this.checkComponentStateChanges();
      } catch (error) {
        this.emit('mttr:monitoring_error', { error });
      }
    }, 2000); // Monitor every 2 seconds
  }

  /**
   * Collect current system metrics
   */
  private async collectSystemMetrics(): Promise<SystemMetrics> {
    // This would integrate with the actual monitoring system
    return {
      timestamp: new Date(),
      responseTime: {
        mean: 150,
        p50: 120,
        p95: 300,
        p99: 500,
        max: 1000,
      },
      throughput: {
        requestsPerSecond: 80,
        operationsPerSecond: 120,
        bytesPerSecond: 800 * 1024,
      },
      errorRate: {
        totalErrors: 5,
        errorRate: 1,
        errorsByType: {
          connection_error: 3,
          timeout_error: 2,
        },
      },
      resourceUsage: {
        cpu: 50,
        memory: 60,
        diskIO: 30,
        networkIO: 40,
        openConnections: 60,
      },
      circuitBreaker: {
        state: 'half-open',
        failureRate: 10,
        numberOfCalls: 80,
        numberOfSuccessfulCalls: 72,
        numberOfFailedCalls: 8,
      },
      health: {
        overallStatus: 'degraded',
        componentStatus: {
          qdrant: 'degraded',
          api: 'healthy',
          monitoring: 'healthy',
        },
        lastHealthCheck: new Date(),
      },
    };
  }

  /**
   * Check for component state changes
   */
  private async checkComponentStateChanges(): Promise<void> {
    // This would monitor component health and record state changes
    // Implementation would integrate with health checking system
  }

  /**
   * Get incident timeline
   */
  getIncidentTimeline(): IncidentTimeline | null {
    return this.timeline ? { ...this.timeline } : null;
  }

  /**
   * Get recovery events
   */
  getRecoveryEvents(): RecoveryEvent[] {
    return [...this.recoveryEvents];
  }

  /**
   * Get component states
   */
  getComponentStates(): Map<string, ComponentState> {
    return new Map(this.componentStates);
  }
}

// Supporting types

interface ComponentState {
  component: string;
  state: 'healthy' | 'degraded' | 'failed' | 'recovering';
  timestamp: Date;
  metadata: Record<string, any>;
}
