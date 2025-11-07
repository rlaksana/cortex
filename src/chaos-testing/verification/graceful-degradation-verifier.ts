/**
 * Graceful Degradation Verifier
 *
 * This module verifies that the system degrades gracefully during chaos scenarios,
 * ensuring proper fallback mechanisms, circuit breaker patterns, and user-facing
 * error handling.
 */

import { EventEmitter } from 'events';
import {
  DegradationVerification,
  SystemMetrics,
  VerificationResults,
  GracefulDegradationResult,
  UserFacingErrorExpectation,
  UserFacingErrorResult,
  ChaosScenario,
  ExperimentExecutionContext
} from '../types/chaos-testing-types';

export interface DegradationMetrics {
  fallbackActivationTime: number;
  circuitBreakerTransitions: CircuitBreakerTransition[];
  serviceAvailability: ServiceAvailabilityMetrics;
  userFacingErrors: UserFacingErrorMetrics;
  performanceImpact: PerformanceImpactMetrics;
}

export interface CircuitBreakerTransition {
  timestamp: Date;
  fromState: 'closed' | 'open' | 'half-open';
  toState: 'closed' | 'open' | 'half-open';
  trigger: string;
  component: string;
}

export interface ServiceAvailabilityMetrics {
  overall: number; // percentage
  byComponent: Record<string, number>;
  timeline: AvailabilityTimepoint[];
}

export interface AvailabilityTimepoint {
  timestamp: Date;
  availability: number;
  component: string;
}

export interface UserFacingErrorMetrics {
  totalErrors: number;
  errorsByType: Record<string, number>;
  errorRates: Record<string, number>;
  retryableErrors: number;
  nonRetryableErrors: number;
}

export interface PerformanceImpactMetrics {
  responseTimeIncrease: number; // percentage
  throughputDecrease: number; // percentage
  errorRateIncrease: number; // percentage
}

export class GracefulDegradationVerifier extends EventEmitter {
  private monitoringActive = false;
  private metricsCollection: DegradationMetrics[] = [];
  private systemBaseline?: SystemMetrics;
  private degradationStartTime?: Date;

  constructor() {
    super();
  }

  /**
   * Start monitoring for graceful degradation
   */
  async startMonitoring(
    scenario: ChaosScenario,
    context: ExperimentExecutionContext
  ): Promise<void> {
    this.monitoringActive = true;
    this.degradationStartTime = new Date();
    this.metricsCollection = [];

    // Establish baseline metrics
    this.systemBaseline = await this.collectBaselineMetrics();

    this.emit('degradation:monitoring_started', { scenario, context });

    // Start continuous metrics collection
    this.startMetricsCollection(scenario, context);
  }

  /**
   * Stop monitoring and perform verification
   */
  async stopMonitoring(): Promise<GracefulDegradationResult> {
    this.monitoringActive = false;

    const finalMetrics = await this.collectCurrentMetrics();
    const result = await this.verifyGracefulDegradation(
      this.systemBaseline!,
      finalMetrics,
      this.metricsCollection
    );

    this.emit('degradation:monitoring_stopped', { result });

    return result;
  }

  /**
   * Verify graceful degradation behavior
   */
  async verifyGracefulDegradation(
    baseline: SystemMetrics,
    current: SystemMetrics,
    metricsHistory: DegradationMetrics[]
  ): Promise<GracefulDegradationResult> {
    const result: GracefulDegradationResult = {
      passed: true,
      fallbackActivated: false,
      degradationTime: 0,
      serviceAvailability: 0,
      circuitBreakerState: 'closed',
      userFacingErrors: []
    };

    // Verify fallback activation
    const fallbackResult = this.verifyFallbackActivation(metricsHistory);
    result.fallbackActivated = fallbackResult.activated;
    result.degradationTime = fallbackResult.activationTime;

    // Verify service availability
    const availabilityResult = this.verifyServiceAvailability(baseline, current, metricsHistory);
    result.serviceAvailability = availabilityResult.overallAvailability;

    if (availabilityResult.overallAvailability < 95) { // 95% threshold
      result.passed = false;
    }

    // Verify circuit breaker behavior
    const circuitBreakerResult = this.verifyCircuitBreakerBehavior(metricsHistory);
    result.circuitBreakerState = circuitBreakerResult.finalState;

    if (!circuitBreakerResult.behavedCorrectly) {
      result.passed = false;
    }

    // Verify user-facing errors
    const errorResult = this.verifyUserFacingErrors(metricsHistory);
    result.userFacingErrors = errorResult.errors;

    if (errorResult.excessiveErrors) {
      result.passed = false;
    }

    return result;
  }

  /**
   * Verify fallback activation
   */
  private verifyFallbackActivation(metricsHistory: DegradationMetrics[]): {
    activated: boolean;
    activationTime: number;
  } {
    let activated = false;
    let activationTime = 0;

    // Look for evidence of fallback activation
    for (const metrics of metricsHistory) {
      if (metrics.fallbackActivationTime > 0) {
        activated = true;
        activationTime = metrics.fallbackActivationTime;
        break;
      }
    }

    return { activated, activationTime };
  }

  /**
   * Verify service availability during degradation
   */
  private verifyServiceAvailability(
    baseline: SystemMetrics,
    current: SystemMetrics,
    metricsHistory: DegradationMetrics[]
  ): { overallAvailability: number; minimumAvailability: number } {
    let overallAvailability = 100;
    let minimumAvailability = 100;

    // Calculate availability from metrics history
    for (const metrics of metricsHistory) {
      const availability = metrics.serviceAvailability.overall;
      overallAvailability = Math.min(overallAvailability, availability);
      minimumAvailability = Math.min(minimumAvailability, availability);
    }

    return { overallAvailability, minimumAvailability };
  }

  /**
   * Verify circuit breaker behavior
   */
  private verifyCircuitBreakerBehavior(
    metricsHistory: DegradationMetrics[]
  ): { behavedCorrectly: boolean; finalState: string; transitionCount: number } {
    let behavedCorrectly = true;
    let finalState = 'closed';
    let transitionCount = 0;

    const transitions: CircuitBreakerTransition[] = [];

    // Collect all circuit breaker transitions
    for (const metrics of metricsHistory) {
      transitions.push(...metrics.circuitBreakerTransitions);
    }

    // Analyze transition patterns
    if (transitions.length > 0) {
      transitionCount = transitions.length;
      finalState = transitions[transitions.length - 1].toState;

      // Check for proper transition patterns
      for (let i = 0; i < transitions.length - 1; i++) {
        const current = transitions[i];
        const next = transitions[i + 1];

        // Validate transitions follow expected patterns
        if (current.toState === 'open' && next.toState === 'half-open') {
          // Expected transition
          continue;
        } else if (current.toState === 'half-open' && next.toState === 'closed') {
          // Expected transition
          continue;
        } else if (current.toState === 'half-open' && next.toState === 'open') {
          // Expected transition (failure in half-open state)
          continue;
        } else {
          // Unexpected transition pattern
          behavedCorrectly = false;
          break;
        }
      }
    }

    return { behavedCorrectly, finalState, transitionCount };
  }

  /**
   * Verify user-facing error behavior
   */
  private verifyUserFacingErrors(
    metricsHistory: DegradationMetrics[]
  ): { errors: UserFacingErrorResult[]; excessiveErrors: boolean } {
    const errors: UserFacingErrorResult[] = [];
    let excessiveErrors = false;

    // Aggregate error metrics
    const totalErrors = metricsHistory.reduce(
      (sum, metrics) => sum + metrics.userFacingErrors.totalErrors,
      0
    );

    const errorsByType = metricsHistory.reduce(
      (acc, metrics) => {
        Object.entries(metrics.userFacingErrors.errorsByType).forEach(([type, count]) => {
          acc[type] = (acc[type] || 0) + count;
        });
        return acc;
      },
      {} as Record<string, number>
    );

    // Check error rates against expectations
    const totalRequests = 1000; // This should come from actual metrics
    const errorRate = (totalErrors / totalRequests) * 100;

    if (errorRate > 5) { // 5% error rate threshold
      excessiveErrors = true;
    }

    // Generate error results
    Object.entries(errorsByType).forEach(([errorType, count]) => {
      const actualRate = (count / totalRequests) * 100;
      errors.push({
        errorType,
        actualRate,
        expectedRate: 0, // Should be configurable
        withinThreshold: actualRate <= 5
      });
    });

    return { errors, excessiveErrors };
  }

  /**
   * Collect baseline metrics before chaos injection
   */
  private async collectBaselineMetrics(): Promise<SystemMetrics> {
    return {
      timestamp: new Date(),
      responseTime: {
        mean: 100,
        p50: 80,
        p95: 200,
        p99: 300,
        max: 500
      },
      throughput: {
        requestsPerSecond: 100,
        operationsPerSecond: 150,
        bytesPerSecond: 1024 * 1024
      },
      errorRate: {
        totalErrors: 0,
        errorRate: 0,
        errorsByType: {}
      },
      resourceUsage: {
        cpu: 30,
        memory: 40,
        diskIO: 10,
        networkIO: 20,
        openConnections: 50
      },
      circuitBreaker: {
        state: 'closed',
        failureRate: 0,
        numberOfCalls: 100,
        numberOfSuccessfulCalls: 100,
        numberOfFailedCalls: 0
      },
      health: {
        overallStatus: 'healthy',
        componentStatus: {
          qdrant: 'healthy',
          api: 'healthy',
          monitoring: 'healthy'
        },
        lastHealthCheck: new Date()
      }
    };
  }

  /**
   * Collect current system metrics
   */
  private async collectCurrentMetrics(): Promise<SystemMetrics> {
    // Implementation would collect actual metrics from monitoring system
    return {
      timestamp: new Date(),
      responseTime: {
        mean: 150,
        p50: 120,
        p95: 300,
        p99: 500,
        max: 1000
      },
      throughput: {
        requestsPerSecond: 80,
        operationsPerSecond: 120,
        bytesPerSecond: 800 * 1024
      },
      errorRate: {
        totalErrors: 10,
        errorRate: 2,
        errorsByType: {
          'connection_error': 5,
          'timeout_error': 3,
          'validation_error': 2
        }
      },
      resourceUsage: {
        cpu: 50,
        memory: 60,
        diskIO: 30,
        networkIO: 40,
        openConnections: 60
      },
      circuitBreaker: {
        state: 'half-open',
        failureRate: 15,
        numberOfCalls: 80,
        numberOfSuccessfulCalls: 68,
        numberOfFailedCalls: 12
      },
      health: {
        overallStatus: 'degraded',
        componentStatus: {
          qdrant: 'degraded',
          api: 'healthy',
          monitoring: 'healthy'
        },
        lastHealthCheck: new Date()
      }
    };
  }

  /**
   * Start continuous metrics collection
   */
  private startMetricsCollection(
    scenario: ChaosScenario,
    context: ExperimentExecutionContext
  ): void {
    const collectionInterval = setInterval(async () => {
      if (!this.monitoringActive) {
        clearInterval(collectionInterval);
        return;
      }

      try {
        const metrics = await this.collectDegradationMetrics();
        this.metricsCollection.push(metrics);

        this.emit('degradation:metrics_collected', { metrics });
      } catch (error) {
        this.emit('degradation:metrics_error', { error });
      }
    }, 1000); // Collect every second
  }

  /**
   * Collect degradation-specific metrics
   */
  private async collectDegradationMetrics(): Promise<DegradationMetrics> {
    const currentMetrics = await this.collectCurrentMetrics();

    return {
      fallbackActivationTime: await this.measureFallbackActivationTime(),
      circuitBreakerTransitions: await this.getCircuitBreakerTransitions(),
      serviceAvailability: await this.calculateServiceAvailability(currentMetrics),
      userFacingErrors: await this.getUserFacingErrorMetrics(),
      performanceImpact: await this.calculatePerformanceImpact(currentMetrics)
    };
  }

  /**
   * Measure fallback activation time
   */
  private async measureFallbackActivationTime(): Promise<number> {
    // Check if fallback storage is active
    const fallbackActive = await this.isFallbackStorageActive();

    if (fallbackActive && this.degradationStartTime) {
      return Date.now() - this.degradationStartTime.getTime();
    }

    return 0;
  }

  /**
   * Check if fallback storage is active
   */
  private async isFallbackStorageActive(): Promise<boolean> {
    // Implementation would check actual fallback storage status
    return false;
  }

  /**
   * Get circuit breaker transitions
   */
  private async getCircuitBreakerTransitions(): Promise<CircuitBreakerTransition[]> {
    // Implementation would track actual circuit breaker state changes
    return [];
  }

  /**
   * Calculate service availability
   */
  private async calculateServiceAvailability(metrics: SystemMetrics): Promise<ServiceAvailabilityMetrics> {
    const overall = 100 - (metrics.errorRate.errorRate * 100);

    return {
      overall,
      byComponent: {
        qdrant: metrics.health.componentStatus.qdrant === 'healthy' ? 100 : 80,
        api: metrics.health.componentStatus.api === 'healthy' ? 100 : 90,
        monitoring: metrics.health.componentStatus.monitoring === 'healthy' ? 100 : 95
      },
      timeline: [{
        timestamp: new Date(),
        availability: overall,
        component: 'overall'
      }]
    };
  }

  /**
   * Get user-facing error metrics
   */
  private async getUserFacingErrorMetrics(): Promise<UserFacingErrorMetrics> {
    return {
      totalErrors: 0,
      errorsByType: {},
      errorRates: {},
      retryableErrors: 0,
      nonRetryableErrors: 0
    };
  }

  /**
   * Calculate performance impact
   */
  private async calculatePerformanceImpact(metrics: SystemMetrics): Promise<PerformanceImpactMetrics> {
    const baseline = this.systemBaseline;

    if (!baseline) {
      return {
        responseTimeIncrease: 0,
        throughputDecrease: 0,
        errorRateIncrease: 0
      };
    }

    const responseTimeIncrease = ((metrics.responseTime.mean - baseline.responseTime.mean) / baseline.responseTime.mean) * 100;
    const throughputDecrease = ((baseline.throughput.requestsPerSecond - metrics.throughput.requestsPerSecond) / baseline.throughput.requestsPerSecond) * 100;
    const errorRateIncrease = metrics.errorRate.errorRate - baseline.errorRate.errorRate;

    return {
      responseTimeIncrease,
      throughputDecrease,
      errorRateIncrease
    };
  }

  /**
   * Verify degradation meets expected criteria
   */
  async verifyAgainstCriteria(
    criteria: DegradationVerification,
    result: GracefulDegradationResult
  ): Promise<boolean> {
    // Verify fallback activation
    if (criteria.expectedFallback && !result.fallbackActivated) {
      return false;
    }

    // Verify degradation time
    if (result.degradationTime > criteria.maxDegradationTime) {
      return false;
    }

    // Verify service availability
    if (result.serviceAvailability < criteria.minServiceAvailability) {
      return false;
    }

    // Verify circuit breaker state
    if (criteria.expectedCircuitBreakerState !== result.circuitBreakerState) {
      return false;
    }

    // Verify user-facing errors
    for (const expectedError of criteria.userFacingErrors) {
      const actualError = result.userFacingErrors.find(e => e.errorType === expectedError.errorType);

      if (!actualError) {
        continue; // Error type didn't occur
      }

      const withinThreshold = actualError.actualRate <= (expectedError.expectedRate * 1.1); // 10% tolerance
      if (!withinThreshold) {
        return false;
      }
    }

    return true;
  }

  /**
   * Reset the verifier state
   */
  reset(): void {
    this.monitoringActive = false;
    this.metricsCollection = [];
    this.systemBaseline = undefined;
    this.degradationStartTime = undefined;
  }
}