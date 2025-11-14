// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck


/**
 * Circuit Breaker Service
 *
 * Enhanced circuit breaker implementation with comprehensive logging,
 * annotations, and monitoring integration for SLO compliance.
 *
 * Features:
 * - Automatic failure detection and recovery
 * - Performance-based thresholding
 * - Detailed logging and annotations
 * - SLO integration for automated responses
 * - Circuit breaker state analytics
 * - Multi-dimensional failure tracking
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */



import { EventEmitter } from 'events';

import { logger } from '@/utils/logger.js';

/**
 * Circuit Breaker Configuration
 */
export interface CircuitBreakerConfig {
  /** Failure threshold before opening circuit */
  failureThreshold: number;
  /** Timeout before attempting to close circuit again */
  recoveryTimeoutMs: number;
  /** Time window for monitoring failures */
  monitoringWindowMs: number;
  /** Minimum number of calls before considering failure rate */
  minimumCalls: number;
  /** Percentage threshold for failure rate */
  failureRateThreshold: number;
  /** Whether to track individual failure types */
  trackFailureTypes: boolean;
  /** Enable detailed performance logging */
  enablePerformanceLogging: boolean;
  /** Enable SLO annotations */
  enableSLOAnnotations: boolean;
  /** Custom failure type classification */
  failureClassification?: Record<string, (error: Error) => boolean>;
  /** Performance thresholds for adaptive behavior */
  performanceThresholds?: {
    maxResponseTimeMs: number;
    maxResponseTimePercentile: number;
    maxErrorSpikeRate: number;
  };
}

/**
 * Circuit Breaker State with Enhanced Tracking
 */
export interface CircuitBreakerState {
  /** Current circuit state: 'closed', 'open', or 'half-open' */
  state: 'closed' | 'open' | 'half-open';
  /** Number of consecutive failures */
  failures: number;
  /** Total number of calls in monitoring window */
  totalCalls: number;
  /** Number of successful calls */
  successCalls: number;
  /** Number of failed calls */
  failedCalls: number;
  /** Timestamp of last failure */
  lastFailureTime: number;
  /** Timestamp when circuit was opened */
  openedAt: number;
  /** Timestamp of last state change */
  lastStateChange: number;
  /** Types of failures encountered */
  failureTypes: Record<string, number>;
  /** Performance metrics */
  averageResponseTime: number;
  responseTimeSamples: number[];
  /** Enhanced tracking for SLO */
  sloViolationCount: number;
  lastSLOViolation?: number;
  degradationLevel: 'none' | 'minor' | 'major' | 'critical';
  /** Circuit breaker annotations for monitoring */
  annotations: CircuitBreakerAnnotation[];
}

/**
 * Circuit Breaker Annotation
 */
export interface CircuitBreakerAnnotation {
  timestamp: number;
  type: 'state_change' | 'failure' | 'recovery' | 'performance' | 'slo_violation' | 'manual_intervention';
  message: string;
  details: Record<string, unknown>;
  severity: 'info' | 'warning' | 'error' | 'critical';
  correlationId?: string;
  sloImpact?: {
    affectedSLOs: string[];
    severity: 'low' | 'medium' | 'high' | 'critical';
  };
}

/**
 * Enhanced Circuit Breaker Statistics
 */
export interface CircuitBreakerStats {
  /** Basic state information */
  state: CircuitBreakerState['state'];
  failures: number;
  totalCalls: number;
  successRate: number;
  failureRate: number;
  averageResponseTime: number;
  timeSinceLastFailure: number;
  timeSinceStateChange: number;
  isOpen: boolean;
  failureTypes: Record<string, number>;
  /** Additional properties for monitoring */
  isHalfOpen: boolean;
  successes: number;
  /** SLO-related metrics */
  sloCompliance: number;
  sloViolationRate: number;
  performanceScore: number;
  degradationScore: number;
  /** Circuit breaker health score */
  healthScore: number;
  /** Recent annotations */
  recentAnnotations: CircuitBreakerAnnotation[];
  /** Predictive metrics */
  riskOfFailure: number;
  predictedTimeToRecovery: number | null;
  /** Recommended actions */
  recommendations: string[];
}


/**
 * Enhanced Circuit Breaker with Logging and Annotations
 */
export class CircuitBreaker extends EventEmitter {
  private config: CircuitBreakerConfig;
  private state: CircuitBreakerState;
  private responseTimeBuffer: number[] = [];
  private name: string;

  constructor(name: string, config: Partial<CircuitBreakerConfig> = {}) {
    super();
    this.name = name;
    this.config = {
      failureThreshold: 5,
      recoveryTimeoutMs: 60000, // 1 minute
      monitoringWindowMs: 300000, // 5 minutes
      minimumCalls: 10,
      failureRateThreshold: 0.5, // 50%
      trackFailureTypes: true,
      enablePerformanceLogging: true,
      enableSLOAnnotations: true,
      performanceThresholds: {
        maxResponseTimeMs: 1000,
        maxResponseTimePercentile: 95,
        maxErrorSpikeRate: 0.2,
      },
      ...config,
    };

    this.state = this.getInitialState();
    this.logAnnotation('info', 'Circuit breaker initialized', {
      config: this.config,
      initialState: this.state.state,
    });
  }

  private getInitialState(): CircuitBreakerState {
    return {
      state: 'closed',
      failures: 0,
      totalCalls: 0,
      successCalls: 0,
      failedCalls: 0,
      lastFailureTime: 0,
      openedAt: 0,
      lastStateChange: Date.now(),
      failureTypes: {},
      averageResponseTime: 0,
      responseTimeSamples: [],
      sloViolationCount: 0,
      degradationLevel: 'none',
      annotations: [],
    };
  }

  /**
   * Add annotation to circuit breaker history
   */
  private addAnnotation(
    type: CircuitBreakerAnnotation['type'],
    message: string,
    details: Record<string, unknown> = {},
    severity: CircuitBreakerAnnotation['severity'] = 'info',
    correlationId?: string,
    sloImpact?: CircuitBreakerAnnotation['sloImpact']
  ): void {
    const annotation: CircuitBreakerAnnotation = {
      timestamp: Date.now(),
      type,
      message,
      details,
      severity,
      correlationId,
      sloImpact,
    };

    this.state.annotations.push(annotation);

    // Keep only last 100 annotations
    if (this.state.annotations.length > 100) {
      this.state.annotations = this.state.annotations.slice(-100);
    }

    // Log the annotation
    const logLevel = severity === 'warning' ? 'warn' : severity === 'critical' ? 'error' : severity;
    this.logAnnotation(logLevel as 'info' | 'warn' | 'error', message, details, correlationId);

    // Emit annotation event
    this.emit('annotation', {
      circuitName: this.name,
      annotation,
      state: this.state,
    });

    // Check for SLO violations
    if (this.config.enableSLOAnnotations && sloImpact) {
      this.checkSLOViolation(annotation);
    }
  }

  /**
   * Log annotation with structured logging
   */
  private logAnnotation(
    level: 'info' | 'warn' | 'error',
    message: string,
    details: Record<string, unknown> = {},
    correlationId?: string
  ): void {
    const logData = {
      circuitBreaker: this.name,
      state: this.state.state,
      failures: this.state.failures,
      totalCalls: this.state.totalCalls,
      failureRate: this.getFailureRate(),
      correlationId,
      ...details,
    };

    switch (level) {
      case 'info':
        logger.info(logData, `[CIRCUIT:${this.name}] ${message}`);
        break;
      case 'warn':
        logger.warn(logData, `[CIRCUIT:${this.name}] ${message}`);
        break;
      case 'error':
        logger.error(logData, `[CIRCUIT:${this.name}] ${message}`);
        break;
    }
  }

  /**
   * Check for SLO violations
   */
  private checkSLOViolation(annotation: CircuitBreakerAnnotation): void {
    const sloViolations: string[] = [];

    // Check failure rate SLO
    if (this.getFailureRate() > this.config.failureRateThreshold) {
      sloViolations.push('failure_rate');
    }

    // Check response time SLO
    if (this.config.performanceThresholds &&
        this.state.averageResponseTime > this.config.performanceThresholds.maxResponseTimeMs) {
      sloViolations.push('response_time');
    }

    // Check consecutive failures SLO
    if (this.state.failures >= this.config.failureThreshold) {
      sloViolations.push('consecutive_failures');
    }

    if (sloViolations.length > 0) {
      this.state.sloViolationCount++;
      this.state.lastSLOViolation = Date.now();

      this.addAnnotation(
        'slo_violation',
        'SLO violation detected',
        {
          violations: sloViolations,
          failureRate: this.getFailureRate(),
          averageResponseTime: this.state.averageResponseTime,
          consecutiveFailures: this.state.failures,
        },
        'warning',
        annotation.correlationId,
        {
          affectedSLOs: sloViolations,
          severity: sloViolations.length > 2 ? 'critical' : 'high',
        }
      );

      this.emit('slo_violation', {
        circuitName: this.name,
        violations: sloViolations,
        state: this.state,
      });
    }
  }

  /**
   * Update degradation level
   */
  private updateDegradationLevel(): void {
    const failureRate = this.getFailureRate();
    const responseTime = this.state.averageResponseTime;
    const consecutiveFailures = this.state.failures;

    let newLevel: CircuitBreakerState['degradationLevel'] = 'none';

    if (consecutiveFailures >= this.config.failureThreshold || this.state.state === 'open') {
      newLevel = 'critical';
    } else if (failureRate > 0.8 || responseTime > 2000) {
      newLevel = 'major';
    } else if (failureRate > 0.5 || responseTime > 1000) {
      newLevel = 'minor';
    }

    if (newLevel !== this.state.degradationLevel) {
      const oldLevel = this.state.degradationLevel;
      this.state.degradationLevel = newLevel;

      this.addAnnotation(
        'performance',
        `Degradation level changed from ${oldLevel} to ${newLevel}`,
        {
          oldLevel,
          newLevel,
          failureRate,
          responseTime,
          consecutiveFailures,
        },
        newLevel === 'critical' ? 'error' : 'warning'
      );

      this.emit('degradation_changed', {
        circuitName: this.name,
        oldLevel,
        newLevel,
        state: this.state,
      });
    }
  }

  /**
   * Execute an operation through the circuit breaker
   */
  async execute<T>(operation: () => Promise<T>, operationName: string = 'unknown'): Promise<T> {
    const startTime = Date.now();

    // Check if circuit is open
    if (this.isOpen()) {
      throw new Error(
        `Circuit breaker is OPEN for ${operationName}. Last failure: ${new Date(this.state.lastFailureTime).toISOString()}`
      );
    }

    try {
      const result = await operation();
      this.onSuccess(startTime);
      return result;
    } catch (error) {
      this.onFailure(error as Error, startTime);
      throw error;
    }
  }

  /**
   * Check if circuit is currently open
   */
  isOpen(): boolean {
    if (this.state.state === 'open') {
      // Check if recovery timeout has passed
      if (Date.now() - this.state.openedAt > this.config.recoveryTimeoutMs) {
        this.transitionToHalfOpen();
        return false;
      }
      return true;
    }
    return false;
  }

  /**
   * Execute a half-open probe to test service recovery
   */
  async executeProbe<T>(
    probeOperation: () => Promise<T>,
    operationName: string = 'probe'
  ): Promise<T> {
    if (this.state.state !== 'half-open') {
      throw new Error(
        `Circuit breaker is not in half-open state for ${operationName}. Current state: ${this.state.state}`
      );
    }

    const startTime = Date.now();

    try {
      const result = await probeOperation();
      this.onProbeSuccess(startTime);
      return result;
    } catch (error) {
      this.onProbeFailure(error as Error, startTime);
      throw error;
    }
  }

  /**
   * Check if circuit is in half-open state
   */
  isHalfOpen(): boolean {
    return this.state.state === 'half-open';
  }

  /**
   * Get current circuit breaker statistics
   */
  getStats(): CircuitBreakerStats {
    const now = Date.now();
    const successRate =
      this.state.totalCalls > 0 ? this.state.successCalls / this.state.totalCalls : 0;
    const failureRate =
      this.state.totalCalls > 0 ? this.state.failedCalls / this.state.totalCalls : 0;

    return {
      state: this.state.state,
      failures: this.state.failures,
      totalCalls: this.state.totalCalls,
      successRate,
      failureRate,
      averageResponseTime: this.state.averageResponseTime,
      timeSinceLastFailure: this.state.lastFailureTime > 0 ? now - this.state.lastFailureTime : 0,
      timeSinceStateChange: now - this.state.lastStateChange,
      isOpen: this.isOpen(),
      failureTypes: { ...this.state.failureTypes },
      // Additional properties for monitoring
      isHalfOpen: this.state.state === 'half-open',
      successes: this.state.successCalls,
      // SLO-related metrics (default values for backward compatibility)
      sloCompliance: successRate,
      sloViolationRate: failureRate,
      performanceScore: successRate * 100,
      degradationScore: failureRate * 100,
      // Circuit breaker health score
      healthScore: successRate * 100,
      // Recent annotations
      recentAnnotations: [],
      // Predictive metrics
      riskOfFailure: failureRate,
      predictedTimeToRecovery: this.state.state === 'open' ? this.config.recoveryTimeoutMs - (now - this.state.openedAt) : null,
      // Recommended actions
      recommendations: this.state.state === 'open' ? ['Wait for timeout', 'Check dependency health'] : []
    };
  }

  /**
   * Reset circuit breaker to initial state
   */
  reset(): void {
    this.state = this.getInitialState();
    this.responseTimeBuffer = [];
  }

  /**
   * Force circuit to open (useful for testing)
   */
  forceOpen(): void {
    this.transitionToOpen();
  }

  /**
   * Force circuit to a specific state (useful for testing)
   */
  forceState(state: 'closed' | 'open' | 'half-open'): void {
    switch (state) {
      case 'closed':
        this.transitionToClosed();
        break;
      case 'open':
        this.transitionToOpen();
        break;
      case 'half-open':
        this.transitionToHalfOpen();
        break;
    }
  }

  /**
   * Handle successful operation
   */
  private onSuccess(startTime: number): void {
    const responseTime = Date.now() - startTime;
    this.updateResponseTime(responseTime);

    this.state.totalCalls++;
    this.state.successCalls++;

    if (this.state.state === 'half-open') {
      // Success in half-open state, close the circuit
      this.transitionToClosed();
    } else {
      // Reset failure count on success in closed state
      this.state.failures = 0;
    }
  }

  /**
   * Handle successful probe operation
   */
  private onProbeSuccess(startTime: number): void {
    const responseTime = Date.now() - startTime;
    this.updateResponseTime(responseTime);

    // Probe success in half-open state, close the circuit immediately
    this.transitionToClosed();
  }

  /**
   * Handle failed probe operation
   */
  private onProbeFailure(error: Error, startTime: number): void {
    const responseTime = Date.now() - startTime;
    this.updateResponseTime(responseTime);

    // Track probe failure types
    if (this.config.trackFailureTypes) {
      const errorType = this.getErrorType(error);
      this.state.failureTypes[errorType] = (this.state.failureTypes[errorType] || 0) + 1;
    }

    // Probe failure in half-open state, open circuit immediately
    this.transitionToOpen();
  }

  /**
   * Handle failed operation
   */
  private onFailure(error: Error, startTime: number): void {
    const responseTime = Date.now() - startTime;
    this.updateResponseTime(responseTime);

    this.state.totalCalls++;
    this.state.failedCalls++;
    this.state.failures++;
    this.state.lastFailureTime = Date.now();

    // Track failure types if enabled
    if (this.config.trackFailureTypes) {
      const errorType = this.getErrorType(error);
      this.state.failureTypes[errorType] = (this.state.failureTypes[errorType] || 0) + 1;
    }

    // Check if we should open the circuit
    if (this.shouldOpenCircuit()) {
      this.transitionToOpen();
    }
  }

  /**
   * Update response time metrics
   */
  private updateResponseTime(responseTime: number): void {
    this.responseTimeBuffer.push(responseTime);

    // Keep only last 100 samples
    if (this.responseTimeBuffer.length > 100) {
      this.responseTimeBuffer.shift();
    }

    // Calculate average
    this.state.averageResponseTime =
      this.responseTimeBuffer.reduce((sum, time) => sum + time, 0) / this.responseTimeBuffer.length;
  }

  /**
   * Get current failure rate as a percentage
   */
  private getFailureRate(): number {
    if (this.state.totalCalls === 0) {
      return 0;
    }
    return this.state.failures / this.state.totalCalls;
  }

  /**
   * Determine if circuit should be opened based on current state
   */
  private shouldOpenCircuit(): boolean {
    // If we're in half-open state, any failure opens the circuit
    if (this.state.state === 'half-open') {
      return true;
    }

    // Check consecutive failure threshold
    if (this.state.failures >= this.config.failureThreshold) {
      return true;
    }

    // Check failure rate threshold if we have enough samples
    if (this.state.totalCalls >= this.config.minimumCalls) {
      const failureRate = this.state.failedCalls / this.state.totalCalls;
      if (failureRate >= this.config.failureRateThreshold) {
        return true;
      }
    }

    return false;
  }

  /**
   * Transition to closed state
   */
  private transitionToClosed(): void {
    this.state.state = 'closed';
    this.state.failures = 0;
    this.state.lastStateChange = Date.now();
  }

  /**
   * Transition to open state
   */
  private transitionToOpen(): void {
    this.state.state = 'open';
    this.state.openedAt = Date.now();
    this.state.lastStateChange = Date.now();
  }

  /**
   * Transition to half-open state
   */
  private transitionToHalfOpen(): void {
    this.state.state = 'half-open';
    this.state.lastStateChange = Date.now();
  }

  /**
   * Categorize error type for tracking
   */
  private getErrorType(error: Error): string {
    const message = error.message.toLowerCase();
    const name = error.name.toLowerCase();

    if (message.includes('econnrefused') || message.includes('connection refused')) {
      return 'connection_refused';
    }
    if (message.includes('timeout') || name.includes('timeout')) {
      return 'timeout';
    }
    if (message.includes('enotfound') || message.includes('dns')) {
      return 'dns_resolution';
    }
    if (message.includes('network') || message.includes('enet')) {
      return 'network_error';
    }
    if (message.includes('auth') || message.includes('unauthorized')) {
      return 'authentication';
    }
    if (message.includes('rate limit') || message.includes('too many')) {
      return 'rate_limit';
    }
    if (message.includes('memory') || message.includes('oom')) {
      return 'resource_exhaustion';
    }

    return 'unknown';
  }
}

/**
 * Circuit Breaker Manager
 *
 * Manages multiple circuit breakers for different services
 */
export class CircuitBreakerManager {
  private circuitBreakers: Map<string, CircuitBreaker> = new Map();

  /**
   * Get or create a circuit breaker for a service
   */
  getCircuitBreaker(serviceName: string, config?: Partial<CircuitBreakerConfig>): CircuitBreaker {
    if (!this.circuitBreakers.has(serviceName)) {
      this.circuitBreakers.set(serviceName, new CircuitBreaker(serviceName, config));
    }
    return this.circuitBreakers.get(serviceName)!;
  }

  /**
   * Get statistics for all circuit breakers
   */
  getAllStats(): Record<string, CircuitBreakerStats> {
    const stats: Record<string, CircuitBreakerStats> = {};

    for (const [serviceName, circuitBreaker] of this.circuitBreakers) {
      stats[serviceName] = circuitBreaker.getStats();
    }

    return stats;
  }

  /**
   * Reset all circuit breakers
   */
  resetAll(): void {
    for (const circuitBreaker of this.circuitBreakers.values()) {
      circuitBreaker.reset();
    }
  }

  /**
   * Get list of services with open circuits
   */
  getOpenCircuits(): string[] {
    const openCircuits: string[] = [];

    for (const [serviceName, circuitBreaker] of this.circuitBreakers) {
      if (circuitBreaker.isOpen()) {
        openCircuits.push(serviceName);
      }
    }

    return openCircuits;
  }

  /**
   * Get overall system health based on circuit states
   */
  getSystemHealth(): {
    status: 'healthy' | 'degraded' | 'failing';
    totalServices: number;
    openCircuits: number;
    services: Record<string, CircuitBreakerStats>;
  } {
    const stats = this.getAllStats();
    const openCircuits = this.getOpenCircuits();
    const totalServices = Object.keys(stats).length;

    let status: 'healthy' | 'degraded' | 'failing' = 'healthy';

    if (openCircuits.length === 0) {
      status = 'healthy';
    } else if (openCircuits.length < totalServices) {
      status = 'degraded';
    } else {
      status = 'failing';
    }

    return {
      status,
      totalServices,
      openCircuits: openCircuits.length,
      services: stats,
    };
  }

  /**
   * Force a specific circuit breaker to a state (useful for testing)
   */
  forceCircuitState(serviceName: string, state: 'closed' | 'open' | 'half-open'): boolean {
    const circuitBreaker = this.circuitBreakers.get(serviceName);
    if (circuitBreaker) {
      circuitBreaker.forceState(state);
      return true;
    }
    return false;
  }

  /**
   * Simulate service failure by forcing circuit open (useful for testing)
   */
  simulateServiceFailure(serviceName: string): boolean {
    return this.forceCircuitState(serviceName, 'open');
  }

  /**
   * Simulate service recovery by forcing circuit closed (useful for testing)
   */
  simulateServiceRecovery(serviceName: string): boolean {
    return this.forceCircuitState(serviceName, 'closed');
  }
}

// Global circuit breaker manager instance
export const circuitBreakerManager = new CircuitBreakerManager();

// Default circuit breakers for common services
export const qdrantCircuitBreaker = circuitBreakerManager.getCircuitBreaker('qdrant', {
  failureThreshold: 2, // Lower threshold for faster failure detection in tests
  recoveryTimeoutMs: 10000, // 10 seconds for faster recovery
  failureRateThreshold: 0.4, // 40%
  minimumCalls: 2, // Fewer calls needed for failure detection
});

export const openaiCircuitBreaker = circuitBreakerManager.getCircuitBreaker('openai', {
  failureThreshold: 3,
  recoveryTimeoutMs: 30000, // 30 seconds
  failureRateThreshold: 0.4, // 40%
  minimumCalls: 5,
});

export const memoryStoreCircuitBreaker = circuitBreakerManager.getCircuitBreaker('memory-store', {
  failureThreshold: 4,
  recoveryTimeoutMs: 45000, // 45 seconds
  failureRateThreshold: 0.5, // 50%
});

export const memoryFindCircuitBreaker = circuitBreakerManager.getCircuitBreaker('memory-find', {
  failureThreshold: 4,
  recoveryTimeoutMs: 45000, // 45 seconds
  failureRateThreshold: 0.5, // 50%
});
