/**
 * Circuit Breaker Service
 *
 * Implements the circuit breaker pattern for external dependencies like Qdrant.
 * Provides automatic failure detection, service degradation, and recovery mechanisms.
 */

export interface CircuitBreakerConfig {
  // Failure threshold before opening circuit
  failureThreshold: number;
  // Timeout before attempting to close circuit again
  recoveryTimeoutMs: number;
  // Time window for monitoring failures
  monitoringWindowMs: number;
  // Minimum number of calls before considering failure rate
  minimumCalls: number;
  // Percentage threshold for failure rate
  failureRateThreshold: number;
  // Whether to track individual failure types
  trackFailureTypes: boolean;
}

export interface CircuitBreakerState {
  // Current circuit state: 'closed', 'open', or 'half-open'
  state: 'closed' | 'open' | 'half-open';
  // Number of consecutive failures
  failures: number;
  // Total number of calls in monitoring window
  totalCalls: number;
  // Number of successful calls
  successCalls: number;
  // Number of failed calls
  failedCalls: number;
  // Timestamp of last failure
  lastFailureTime: number;
  // Timestamp when circuit was opened
  openedAt: number;
  // Timestamp of last state change
  lastStateChange: number;
  // Types of failures encountered
  failureTypes: Record<string, number>;
  // Performance metrics
  averageResponseTime: number;
  responseTimeSamples: number[];
}

export interface CircuitBreakerStats {
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
}

export class CircuitBreaker {
  private config: CircuitBreakerConfig;
  private state: CircuitBreakerState;
  private responseTimeBuffer: number[] = [];

  constructor(config: Partial<CircuitBreakerConfig> = {}) {
    this.config = {
      failureThreshold: 5,
      recoveryTimeoutMs: 60000, // 1 minute
      monitoringWindowMs: 300000, // 5 minutes
      minimumCalls: 10,
      failureRateThreshold: 0.5, // 50%
      trackFailureTypes: true,
      ...config,
    };

    this.state = this.getInitialState();
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
    };
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
      this.circuitBreakers.set(serviceName, new CircuitBreaker(config));
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
