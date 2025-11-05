/**
 * Circuit Breaker Service Adapter
 *
 * Adapter class that bridges the gap between CircuitBreakerManager implementation
 * and the ICircuitBreakerService interface requirements.
 *
 * Implements the adapter pattern to provide interface compliance while
 * maintaining backward compatibility with existing CircuitBreakerManager.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { CircuitBreakerManager } from '../../services/circuit-breaker.service.js';
import type { ICircuitBreakerService } from '../service-interfaces.js';
import { logger } from '../../utils/logger.js';

/**
 * Adapter that wraps CircuitBreakerManager to implement ICircuitBreakerService interface
 */
export class CircuitBreakerServiceAdapter implements ICircuitBreakerService {
  private circuitBreakerManager: CircuitBreakerManager;
  private defaultServiceName: string = 'default';

  constructor(circuitBreakerManager: CircuitBreakerManager, defaultServiceName?: string) {
    this.circuitBreakerManager = circuitBreakerManager;
    if (defaultServiceName) {
      this.defaultServiceName = defaultServiceName;
    }
  }

  /**
   * Execute an operation through circuit breaker - required by ICircuitBreakerService interface
   * This method was missing from CircuitBreakerManager implementation
   */
  async execute<T>(operation: () => Promise<T>, serviceName: string): Promise<T> {
    try {
      logger.debug({ serviceName }, 'Executing operation via circuit breaker adapter');

      // Get or create circuit breaker for the specified service
      const circuitBreaker = this.circuitBreakerManager.getCircuitBreaker(serviceName);

      // Execute operation through circuit breaker
      return await circuitBreaker.execute(operation, serviceName);
    } catch (error) {
      logger.error({ error, serviceName }, 'Circuit breaker operation failed via adapter');
      throw error;
    }
  }

  /**
   * Get circuit breaker state - required by ICircuitBreakerService interface
   * This method was missing from CircuitBreakerManager implementation
   */
  getState(serviceName: string): string {
    try {
      logger.debug({ serviceName }, 'Getting circuit breaker state via adapter');

      // Get circuit breaker for the specified service
      const circuitBreaker = this.circuitBreakerManager.getCircuitBreaker(serviceName);

      // Get circuit breaker statistics
      const stats = circuitBreaker.getStats();

      // Return the state as string
      return stats.state;
    } catch (error) {
      logger.error({ error, serviceName }, 'Failed to get circuit breaker state via adapter');
      return 'unknown';
    }
  }

  /**
   * Reset circuit breaker - required by ICircuitBreakerService interface
   * This method was missing from CircuitBreakerManager implementation
   */
  reset(serviceName: string): void {
    try {
      logger.debug({ serviceName }, 'Resetting circuit breaker via adapter');

      // Get circuit breaker for the specified service
      const circuitBreaker = this.circuitBreakerManager.getCircuitBreaker(serviceName);

      // Reset the circuit breaker
      circuitBreaker.reset();
    } catch (error) {
      logger.error({ error, serviceName }, 'Failed to reset circuit breaker via adapter');
      throw error;
    }
  }

  /**
   * Get statistics for all circuit breakers
   * Provides additional functionality beyond the interface requirements
   */
  getAllStats(): Record<string, any> {
    return this.circuitBreakerManager.getAllStats();
  }

  /**
   * Get list of services with open circuits
   * Provides additional functionality beyond the interface requirements
   */
  getOpenCircuits(): string[] {
    return this.circuitBreakerManager.getOpenCircuits();
  }

  /**
   * Get overall system health based on circuit states
   * Provides additional functionality beyond the interface requirements
   */
  getSystemHealth(): any {
    return this.circuitBreakerManager.getSystemHealth();
  }

  /**
   * Execute operation using default service name
   * Convenience method for operations without explicit service naming
   */
  async executeWithDefault<T>(operation: () => Promise<T>): Promise<T> {
    return this.execute(operation, this.defaultServiceName);
  }

  /**
   * Get state using default service name
   * Convenience method for state without explicit service naming
   */
  getDefaultState(): string {
    return this.getState(this.defaultServiceName);
  }

  /**
   * Reset using default service name
   * Convenience method for reset without explicit service naming
   */
  resetDefault(): void {
    this.reset(this.defaultServiceName);
  }

  /**
   * Get the underlying CircuitBreakerManager instance for advanced operations
   * This provides access to CircuitBreakerManager-specific methods if needed
   */
  getCircuitBreakerManager(): CircuitBreakerManager {
    return this.circuitBreakerManager;
  }
}
