/**
 * Service Response Handler Integration
 *
 * Provides integration utilities for connecting service response builders
 * with existing error handling and monitoring systems.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { logger } from './logger.js';
import { ServiceErrorFactory, ServiceResponseBuilder, ServiceResponseValidator } from './service-response-builders.js';
import type { ServiceResponse } from '../interfaces/service-interfaces.js';

/**
 * Service response handler for integration with existing systems
 */
export class ServiceResponseHandler {
  /**
   * Wrap async operations with standardized error handling and response building
   */
  static async handleOperation<T>(
    operation: () => Promise<T>,
    operationName: string,
    metadata?: Record<string, unknown>
  ): Promise<ServiceResponse<T>> {
    const startTime = Date.now();

    try {
      logger.debug(
        {
          operation: operationName,
          metadata,
        },
        'Starting service operation'
      );

      const result = await operation();

      const response = ServiceResponseBuilder.success(result, {
        processingTimeMs: Date.now() - startTime,
        source: operationName,
        ...metadata,
      });

      logger.debug(
        {
          operation: operationName,
          processingTime: Date.now() - startTime,
          success: true,
        },
        'Service operation completed successfully'
      );

      return response;
    } catch (error) {
      const processingTime = Date.now() - startTime;
      const serviceError = this.createServiceError(error, operationName);

      const response = ServiceResponseBuilder.error(
        serviceError.code,
        serviceError.message,
        serviceError.details,
        {
          processingTimeMs: processingTime,
          source: operationName,
          ...metadata,
        }
      );

      logger.error(
        {
          operation: operationName,
          processingTime,
          error: serviceError,
          success: false,
        },
        'Service operation failed'
      );

      return response as ServiceResponse<T>;
    }
  }

  /**
   * Create a standardized service error from any error
   */
  private static createServiceError(error: unknown, operationName: string): {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  } {
    if (this.isServiceError(error)) {
      return {
        code: error.code,
        message: error.message,
        details: error.details,
      };
    }

    if (error instanceof Error) {
      return {
        code: this.determineErrorCode(error),
        message: error.message,
        details: {
          operation: operationName,
          stack: error.stack,
        },
      };
    }

    return {
      code: 'UNKNOWN_ERROR',
      message: String(error),
      details: {
        operation: operationName,
      },
    };
  }

  /**
   * Check if error is already a service error
   */
  private static isServiceError(error: unknown): error is {
    code: string;
    message: string;
    timestamp: string;
    details?: Record<string, unknown>;
    retryable?: boolean;
  } {
    return (
      typeof error === 'object' &&
      error !== null &&
      'code' in error &&
      'message' in error &&
      'timestamp' in error
    );
  }

  /**
   * Determine error code based on error characteristics
   */
  private static determineErrorCode(error: Error): string {
    if (error.name === 'ValidationError') {
      return 'VALIDATION_ERROR';
    }

    if (error.name === 'DatabaseError' || error.message.includes('database')) {
      return 'DATABASE_ERROR';
    }

    if (error.name === 'NetworkError' || error.message.includes('network')) {
      return 'NETWORK_ERROR';
    }

    if (error.name === 'TimeoutError' || error.message.includes('timeout')) {
      return 'TIMEOUT_ERROR';
    }

    if (error.message.includes('rate limit')) {
      return 'RATE_LIMIT_ERROR';
    }

    if (error.message.includes('unauthorized') || error.message.includes('forbidden')) {
      return 'AUTHORIZATION_ERROR';
    }

    if (error.message.includes('not found')) {
      return 'NOT_FOUND_ERROR';
    }

    if (error.message.includes('conflict')) {
      return 'CONFLICT_ERROR';
    }

    return 'UNKNOWN_ERROR';
  }
}

/**
 * Circuit breaker pattern integration with service responses
 */
export class ServiceCircuitBreaker {
  private failures: number = 0;
  private lastFailureTime: number = 0;
  private state: 'closed' | 'open' | 'half-open' = 'closed';

  constructor(
    private readonly failureThreshold: number = 5,
    private readonly timeout: number = 60000,
    private readonly monitoringPeriod: number = 30000
  ) {}

  /**
   * Execute operation with circuit breaker protection
   */
  async execute<T>(
    operation: () => Promise<T>,
    operationName: string
  ): Promise<ServiceResponse<T>> {
    if (this.state === 'open') {
      if (Date.now() - this.lastFailureTime > this.timeout) {
        this.state = 'half-open';
      } else {
        return ServiceErrorFactory.internal(
          `Circuit breaker is open for ${operationName}`,
          {
            code: 'SERVICE_UNAVAILABLE',
            failureCount: this.failures,
            timeSinceLastFailure: Date.now() - this.lastFailureTime,
          }
        );
      }
    }

    return ServiceResponseHandler.handleOperation(async () => {
      const result = await operation();
      this.onSuccess();
      return result;
    }, operationName, {
      circuitBreakerState: this.state,
      failureCount: this.failures,
    });
  }

  private onSuccess(): void {
    this.failures = 0;
    this.state = 'closed';
  }

  private onFailure(): void {
    this.failures++;
    this.lastFailureTime = Date.now();

    if (this.failures >= this.failureThreshold) {
      this.state = 'open';
    }
  }

  getState(): 'closed' | 'open' | 'half-open' {
    return this.state;
  }

  getFailures(): number {
    return this.failures;
  }

  reset(): void {
    this.failures = 0;
    this.state = 'closed';
    this.lastFailureTime = 0;
  }
}

/**
 * Service response middleware for request/response processing
 */
export class ServiceResponseMiddleware {
  /**
   * Add correlation ID to responses
   */
  static withCorrelationId<T>(
    response: ServiceResponse<T>,
    correlationId: string
  ): ServiceResponse<T> {
    return {
      ...response,
      metadata: {
        ...response.metadata,
        requestId: correlationId,
      },
    };
  }

  /**
   * Add version information to responses
   */
  static withVersion<T>(
    response: ServiceResponse<T>,
    version: string
  ): ServiceResponse<T> {
    return {
      ...response,
      metadata: {
        ...response.metadata,
        version,
      },
    };
  }

  /**
   * Add caching metadata
   */
  static withCacheInfo<T>(
    response: ServiceResponse<T>,
    cacheHit: boolean,
    cacheKey?: string
  ): ServiceResponse<T> {
    return {
      ...response,
      metadata: {
        ...response.metadata,
        cached: cacheHit,
        source: cacheKey ? `cache:${cacheKey}` : response.metadata?.source,
      },
    };
  }

  /**
   * Sanitize response for external consumption
   */
  static sanitize<T>(response: ServiceResponse<T>): ServiceResponse<T> {
    const sanitized = { ...response };

    // Remove sensitive information from metadata
    if (sanitized.metadata) {
      const { requestId, ...publicMetadata } = sanitized.metadata;
      sanitized.metadata = publicMetadata;
    }

    // Remove stack traces from error details
    if (sanitized.error?.details?.stack) {
      const { stack, ...publicDetails } = sanitized.error.details;
      sanitized.error.details = publicDetails;
    }

    return sanitized;
  }

  /**
   * Validate response before sending
   */
  static validate<T>(response: ServiceResponse<T>): ServiceResponse<T> {
    if (!ServiceResponseValidator.isValid(response)) {
      logger.error({ response }, 'Invalid service response detected');
      return ServiceErrorFactory.internal('Invalid response format');
    }

    return response;
  }
}

/**
 * Extended error factory with service-specific errors
 */
export class ExtendedServiceErrorFactory {
  /**
   * Create service unavailable error
   */
  static serviceUnavailable(
    message: string = 'Service temporarily unavailable',
    details?: Record<string, unknown>
  ): ServiceResponse<never> {
    return ServiceErrorFactory.internal(
      message,
      {
        code: 'SERVICE_UNAVAILABLE',
        ...details
      }
    );
  }

  /**
   * Create timeout error
   */
  static timeout(
    operation: string,
    timeoutMs: number,
    details?: Record<string, unknown>
  ): ServiceResponse<never> {
    return ServiceErrorFactory.internal(
      `Operation '${operation}' timed out after ${timeoutMs}ms`,
      {
        code: 'TIMEOUT_ERROR',
        ...details
      }
    );
  }

  /**
   * Create resource exhausted error
   */
  static resourceExhausted(
    resource: string,
    details?: Record<string, unknown>
  ): ServiceResponse<never> {
    return ServiceErrorFactory.internal(
      `Resource '${resource}' exhausted`,
      {
        code: 'RESOURCE_EXHAUSTED',
        ...details
      }
    );
  }
}