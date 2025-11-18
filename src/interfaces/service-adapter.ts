/**
 * Service Adapter Framework
 *
 * Provides consistent error handling, response formatting, and monitoring
 * for all service implementations. Ensures uniform behavior across the service layer.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { randomUUID } from 'crypto';

import type {
  IBaseService,
  ServiceError,
  ServiceMetadata,
  ServiceResponse,
} from './service-interfaces.js';
import { ServiceResponseHandler } from '../utils/service-response-handler-integration.js';
import { logger } from '../utils/logger.js';

/**
 * Service adapter base class that provides consistent error handling and response formatting
 */
export abstract class ServiceAdapterBase implements IBaseService {
  protected serviceName: string;
  protected version: string;
  protected startTime: number;

  constructor(serviceName: string, version: string = '2.0.0') {
    this.serviceName = serviceName;
    this.version = version;
    this.startTime = Date.now();
  }

  /**
   * Execute a service operation with consistent error handling and metrics
   */
  protected async executeOperation<T>(
    operation: () => Promise<T>,
    operationName: string,
    metadata?: Record<string, unknown>
  ): Promise<ServiceResponse<T>> {
    const requestId = randomUUID();
    const fullOperationName = `${this.serviceName}.${operationName}`;

    const response = await ServiceResponseHandler.handleOperation(
      operation,
      fullOperationName,
      {
        requestId,
        serviceName: this.serviceName,
        version: this.version,
        ...metadata,
      }
    );

    // Add correlation ID if not present
    if (!response.metadata?.requestId) {
      response.metadata = {
        ...response.metadata,
        requestId,
      };
    }

    return response;
  }

  /**
   * Execute a streaming operation with consistent error handling
   */
  protected async *executeStreamingOperation<T>(
    operation: () => AsyncGenerator<T>,
    operationName: string,
    metadata?: Record<string, unknown>
  ): AsyncGenerator<ServiceResponse<T>> {
    const startTime = Date.now();
    const requestId = randomUUID();

    try {
      logger.debug(
        {
          serviceName: this.serviceName,
          operation: operationName,
          requestId,
          metadata,
          streaming: true,
        },
        'Starting streaming service operation'
      );

      for await (const result of operation()) {
        const processingTime = Date.now() - startTime;

        yield {
          success: true,
          data: result,
          metadata: {
            serviceName: this.serviceName,
            processingTimeMs: processingTime,
            requestId,
            source: this.serviceName,
            version: this.version,
            streaming: true,
            ...metadata,
          },
        };
      }

      logger.debug(
        {
          serviceName: this.serviceName,
          operation: operationName,
          requestId,
          totalProcessingTime: Date.now() - startTime,
          streaming: true,
        },
        'Streaming service operation completed successfully'
      );
    } catch (error) {
      const processingTime = Date.now() - startTime;
      const serviceError = this.createServiceError(error, operationName);

      yield {
        success: false,
        error: serviceError,
        metadata: {
          serviceName: this.serviceName,
          processingTimeMs: processingTime,
          requestId,
          source: this.serviceName,
          version: this.version,
          streaming: true,
          ...metadata,
        },
      };

      logger.error(
        {
          serviceName: this.serviceName,
          operation: operationName,
          requestId,
          processingTime,
          error: serviceError,
          streaming: true,
        },
        'Streaming service operation failed'
      );
    }
  }

  /**
   * Create a standardized service error from any error
   */
  private createServiceError(error: unknown, operationName: string): ServiceError {
    if (this.isServiceError(error)) {
      return error;
    }

    if (error instanceof Error) {
      return {
        code: this.determineErrorCode(error),
        message: error.message,
        details: {
          operation: operationName,
          serviceName: this.serviceName,
          stack: error.stack,
        },
        timestamp: new Date().toISOString(),
        retryable: this.isRetryableError(error),
      };
    }

    return {
      code: 'UNKNOWN_ERROR',
      message: String(error),
      details: {
        operation: operationName,
        serviceName: this.serviceName,
      },
      timestamp: new Date().toISOString(),
      retryable: false,
    };
  }

  /**
   * Check if error is already a ServiceError
   */
  private isServiceError(error: unknown): error is ServiceError {
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
  private determineErrorCode(error: Error): string {
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

  /**
   * Determine if error is retryable
   */
  private isRetryableError(error: Error): boolean {
    const retryablePatterns = [
      /timeout/i,
      /network/i,
      /connection/i,
      /rate limit/i,
      /temporary/i,
      /service unavailable/i,
    ];

    const nonRetryablePatterns = [
      /validation/i,
      /unauthorized/i,
      /forbidden/i,
      /not found/i,
      /conflict/i,
    ];

    const message = error.message.toLowerCase();

    // Check for non-retryable patterns first
    if (nonRetryablePatterns.some((pattern) => pattern.test(message))) {
      return false;
    }

    // Check for retryable patterns
    return retryablePatterns.some((pattern) => pattern.test(message));
  }

  /**
   * Health check implementation
   */
  abstract healthCheck(): Promise<ServiceResponse<{ status: 'healthy' | 'unhealthy' }>>;

  /**
   * Get service status implementation
   */
  async getStatus(): Promise<
    ServiceResponse<{
      initialized: boolean;
      uptime: number;
      lastCheck: string;
    }>
  > {
    return this.executeOperation(async () => {
      const now = Date.now();
      return {
        initialized: true,
        uptime: now - this.startTime,
        lastCheck: new Date().toISOString(),
      };
    }, 'getStatus');
  }

  /**
   * Reset service state (optional implementation)
   */
  async reset(): Promise<ServiceResponse<void>> {
    return this.executeOperation(async () => {
      // Default implementation does nothing
      // Services can override this if they have state to reset
    }, 'reset');
  }
}

/**
 * Generic service adapter for knowledge services
 */
export abstract class KnowledgeServiceAdapter<
  TData = unknown,
  TFilter = unknown,
> extends ServiceAdapterBase {
  constructor(serviceName: string) {
    super(serviceName);
  }

  /**
   * Store operation with consistent error handling
   */
  protected async storeOperation(
    data: TData,
    scope: Record<string, unknown>,
    operation: (data: TData, scope: Record<string, unknown>) => Promise<{ id: string }>
  ): Promise<ServiceResponse<{ id: string }>> {
    return this.executeOperation(() => operation(data, scope), 'store', { scope });
  }

  /**
   * Get operation with consistent error handling
   */
  protected async getOperation<T>(
    id: string,
    scope: Record<string, unknown> | undefined,
    operation: (id: string, scope?: Record<string, unknown>) => Promise<T>
  ): Promise<ServiceResponse<T>> {
    return this.executeOperation(() => operation(id, scope), 'get', { id, scope });
  }

  /**
   * Update operation with consistent error handling
   */
  protected async updateOperation(
    id: string,
    data: Partial<TData>,
    scope: Record<string, unknown> | undefined,
    operation: (
      id: string,
      data: Partial<TData>,
      scope?: Record<string, unknown>
    ) => Promise<{ id: string }>
  ): Promise<ServiceResponse<{ id: string }>> {
    return this.executeOperation(() => operation(id, data, scope), 'update', { id, scope });
  }

  /**
   * Delete operation with consistent error handling
   */
  protected async deleteOperation(
    id: string,
    scope: Record<string, unknown> | undefined,
    operation: (id: string, scope?: Record<string, unknown>) => Promise<{ deleted: boolean }>
  ): Promise<ServiceResponse<{ deleted: boolean }>> {
    return this.executeOperation(() => operation(id, scope), 'delete', { id, scope });
  }

  /**
   * Search operation with consistent error handling
   */
  protected async searchOperation<T>(
    query: string,
    filters: TFilter | undefined,
    options: Record<string, unknown> | undefined,
    operation: (query: string, filters?: TFilter, options?: Record<string, unknown>) => Promise<T>
  ): Promise<ServiceResponse<T>> {
    return this.executeOperation(() => operation(query, filters, options), 'search', {
      query,
      filters,
      options,
    });
  }
}

/**
 * Service registry for managing service instances
 */
export class ServiceRegistry {
  private static instance: ServiceRegistry;
  private services: Map<string, IBaseService> = new Map();

  private constructor() {}

  static getInstance(): ServiceRegistry {
    if (!ServiceRegistry.instance) {
      ServiceRegistry.instance = new ServiceRegistry();
    }
    return ServiceRegistry.instance;
  }

  /**
   * Register a service
   */
  register<T extends IBaseService>(name: string, service: T): void {
    this.services.set(name, service);
    logger.info({ serviceName: name }, 'Service registered');
  }

  /**
   * Get a service
   */
  get<T extends IBaseService>(name: string): T | undefined {
    const service = this.services.get(name);
    return service as T | undefined;
  }

  /**
   * Unregister a service
   */
  unregister(name: string): void {
    this.services.delete(name);
    logger.info({ serviceName: name }, 'Service unregistered');
  }

  /**
   * Get all registered service names
   */
  getServiceNames(): string[] {
    return Array.from(this.services.keys());
  }

  /**
   * Health check all registered services
   */
  async healthCheckAll(): Promise<
    Record<string, ServiceResponse<{ status: 'healthy' | 'unhealthy' }>>
  > {
    const results: Record<string, ServiceResponse<{ status: 'healthy' | 'unhealthy' }>> = {};

    for (const [name, service] of this.services.entries()) {
      try {
        results[name] = await service.healthCheck();
      } catch (error) {
        results[name] = {
          success: false,
          error: {
            code: 'HEALTH_CHECK_ERROR',
            message: String(error),
            timestamp: new Date().toISOString(),
            retryable: false,
          },
        };
      }
    }

    return results;
  }
}

/**
 * Decorator for adding service metadata
 */
export function ServiceMetadata(metadata: { name: string; version?: string }) {
  return function <T extends new (...args: any[]) => ServiceAdapterBase>(constructor: T) {
    return class extends constructor {
      public override serviceName = metadata.name;
      public override version = metadata.version || '2.0.0';

      public override async healthCheck(): Promise<
        import('./service-interfaces.js').ServiceResponse<{ status: 'healthy' | 'unhealthy' }>
      > {
        return {
          success: true,
          data: { status: 'healthy' as const },
          metadata: {
            serviceName: this.serviceName,
            version: this.version,
            processingTimeMs: 0,
          },
        };
      }
    };
  };
}

/**
 * Circuit breaker pattern implementation for service resilience
 */
export class CircuitBreaker {
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
  async execute<T>(operation: () => Promise<T>): Promise<T> {
    if (this.state === 'open') {
      if (Date.now() - this.lastFailureTime > this.timeout) {
        this.state = 'half-open';
      } else {
        throw new Error('Circuit breaker is open');
      }
    }

    try {
      const result = await operation();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
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
