/**
 * Error Handling Middleware for Cortex MCP
 *
 * Provides standardized error handling middleware for different layers:
 * - API layer (MCP tools)
 * - Service layer
 * - Database layer
 */

import {
  ErrorHandler,
  BaseError,
  ErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../utils/error-handler.js';
import { logger } from '../utils/logger.js';

// API Error Handler for MCP tool responses
export class ApiErrorHandler {
  /**
   * Handle MCP tool errors and return standardized responses
   */
  static handleToolCall(
    error: any,
    toolName: string,
    args?: any
  ): { content: Array<{ type: string; text: string }> } {
    const standardError = ErrorHandler.standardize(error, `tool.${toolName}`);

    // Log with tool context
    standardError.log({
      tool: toolName,
      arguments: args,
      layer: 'api',
    });

    // Return user-friendly response
    return {
      content: [
        {
          type: 'text',
          text: `❌ ${standardError.userMessage}`,
        },
      ],
    };
  }

  /**
   * Validate tool arguments with standardized error handling
   */
  static validateArguments(args: any, schema: Record<string, any>): void {
    if (!args || typeof args !== 'object') {
      throw new BaseError({
        code: ErrorCode.INVALID_INPUT,
        category: ErrorCategory.VALIDATION,
        severity: ErrorSeverity.MEDIUM,
        message: 'Arguments must be an object',
        userMessage: 'Invalid arguments provided',
        context: { received: typeof args },
      });
    }

    // Check required fields
    const required = Object.entries(schema)
      .filter(([_, config]) => config.required)
      .map(([field]) => field);

    const missing = required.filter((field) => !(field in args));
    if (missing.length > 0) {
      throw new BaseError({
        code: ErrorCode.MISSING_REQUIRED_FIELD,
        category: ErrorCategory.VALIDATION,
        severity: ErrorSeverity.MEDIUM,
        message: `Missing required fields: ${missing.join(', ')}`,
        userMessage: `Missing required fields: ${missing.join(', ')}`,
        context: { missing, received: Object.keys(args) },
      });
    }

    // Validate field types
    Object.entries(schema).forEach(([field, config]: [string, any]) => {
      if (field in args) {
        const value = args[field];
        const expectedType = config.type;

        if (expectedType && typeof value !== expectedType) {
          throw new BaseError({
            code: ErrorCode.INVALID_FORMAT,
            category: ErrorCategory.VALIDATION,
            severity: ErrorSeverity.MEDIUM,
            message: `Field '${field}' must be of type ${expectedType}, got ${typeof value}`,
            userMessage: `Invalid format for field: ${field}`,
            context: { field, expectedType, receivedType: typeof value, value },
          });
        }
      }
    });
  }
}

// Service Layer Error Handler
export class ServiceErrorHandler {
  /**
   * Wrap service methods with consistent error handling
   */
  static async wrapServiceMethod<T>(
    methodName: string,
    operation: () => Promise<T>,
    options: {
      fallback?: (error: BaseError) => T;
      rethrow?: boolean;
      category?: ErrorCategory;
    } = {}
  ): Promise<T> {
    return ErrorHandler.wrapAsync(operation, {
      operationName: `service.${methodName}`,
      category: options.category,
      fallback: options.fallback,
      rethrow: options.rethrow,
    });
  }

  /**
   * Handle database operation errors
   */
  static handleDatabaseError(error: any, operation: string, context?: Record<string, any>): never {
    const standardError = ErrorHandler.standardize(
      error,
      `database.${operation}`,
      ErrorCategory.DATABASE
    );

    // Add database context
    if (context) {
      standardError.context = { ...standardError.context, ...context };
    }

    standardError.log({ layer: 'database', operation });
    throw standardError;
  }

  /**
   * Handle authentication errors
   */
  static handleAuthenticationError(
    error: any,
    operation: string,
    context?: Record<string, any>
  ): never {
    const standardError = ErrorHandler.standardize(
      error,
      `auth.${operation}`,
      ErrorCategory.AUTHENTICATION
    );

    if (context) {
      standardError.context = { ...standardError.context, ...context };
    }

    standardError.log({ layer: 'authentication', operation });
    throw standardError;
  }

  /**
   * Handle authorization errors
   */
  static handleAuthorizationError(
    error: any,
    operation: string,
    context?: Record<string, any>
  ): never {
    const standardError = ErrorHandler.standardize(
      error,
      `authz.${operation}`,
      ErrorCategory.AUTHORIZATION
    );

    if (context) {
      standardError.context = { ...standardError.context, ...context };
    }

    standardError.log({ layer: 'authorization', operation });
    throw standardError;
  }
}

// Database Error Handler
export class DatabaseErrorHandler {
  /**
   * Handle database connection errors
   */
  static handleConnectionError(error: any, context?: Record<string, any>): never {
    const standardError = new BaseError({
      code: ErrorCode.DATABASE_CONNECTION_FAILED,
      category: ErrorCategory.DATABASE,
      severity: ErrorSeverity.CRITICAL,
      message: `Database connection failed: ${error instanceof Error ? error.message : String(error)}`,
      userMessage: 'Database connection failed',
      context: { ...context, originalError: error instanceof Error ? error.name : 'Unknown' },
      retryable: true,
    });

    standardError.log({ layer: 'database', operation: 'connect' });
    throw standardError;
  }

  /**
   * Handle database query errors
   */
  static handleQueryError(error: any, query: string, params?: any[]): never {
    const standardError = new BaseError({
      code: ErrorCode.DATABASE_QUERY_FAILED,
      category: ErrorCategory.DATABASE,
      severity: ErrorSeverity.HIGH,
      message: `Database query failed: ${error instanceof Error ? error.message : String(error)}`,
      userMessage: 'Database operation failed',
      context: {
        query: query.substring(0, 100),
        params,
        originalError: error instanceof Error ? error.name : 'Unknown',
      },
      retryable: true,
    });

    standardError.log({ layer: 'database', operation: 'query' });
    throw standardError;
  }

  /**
   * Handle record not found errors
   */
  static handleNotFoundError(entityType: string, identifier: string | Record<string, any>): never {
    const standardError = new BaseError({
      code: ErrorCode.RECORD_NOT_FOUND,
      category: ErrorCategory.DATABASE,
      severity: ErrorSeverity.MEDIUM,
      message: `${entityType} not found: ${JSON.stringify(identifier)}`,
      userMessage: `${entityType} not found`,
      context: { entityType, identifier },
    });

    standardError.log({ layer: 'database', operation: 'find' });
    throw standardError;
  }

  /**
   * Handle duplicate record errors
   */
  static handleDuplicateError(entityType: string, identifier: string | Record<string, any>): never {
    const standardError = new BaseError({
      code: ErrorCode.DUPLICATE_RECORD,
      category: ErrorCategory.DATABASE,
      severity: ErrorSeverity.MEDIUM,
      message: `Duplicate ${entityType}: ${JSON.stringify(identifier)}`,
      userMessage: `${entityType} already exists`,
      context: { entityType, identifier },
    });

    standardError.log({ layer: 'database', operation: 'create' });
    throw standardError;
  }
}

// Async Error Handler Utility
export class AsyncErrorHandler {
  /**
   * Create a safe async wrapper that never throws
   */
  static safe<T>(
    operation: () => Promise<T>,
    fallback?: T
  ): Promise<{ success: boolean; data?: T; error?: BaseError }> {
    return ErrorHandler.wrapAsync(
      async () => {
        try {
          const data = await operation();
          return { success: true, data };
        } catch (error) {
          const standardError = ErrorHandler.standardize(error, 'safe_operation');
          standardError.log();
          return {
            success: false,
            error: standardError,
            data: fallback,
          };
        }
      },
      {
        operationName: 'safe_wrapper',
        rethrow: false,
      }
    );
  }

  /**
   * Create a retry wrapper for async operations
   */
  static async retry<T>(
    operation: () => Promise<T>,
    options: {
      maxAttempts?: number;
      baseDelay?: number;
      maxDelay?: number;
      retryableErrors?: ErrorCode[];
      context?: Record<string, any>;
    } = {}
  ): Promise<T> {
    const {
      maxAttempts = 3,
      baseDelay = 1000,
      maxDelay = 10000,
      retryableErrors = [],
      context = {},
    } = options;

    let lastError: BaseError | null = null;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        return await operation();
      } catch (error) {
        lastError = ErrorHandler.standardize(error, 'retry_operation');

        // Check if error is retryable
        const isRetryable =
          ErrorHandler.isRetryable(lastError) &&
          (retryableErrors.length === 0 || retryableErrors.includes(lastError.code));

        if (!isRetryable || attempt === maxAttempts) {
          break;
        }

        // Log retry attempt
        logger.warn(
          {
            attempt,
            maxAttempts,
            error: lastError.code,
            message: lastError.message,
            ...context,
          },
          'Retrying operation after error'
        );

        // Calculate delay
        const delay = Math.min(baseDelay * Math.pow(2, attempt - 1), maxDelay);

        // Wait before retry
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }

    // All attempts failed, throw last error
    if (lastError) {
      lastError.log({ ...context, finalAttempt: true });
      throw lastError;
    }

    throw new BaseError({
      code: ErrorCode.UNKNOWN_ERROR,
      category: ErrorCategory.SYSTEM,
      severity: ErrorSeverity.HIGH,
      message: 'All retry attempts failed',
      userMessage: 'Operation failed after multiple attempts',
      context: { ...context, attempts: maxAttempts },
    });
  }
}

// Error Recovery Utilities
export class ErrorRecovery {
  /**
   * Attempt graceful degradation
   */
  static async gracefulDegradation<T>(
    primaryOperation: () => Promise<T>,
    fallbackOperations: Array<() => Promise<T>>,
    context?: Record<string, any>
  ): Promise<T> {
    let lastError: BaseError | null = null;

    // Try primary operation
    try {
      return await primaryOperation();
    } catch (error) {
      lastError = ErrorHandler.standardize(error, 'graceful_degradation');
      logger.warn(
        { ...context, operation: 'primary' },
        'Primary operation failed, trying fallbacks'
      );
    }

    // Try fallback operations
    for (let i = 0; i < fallbackOperations.length; i++) {
      try {
        const result = await fallbackOperations[i]();
        logger.info({ ...context, fallbackIndex: i }, 'Fallback operation succeeded');
        return result;
      } catch (error) {
        lastError = ErrorHandler.standardize(error, 'graceful_degradation');
        logger.warn({ ...context, fallbackIndex: i }, 'Fallback operation failed');
      }
    }

    // All operations failed
    if (lastError) {
      lastError.log({ ...context, allAttemptsFailed: true });
      throw lastError;
    }

    throw new BaseError({
      code: ErrorCode.UNKNOWN_ERROR,
      category: ErrorCategory.SYSTEM,
      severity: ErrorSeverity.HIGH,
      message: 'All operations failed including fallbacks',
      userMessage: 'Service temporarily unavailable',
      context,
    });
  }

  /**
   * Circuit breaker pattern implementation
   */
  static createCircuitBreaker<T>(
    operation: () => Promise<T>,
    options: {
      failureThreshold?: number;
      recoveryTimeout?: number;
      monitoringPeriod?: number;
    } = {}
  ) {
    const {
      failureThreshold = 5,
      recoveryTimeout = 60000, // 1 minute
      monitoringPeriod = 10000, // 10 seconds
    } = options;

    let state: 'CLOSED' | 'OPEN' | 'HALF_OPEN' = 'CLOSED';
    let failureCount = 0;
    let lastFailureTime = 0;
    let nextAttempt = 0;

    return {
      async execute(): Promise<T> {
        const now = Date.now();

        if (state === 'OPEN') {
          if (now < nextAttempt) {
            throw new BaseError({
              code: ErrorCode.SERVICE_UNAVAILABLE,
              category: ErrorCategory.NETWORK,
              severity: ErrorSeverity.HIGH,
              message: 'Circuit breaker is OPEN',
              userMessage: 'Service temporarily unavailable',
              context: { state, nextAttempt: new Date(nextAttempt).toISOString() },
              retryable: false,
            });
          }
          state = 'HALF_OPEN';
        }

        try {
          const result = await operation();

          if (state === 'HALF_OPEN') {
            state = 'CLOSED';
            failureCount = 0;
            logger.info('Circuit breaker CLOSED after successful operation');
          }

          return result;
        } catch (error) {
          failureCount++;
          lastFailureTime = now;

          if (failureCount >= failureThreshold) {
            state = 'OPEN';
            nextAttempt = now + recoveryTimeout;
            logger.warn(
              {
                failureCount,
                failureThreshold,
                recoveryTimeout,
                nextAttempt: new Date(nextAttempt).toISOString(),
              },
              'Circuit breaker OPENED'
            );
          }

          throw ErrorHandler.standardize(error, 'circuit_breaker');
        }
      },

      getState() {
        return {
          state,
          failureCount,
          failureThreshold,
          lastFailureTime,
          nextAttempt,
        };
      },

      reset() {
        state = 'CLOSED';
        failureCount = 0;
        lastFailureTime = 0;
        nextAttempt = 0;
        logger.info('Circuit breaker manually reset');
      },
    };
  }
}
