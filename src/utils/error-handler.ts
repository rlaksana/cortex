/**
 * Unified Error Handling Framework for Cortex MCP
 *
 * Provides consistent error classification, handling, and response patterns
 * across all service layers and entry points.
 */

import { logger } from '@/utils/logger.js';

// Error severity levels
export enum ErrorSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

// Error categories for classification
export enum ErrorCategory {
  VALIDATION = 'validation',
  AUTHENTICATION = 'authentication',
  AUTHORIZATION = 'authorization',
  DATABASE = 'database',
  NETWORK = 'network',
  EXTERNAL_API = 'external_api',
  BUSINESS_LOGIC = 'business_logic',
  SYSTEM = 'system',
  CONFIGURATION = 'configuration',
  RATE_LIMIT = 'rate_limit',
  IMMUTABILITY = 'immutability',
}

// Standard error codes
export enum ErrorCode {
  // Validation errors (1000-1099)
  INVALID_INPUT = 'E1001',
  MISSING_REQUIRED_FIELD = 'E1002',
  INVALID_FORMAT = 'E1003',
  VALIDATION_FAILED = 'E1004',

  // Authentication errors (1100-1199)
  INVALID_CREDENTIALS = 'E1101',
  TOKEN_EXPIRED = 'E1102',
  TOKEN_INVALID = 'E1103',
  SESSION_EXPIRED = 'E1104',
  API_KEY_INVALID = 'E1105',
  API_KEY_EXPIRED = 'E1106',

  // Authorization errors (1200-1299)
  INSUFFICIENT_PERMISSIONS = 'E1201',
  ACCESS_DENIED = 'E1202',
  SCOPE_VIOLATION = 'E1203',

  // Database errors (1300-1399)
  DATABASE_CONNECTION_FAILED = 'E1301',
  DATABASE_QUERY_FAILED = 'E1302',
  RECORD_NOT_FOUND = 'E1303',
  DUPLICATE_RECORD = 'E1304',
  DATABASE_TIMEOUT = 'E1305',

  // Network errors (1400-1499)
  NETWORK_UNREACHABLE = 'E1401',
  CONNECTION_TIMEOUT = 'E1402',
  SERVICE_UNAVAILABLE = 'E1403',

  // External API errors (1500-1599)
  EXTERNAL_API_ERROR = 'E1501',
  EXTERNAL_API_TIMEOUT = 'E1502',
  EXTERNAL_API_RATE_LIMIT = 'E1503',
  EXTERNAL_API_QUOTA_EXCEEDED = 'E1504',

  // Business logic errors (1600-1699)
  BUSINESS_RULE_VIOLATION = 'E1601',
  IMMUTABILITY_VIOLATION = 'E1602',
  WORKFLOW_VIOLATION = 'E1603',
  RESOURCE_LIMIT_EXCEEDED = 'E1604',

  // System errors (1700-1799)
  INTERNAL_ERROR = 'E1701',
  SYSTEM_OVERLOAD = 'E1702',
  MEMORY_EXHAUSTED = 'E1703',
  DISK_FULL = 'E1704',

  // Configuration errors (1800-1899)
  CONFIGURATION_ERROR = 'E1801',
  MISSING_ENVIRONMENT_VARIABLE = 'E1802',
  INVALID_CONFIGURATION = 'E1803',

  // Rate limit errors (1900-1999)
  RATE_LIMIT_EXCEEDED = 'E1901',
  QUOTA_EXCEEDED = 'E1902',

  // Generic errors (9000-9999)
  UNKNOWN_ERROR = 'E9001',
  PROCESSING_ERROR = 'E9002',
  BATCH_ERROR = 'E9003',
}

// Base error class
export abstract class BaseError extends Error {
  public readonly code: ErrorCode;
  public readonly category: ErrorCategory;
  public readonly severity: ErrorSeverity;
  public readonly context?: Record<string, unknown>;
  public readonly userMessage: string;
  public readonly technicalDetails?: string;
  public readonly timestamp: string;
  public readonly retryable: boolean;

  constructor({
    code,
    category,
    severity,
    message,
    userMessage,
    context,
    technicalDetails,
    retryable = false,
  }: {
    code: ErrorCode;
    category: ErrorCategory;
    severity: ErrorSeverity;
    message: string;
    userMessage: string;
    context?: Record<string, unknown>;
    technicalDetails?: string;
    retryable?: boolean;
  }) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.category = category;
    this.severity = severity;
    this.context = context ?? {};
    this.userMessage = userMessage;
    this.technicalDetails = technicalDetails ?? '';
    this.timestamp = new Date().toISOString();
    this.retryable = retryable;

    // Ensure stack trace is preserved
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }

  // Convert to standardized error response
  toResponse(): StandardErrorResponse {
    return {
      error: {
        code: this.code,
        category: this.category,
        severity: this.severity,
        message: this.userMessage,
        ...(this.technicalDetails !== undefined
          ? { technical_details: this.technicalDetails }
          : {}),
        timestamp: this.timestamp,
        retryable: this.retryable,
        ...(this.context !== undefined ? { context: this.context } : {}),
      },
    };
  }

  // Log with structured context
  log(additionalContext?: Record<string, unknown>): void {
    const logContext = {
      error: {
        name: this.name,
        code: this.code,
        category: this.category,
        severity: this.severity,
        message: this.message,
        technicalDetails: this.technicalDetails,
        context: { ...this.context, ...additionalContext },
      },
    };

    switch (this.severity) {
      case ErrorSeverity.CRITICAL:
      case ErrorSeverity.HIGH:
        logger.error(logContext, `${this.category.toUpperCase()}: ${this.message}`);
        break;
      case ErrorSeverity.MEDIUM:
        logger.warn(logContext, `${this.category.toUpperCase()}: ${this.message}`);
        break;
      case ErrorSeverity.LOW:
        logger.info(logContext, `${this.category.toUpperCase()}: ${this.message}`);
        break;
    }
  }
}

// Specific error classes
export class ValidationError extends BaseError {
  constructor(
    message: string,
    userMessage: string = 'Invalid input provided',
    context?: Record<string, unknown>
  ) {
    super({
      code: ErrorCode.VALIDATION_FAILED,
      category: ErrorCategory.VALIDATION,
      severity: ErrorSeverity.MEDIUM,
      message,
      userMessage,
      ...(context !== undefined ? { context } : {}),
    });
  }
}

export class AuthenticationError extends BaseError {
  constructor(
    message: string,
    userMessage: string = 'Authentication failed',
    context?: Record<string, unknown>
  ) {
    super({
      code: ErrorCode.INVALID_CREDENTIALS,
      category: ErrorCategory.AUTHENTICATION,
      severity: ErrorSeverity.HIGH,
      message,
      userMessage,
      ...(context !== undefined ? { context } : {}),
    });
  }
}

export class AuthorizationError extends BaseError {
  constructor(
    message: string,
    userMessage: string = 'Access denied',
    context?: Record<string, unknown>
  ) {
    super({
      code: ErrorCode.INSUFFICIENT_PERMISSIONS,
      category: ErrorCategory.AUTHORIZATION,
      severity: ErrorSeverity.HIGH,
      message,
      userMessage,
      ...(context !== undefined ? { context } : {}),
    });
  }
}

export class DatabaseError extends BaseError {
  constructor(message: string, context?: Record<string, unknown>, retryable: boolean = true) {
    super({
      code: ErrorCode.DATABASE_QUERY_FAILED,
      category: ErrorCategory.DATABASE,
      severity: ErrorSeverity.HIGH,
      message,
      userMessage: 'Database operation failed',
      ...(context !== undefined ? { context } : {}),
      retryable,
    });
  }
}

export class NetworkError extends BaseError {
  constructor(
    message: string,
    userMessage: string = 'Network connection failed',
    context?: Record<string, unknown>
  ) {
    super({
      code: ErrorCode.NETWORK_UNREACHABLE,
      category: ErrorCategory.NETWORK,
      severity: ErrorSeverity.MEDIUM,
      message,
      userMessage,
      ...(context !== undefined ? { context } : {}),
      retryable: true,
    });
  }
}

export class ExternalApiError extends BaseError {
  constructor(
    message: string,
    userMessage: string = 'External service unavailable',
    context?: Record<string, unknown>
  ) {
    super({
      code: ErrorCode.EXTERNAL_API_ERROR,
      category: ErrorCategory.EXTERNAL_API,
      severity: ErrorSeverity.MEDIUM,
      message,
      userMessage,
      ...(context !== undefined ? { context } : {}),
      retryable: true,
    });
  }
}

export class BusinessLogicError extends BaseError {
  constructor(
    message: string,
    userMessage: string = 'Operation not allowed',
    context?: Record<string, unknown>
  ) {
    super({
      code: ErrorCode.BUSINESS_RULE_VIOLATION,
      category: ErrorCategory.BUSINESS_LOGIC,
      severity: ErrorSeverity.MEDIUM,
      message,
      userMessage,
      ...(context !== undefined ? { context } : {}),
    });
  }
}

export class ImmutabilityViolationError extends BaseError {
  constructor(
    message: string,
    userMessage: string = 'Cannot modify immutable data',
    context?: Record<string, unknown>
  ) {
    super({
      code: ErrorCode.IMMUTABILITY_VIOLATION,
      category: ErrorCategory.IMMUTABILITY,
      severity: ErrorSeverity.HIGH,
      message,
      userMessage,
      ...(context !== undefined ? { context } : {}),
    });
  }
}

export class SystemError extends BaseError {
  constructor(message: string, context?: Record<string, unknown>) {
    super({
      code: ErrorCode.INTERNAL_ERROR,
      category: ErrorCategory.SYSTEM,
      severity: ErrorSeverity.CRITICAL,
      message,
      userMessage: 'System error occurred',
      ...(context !== undefined ? { context } : {}),
    });
  }
}

export class ConfigurationError extends BaseError {
  constructor(
    message: string,
    userMessage: string = 'System configuration error',
    context?: Record<string, unknown>
  ) {
    super({
      code: ErrorCode.CONFIGURATION_ERROR,
      category: ErrorCategory.CONFIGURATION,
      severity: ErrorSeverity.CRITICAL,
      message,
      userMessage,
      ...(context !== undefined ? { context } : {}),
    });
  }
}

export class RateLimitError extends BaseError {
  constructor(
    message: string,
    userMessage: string = 'Rate limit exceeded',
    context?: Record<string, unknown>
  ) {
    super({
      code: ErrorCode.RATE_LIMIT_EXCEEDED,
      category: ErrorCategory.RATE_LIMIT,
      severity: ErrorSeverity.MEDIUM,
      message,
      userMessage,
      ...(context !== undefined ? { context } : {}),
      retryable: true,
    });
  }
}

// Standard error response interface
export interface StandardErrorResponse {
  error: {
    code: ErrorCode;
    category: ErrorCategory;
    severity: ErrorSeverity;
    message: string;
    technical_details?: string;
    timestamp: string;
    retryable: boolean;
    context?: Record<string, unknown>;
  };
}

// Error handler utilities
export class ErrorHandler {
  /**
   * Wrap async functions with consistent error handling
   */
  static async wrapAsync<T>(
    operation: () => Promise<T>,
    context: {
      operationName: string;
      category?: ErrorCategory;
      fallback?: (_error: Error) => T;
      rethrow?: boolean;
    }
  ): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      const standardError = ErrorHandler.standardize(error, context.operationName);

      // Log the error
      standardError.log({ operation: context.operationName });

      // Return fallback if provided
      if (context.fallback) {
        return context.fallback(standardError);
      }

      // Re-throw if requested
      if (context.rethrow) {
        throw standardError;
      }

      // Return as unknown (TypeScript compatibility)
      throw standardError;
    }
  }

  /**
   * Standardize any error into our error classes
   */
  static standardize(error: unknown, operationName: string): BaseError {
    // If it's already a BaseError, return as-is
    if (error instanceof BaseError) {
      return error;
    }

    // If it's an Error, convert to appropriate type
    if (error instanceof Error) {
      const message = error.message;
      const context = { originalError: error.name, operationName };

      // Analyze error message to categorize
      if (message.includes('validation') || message.includes('invalid')) {
        return new ValidationError(message, 'Validation failed', context);
      }
      if (message.includes('unauthorized') || message.includes('forbidden')) {
        return new AuthorizationError(message, 'Access denied', context);
      }
      if (message.includes('database') || message.includes('connection')) {
        return new DatabaseError(message);
      }
      if (message.includes('network') || message.includes('timeout')) {
        return new NetworkError(message);
      }
      if (message.includes('rate limit') || message.includes('quota')) {
        return new RateLimitError(message);
      }
      if (message.includes('immutable') || message.includes('cannot modify')) {
        return new ImmutabilityViolationError(message);
      }

      // Default to system error
      return new SystemError(message);
    }

    // For non-Error objects, create a generic error
    return new SystemError(`Unknown error: ${String(error)}`, {
      originalValue: error,
      operationName,
    });
  }

  /**
   * Create a user-friendly response from any error
   */
  static createUserResponse(error: unknown): { content: Array<{ type: string; text: string }> } {
    const standardError = ErrorHandler.standardize(error, 'unknown');

    // Log the error
    standardError.log();

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
   * Determine if an error is retryable
   */
  static isRetryable(error: unknown): boolean {
    const standardError = ErrorHandler.standardize(error, 'unknown');
    return standardError.retryable;
  }

  /**
   * Get recommended retry delay in milliseconds
   */
  static getRetryDelay(_error: unknown, attempt: number = 1): number {
    // Base delay with exponential backoff
    const baseDelay = 1000; // 1 second
    const maxDelay = 30000; // 30 seconds
    const delay = Math.min(baseDelay * Math.pow(2, attempt - 1), maxDelay);

    // Add jitter
    const jitter = Math.random() * 0.1 * delay;
    return Math.floor(delay + jitter);
  }
}

// Error boundary class for React-like error handling
export class ErrorBoundary {
  private errors: BaseError[] = [];
  private maxErrors: number;
  private timeWindow: number; // in milliseconds

  constructor(maxErrors: number = 10, timeWindow: number = 60000) {
    this.maxErrors = maxErrors;
    this.timeWindow = timeWindow;
  }

  /**
   * Check if circuit breaker should be opened
   */
  shouldTrip(): boolean {
    const now = Date.now();
    const recentErrors = this.errors.filter(
      (error) => now - new Date(error.timestamp).getTime() < this.timeWindow
    );

    this.errors = recentErrors;
    return this.errors.length >= this.maxErrors;
  }

  /**
   * Record an error
   */
  recordError(error: BaseError): void {
    this.errors.push(error);

    // Clean old errors
    const now = Date.now();
    this.errors = this.errors.filter(
      (error) => now - new Date(error.timestamp).getTime() < this.timeWindow
    );
  }

  /**
   * Reset the error boundary
   */
  reset(): void {
    this.errors = [];
  }

  /**
   * Get error statistics
   */
  getStats(): {
    totalErrors: number;
    errorsByCategory: Record<string, number>;
    errorsBySeverity: Record<string, number>;
  } {
    const errorsByCategory: Record<string, number> = {};
    const errorsBySeverity: Record<string, number> = {};

    this.errors.forEach((error) => {
      errorsByCategory[error.category] = (errorsByCategory[error.category] || 0) + 1;
      errorsBySeverity[error.severity] = (errorsBySeverity[error.severity] || 0) + 1;
    });

    return {
      totalErrors: this.errors.length,
      errorsByCategory,
      errorsBySeverity,
    };
  }
}

// Export error boundary instance
export const globalErrorBoundary = new ErrorBoundary();
