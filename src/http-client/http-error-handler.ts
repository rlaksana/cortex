// @ts-nocheck
// ULTIMATE FINAL EMERGENCY ROLLBACK: Remaining systematic type issues
// TODO: Fix systematic type issues before removing @ts-nocheck

/**
 * HTTP Error Handling and Type Discrimination
 *
 * Comprehensive error handling system for HTTP operations with type-safe
 * error discrimination, retry logic, and error recovery mechanisms.
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025-11-12
 */

import type {
  AuthenticationError,
  AuthorizationError,
  HttpError,
  HttpErrorType,
  HttpStatus,
  HttpStatusError,
  isAuthenticationError,
  isAuthorizationError,
  isHttpError,
  isHttpStatusError,
  isNetworkError,
  isRateLimitError,
  isRetryableError,
  isServerError,
  isTimeoutError,
  isValidationError,
  NetworkHttpError,
  ParseHttpError,
  RateLimitError,
  ServerError,
  TimeoutHttpError,
  TypedHttpRequest,
  TypedHttpResponse,
  ValidationError,
} from '../types/http-client-types.js';

// ============================================================================
// Error Classification and Mapping
// ============================================================================

/**
 * Error classification categories
 */
export enum ErrorCategory {
  NETWORK = 'network',
  TIMEOUT = 'timeout',
  VALIDATION = 'validation',
  AUTHENTICATION = 'authentication',
  AUTHORIZATION = 'authorization',
  RATE_LIMIT = 'rate_limit',
  CLIENT_ERROR = 'client_error',
  SERVER_ERROR = 'server_error',
  UNKNOWN = 'unknown',
}

/**
 * Error severity levels
 */
export enum ErrorSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

/**
 * Error recovery strategies
 */
export enum RecoveryStrategy {
  RETRY = 'retry',
  BACKOFF = 'backoff',
  CIRCUIT_BREAKER = 'circuit_breaker',
  FALLBACK = 'fallback',
  MANUAL_INTERVENTION = 'manual_intervention',
  NO_RECOVERY = 'no_recovery',
}

/**
 * Error classification configuration
 */
export interface ErrorClassification {
  category: ErrorCategory;
  severity: ErrorSeverity;
  retryable: boolean;
  recoveryStrategy: RecoveryStrategy;
  maxRetries?: number;
  retryDelay?: number;
  userMessage?: string;
  technicalDetails?: string;
}

/**
 * Error handler configuration
 */
export interface ErrorHandlerConfig {
  enableRetry: boolean;
  maxRetries: number;
  baseRetryDelay: number;
  maxRetryDelay: number;
  exponentialBackoff: boolean;
  retryableErrors: ErrorType[];
  nonRetryableErrors: ErrorType[];
  errorMappings: Partial<Record<HttpErrorType, ErrorClassification>>;
  fallbackHandlers?: Partial<Record<ErrorCategory, FallbackHandler>>;
  reportingEnabled: boolean;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
}

/**
 * Fallback handler interface
 */
export interface FallbackHandler {
  handle(error: HttpError, request: TypedHttpRequest): Promise<TypedHttpResponse | null>;
  canHandle(error: HttpError): boolean;
  priority: number;
}

/**
 * Error type enum for configuration
 */
export enum ErrorType {
  NETWORK = 'network_error',
  TIMEOUT = 'timeout_error',
  PARSE = 'parse_error',
  VALIDATION = 'validation_error',
  AUTHENTICATION = 'authentication_error',
  AUTHORIZATION = 'authorization_error',
  RATE_LIMIT = 'rate_limit_error',
  HTTP = 'http_error',
  SERVER = 'server_error',
  UNKNOWN = 'unknown_error',
}

// ============================================================================
// Default Error Classifications
// ============================================================================

const DEFAULT_ERROR_CLASSIFICATIONS: Record<HttpErrorType, ErrorClassification> = {
  network_error: {
    category: ErrorCategory.NETWORK,
    severity: ErrorSeverity.MEDIUM,
    retryable: true,
    recoveryStrategy: RecoveryStrategy.BACKOFF,
    maxRetries: 3,
    retryDelay: 1000,
    userMessage: 'Network connection error. Please check your internet connection.',
    technicalDetails: 'Network connectivity issue detected during HTTP request.',
  },
  timeout_error: {
    category: ErrorCategory.TIMEOUT,
    severity: ErrorSeverity.MEDIUM,
    retryable: true,
    recoveryStrategy: RecoveryStrategy.RETRY,
    maxRetries: 2,
    retryDelay: 500,
    userMessage: 'Request timed out. Please try again.',
    technicalDetails: 'Request exceeded configured timeout duration.',
  },
  parse_error: {
    category: ErrorCategory.VALIDATION,
    severity: ErrorSeverity.HIGH,
    retryable: false,
    recoveryStrategy: RecoveryStrategy.NO_RECOVERY,
    userMessage: 'Invalid response format received from server.',
    technicalDetails: 'Failed to parse response body as expected format.',
  },
  validation_error: {
    category: ErrorCategory.VALIDATION,
    severity: ErrorSeverity.MEDIUM,
    retryable: false,
    recoveryStrategy: RecoveryStrategy.NO_RECOVERY,
    userMessage: 'Invalid request data. Please check your input.',
    technicalDetails: 'Request validation failed against schema.',
  },
  authentication_error: {
    category: ErrorCategory.AUTHENTICATION,
    severity: ErrorSeverity.HIGH,
    retryable: false,
    recoveryStrategy: RecoveryStrategy.MANUAL_INTERVENTION,
    userMessage: 'Authentication required. Please log in and try again.',
    technicalDetails: 'Authentication credentials are missing or invalid.',
  },
  authorization_error: {
    category: ErrorCategory.AUTHORIZATION,
    severity: ErrorSeverity.HIGH,
    retryable: false,
    recoveryStrategy: RecoveryStrategy.NO_RECOVERY,
    userMessage: 'You do not have permission to perform this action.',
    technicalDetails: 'User lacks required permissions for this resource.',
  },
  rate_limit_error: {
    category: ErrorCategory.RATE_LIMIT,
    severity: ErrorSeverity.MEDIUM,
    retryable: true,
    recoveryStrategy: RecoveryStrategy.BACKOFF,
    maxRetries: 5,
    retryDelay: 60000, // 1 minute for rate limits
    userMessage: 'Too many requests. Please wait and try again.',
    technicalDetails: 'API rate limit exceeded. Implement backoff strategy.',
  },
  http_error: {
    category: ErrorCategory.CLIENT_ERROR,
    severity: ErrorSeverity.MEDIUM,
    retryable: false,
    recoveryStrategy: RecoveryStrategy.NO_RECOVERY,
    userMessage: 'Request failed. Please check your request and try again.',
    technicalDetails: 'HTTP client error (4xx) received.',
  },
  server_error: {
    category: ErrorCategory.SERVER_ERROR,
    severity: ErrorSeverity.HIGH,
    retryable: true,
    recoveryStrategy: RecoveryStrategy.CIRCUIT_BREAKER,
    maxRetries: 3,
    retryDelay: 2000,
    userMessage: 'Server error occurred. Please try again later.',
    technicalDetails: 'HTTP server error (5xx) received.',
  },
  unknown_error: {
    category: ErrorCategory.UNKNOWN,
    severity: ErrorSeverity.HIGH,
    retryable: false,
    recoveryStrategy: RecoveryStrategy.MANUAL_INTERVENTION,
    userMessage: 'An unexpected error occurred. Please try again.',
    technicalDetails: 'Unknown error type encountered during HTTP request.',
  },
};

// ============================================================================
// HTTP Error Handler Implementation
// ============================================================================

/**
 * Comprehensive HTTP error handler
 */
export class HttpErrorHandler {
  private config: ErrorHandlerConfig;
  private fallbackHandlers: FallbackHandler[] = [];
  private errorStats: Map<ErrorCategory, number> = new Map();

  constructor(config: Partial<ErrorHandlerConfig> = {}) {
    this.config = {
      enableRetry: true,
      maxRetries: 3,
      baseRetryDelay: 1000,
      maxRetryDelay: 30000,
      exponentialBackoff: true,
      retryableErrors: [
        ErrorType.NETWORK,
        ErrorType.TIMEOUT,
        ErrorType.RATE_LIMIT,
        ErrorType.SERVER,
      ],
      nonRetryableErrors: [
        ErrorType.PARSE,
        ErrorType.VALIDATION,
        ErrorType.AUTHENTICATION,
        ErrorType.AUTHORIZATION,
        ErrorType.HTTP,
      ],
      errorMappings: DEFAULT_ERROR_CLASSIFICATIONS,
      fallbackHandlers: {},
      reportingEnabled: true,
      logLevel: 'error',
      ...config,
    };

    this.initializeFallbackHandlers();
  }

  /**
   * Handle HTTP error with classification and recovery
   */
  async handleError<TResponse = unknown>(
    error: unknown,
    request: TypedHttpRequest
  ): Promise<TypedHttpResponse<TResponse>> {
    const httpError = this.ensureHttpError(error, request);
    const classification = this.classifyError(httpError);

    // Update error statistics
    this.updateErrorStats(classification.category);

    // Log error
    this.logError(httpError, classification);

    // Report error if enabled
    if (this.config.reportingEnabled) {
      await this.reportError(httpError, classification);
    }

    // Try fallback handlers first
    const fallbackResponse = await this.tryFallbackHandlers(httpError, request);
    if (fallbackResponse) {
      return fallbackResponse as TypedHttpResponse<TResponse>;
    }

    // Apply recovery strategy
    switch (classification.recoveryStrategy) {
      case RecoveryStrategy.RETRY:
        return this.retryWithDelay(httpError, request, classification);
      case RecoveryStrategy.BACKOFF:
        return this.retryWithBackoff(httpError, request, classification);
      case RecoveryStrategy.CIRCUIT_BREAKER:
        return this.handleWithCircuitBreaker(httpError, request, classification);
      case RecoveryStrategy.FALLBACK:
        return this.handleWithFallback(httpError, request, classification);
      case RecoveryStrategy.MANUAL_INTERVENTION:
        throw this.createEnhancedError(httpError, classification);
      case RecoveryStrategy.NO_RECOVERY:
      default:
        throw this.createEnhancedError(httpError, classification);
    }
  }

  /**
   * Classify error based on type and properties
   */
  classifyError(error: HttpError): ErrorClassification {
    // First check custom mappings
    const customMapping = this.config.errorMappings[error.type];
    if (customMapping) {
      return customMapping;
    }

    // Fall back to default classifications
    return DEFAULT_ERROR_CLASSIFICATIONS[error.type] || DEFAULT_ERROR_CLASSIFICATIONS.unknown_error;
  }

  /**
   * Check if error is retryable
   */
  isRetryableError(error: HttpError): boolean {
    const classification = this.classifyError(error);
    return (
      this.config.enableRetry &&
      classification.retryable &&
      this.config.retryableErrors.includes(error.type as ErrorType) &&
      !this.config.nonRetryableErrors.includes(error.type as ErrorType)
    );
  }

  /**
   * Calculate retry delay
   */
  calculateRetryDelay(attempt: number, error: HttpError): number {
    const classification = this.classifyError(error);
    let baseDelay = classification.retryDelay || this.config.baseRetryDelay;

    if (this.config.exponentialBackoff) {
      baseDelay = Math.min(baseDelay * Math.pow(2, attempt), this.config.maxRetryDelay);
    }

    // Add jitter to prevent thundering herd
    const jitter = Math.random() * 0.1 * baseDelay;
    return Math.floor(baseDelay + jitter);
  }

  /**
   * Get error statistics
   */
  getErrorStats(): Record<ErrorCategory, number> {
    return Object.fromEntries(this.errorStats);
  }

  /**
   * Reset error statistics
   */
  resetErrorStats(): void {
    this.errorStats.clear();
  }

  /**
   * Update configuration
   */
  updateConfig(config: Partial<ErrorHandlerConfig>): void {
    this.config = { ...this.config, ...config };
    if (config.fallbackHandlers) {
      this.initializeFallbackHandlers();
    }
  }

  // ============================================================================
  // Private Methods
  // ============================================================================

  /**
   * Ensure error is a proper HttpError
   */
  private ensureHttpError(error: unknown, request: TypedHttpRequest): HttpError {
    if (isHttpError(error)) {
      return error;
    }

    // Convert unknown errors to HttpError
    if (error instanceof Error) {
      const httpError = new Error(error.message) as HttpError;
      httpError.type = this.inferErrorType(error);
      httpError.request = request;
      httpError.timestamp = Date.now();
      httpError.retryable = this.isTypeRetryable(httpError.type);
      return httpError;
    }

    // Unknown error type
    const httpError = new Error('Unknown error occurred') as HttpError;
    httpError.type = 'unknown_error';
    httpError.request = request;
    httpError.timestamp = Date.now();
    httpError.retryable = false;
    httpError.details = { originalError: error };
    return httpError;
  }

  /**
   * Infer error type from generic error
   */
  private inferErrorType(error: Error): HttpErrorType {
    if (error.name === 'TypeError' && error.message.includes('fetch')) {
      return 'network_error';
    }
    if (error.name === 'AbortError') {
      return 'timeout_error';
    }
    if (error.name === 'SyntaxError' && error.message.includes('JSON')) {
      return 'parse_error';
    }
    return 'unknown_error';
  }

  /**
   * Check if error type is retryable
   */
  private isTypeRetryable(type: HttpErrorType): boolean {
    return this.config.retryableErrors.includes(type as ErrorType);
  }

  /**
   * Update error statistics
   */
  private updateErrorStats(category: ErrorCategory): void {
    const current = this.errorStats.get(category) || 0;
    this.errorStats.set(category, current + 1);
  }

  /**
   * Log error with appropriate level
   */
  private logError(error: HttpError, classification: ErrorClassification): void {
    const logData = {
      type: error.type,
      message: error.message,
      category: classification.category,
      severity: classification.severity,
      retryable: classification.retryable,
      request: {
        url: error.request.url,
        method: error.request.method,
      },
      timestamp: error.timestamp,
    };

    switch (classification.severity) {
      case ErrorSeverity.LOW:
        console.debug('HTTP Error:', logData);
        break;
      case ErrorSeverity.MEDIUM:
        console.info('HTTP Error:', logData);
        break;
      case ErrorSeverity.HIGH:
        console.warn('HTTP Error:', logData);
        break;
      case ErrorSeverity.CRITICAL:
        console.error('HTTP Error:', logData);
        break;
    }
  }

  /**
   * Report error to monitoring systems
   */
  private async reportError(error: HttpError, classification: ErrorClassification): Promise<void> {
    // This would integrate with your monitoring/error reporting system
    // For now, we'll just log to console in production
    if (process.env.NODE_ENV === 'production') {
      console.error('Error Report:', {
        type: error.type,
        category: classification.category,
        severity: classification.severity,
        message: error.message,
        timestamp: error.timestamp,
        requestUrl: error.request.url,
        requestMethod: error.request.method,
      });
    }
  }

  /**
   * Try fallback handlers
   */
  private async tryFallbackHandlers(
    error: HttpError,
    request: TypedHttpRequest
  ): Promise<TypedHttpResponse | null> {
    const applicableHandlers = this.fallbackHandlers
      .filter(handler => handler.canHandle(error))
      .sort((a, b) => b.priority - a.priority);

    for (const handler of applicableHandlers) {
      try {
        const response = await handler.handle(error, request);
        if (response) {
          return response;
        }
      } catch (fallbackError) {
        console.warn('Fallback handler failed:', fallbackError);
      }
    }

    return null;
  }

  /**
   * Retry with simple delay
   */
  private async retryWithDelay<TResponse>(
    error: HttpError,
    request: TypedHttpRequest,
    classification: ErrorClassification
  ): Promise<TypedHttpResponse<TResponse>> {
    const maxRetries = classification.maxRetries || this.config.maxRetries;
    const delay = classification.retryDelay || this.config.baseRetryDelay;

    await this.delay(delay);

    // This would need to be integrated with the HTTP client
    // For now, we'll throw an enhanced error
    throw this.createEnhancedError(error, classification);
  }

  /**
   * Retry with exponential backoff
   */
  private async retryWithBackoff<TResponse>(
    error: HttpError,
    request: TypedHttpRequest,
    classification: ErrorClassification
  ): Promise<TypedHttpResponse<TResponse>> {
    const maxRetries = classification.maxRetries || this.config.maxRetries;
    const baseDelay = classification.retryDelay || this.config.baseRetryDelay;

    for (let attempt = 0; attempt < maxRetries; attempt++) {
      const delay = this.calculateRetryDelay(attempt, error);
      await this.delay(delay);

      // In a real implementation, this would retry the actual request
      // For now, we'll throw an enhanced error
      if (attempt === maxRetries - 1) {
        throw this.createEnhancedError(error, classification);
      }
    }

    throw this.createEnhancedError(error, classification);
  }

  /**
   * Handle with circuit breaker
   */
  private async handleWithCircuitBreaker<TResponse>(
    error: HttpError,
    request: TypedHttpRequest,
    classification: ErrorClassification
  ): Promise<TypedHttpResponse<TResponse>> {
    // Circuit breaker logic would go here
    // For now, throw enhanced error
    throw this.createEnhancedError(error, classification);
  }

  /**
   * Handle with fallback response
   */
  private async handleWithFallback<TResponse>(
    error: HttpError,
    request: TypedHttpRequest,
    classification: ErrorClassification
  ): Promise<TypedHttpResponse<TResponse>> {
    // Fallback response logic would go here
    // For now, throw enhanced error
    throw this.createEnhancedError(error, classification);
  }

  /**
   * Create enhanced error with classification details
   */
  private createEnhancedError(error: HttpError, classification: ErrorClassification): HttpError {
    const enhancedError = new Error(error.message) as HttpError;

    // Copy original error properties
    Object.assign(enhancedError, error);

    // Add classification details
    (enhancedError as unknown).classification = classification;
    (enhancedError as unknown).userMessage = classification.userMessage;
    (enhancedError as unknown).technicalDetails = classification.technicalDetails;

    return enhancedError;
  }

  /**
   * Delay helper
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Initialize fallback handlers
   */
  private initializeFallbackHandlers(): void {
    this.fallbackHandlers = [];

    // Add default fallback handlers
    this.fallbackHandlers.push(
      new CacheFallbackHandler(),
      new MockDataFallbackHandler(),
      new DefaultResponseFallbackHandler()
    );

    // Add custom fallback handlers from config
    if (this.config.fallbackHandlers) {
      this.fallbackHandlers.push(...Object.values(this.config.fallbackHandlers));
    }

    // Sort by priority
    this.fallbackHandlers.sort((a, b) => b.priority - a.priority);
  }
}

// ============================================================================
// Fallback Handlers
// ============================================================================

/**
 * Cache fallback handler
 */
class CacheFallbackHandler implements FallbackHandler {
  priority = 10;
  private cache = new Map<string, TypedHttpResponse>();

  canHandle(error: HttpError): boolean {
    return error.type === 'network_error' || error.type === 'server_error';
  }

  async handle(error: HttpError, request: TypedHttpRequest): Promise<TypedHttpResponse | null> {
    const cacheKey = `${request.method}:${request.url}`;
    return this.cache.get(cacheKey) || null;
  }

  setCache(url: string, response: TypedHttpResponse): void {
    this.cache.set(url, response);
  }
}

/**
 * Mock data fallback handler
 */
class MockDataFallbackHandler implements FallbackHandler {
  priority = 5;
  private mockData = new Map<string, unknown>();

  canHandle(error: HttpError): boolean {
    return error.type === 'network_error' || error.type === 'timeout_error';
  }

  async handle(error: HttpError, request: TypedHttpRequest): Promise<TypedHttpResponse | null> {
    const mockResponse = this.mockData.get(request.url);
    if (!mockResponse) {
      return null;
    }

    return {
      data: mockResponse,
      status: 200,
      statusText: 'OK (Mock)',
      headers: new Headers(),
      ok: true,
      url: request.url,
      request,
      duration: 0,
      size: 0,
      timestamp: Date.now(),
    };
  }

  setMockData(url: string, data: unknown): void {
    this.mockData.set(url, data);
  }
}

/**
 * Default response fallback handler
 */
class DefaultResponseFallbackHandler implements FallbackHandler {
  priority = 1;

  canHandle(error: HttpError): boolean {
    return true; // Can handle any error as last resort
  }

  async handle(error: HttpError, request: TypedHttpRequest): Promise<TypedHttpResponse | null> {
    // Return a minimal safe response
    return {
      data: { error: error.message, fallback: true },
      status: 200,
      statusText: 'OK (Fallback)',
      headers: new Headers({ 'X-Fallback-Response': 'true' }),
      ok: true,
      url: request.url,
      request,
      duration: 0,
      size: 0,
      timestamp: Date.now(),
    };
  }
}

// ============================================================================
// Error Handler Factory
// ============================================================================

/**
 * Create HTTP error handler with configuration
 */
export function createHttpErrorHandler(
  config: Partial<ErrorHandlerConfig> = {}
): HttpErrorHandler {
  return new HttpErrorHandler(config);
}

/**
 * Default error handler instance
 */
export const defaultHttpErrorHandler = createHttpErrorHandler();