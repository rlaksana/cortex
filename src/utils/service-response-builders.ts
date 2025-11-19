/**
 * Service Response Builders
 *
 * Provides type-safe response builders for consistent service response creation
 * with runtime validation and standardized error handling.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import type { ServiceMetadata,ServiceResponse } from '../interfaces/service-interfaces.js';

/**
 * Response builder for creating standardized ServiceResponse objects
 */
export class ServiceResponseBuilder<T = unknown> {
  private response: Partial<ServiceResponse<T>> = {
    success: false,
  };

  private metadata: Partial<ServiceMetadata> = {};

  /**
   * Create a successful response
   */
  static success<T>(
    data: T,
    metadata?: Partial<ServiceMetadata>
  ): ServiceResponse<T> {
    const builder = new ServiceResponseBuilder<T>();
    builder.response.success = true;
    builder.response.data = data;

    if (metadata) {
      builder.metadata = { ...metadata };
    }

    return builder.build();
  }

  /**
   * Create an error response
   */
  static error<T = never>(
    code: string,
    message: string,
    details?: Record<string, unknown>,
    metadata?: Partial<ServiceMetadata>
  ): ServiceResponse<T> {
    const builder = new ServiceResponseBuilder<T>();
    builder.response.success = false;
    builder.response.error = {
      code,
      message,
      details,
      timestamp: new Date().toISOString(),
      retryable: ServiceResponseBuilder.isRetryableError(code),
    };

    if (metadata) {
      builder.metadata = { ...metadata };
    }

    return builder.build();
  }

  /**
   * Add metadata to the response
   */
  withMetadata(metadata: Partial<ServiceMetadata>): this {
    this.metadata = { ...this.metadata, ...metadata };
    return this;
  }

  /**
   * Add processing time to metadata
   */
  withProcessingTime(startTime: number): this {
    this.metadata.processingTimeMs = Date.now() - startTime;
    return this;
  }

  /**
   * Add request ID to metadata
   */
  withRequestId(requestId: string): this {
    this.metadata.requestId = requestId;
    return this;
  }

  /**
   * Mark response as cached
   */
  markAsCached(source?: string): this {
    this.metadata.cached = true;
    if (source) {
      this.metadata.source = source;
    }
    return this;
  }

  /**
   * Build the final response
   */
  build(): ServiceResponse<T> {
    const response: ServiceResponse<T> = {
      success: this.response.success || false,
    };

    if (this.response.data !== undefined) {
      response.data = this.response.data;
    }

    if (this.response.error) {
      response.error = this.response.error;
    }

    if (Object.keys(this.metadata).length > 0) {
      response.metadata = this.metadata as ServiceMetadata;
    }

    return response;
  }

  /**
   * Determine if an error is retryable based on error code
   */
  private static isRetryableError(code: string): boolean {
    const retryableCodes = [
      'TIMEOUT_ERROR',
      'NETWORK_ERROR',
      'CONNECTION_ERROR',
      'RATE_LIMIT_ERROR',
      'SERVICE_UNAVAILABLE',
      'DATABASE_CONNECTION_ERROR',
    ];

    return retryableCodes.includes(code);
  }
}

/**
 * Type guard for validating ServiceResponse structure
 */
export function isServiceResponse<T = unknown>(
  response: unknown
): response is ServiceResponse<T> {
  if (!response || typeof response !== 'object') {
    return false;
  }

  const resp = response as Record<string, unknown>;

  // Check required fields
  if (typeof resp.success !== 'boolean') {
    return false;
  }

  // If successful, should have data
  if (resp.success && resp.data === undefined) {
    return false;
  }

  // If unsuccessful, should have error
  if (!resp.success && !resp.error) {
    return false;
  }

  // Validate error structure if present
  if (resp.error) {
    const error = resp.error as Record<string, unknown>;
    if (
      typeof error.code !== 'string' ||
      typeof error.message !== 'string' ||
      typeof error.timestamp !== 'string'
    ) {
      return false;
    }
  }

  return true;
}

/**
 * Runtime validator for service responses
 */
export class ServiceResponseValidator {
  /**
   * Validate and throw if invalid
   */
  static validate<T>(response: unknown): asserts response is ServiceResponse<T> {
    if (!isServiceResponse<T>(response)) {
      throw new Error('Invalid ServiceResponse structure');
    }
  }

  /**
   * Validate and return boolean result
   */
  static isValid<T>(response: unknown): response is ServiceResponse<T> {
    return isServiceResponse<T>(response);
  }

  /**
   * Validate response data against expected type
   */
  static validateData<T>(
    response: ServiceResponse<T>,
    validator: (data: unknown) => data is T
  ): response is ServiceResponse<T> {
    if (!response.success || response.data === undefined) {
      return false;
    }

    return validator(response.data);
  }
}

/**
 * Common error code factory
 */
export class ServiceErrorCodes {
  static readonly VALIDATION_ERROR = 'VALIDATION_ERROR';
  static readonly NOT_FOUND_ERROR = 'NOT_FOUND_ERROR';
  static readonly DATABASE_ERROR = 'DATABASE_ERROR';
  static readonly NETWORK_ERROR = 'NETWORK_ERROR';
  static readonly TIMEOUT_ERROR = 'TIMEOUT_ERROR';
  static readonly RATE_LIMIT_ERROR = 'RATE_LIMIT_ERROR';
  static readonly AUTHORIZATION_ERROR = 'AUTHORIZATION_ERROR';
  static readonly CONFLICT_ERROR = 'CONFLICT_ERROR';
  static readonly INTERNAL_ERROR = 'INTERNAL_ERROR';
  static readonly SERVICE_UNAVAILABLE = 'SERVICE_UNAVAILABLE';
  static readonly UNKNOWN_ERROR = 'UNKNOWN_ERROR';
}

/**
 * Error response factory for common scenarios
 */
export class ServiceErrorFactory {
  /**
   * Create validation error
   */
  static validation(
    message: string,
    field?: string,
    details?: Record<string, unknown>
  ): ServiceResponse<never> {
    return ServiceResponseBuilder.error(
      ServiceErrorCodes.VALIDATION_ERROR,
      message,
      { field, ...details }
    );
  }

  /**
   * Create not found error
   */
  static notFound(
    resource: string,
    identifier: string,
    details?: Record<string, unknown>
  ): ServiceResponse<never> {
    return ServiceResponseBuilder.error(
      ServiceErrorCodes.NOT_FOUND_ERROR,
      `${resource} with identifier '${identifier}' not found`,
      details
    );
  }

  /**
   * Create database error
   */
  static database(
    message: string,
    details?: Record<string, unknown>
  ): ServiceResponse<never> {
    return ServiceResponseBuilder.error(
      ServiceErrorCodes.DATABASE_ERROR,
      message,
      details
    );
  }

  /**
   * Create rate limit error
   */
  static rateLimit(
    retryAfter?: number,
    details?: Record<string, unknown>
  ): ServiceResponse<never> {
    return ServiceResponseBuilder.error(
      ServiceErrorCodes.RATE_LIMIT_ERROR,
      'Rate limit exceeded',
      { retryAfter, ...details }
    );
  }

  /**
   * Create authorization error
   */
  static authorization(
    message: string = 'Unauthorized access',
    details?: Record<string, unknown>
  ): ServiceResponse<never> {
    return ServiceResponseBuilder.error(
      ServiceErrorCodes.AUTHORIZATION_ERROR,
      message,
      details
    );
  }

  /**
   * Create conflict error
   */
  static conflict(
    message: string,
    details?: Record<string, unknown>
  ): ServiceResponse<never> {
    return ServiceResponseBuilder.error(
      ServiceErrorCodes.CONFLICT_ERROR,
      message,
      details
    );
  }

  /**
   * Create internal server error
   */
  static internal(
    message: string = 'Internal server error',
    details?: Record<string, unknown>
  ): ServiceResponse<never> {
    return ServiceResponseBuilder.error(
      ServiceErrorCodes.INTERNAL_ERROR,
      message,
      details
    );
  }
}

/**
 * Type validators for common data structures
 */
export class TypeValidators {
  /**
   * Validate string data
   */
  static isString(data: unknown): data is string {
    return typeof data === 'string';
  }

  /**
   * Validate number data
   */
  static isNumber(data: unknown): data is number {
    return typeof data === 'number' && !isNaN(data);
  }

  /**
   * Validate boolean data
   */
  static isBoolean(data: unknown): data is boolean {
    return typeof data === 'boolean';
  }

  /**
   * Validate array data
   */
  static isArray<T>(validator: (item: unknown) => item is T) {
    return (data: unknown): data is T[] => {
      return Array.isArray(data) && data.every(validator);
    };
  }

  /**
   * Validate object data
   */
  static isObject(data: unknown): data is Record<string, unknown> {
    return data !== null && typeof data === 'object' && !Array.isArray(data);
  }

  /**
   * Validate object with specific shape
   */
  static isObjectShape<T extends Record<string, unknown>>(
    shape: { [K in keyof T]: (data: unknown) => data is T[K] }
  ) {
    return (data: unknown): data is T => {
      if (!TypeValidators.isObject(data)) {
        return false;
      }

      for (const [key, validator] of Object.entries(shape)) {
        if (!validator(data[key])) {
          return false;
        }
      }

      return true;
    };
  }
}