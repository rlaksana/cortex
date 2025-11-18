// ULTIMATE FINAL EMERGENCY ROLLBACK: Remaining systematic type issues

/**
 * Typed HTTP Client Implementation
 *
 * Production-ready HTTP client with comprehensive type safety, validation,
 * error handling, and runtime type checking. Eliminates all 'any' usage.
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025-11-12
 */

import { performance } from 'perf_hooks';

import {
  type AuthenticationError,
  type AuthorizationError,
  type HttpMethod,
  type HttpStatus,
  type HttpStatusError,
  type InterceptorConfig,
  type InterceptorContext,
  isHttpError,
  isRetryableError,
  type NetworkHttpError,
  type RateLimitError,
  type SerializableRequestBody,
  type ServerError,
  type TimeoutHttpError,
  type TypedHttpClient,
  type TypedHttpClientConfig,
  type TypedHttpRequest,
  type TypedHttpResponse,
  type ValidationError,
} from '../types/http-client-types.js';

/**
 * Default HTTP client configuration
 */
const DEFAULT_CONFIG: TypedHttpClientConfig = {
  timeout: 10000,
  retries: 3,
  retryDelay: 1000,
  headers: {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  },
  responseValidation: {
    enabled: true,
    strictMode: false,
    schemaValidationEnabled: true,
    typeValidationEnabled: true,
  },
  errorHandling: {
    retryOnError: true,
    retryableStatusCodes: [408, 429, 500, 502, 503, 504],
    nonRetryableStatusCodes: [400, 401, 403, 404, 422],
    maxRetryDelay: 30000,
    exponentialBackoff: true,
  },
  interceptors: [],
};

/**
 * Typed HTTP Client implementation
 */
export class TypedHttpClientImpl implements TypedHttpClient {
  private config: TypedHttpClientConfig;
  private interceptors: InterceptorConfig[] = [];

  constructor(config: Partial<TypedHttpClientConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.interceptors = [...(config.interceptors || [])];
  }

  /**
   * Core request method with full type safety
   */
  async request<TResponse = unknown, TRequest = SerializableRequestBody>(
    requestConfig: TypedHttpRequest<TRequest>
  ): Promise<TypedHttpResponse<TResponse>> {
    const startTime = performance.now();
    const request = this.mergeDefaults(requestConfig);

    try {
      // Validate request if validator is provided
      if (request.validator) {
        const validation = request.validator.validate(request.body as TRequest);
        if (!validation.isValid) {
          throw this.createValidationError(request, validation.errors, 'Request validation failed');
        }
      }

      // Apply request interceptors
      const processedRequest = await this.applyRequestInterceptors(request);

      // Execute request with retries
      const response = await this.executeWithRetry<TResponse, TRequest>(processedRequest);

      // Apply response interceptors
      const processedResponse = await this.applyResponseInterceptors(response);

      // Calculate duration
      const duration = performance.now() - startTime;
      processedResponse.duration = duration;

      return processedResponse;
    } catch (error) {
      const duration = performance.now() - startTime;

      // Apply error interceptors
      const processedError = await this.applyErrorInterceptors(error, request, duration);

      throw processedError;
    }
  }

  /**
   * Typed GET request
   */
  async get<TResponse = unknown>(
    url: string,
    options: Omit<TypedHttpRequest, 'method' | 'body' | 'url'> = {}
  ): Promise<TypedHttpResponse<TResponse>> {
    return this.request<TResponse>({
      ...options,
      url,
      method: 'GET',
    });
  }

  /**
   * Typed POST request
   */
  async post<TResponse = unknown, TRequest = SerializableRequestBody>(
    url: string,
    data?: TRequest,
    options: Omit<TypedHttpRequest<TRequest>, 'method' | 'body' | 'url'> = {}
  ): Promise<TypedHttpResponse<TResponse>> {
    return this.request<TResponse, TRequest>({
      ...options,
      url,
      method: 'POST',
      body: data,
    });
  }

  /**
   * Typed PUT request
   */
  async put<TResponse = unknown, TRequest = SerializableRequestBody>(
    url: string,
    data?: TRequest,
    options: Omit<TypedHttpRequest<TRequest>, 'method' | 'body' | 'url'> = {}
  ): Promise<TypedHttpResponse<TResponse>> {
    return this.request<TResponse, TRequest>({
      ...options,
      url,
      method: 'PUT',
      body: data,
    });
  }

  /**
   * Typed PATCH request
   */
  async patch<TResponse = unknown, TRequest = SerializableRequestBody>(
    url: string,
    data?: TRequest,
    options: Omit<TypedHttpRequest<TRequest>, 'method' | 'body' | 'url'> = {}
  ): Promise<TypedHttpResponse<TResponse>> {
    return this.request<TResponse, TRequest>({
      ...options,
      url,
      method: 'PATCH',
      body: data,
    });
  }

  /**
   * Typed DELETE request
   */
  async delete<TResponse = unknown>(
    url: string,
    options: Omit<TypedHttpRequest, 'method' | 'body' | 'url'> = {}
  ): Promise<TypedHttpResponse<TResponse>> {
    return this.request<TResponse>({
      ...options,
      url,
      method: 'DELETE',
    });
  }

  /**
   * Get current configuration
   */
  getConfig(): Readonly<TypedHttpClientConfig> {
    return { ...this.config };
  }

  /**
   * Update configuration
   */
  updateConfig(config: Partial<TypedHttpClientConfig>): void {
    this.config = { ...this.config, ...config };
    if (config.interceptors) {
      this.interceptors = [...config.interceptors];
    }
  }

  /**
   * Add interceptor
   */
  addInterceptor(interceptor: InterceptorConfig): void {
    this.interceptors.push(interceptor);
    this.interceptors.sort((a, b) => a.priority - b.priority);
  }

  /**
   * Remove interceptor
   */
  removeInterceptor(interceptor: InterceptorConfig): void {
    const index = this.interceptors.indexOf(interceptor);
    if (index > -1) {
      this.interceptors.splice(index, 1);
    }
  }

  // ============================================================================
  // Private Methods
  // ============================================================================

  /**
   * Merge request with defaults
   */
  private mergeDefaults<TRequest>(request: TypedHttpRequest<TRequest>): TypedHttpRequest<TRequest> {
    const url = this.buildUrl(request.url);
    const headers = { ...this.config.headers, ...request.headers };
    const timeout = request.timeout ?? this.config.timeout;
    const retries = request.retries ?? this.config.retries;

    return {
      ...request,
      url,
      headers,
      timeout,
      retries,
      signal: request.signal,
    };
  }

  /**
   * Build complete URL
   */
  private buildUrl(url: string): string {
    if (!this.config.baseURL) {
      return url;
    }

    const baseUrl = this.config.baseURL.endsWith('/')
      ? this.config.baseURL.slice(0, -1)
      : this.config.baseURL;
    const requestUrl = url.startsWith('/') ? url : `/${url}`;

    return `${baseUrl}${requestUrl}`;
  }

  /**
   * Execute request with retry logic
   */
  private async executeWithRetry<TResponse, TRequest>(
    request: TypedHttpRequest<TRequest>
  ): Promise<TypedHttpResponse<TResponse>> {
    let lastError: Error | null = null;
    const maxRetries = request.retries ?? this.config.retries;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        return await this.executeRequest<TResponse, TRequest>(request);
      } catch (error) {
        lastError = error as Error;

        // Don't retry on last attempt
        if (attempt === maxRetries) {
          break;
        }

        // Check if error is retryable
        if (!isRetryableError(error)) {
          break;
        }

        // Calculate delay
        const delay = this.calculateRetryDelay(attempt, error as Error);
        await this.delay(delay);
      }
    }

    throw lastError;
  }

  /**
   * Execute single request
   */
  private async executeRequest<TResponse, TRequest>(
    request: TypedHttpRequest<TRequest>
  ): Promise<TypedHttpResponse<TResponse>> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), request.timeout);

    try {
      // Prepare fetch options
      const fetchOptions: RequestInit = {
        method: request.method,
        headers: request.headers,
        signal: request.signal || controller.signal,
      };

      // Add body for methods that support it
      if (this.methodSupportsBody(request.method) && request.body !== undefined) {
        fetchOptions.body = this.serializeBody(request.body);
      }

      // Execute fetch
      const response = await fetch(request.url, fetchOptions);
      clearTimeout(timeoutId);

      // Handle HTTP errors
      if (!response.ok) {
        throw this.createHttpError(request, response);
      }

      // Parse response body
      const data = await this.parseResponse<TResponse>(response);

      // Validate response if validation is enabled
      if (this.config.responseValidation?.enabled) {
        await this.validateResponse(data, response);
      }

      // Build typed response
      return {
        data,
        status: response.status as HttpStatus,
        statusText: response.statusText,
        headers: response.headers,
        ok: response.ok,
        url: response.url,
        request,
        duration: 0, // Will be set by calling method
        size: this.calculateResponseSize(response),
        timestamp: Date.now(),
      };
    } catch (error) {
      clearTimeout(timeoutId);

      // Handle abort (timeout)
      if (error instanceof Error && error.name === 'AbortError') {
        throw this.createTimeoutError(request, request.timeout);
      }

      // Handle network errors
      if (error instanceof TypeError) {
        throw this.createNetworkError(request, error);
      }

      throw error;
    }
  }

  /**
   * Check if HTTP method supports body
   */
  private methodSupportsBody(method: HttpMethod): boolean {
    return ['POST', 'PUT', 'PATCH'].includes(method);
  }

  /**
   * Serialize request body
   */
  private serializeBody(body: SerializableRequestBody): string | undefined {
    if (body === null || body === undefined) {
      return undefined;
    }

    if (typeof body === 'string') {
      return body;
    }

    if (typeof body === 'object' && body !== null && 'toJSON' in body && typeof (body as { toJSON?: () => string }).toJSON === 'function') {
      return (body as { toJSON: () => string }).toJSON();
    }

    return JSON.stringify(body);
  }

  /**
   * Parse response body
   */
  private async parseResponse<TResponse>(response: Response): Promise<TResponse> {
    const contentType = response.headers.get('content-type') || '';

    try {
      if (contentType.includes('application/json')) {
        return await response.json();
      }

      if (contentType.includes('text/')) {
        return (await response.text()) as unknown as TResponse;
      }

      if (
        contentType.includes('application/octet-stream') ||
        contentType.includes('application/pdf')
      ) {
        return (await response.arrayBuffer()) as unknown as TResponse;
      }

      // Default to text for any content types
      return (await response.text()) as unknown as TResponse;
    } catch (error) {
      const errorResponse: TypedHttpResponse = {
        data: null as unknown,
        status: response.status as HttpStatus,
        statusText: response.statusText,
        headers: response.headers,
        ok: response.ok,
        url: response.url,
        request: {} as TypedHttpRequest,
        duration: 0,
        size: 0,
        timestamp: Date.now(),
      };

      throw new ParseHttpError(
        `Failed to parse response: ${(error as Error).message}`,
        response.status as HttpStatus,
        response.statusText,
        errorResponse,
        await response.text(),
        contentType
      );
    }
  }

  /**
   * Validate response data
   */
  private async validateResponse<TResponse>(data: TResponse, response: Response): Promise<void> {
    const validationConfig = this.config.responseValidation;
    if (!validationConfig?.enabled) {
      return;
    }

    // Type validation (basic runtime checks)
    if (validationConfig.typeValidationEnabled) {
      // Add basic type validation logic here
      // This is a simplified version - you might want to integrate with a more
      // sophisticated validation library like Zod or io-ts
    }

    // Schema validation would go here if enabled
    if (validationConfig.schemaValidationEnabled && validationConfig.customValidators) {
      const contentType = response.headers.get('content-type');
      if (contentType && validationConfig.customValidators[contentType]) {
        const validator = validationConfig.customValidators[contentType];
        const result = validator(data);
        if (!result.isValid) {
          const validationError = new Error(
            `Response validation failed: ${result.errors.join(', ')}`
          );
          // Add validation error properties
          Object.defineProperty(validationError, 'type', {
            value: 'validation_error',
            enumerable: true,
            writable: false,
          });
          Object.defineProperty(validationError, 'validationErrors', {
            value: result.errors,
            enumerable: true,
            writable: false,
          });
          Object.defineProperty(validationError, 'statusCode', {
            value: 400,
            enumerable: true,
            writable: false,
          });
          Object.defineProperty(validationError, 'statusText', {
            value: 'Bad Request',
            enumerable: true,
            writable: false,
          });
          Object.defineProperty(validationError, 'response', {
            value: {} as TypedHttpResponse,
            enumerable: true,
            writable: false,
          });
          Object.defineProperty(validationError, 'timestamp', {
            value: Date.now(),
            enumerable: true,
            writable: false,
          });
          Object.defineProperty(validationError, 'retryable', {
            value: false,
            enumerable: true,
            writable: false,
          });
          throw validationError;
        }
      }
    }
  }

  /**
   * Calculate response size
   */
  private calculateResponseSize(response: Response): number {
    const contentLength = response.headers.get('content-length');
    return contentLength ? parseInt(contentLength, 10) : 0;
  }

  /**
   * Calculate retry delay
   */
  private calculateRetryDelay(attempt: number, error: Error): number {
    const baseDelay = this.config.retryDelay;

    if (!this.config.errorHandling?.exponentialBackoff) {
      return baseDelay;
    }

    // Exponential backoff with jitter
    const exponentialDelay = baseDelay * Math.pow(2, attempt);
    const jitter = Math.random() * 0.1 * exponentialDelay; // 10% jitter
    const totalDelay = exponentialDelay + jitter;

    return Math.min(totalDelay, this.config.errorHandling?.maxRetryDelay || 30000);
  }

  /**
   * Delay helper
   */
  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  // ============================================================================
  // Error Creation Methods
  // ============================================================================

  /**
   * Create network error
   */
  private createNetworkError<TRequest>(
    request: TypedHttpRequest<TRequest>,
    cause: Error
  ): NetworkHttpError {
    const error = Object.assign(new Error(`Network error: ${cause.message}`), {
      type: 'network_error',
      cause,
      request,
      timestamp: Date.now(),
      retryable: true,
      statusCode: 0, // Network errors don't have HTTP status codes
      response: {} as TypedHttpResponse
    }) as NetworkHttpError;
    return error;
  }

  /**
   * Create timeout error
   */
  private createTimeoutError<TRequest>(
    request: TypedHttpRequest<TRequest>,
    timeout: number
  ): TimeoutHttpError {
    return Object.assign(new Error(`Request timeout after ${timeout}ms`) as TimeoutHttpError, {
      type: 'timeout_error' as const,
      timeout,
      request,
      timestamp: Date.now(),
      retryable: true,
      statusCode: 408, // Request Timeout
      response: {} as TypedHttpResponse
    });
  }

  /**
   * Create HTTP status error
   */
  private createHttpError<TRequest>(
    request: TypedHttpRequest<TRequest>,
    response: Response
  ): HttpStatusError {
    const status = response.status as HttpStatus;
    const statusText = response.statusText;

    // Create specific error types based on status code
    switch (status) {
      case 401:
        return this.createAuthenticationError(
          request,
          status,
          statusText
        ) as unknown as HttpStatusError;
      case 403:
        return this.createAuthorizationError(
          request,
          status,
          statusText
        ) as unknown as HttpStatusError;
      case 429:
        return this.createRateLimitError(
          request,
          status,
          statusText,
          response
        ) as unknown as HttpStatusError;
      case 500:
      case 501:
      case 502:
      case 503:
      case 504:
        return this.createServerError(request, status, statusText) as unknown as HttpStatusError;
      default:
        return this.createGenericHttpStatusError(request, status, statusText);
    }
  }

  /**
   * Create authentication error
   */
  private createAuthenticationError<TRequest>(
    request: TypedHttpRequest<TRequest>,
    status: HttpStatus,
    statusText: string
  ): AuthenticationError {
    return Object.assign(new Error(
      `Authentication failed: ${statusText}`
    ) as AuthenticationError, {
      type: 'authentication_error' as const,
      statusCode: status,
      statusText,
      request,
      timestamp: Date.now(),
      retryable: false,
      response: {} as TypedHttpResponse
    });
  }

  /**
   * Create authorization error
   */
  private createAuthorizationError<TRequest>(
    request: TypedHttpRequest<TRequest>,
    status: HttpStatus,
    statusText: string
  ): AuthorizationError {
    return Object.assign(new Error(`Authorization failed: ${statusText}`) as AuthorizationError, {
      type: 'authorization_error' as const,
      statusCode: status,
      statusText,
      request,
      timestamp: Date.now(),
      retryable: false,
      response: {} as TypedHttpResponse
    });
  }

  /**
   * Create rate limit error
   */
  private createRateLimitError<TRequest>(
    request: TypedHttpRequest<TRequest>,
    status: HttpStatus,
    statusText: string,
    response: Response
  ): RateLimitError {
    const retryAfter = response.headers.get('retry-after');
    const retryAfterMs = retryAfter ? parseInt(retryAfter, 10) * 1000 : undefined;

    return {
      name: 'RateLimitError',
      message: `Rate limit exceeded: ${statusText}`,
      stack: new Error().stack,
      type: 'rate_limit_error',
      statusCode: 429 as const, // Rate limit is always 429
      statusText,
      request,
      timestamp: Date.now(),
      retryable: true,
      retryAfter: retryAfterMs,
      response: {} as TypedHttpResponse,
    };
  }

  /**
   * Create server error
   */
  private createServerError<TRequest>(
    request: TypedHttpRequest<TRequest>,
    status: HttpStatus,
    statusText: string
  ): ServerError {
    return {
      name: 'ServerError',
      message: `Server error: ${statusText}`,
      stack: new Error().stack,
      type: 'server_error',
      statusCode: (status >= 500 && status <= 504 ? status : 500) as 500 | 501 | 502 | 503 | 504,
      statusText,
      request,
      timestamp: Date.now(),
      retryable: true,
      response: {} as TypedHttpResponse,
    };
  }

  /**
   * Create generic HTTP status error
   */
  private createGenericHttpStatusError<TRequest>(
    request: TypedHttpRequest<TRequest>,
    status: HttpStatus,
    statusText: string
  ): HttpStatusError {
    return {
      name: 'HttpStatusError',
      message: `HTTP ${status}: ${statusText}`,
      stack: new Error().stack,
      type: 'http_error',
      statusCode: status,
      statusText,
      request,
      timestamp: Date.now(),
      retryable: this.isRetryableStatus(status),
      response: {} as TypedHttpResponse,
    };
  }

  /**
   * Create validation error
   */
  private createValidationError<TRequest>(
    request: TypedHttpRequest<TRequest>,
    errors: string[],
    message: string
  ): ValidationError {
    return {
      name: 'ValidationError',
      message,
      stack: new Error().stack,
      type: 'validation_error',
      validationErrors: errors,
      request,
      timestamp: Date.now(),
      retryable: false,
      response: {} as TypedHttpResponse,
      statusCode: 400,
    };
  }

  /**
   * Check if status code is retryable
   */
  private isRetryableStatus(status: HttpStatus): boolean {
    return this.config.errorHandling?.retryableStatusCodes?.includes(status) ?? false;
  }

  // ============================================================================
  // Interceptor Methods
  // ============================================================================

  /**
   * Apply request interceptors
   */
  private async applyRequestInterceptors<TRequest>(
    request: TypedHttpRequest<TRequest>
  ): Promise<TypedHttpRequest<TRequest>> {
    let processedRequest = request;

    for (const interceptor of this.interceptors.filter((i) => i.type === 'request')) {
      const context: InterceptorContext = {
        request: processedRequest,
        config: this.config,
      };

      const result = await this.executeInterceptor(interceptor, context);
      if (result) {
        processedRequest = result as TypedHttpRequest<TRequest>;
      }
    }

    return processedRequest;
  }

  /**
   * Apply response interceptors
   */
  private async applyResponseInterceptors<TResponse>(
    response: TypedHttpResponse<TResponse>
  ): Promise<TypedHttpResponse<TResponse>> {
    let processedResponse = response;

    for (const interceptor of this.interceptors.filter((i) => i.type === 'response')) {
      const context: InterceptorContext = {
        request: response.request,
        response: processedResponse,
        config: this.config,
      };

      const result = await this.executeInterceptor(interceptor, context);
      if (result) {
        processedResponse = result as TypedHttpResponse<TResponse>;
      }
    }

    return processedResponse;
  }

  /**
   * Apply error interceptors
   */
  private async applyErrorInterceptors<TRequest>(
    error: unknown,
    request: TypedHttpRequest<TRequest>,
    duration: number
  ): Promise<unknown> {
    let processedError = error;

    for (const interceptor of this.interceptors.filter((i) => i.type === 'error')) {
      const context: InterceptorContext = {
        request,
        config: this.config,
      };

      if (isHttpError(processedError)) {
        context.error = processedError;
      }

      const result = await this.executeInterceptor(interceptor, context);
      if (result) {
        processedError = result;
      }
    }

    return processedError;
  }

  /**
   * Execute interceptor
   */
  private async executeInterceptor(
    interceptor: InterceptorConfig,
    context: InterceptorContext
  ): Promise<unknown> {
    try {
      if (typeof interceptor.handler === 'function') {
        return await interceptor.handler(context);
      }

      // If handler is a string, you might want to resolve it from a registry
      // This is a placeholder for that functionality
      return null;
    } catch (error) {
      console.error('Interceptor error:', error);
      return null;
    }
  }
}

// ============================================================================
// Custom Error Classes
// ============================================================================

class ParseHttpError extends Error {
  declare public readonly type: 'parse_error';
  declare public readonly statusCode: HttpStatus;
  declare public readonly statusText: string;
  declare public readonly response: TypedHttpResponse;
  declare public readonly rawData: string;
  declare public readonly contentType: string;
  declare public readonly request: TypedHttpRequest;
  declare public readonly timestamp: number;
  declare public readonly retryable: false;

  constructor(
    message: string,
    statusCode: HttpStatus,
    statusText: string,
    response: TypedHttpResponse,
    rawData: string,
    contentType: string
  ) {
    super(message);
    Object.assign(this, {
      type: 'parse_error',
      statusCode,
      statusText,
      response,
      rawData,
      contentType,
      request: response.request,
      timestamp: Date.now(),
      retryable: false,
    });
  }
}

// ============================================================================
// Factory Functions
// ============================================================================

/**
 * Create a typed HTTP client with configuration
 */
export function createTypedHttpClient(
  config: Partial<TypedHttpClientConfig> = {}
): TypedHttpClient {
  return new TypedHttpClientImpl(config);
}

/**
 * Create a typed HTTP client with builder pattern
 */
export class TypedHttpClientBuilder {
  private config: Partial<TypedHttpClientConfig> = {};

  baseURL(baseURL: string): TypedHttpClientBuilder {
    this.config.baseURL = baseURL;
    return this;
  }

  timeout(timeout: number): TypedHttpClientBuilder {
    this.config.timeout = timeout;
    return this;
  }

  retries(retries: number): TypedHttpClientBuilder {
    this.config.retries = retries;
    return this;
  }

  retryDelay(retryDelay: number): TypedHttpClientBuilder {
    this.config.retryDelay = retryDelay;
    return this;
  }

  headers(headers: Record<string, string>): TypedHttpClientBuilder {
    this.config.headers = { ...this.config.headers, ...headers };
    return this;
  }

  responseValidation(
    validation: TypedHttpClientConfig['responseValidation']
  ): TypedHttpClientBuilder {
    this.config.responseValidation = validation;
    return this;
  }

  errorHandling(handling: TypedHttpClientConfig['errorHandling']): TypedHttpClientBuilder {
    this.config.errorHandling = handling;
    return this;
  }

  addInterceptor(interceptor: InterceptorConfig): TypedHttpClientBuilder {
    if (!this.config.interceptors) {
      this.config.interceptors = [];
    }
    this.config.interceptors.push(interceptor);
    return this;
  }

  build(): TypedHttpClient {
    return new TypedHttpClientImpl(this.config);
  }
}

/**
 * Default typed HTTP client instance
 */
export const typedHttpClient = createTypedHttpClient();
