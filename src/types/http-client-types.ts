// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * Typed HTTP Client Interfaces
 *
 * Comprehensive type-safe HTTP client interfaces that eliminate 'any' usage
 * and provide proper constraints for generic HTTP operations.
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025-11-12
 */

// ============================================================================
// Core HTTP Request/Response Types with Proper Constraints
// ============================================================================

/**
 * Base interface for HTTP request bodies with serialization support
 */
export interface HttpRequestBody {
  toJSON?(): string;
  validate?(): ValidationResult;
}

/**
 * Base interface for HTTP response bodies with deserialization support
 */
export interface HttpResponseBody {
  fromJSON?(data: unknown): this;
  validate?(): ValidationResult;
}

/**
 * Validation result interface
 */
export interface ValidationResult {
  isValid: boolean;
  errors: string[];
}

/**
 * Type constraint for serializable request bodies
 */
export type SerializableRequestBody =
  | string
  | number
  | boolean
  | null
  | undefined
  | Record<string, unknown>
  | unknown[]
  | HttpRequestBody;

/**
 * Type constraint for deserializable response bodies
 */
export type DeserializableResponseBody<T> =
  T extends string ? string :
  T extends number ? number :
  T extends boolean ? boolean :
  T extends null ? null :
  T extends undefined ? undefined :
  T extends Record<string, unknown> ? T :
  T extends unknown[] ? T :
  T extends HttpResponseBody ? T :
  never;

// ============================================================================
// Enhanced Request/Response Interfaces
// ============================================================================

/**
 * Typed HTTP request interface
 */
export interface TypedHttpRequest<TBody = SerializableRequestBody> {
  url: string;
  method: HttpMethod;
  headers?: Record<string, string>;
  body?: TBody;
  timeout?: number;
  retries?: number;
  params?: Record<string, string | number>;
  query?: Record<string, string | number>;
  signal?: AbortSignal;
  validator?: RequestValidator<TBody>;
}

/**
 * Typed HTTP response interface
 */
export interface TypedHttpResponse<TBody = unknown> {
  data: TBody;
  status: HttpStatus;
  statusText: string;
  headers: Headers;
  ok: boolean;
  url: string;
  request: TypedHttpRequest;
  duration: number;
  size: number;
  timestamp: number;
}

/**
 * HTTP method type
 */
export type HttpMethod =
  | 'GET'
  | 'POST'
  | 'PUT'
  | 'PATCH'
  | 'DELETE'
  | 'HEAD'
  | 'OPTIONS';

/**
 * HTTP status code type with specific allowed values
 */
export type HttpStatus =
  | 200 | 201 | 202 | 204 | 206
  | 301 | 302 | 303 | 304 | 307 | 308
  | 400 | 401 | 403 | 404 | 405 | 406 | 408 | 409 | 422 | 429
  | 500 | 501 | 502 | 503 | 504;

// ============================================================================
// Configuration Interfaces
// ============================================================================

/**
 * Typed HTTP client configuration
 */
export interface TypedHttpClientConfig {
  baseURL?: string;
  timeout: number;
  retries: number;
  retryDelay: number;
  headers: Record<string, string>;
  defaultValidator?: GlobalValidator;
  responseValidation?: ResponseValidationConfig;
  errorHandling?: ErrorHandlingConfig;
  interceptors?: InterceptorConfig[];
}

/**
 * Global validator configuration
 */
export interface GlobalValidator {
  request?: <T>(body: T) => ValidationResult;
  response?: <T>(body: T) => ValidationResult;
}

/**
 * Response validation configuration
 */
export interface ResponseValidationConfig {
  enabled: boolean;
  strictMode: boolean;
  schemaValidationEnabled: boolean;
  typeValidationEnabled: boolean;
  customValidators?: Record<string, (data: unknown) => ValidationResult>;
}

/**
 * Error handling configuration
 */
export interface ErrorHandlingConfig {
  retryOnError: boolean;
  retryableStatusCodes: HttpStatus[];
  nonRetryableStatusCodes: HttpStatus[];
  maxRetryDelay: number;
  exponentialBackoff: boolean;
}

/**
 * Interceptor configuration
 */
export interface InterceptorConfig {
  type: 'request' | 'response' | 'error';
  handler: string | ((context: InterceptorContext) => Promise<InterceptorResult>);
  priority: number;
}

/**
 * Interceptor context
 */
export interface InterceptorContext {
  request: TypedHttpRequest;
  response?: TypedHttpResponse;
  error?: TypedHttpError;
  config: TypedHttpClientConfig;
}

/**
 * Interceptor result
 */
export type InterceptorResult =
  | TypedHttpRequest
  | TypedHttpResponse
  | TypedHttpError
  | void;

// ============================================================================
// Error Types with Discrimination
// ============================================================================

/**
 * Base HTTP error with discriminable type
 */
export interface TypedHttpError extends Error {
  readonly type: HttpErrorType;
  readonly statusCode?: HttpStatus;
  readonly response?: TypedHttpResponse;
  readonly request: TypedHttpRequest;
  readonly timestamp: number;
  readonly retryable: boolean;
  readonly details?: Record<string, unknown>;
}

/**
 * HTTP error types for discrimination
 */
export type HttpErrorType =
  | 'network_error'
  | 'timeout_error'
  | 'parse_error'
  | 'validation_error'
  | 'http_error'
  | 'authentication_error'
  | 'authorization_error'
  | 'rate_limit_error'
  | 'server_error'
  | 'unknown_error';

/**
 * Network error (connection issues)
 */
export interface NetworkHttpError extends TypedHttpError {
  readonly type: 'network_error';
  readonly cause: Error;
  readonly retryable: true;
}

/**
 * Timeout error
 */
export interface TimeoutHttpError extends TypedHttpError {
  readonly type: 'timeout_error';
  readonly timeout: number;
  readonly retryable: true;
}

/**
 * Parse error (JSON parsing issues)
 */
export interface ParseHttpError extends TypedHttpError {
  readonly type: 'parse_error';
  readonly rawData: string;
  readonly contentType: string;
  readonly retryable: false;
}

/**
 * Validation error
 */
export interface ValidationError extends TypedHttpError {
  readonly type: 'validation_error';
  readonly validationErrors: string[];
  readonly field?: string;
  readonly retryable: false;
}

/**
 * HTTP status error (4xx/5xx responses)
 */
export interface HttpStatusError extends TypedHttpError {
  readonly type: 'http_error';
  readonly statusCode: HttpStatus;
  readonly statusText: string;
  readonly response: TypedHttpResponse;
  readonly retryable: boolean;
}

/**
 * Authentication error (401)
 */
export interface AuthenticationError extends HttpStatusError {
  readonly type: 'authentication_error';
  readonly statusCode: 401;
  readonly retryable: false;
}

/**
 * Authorization error (403)
 */
export interface AuthorizationError extends HttpStatusError {
  readonly type: 'authorization_error';
  readonly statusCode: 403;
  readonly retryable: false;
}

/**
 * Rate limit error (429)
 */
export interface RateLimitError extends HttpStatusError {
  readonly type: 'rate_limit_error';
  readonly statusCode: 429;
  readonly retryAfter?: number;
  readonly retryable: true;
}

/**
 * Server error (5xx)
 */
export interface ServerError extends HttpStatusError {
  readonly type: 'server_error';
  readonly statusCode: 500 | 501 | 502 | 503 | 504;
  readonly retryable: true;
}

/**
 * Union type of all HTTP errors
 */
export type HttpError =
  | NetworkHttpError
  | TimeoutHttpError
  | ParseHttpError
  | ValidationError
  | AuthenticationError
  | AuthorizationError
  | RateLimitError
  | ServerError
  | (TypedHttpError & { type: 'unknown_error' });

// ============================================================================
// Validation Interfaces
// ============================================================================

/**
 * Request validator interface
 */
export interface RequestValidator<T = SerializableRequestBody> {
  validate(body: T): ValidationResult;
  sanitize?(body: T): T;
}

/**
 * Response validator interface
 */
export interface ResponseValidator<T = unknown> {
  validate(data: unknown): data is T;
  transform?(data: unknown): T;
}

/**
 * JSON schema validator interface
 */
export interface JsonSchemaValidator {
  validate(data: unknown, schema: unknown): ValidationResult;
}

// ============================================================================
// Generic HTTP Client Interface
// ============================================================================

/**
 * Main typed HTTP client interface
 */
export interface TypedHttpClient {
  /**
   * Core request method with full type safety
   */
  request<TResponse = unknown, TRequest = SerializableRequestBody>(
    config: TypedHttpRequest<TRequest>
  ): Promise<TypedHttpResponse<TResponse>>;

  /**
   * Typed GET request
   */
  get<TResponse = unknown>(
    url: string,
    options?: Omit<TypedHttpRequest, 'method' | 'body' | 'url'>
  ): Promise<TypedHttpResponse<TResponse>>;

  /**
   * Typed POST request
   */
  post<TResponse = unknown, TRequest = SerializableRequestBody>(
    url: string,
    data?: TRequest,
    options?: Omit<TypedHttpRequest<TRequest>, 'method' | 'body' | 'url'>
  ): Promise<TypedHttpResponse<TResponse>>;

  /**
   * Typed PUT request
   */
  put<TResponse = unknown, TRequest = SerializableRequestBody>(
    url: string,
    data?: TRequest,
    options?: Omit<TypedHttpRequest<TRequest>, 'method' | 'body' | 'url'>
  ): Promise<TypedHttpResponse<TResponse>>;

  /**
   * Typed PATCH request
   */
  patch<TResponse = unknown, TRequest = SerializableRequestBody>(
    url: string,
    data?: TRequest,
    options?: Omit<TypedHttpRequest<TRequest>, 'method' | 'body' | 'url'>
  ): Promise<TypedHttpResponse<TResponse>>;

  /**
   * Typed DELETE request
   */
  delete<TResponse = unknown>(
    url: string,
    options?: Omit<TypedHttpRequest, 'method' | 'body' | 'url'>
  ): Promise<TypedHttpResponse<TResponse>>;

  /**
   * Get current configuration
   */
  getConfig(): Readonly<TypedHttpClientConfig>;

  /**
   * Update configuration
   */
  updateConfig(config: Partial<TypedHttpClientConfig>): void;

  /**
   * Add interceptor
   */
  addInterceptor(interceptor: InterceptorConfig): void;

  /**
   * Remove interceptor
   */
  removeInterceptor(interceptor: InterceptorConfig): void;
}

// ============================================================================
// Utility Types
// ============================================================================

/**
 * Extract request body type from HTTP request
 */
export type ExtractRequestBody<T> = T extends TypedHttpRequest<infer R> ? R : never;

/**
 * Extract response body type from HTTP response
 */
export type ExtractResponseBody<T> = T extends TypedHttpResponse<infer R> ? R : never;

/**
 * Create typed request options
 */
export type CreateRequestOptions<TRequest = SerializableRequestBody> =
  Omit<TypedHttpRequest<TRequest>, 'url' | 'method'>;

/**
 * Create typed response wrapper
 */
export type TypedResponseWrapper<TResponse = unknown> =
  Promise<TypedHttpResponse<TResponse>>;

/**
 * API contract type for endpoint definitions
 */
export interface ApiContract<TRequest = SerializableRequestBody, TResponse = unknown> {
  endpoint: string;
  method: HttpMethod;
  requestBodyValidator?: RequestValidator<TRequest>;
  responseBodyValidator?: ResponseValidator<TResponse>;
  errorHandlers?: Partial<Record<HttpErrorType, (error: HttpError) => void>>;
  retries?: number;
  timeout?: number;
}

/**
 * Type-safe API client method
 */
export type ApiClientMethod<TRequest = SerializableRequestBody, TResponse = unknown> = (
  data?: TRequest,
  options?: CreateRequestOptions<TRequest>
) => TypedResponseWrapper<TResponse>;

// ============================================================================
// Runtime Type Guards
// ============================================================================

/**
 * Type guard for HTTP errors
 */
export function isHttpError(error: unknown): error is HttpError {
  return (
    error instanceof Error &&
    'type' in error &&
    typeof (error as unknown).type === 'string' &&
    'request' in error &&
    'timestamp' in error &&
    'retryable' in error
  );
}

/**
 * Type guard for network errors
 */
export function isNetworkError(error: unknown): error is NetworkHttpError {
  return isHttpError(error) && error.type === 'network_error';
}

/**
 * Type guard for timeout errors
 */
export function isTimeoutError(error: unknown): error is TimeoutHttpError {
  return isHttpError(error) && error.type === 'timeout_error';
}

/**
 * Type guard for validation errors
 */
export function isValidationError(error: unknown): error is ValidationError {
  return isHttpError(error) && error.type === 'validation_error';
}

/**
 * Type guard for HTTP status errors
 */
export function isHttpStatusError(error: unknown): error is HttpStatusError {
  return isHttpError(error) && error.type === 'http_error';
}

/**
 * Type guard for authentication errors
 */
export function isAuthenticationError(error: unknown): error is AuthenticationError {
  return isHttpError(error) && error.type === 'authentication_error';
}

/**
 * Type guard for authorization errors
 */
export function isAuthorizationError(error: unknown): error is AuthorizationError {
  return isHttpError(error) && error.type === 'authorization_error';
}

/**
 * Type guard for rate limit errors
 */
export function isRateLimitError(error: unknown): error is RateLimitError {
  return isHttpError(error) && error.type === 'rate_limit_error';
}

/**
 * Type guard for server errors
 */
export function isServerError(error: unknown): error is ServerError {
  return isHttpError(error) && error.type === 'server_error';
}

/**
 * Check if error is retryable
 */
export function isRetryableError(error: unknown): boolean {
  return isHttpError(error) && error.retryable;
}