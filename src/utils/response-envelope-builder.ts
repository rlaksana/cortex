/**
 * MCP Response Envelope Builder
 *
 * Type-safe response builders for creating standardized MCP tool responses
 * using envelope patterns to eliminate 'any' usage.
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

import { v4 as uuidv4 } from 'uuid';

import {
  type DatabaseErrorDetails,
  type MemoryFindResult,
  type MemoryStoreResult,
  type RateLimitErrorDetails,
  type SystemStatusResult,
  type ValidationErrorDetails} from '../types/mcp-response-data.types';
import {
  type ErrorEnvelope,
  isErrorEnvelope,
  isSuccessEnvelope,
  type PaginatedEnvelope,
  type ResponseEnvelope,
  type StreamingEnvelope,
  type SuccessEnvelope} from '../types/response-envelope.types';
import { createResponseMeta, type SearchStrategy, type UnifiedResponseMeta } from '../types/unified-response.interface';

/**
 * Response envelope builder context
 */
interface EnvelopeBuilderContext {
  operationType: string;
  startTime: number;
  requestId: string;
  operationId?: string;
  apiVersion: string;
}

/**
 * Error codes for standardized error handling
 */
export enum ErrorCode {
  // Validation errors (400)
  VALIDATION_FAILED = 'VALIDATION_FAILED',
  INVALID_INPUT = 'INVALID_INPUT',
  MISSING_REQUIRED_FIELD = 'MISSING_REQUIRED_FIELD',
  INVALID_FORMAT = 'INVALID_FORMAT',

  // Authentication/Authorization errors (401/403)
  UNAUTHORIZED = 'UNAUTHORIZED',
  FORBIDDEN = 'FORBIDDEN',
  INVALID_API_KEY = 'INVALID_API_KEY',
  INSUFFICIENT_PERMISSIONS = 'INSUFFICIENT_PERMISSIONS',

  // Rate limiting errors (429)
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  QUOTA_EXCEEDED = 'QUOTA_EXCEEDED',

  // Resource errors (404/409)
  NOT_FOUND = 'NOT_FOUND',
  ALREADY_EXISTS = 'ALREADY_EXISTS',
  CONFLICT = 'CONFLICT',

  // Server errors (500)
  INTERNAL_SERVER_ERROR = 'INTERNAL_SERVER_ERROR',
  DATABASE_ERROR = 'DATABASE_ERROR',
  EXTERNAL_SERVICE_ERROR = 'EXTERNAL_SERVICE_ERROR',
  TIMEOUT = 'TIMEOUT',
  UNAVAILABLE = 'UNAVAILABLE',

  // Business logic errors
  PROCESSING_FAILED = 'PROCESSING_FAILED',
  STORAGE_LIMIT_EXCEEDED = 'STORAGE_LIMIT_EXCEEDED',
  INVALID_OPERATION = 'INVALID_OPERATION'
}

/**
 * Type-safe response envelope builder
 */
export class ResponseEnvelopeBuilder {
  private context: EnvelopeBuilderContext;

  constructor(operationType: string, startTime?: number, apiVersion: string = '1.0.0') {
    this.context = {
      operationType,
      startTime: startTime || Date.now(),
      requestId: uuidv4(),
      apiVersion
    };
  }

  /**
   * Set operation ID for tracking
   */
  setOperationId(operationId: string): ResponseEnvelopeBuilder {
    this.context.operationId = operationId;
    return this;
  }

  /**
   * Create a success envelope
   */
  createSuccessEnvelope<TData>(
    data: TData,
    meta: UnifiedResponseMeta,
    message?: string,
    rateLimit?: SuccessEnvelope['rate_limit']
  ): SuccessEnvelope<TData> {
    return {
      type: 'success',
      success: true,
      data,
      meta,
      timestamp: new Date().toISOString(),
      request_id: this.context.requestId,
      operation_id: this.context.operationId,
      api_version: this.context.apiVersion,
      ...(message && { message }),
      ...(rateLimit && { rate_limit: rateLimit })
    };
  }

  /**
   * Create an error envelope
   */
  createErrorEnvelope<TErrorData = unknown>(
    code: ErrorCode,
    message: string,
    errorType: string = code,
    details?: TErrorData,
    retryable: boolean = false,
    retryAfterMs?: number
  ): ErrorEnvelope<TErrorData> {
    const errorId = uuidv4();
    const error = new Error(message);

    return {
      type: 'error',
      success: false,
      data: null,
      meta: createResponseMeta({
        strategy: 'error',
        vector_used: false,
        degraded: true,
        source: 'cortex_memory',
        execution_time_ms: Date.now() - this.context.startTime,
        confidence_score: 0.0,
        additional: {
          error_id: errorId,
          error_code: code,
          error_type: errorType,
          operation_type: this.context.operationType
        }
      }),
      timestamp: new Date().toISOString(),
      request_id: this.context.requestId,
      operation_id: this.context.operationId,
      api_version: this.context.apiVersion,
      error: {
        code,
        message,
        type: errorType,
        ...(process.env.NODE_ENV === 'development' && { stack: error.stack }),
        ...(details && { details }),
        retryable,
        ...(retryAfterMs && { retry_after_ms: retryAfterMs })
      },
      error_id: errorId
    };
  }

  /**
   * Create a paginated envelope
   */
  createPaginatedEnvelope<TData>(
    items: TData[],
    pagination: PaginatedEnvelope['pagination'],
    meta: UnifiedResponseMeta,
    summary?: Record<string, unknown>
  ): PaginatedEnvelope<TData> {
    return {
      type: 'paginated',
      success: true,
      data: items,
      meta,
      timestamp: new Date().toISOString(),
      request_id: this.context.requestId,
      operation_id: this.context.operationId,
      api_version: this.context.apiVersion,
      pagination,
      ...(summary && { summary })
    };
  }

  /**
   * Create a streaming envelope
   */
  createStreamingEnvelope<TData>(
    data: TData,
    streamId: string,
    chunkNumber: number,
    status: StreamingEnvelope['stream']['status'],
    meta: UnifiedResponseMeta,
    streamMetadata?: StreamingEnvelope['stream_metadata']
  ): StreamingEnvelope<TData> {
    return {
      type: 'streaming',
      success: true,
      data,
      meta,
      timestamp: new Date().toISOString(),
      request_id: this.context.requestId,
      operation_id: this.context.operationId,
      api_version: this.context.apiVersion,
      stream: {
        stream_id: streamId,
        chunk_number: chunkNumber,
        status,
        is_final: status === 'completed'
      },
      ...(streamMetadata && { stream_metadata: streamMetadata })
    };
  }

  /**
   * Create a memory store success response
   */
  createMemoryStoreSuccess(
    result: MemoryStoreResult,
    strategy: SearchStrategy = 'autonomous_deduplication',
    vectorUsed: boolean = true,
    degraded: boolean = false
  ): SuccessEnvelope<MemoryStoreResult> {
    const duration = Date.now() - this.context.startTime;

    return this.createSuccessEnvelope(
      result,
      createResponseMeta({
        strategy,
        vector_used: vectorUsed,
        degraded,
        source: 'cortex_memory',
        execution_time_ms: duration,
        confidence_score: result.summary.success_rate,
        additional: {
          operation_type: 'memory_store',
          batch_id: result.batch_id,
          items_processed: result.summary.total_attempted,
          items_stored: result.summary.total_stored,
          items_failed: result.summary.total_failed,
          success_rate: result.summary.success_rate
        }
      }),
      `Successfully stored ${result.summary.total_stored} of ${result.summary.total_attempted} items`
    );
  }

  /**
   * Create a memory find success response
   */
  createMemoryFindSuccess(
    result: MemoryFindResult,
    strategy: SearchStrategy = 'auto',
    vectorUsed: boolean = false,
    degraded: boolean = false
  ): SuccessEnvelope<MemoryFindResult> {
    const duration = Date.now() - this.context.startTime;

    return this.createSuccessEnvelope(
      result,
      createResponseMeta({
        strategy,
        vector_used: vectorUsed,
        degraded,
        source: 'cortex_memory',
        execution_time_ms: duration,
        confidence_score: result.confidence,
        additional: {
          operation_type: 'memory_find',
          search_id: result.search_id,
          query: result.query,
          results_found: result.total,
          items_returned: result.items.length,
          confidence: result.confidence,
          expansion_type: result.expansion?.type,
          expansion_items_added: result.expansion?.items_added
        }
      }),
      `Found ${result.total} results for query: "${result.query}"`
    );
  }

  /**
   * Create a system status success response
   */
  createSystemStatusSuccess(
    result: SystemStatusResult,
    strategy: SearchStrategy = 'health_check'
  ): SuccessEnvelope<SystemStatusResult> {
    const duration = Date.now() - this.context.startTime;

    return this.createSuccessEnvelope(
      result,
      createResponseMeta({
        strategy,
        vector_used: false,
        degraded: result.status === 'degraded',
        source: 'cortex_memory',
        execution_time_ms: duration,
        confidence_score: result.status === 'healthy' ? 1.0 : 0.5,
        additional: {
          operation_type: 'system_status',
          system_status: result.status,
          component_count: Object.keys(result.components).length,
          api_version: result.version.api_version,
          server_version: result.version.server_version
        }
      }),
      `System status: ${result.status.toUpperCase()}`
    );
  }

  /**
   * Create a validation error response
   */
  createValidationError(
    validationErrors: ValidationErrorDetails[],
    message: string = 'Validation failed'
  ): ErrorEnvelope<ValidationErrorDetails[]> {
    return this.createErrorEnvelope(
      ErrorCode.VALIDATION_FAILED,
      message,
      'ValidationError',
      validationErrors,
      false
    );
  }

  /**
   * Create a rate limit error response
   */
  createRateLimitError(
    details: RateLimitErrorDetails,
    message: string = 'Rate limit exceeded'
  ): ErrorEnvelope<RateLimitErrorDetails> {
    return this.createErrorEnvelope(
      ErrorCode.RATE_LIMIT_EXCEEDED,
      message,
      'RateLimitError',
      details,
      true,
      details.reset_in_seconds * 1000
    );
  }

  /**
   * Create a database error response
   */
  createDatabaseError(
    error: Error,
    details: DatabaseErrorDetails,
    message: string = 'Database operation failed'
  ): ErrorEnvelope<DatabaseErrorDetails> {
    return this.createErrorEnvelope(
      ErrorCode.DATABASE_ERROR,
      message,
      'DatabaseError',
      details,
      true
    );
  }

  /**
   * Create a generic server error response
   */
  createServerError(
    error: Error,
    message?: string
  ): ErrorEnvelope<{ original_error: string }> {
    return this.createErrorEnvelope(
      ErrorCode.INTERNAL_SERVER_ERROR,
      message || error.message,
      error.constructor.name,
      { original_error: error.message },
      false
    );
  }

  /**
   * Get current builder context
   */
  getContext(): EnvelopeBuilderContext {
    return { ...this.context };
  }
}

/**
 * Factory function for creating response envelope builders
 */
export function createResponseEnvelopeBuilder(
  operationType: string,
  startTime?: number,
  apiVersion?: string
): ResponseEnvelopeBuilder {
  return new ResponseEnvelopeBuilder(operationType, startTime, apiVersion);
}

/**
 * Utility function to extract success data from response envelope
 */
export function extractSuccessData<T>(envelope: ResponseEnvelope<T>): T | null {
  return isSuccessEnvelope(envelope) ? envelope.data : null;
}

/**
 * Utility function to extract error information from response envelope
 */
export function extractErrorInfo<TErrorData>(
  envelope: ResponseEnvelope<unknown, TErrorData>
): ErrorEnvelope<TErrorData>['error'] | null {
  return isErrorEnvelope(envelope) ? envelope.error : null;
}

/**
 * Utility function to check if response envelope indicates success
 */
export function isSuccessfulResponse<T>(envelope: ResponseEnvelope<T>): boolean {
  return isSuccessEnvelope(envelope) && envelope.success;
}

/**
 * Utility function to check if response envelope indicates an error
 */
export function isErrorResponse<TErrorData>(
  envelope: ResponseEnvelope<unknown, TErrorData>
): boolean {
  return isErrorEnvelope(envelope) && !envelope.success;
}