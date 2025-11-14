/**
 * MCP Tool Response Envelope Types
 *
 * Standardized response envelope interfaces for all MCP tools to ensure
 * type safety, consistency, and eliminate 'any' usage in tool responses.
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

import { SearchStrategy, type UnifiedResponseMeta } from './unified-response.interface';

/**
 * Base envelope interface that all response envelopes extend
 */
export interface BaseResponseEnvelope<TData = unknown> {
  /**
   * Response data payload
   */
  data: TData;

  /**
   * Standardized metadata across all tools
   */
  meta: UnifiedResponseMeta;

  /**
   * Response timestamp (ISO 8601)
   */
  timestamp: string;

  /**
   * Unique request identifier for tracing
   */
  request_id: string;

  /**
   * Operation identifier for tracking
   */
  operation_id?: string;

  /**
   * API version for compatibility tracking
   */
  api_version: string;
}

/**
 * Success response envelope
 */
export interface SuccessEnvelope<TData = unknown> extends BaseResponseEnvelope<TData> {
  /**
   * Response type discriminator
   */
  type: 'success';

  /**
   * Success status
   */
  success: true;

  /**
   * Optional success message
   */
  message?: string;

  /**
   * Rate limiting information (when available)
   */
  rate_limit?: {
    allowed: boolean;
    remaining: number;
    reset_time: string;
    identifier: string;
  };
}

/**
 * Error response envelope
 */
export interface ErrorEnvelope<TErrorData = unknown> extends BaseResponseEnvelope<null> {
  /**
   * Response type discriminator
   */
  type: 'error';

  /**
   * Success status
   */
  success: false;

  /**
   * Error information
   */
  error: {
    /**
     * Error code for programmatic handling
     */
    code: string;

    /**
     * Human-readable error message
     */
    message: string;

    /**
     * Error type/category
     */
    type: string;

    /**
     * Stack trace (in development environments)
     */
    stack?: string;

    /**
     * Additional error context
     */
    details?: TErrorData;

    /**
     * Whether this is a retryable error
     */
    retryable: boolean;

    /**
     * Suggested retry delay in milliseconds (if retryable)
     */
    retry_after_ms?: number;
  };

  /**
   * Error correlation ID for debugging
   */
  error_id: string;
}

/**
 * Paginated response envelope
 */
export interface PaginatedEnvelope<TData = unknown> extends BaseResponseEnvelope<TData[]> {
  /**
   * Response type discriminator
   */
  type: 'paginated';

  /**
   * Success status
   */
  success: true;

  /**
   * Pagination information
   */
  pagination: {
    /**
     * Current page number (1-based)
     */
    page: number;

    /**
     * Number of items per page
     */
    per_page: number;

    /**
     * Total number of items across all pages
     */
    total: number;

    /**
     * Total number of pages
     */
    total_pages: number;

    /**
     * Whether there's a next page
     */
    has_next: boolean;

    /**
     * Whether there's a previous page
     */
    has_prev: boolean;

    /**
     * Cursor for next page (if using cursor-based pagination)
     */
    next_cursor?: string;

    /**
     * Cursor for previous page (if using cursor-based pagination)
     */
    prev_cursor?: string;
  };

  /**
   * Optional summary statistics for the dataset
   */
  summary?: Record<string, unknown>;
}

/**
 * Streaming response envelope
 */
export interface StreamingEnvelope<TData = unknown> extends BaseResponseEnvelope<TData> {
  /**
   * Response type discriminator
   */
  type: 'streaming';

  /**
   * Success status (initially true, may change if stream fails)
   */
  success: true;

  /**
   * Stream information
   */
  stream: {
    /**
     * Unique stream identifier
     */
    stream_id: string;

    /**
     * Current chunk number
     */
    chunk_number: number;

    /**
     * Total number of chunks (if known)
     */
    total_chunks?: number;

    /**
     * Whether this is the final chunk
     */
    is_final: boolean;

    /**
     * Stream status
     */
    status: 'active' | 'completed' | 'error' | 'timeout';
  };

  /**
   * Stream metadata
   */
  stream_metadata?: {
    /**
     * Content type of the stream
     */
    content_type?: string;

    /**
     * Estimated total size (if known)
     */
    estimated_size_bytes?: number;

    /**
     * Transfer progress (0-1)
     */
    progress?: number;
  };
}

/**
 * Union type of all possible response envelopes
 */
export type ResponseEnvelope<TData = unknown, TErrorData = unknown> =
  | SuccessEnvelope<TData>
  | ErrorEnvelope<TErrorData>
  | PaginatedEnvelope<TData>
  | StreamingEnvelope<TData>;

/**
 * Type guard to check if envelope is a success envelope
 */
export function isSuccessEnvelope<TData = unknown>(
  envelope: ResponseEnvelope<TData>
): envelope is SuccessEnvelope<TData> {
  return envelope.type === 'success';
}

/**
 * Type guard to check if envelope is an error envelope
 */
export function isErrorEnvelope<TErrorData = unknown>(
  envelope: ResponseEnvelope<unknown, TErrorData>
): envelope is ErrorEnvelope<TErrorData> {
  return envelope.type === 'error';
}

/**
 * Type guard to check if envelope is a paginated envelope
 */
export function isPaginatedEnvelope<TData = unknown>(
  envelope: ResponseEnvelope<TData>
): envelope is PaginatedEnvelope<TData> {
  return envelope.type === 'paginated';
}

/**
 * Type guard to check if envelope is a streaming envelope
 */
export function isStreamingEnvelope<TData = unknown>(
  envelope: ResponseEnvelope<TData>
): envelope is StreamingEnvelope<TData> {
  return envelope.type === 'streaming';
}

/**
 * Helper type to extract data from a success envelope
 */
export type ExtractSuccessData<T> = T extends SuccessEnvelope<infer U> ? U : never;

/**
 * Helper type to extract error data from an error envelope
 */
export type ExtractErrorData<T> = T extends ErrorEnvelope<infer U> ? U : never;

/**
 * Helper type to extract paginated data from a paginated envelope
 */
export type ExtractPaginatedData<T> = T extends PaginatedEnvelope<infer U> ? U[] : never;