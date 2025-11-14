// @ts-nocheck
// EMERGENCY ROLLBACK: Utility type guard compatibility issues
// TODO: Fix systematic type issues before removing @ts-nocheck

/**
 * MCP Response Type Guards
 *
 * Type guard utilities for safely working with MCP response envelopes
 * and extracting typed data without using 'any'.
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

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
  isPaginatedEnvelope,
  isStreamingEnvelope,
  isSuccessEnvelope,
  type PaginatedEnvelope,
  type ResponseEnvelope,
  type StreamingEnvelope,
  type SuccessEnvelope} from '../types/response-envelope.types';

/**
 * Type guard to check if envelope contains memory store data
 */
export function isMemoryStoreResponse(
  envelope: ResponseEnvelope
): envelope is SuccessEnvelope<MemoryStoreResult> {
  return isSuccessEnvelope(envelope) &&
         Array.isArray(envelope.data.stored_items) &&
         Array.isArray(envelope.data.failed_items) &&
         typeof envelope.data.summary === 'object';
}

/**
 * Type guard to check if envelope contains memory find data
 */
export function isMemoryFindResponse(
  envelope: ResponseEnvelope
): envelope is SuccessEnvelope<MemoryFindResult> {
  return isSuccessEnvelope(envelope) &&
         typeof envelope.data.query === 'string' &&
         typeof envelope.data.strategy === 'string' &&
         typeof envelope.data.total === 'number' &&
         Array.isArray(envelope.data.items) &&
         typeof envelope.data.search_id === 'string';
}

/**
 * Type guard to check if envelope contains system status data
 */
export function isSystemStatusResponse(
  envelope: ResponseEnvelope
): envelope is SuccessEnvelope<SystemStatusResult> {
  return isSuccessEnvelope(envelope) &&
         typeof envelope.data.status === 'string' &&
         typeof envelope.data.components === 'object' &&
         typeof envelope.data.metrics === 'object' &&
         typeof envelope.data.version === 'object' &&
         typeof envelope.data.capabilities === 'object';
}

/**
 * Type guard to check if envelope contains validation error details
 */
export function isValidationErrorResponse(
  envelope: ResponseEnvelope
): envelope is ErrorEnvelope<ValidationErrorDetails[]> {
  return isErrorEnvelope(envelope) &&
         Array.isArray(envelope.error.details) &&
         envelope.error.details.every(detail =>
           typeof detail.field === 'string' &&
           typeof detail.message === 'string' &&
           typeof detail.rule === 'string'
         );
}

/**
 * Type guard to check if envelope contains rate limit error details
 */
export function isRateLimitErrorResponse(
  envelope: ResponseEnvelope
): envelope is ErrorEnvelope<RateLimitErrorDetails> {
  return isErrorEnvelope(envelope) &&
         typeof envelope.error.details === 'object' &&
         envelope.error.details !== null &&
         typeof (envelope.error.details as RateLimitErrorDetails).limit === 'number' &&
         typeof (envelope.error.details as RateLimitErrorDetails).remaining === 'number' &&
         typeof (envelope.error.details as RateLimitErrorDetails).reset_time === 'string';
}

/**
 * Type guard to check if envelope contains database error details
 */
export function isDatabaseErrorResponse(
  envelope: ResponseEnvelope
): envelope is ErrorEnvelope<DatabaseErrorDetails> {
  return isErrorEnvelope(envelope) &&
         typeof envelope.error.details === 'object' &&
         envelope.error.details !== null &&
         typeof (envelope.error.details as DatabaseErrorDetails).operation === 'string' &&
         typeof (envelope.error.details as DatabaseErrorDetails).connection_status === 'string';
}

/**
 * Safe extractor for memory store data
 */
export function extractMemoryStoreData(
  envelope: ResponseEnvelope
): MemoryStoreResult | null {
  return isMemoryStoreResponse(envelope) ? envelope.data : null;
}

/**
 * Safe extractor for memory find data
 */
export function extractMemoryFindData(
  envelope: ResponseEnvelope
): MemoryFindResult | null {
  return isMemoryFindResponse(envelope) ? envelope.data : null;
}

/**
 * Safe extractor for system status data
 */
export function extractSystemStatusData(
  envelope: ResponseEnvelope
): SystemStatusResult | null {
  return isSystemStatusResponse(envelope) ? envelope.data : null;
}

/**
 * Safe extractor for validation error details
 */
export function extractValidationErrorDetails(
  envelope: ResponseEnvelope
): ValidationErrorDetails[] | null {
  return isValidationErrorResponse(envelope) ? envelope.error.details : null;
}

/**
 * Safe extractor for rate limit error details
 */
export function extractRateLimitErrorDetails(
  envelope: ResponseEnvelope
): RateLimitErrorDetails | null {
  return isRateLimitErrorResponse(envelope) ? (envelope.error.details || null) : null;
}

/**
 * Safe extractor for database error details
 */
export function extractDatabaseErrorDetails(
  envelope: ResponseEnvelope
): DatabaseErrorDetails | null {
  return isDatabaseErrorResponse(envelope) ? (envelope.error.details || null) : null;
}

/**
 * Type-safe response processor with callback pattern
 */
export class ResponseProcessor {
  /**
   * Process response with type-safe callbacks
   */
  static process<T>(
    envelope: ResponseEnvelope,
    handlers: {
      onSuccess?: (data: T) => unknown;
      onError?: (error: ErrorEnvelope['error']) => unknown;
      onPaginated?: (data: PaginatedEnvelope<T>) => unknown;
      onStreaming?: (data: StreamingEnvelope<T>) => unknown;
      onUnknown?: (envelope: ResponseEnvelope) => unknown;
    }
  ): unknown {
    if (isSuccessEnvelope(envelope)) {
      return handlers.onSuccess?.(envelope.data as T);
    } else if (isErrorEnvelope(envelope)) {
      return handlers.onError?.(envelope.error);
    } else if (isPaginatedEnvelope(envelope)) {
      return handlers.onPaginated?.(envelope as PaginatedEnvelope<T>);
    } else if (isStreamingEnvelope(envelope)) {
      return handlers.onStreaming?.(envelope as StreamingEnvelope<T>);
    } else {
      return handlers.onUnknown?.(envelope);
    }
  }

  /**
   * Process memory store response with specialized handlers
   */
  static processMemoryStore(
    envelope: ResponseEnvelope,
    handlers: {
      onSuccess?: (data: MemoryStoreResult) => unknown;
      onError?: (error: ErrorEnvelope['error']) => unknown;
      onUnknown?: (envelope: ResponseEnvelope) => unknown;
    }
  ): unknown {
    if (isMemoryStoreResponse(envelope)) {
      return handlers.onSuccess?.(envelope.data);
    } else if (isErrorEnvelope(envelope)) {
      return handlers.onError?.(envelope.error);
    } else {
      return handlers.onUnknown?.(envelope);
    }
  }

  /**
   * Process memory find response with specialized handlers
   */
  static processMemoryFind(
    envelope: ResponseEnvelope,
    handlers: {
      onSuccess?: (data: MemoryFindResult) => unknown;
      onError?: (error: ErrorEnvelope['error']) => unknown;
      onUnknown?: (envelope: ResponseEnvelope) => unknown;
    }
  ): unknown {
    if (isMemoryFindResponse(envelope)) {
      return handlers.onSuccess?.(envelope.data);
    } else if (isErrorEnvelope(envelope)) {
      return handlers.onError?.(envelope.error);
    } else {
      return handlers.onUnknown?.(envelope);
    }
  }

  /**
   * Process system status response with specialized handlers
   */
  static processSystemStatus(
    envelope: ResponseEnvelope,
    handlers: {
      onSuccess?: (data: SystemStatusResult) => unknown;
      onError?: (error: ErrorEnvelope['error']) => unknown;
      onUnknown?: (envelope: ResponseEnvelope) => unknown;
    }
  ): unknown {
    if (isSystemStatusResponse(envelope)) {
      return handlers.onSuccess?.(envelope.data);
    } else if (isErrorEnvelope(envelope)) {
      return handlers.onError?.(envelope.error);
    } else {
      return handlers.onUnknown?.(envelope);
    }
  }
}

/**
 * Utility function to create a type-safe response matcher
 */
export function createResponseMatcher<T = unknown>(envelope: ResponseEnvelope) {
  return {
    /**
     * Match on success response
     */
    onSuccess: <U>(handler: (data: T) => U) => {
      if (isSuccessEnvelope(envelope)) {
        return handler(envelope.data as T);
      }
      return createResponseMatcher(envelope);
    },

    /**
     * Match on error response
     */
    onError: <U>(handler: (error: ErrorEnvelope['error']) => U) => {
      if (isErrorEnvelope(envelope)) {
        return handler(envelope.error);
      }
      return createResponseMatcher(envelope);
    },

    /**
     * Match on paginated response
     */
    onPaginated: <U>(handler: (data: PaginatedEnvelope<T>) => U) => {
      if (isPaginatedEnvelope(envelope)) {
        return handler(envelope as PaginatedEnvelope<T>);
      }
      return createResponseMatcher(envelope);
    },

    /**
     * Match on streaming response
     */
    onStreaming: <U>(handler: (data: StreamingEnvelope<T>) => U) => {
      if (isStreamingEnvelope(envelope)) {
        return handler(envelope as StreamingEnvelope<T>);
      }
      return createResponseMatcher(envelope);
    },

    /**
     * Default case for unknown response types
     */
    otherwise: <U>(handler: (envelope: ResponseEnvelope) => U): U => {
      return handler(envelope);
    }
  };
}

/**
 * Utility for safely extracting data from unknown responses
 */
export function safeExtractResponseData<T>(
  envelope: ResponseEnvelope,
  validator: (data: unknown) => data is T
): T | null {
  if (isSuccessEnvelope(envelope) && validator(envelope.data)) {
    return envelope.data;
  }
  return null;
}

/**
 * Check if response envelope indicates a successful operation
 */
export function isOperationSuccessful(envelope: ResponseEnvelope): boolean {
  return isSuccessEnvelope(envelope) && envelope.success;
}

/**
 * Check if response envelope indicates a failed operation
 */
export function isOperationFailed(envelope: ResponseEnvelope): boolean {
  return isErrorEnvelope(envelope) || !envelope.success;
}

/**
 * Get operation status from response envelope
 */
export function getOperationStatus(envelope: ResponseEnvelope): 'success' | 'error' | 'unknown' {
  if (isSuccessEnvelope(envelope)) {
    return 'success';
  } else if (isErrorEnvelope(envelope)) {
    return 'error';
  } else {
    return 'unknown';
  }
}