// EMERGENCY ROLLBACK: Utility type guard compatibility issues

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
  type ValidationErrorDetails,
} from '../types/mcp-response-data.types';
import {
  type ErrorEnvelope,
  isErrorEnvelope,
  isPaginatedEnvelope,
  isStreamingEnvelope,
  isSuccessEnvelope,
  type PaginatedEnvelope,
  type ResponseEnvelope,
  type StreamingEnvelope,
  type SuccessEnvelope,
} from '../types/response-envelope.types';

/**
 * Type guard to check if envelope contains memory store data
 */
export function isMemoryStoreResponse(
  envelope: ResponseEnvelope
): envelope is SuccessEnvelope<MemoryStoreResult> {
  if (!isSuccessEnvelope(envelope)) {
    return false;
  }

  const data = envelope.data;
  if (!data || typeof data !== 'object') {
    return false;
  }

  const dataObj = data as Record<string, unknown>;

  // Check if this looks like memory store data
  const hasValidStructure = (
    (Array.isArray(dataObj.stored_items) && Array.isArray(dataObj.failed_items)) ||
    (typeof dataObj.stored === 'number' && typeof dataObj.skipped === 'number') ||
    (typeof dataObj.summary === 'object' && dataObj.summary !== null)
  );

  return hasValidStructure;
}

/**
 * Type guard to check if envelope contains memory find data
 */
export function isMemoryFindResponse(
  envelope: ResponseEnvelope
): envelope is SuccessEnvelope<MemoryFindResult> {
  if (!isSuccessEnvelope(envelope)) {
    return false;
  }

  const data = envelope.data;
  if (!data || typeof data !== 'object') {
    return false;
  }

  const dataObj = data as Record<string, unknown>;

  // Check required fields with type safety
  const hasValidQuery = typeof dataObj.query === 'string';
  const hasValidTotal = typeof dataObj.total === 'number' && dataObj.total >= 0;
  const hasValidItems = Array.isArray(dataObj.items) || Array.isArray(dataObj.results);

  return hasValidQuery && (hasValidTotal || hasValidItems);
}

/**
 * Type guard to check if envelope contains system status data
 */
export function isSystemStatusResponse(
  envelope: ResponseEnvelope
): envelope is SuccessEnvelope<SystemStatusResult> {
  if (!isSuccessEnvelope(envelope)) {
    return false;
  }

  const data = envelope.data;
  if (!data || typeof data !== 'object') {
    return false;
  }

  const dataObj = data as Record<string, unknown>;

  // Check required field
  const hasValidStatus = typeof dataObj.status === 'string';

  // Optional fields should be objects if present
  const hasValidComponents = !dataObj.components || (
    typeof dataObj.components === 'object' && dataObj.components !== null && !Array.isArray(dataObj.components)
  );
  const hasValidMetrics = !dataObj.metrics || (
    typeof dataObj.metrics === 'object' && dataObj.metrics !== null && !Array.isArray(dataObj.metrics)
  );

  return hasValidStatus && hasValidComponents && hasValidMetrics;
}

/**
 * Type guard to check if envelope contains validation error details
 */
export function isValidationErrorResponse(
  envelope: ResponseEnvelope
): envelope is ErrorEnvelope<ValidationErrorDetails[]> {
  return (
    isErrorEnvelope(envelope) &&
    Array.isArray(envelope.error.details) &&
    envelope.error.details.every(
      (detail) =>
        typeof detail.field === 'string' &&
        typeof detail.message === 'string' &&
        typeof detail.rule === 'string'
    )
  );
}

/**
 * Type guard to check if envelope contains rate limit error details
 */
export function isRateLimitErrorResponse(
  envelope: ResponseEnvelope
): envelope is ErrorEnvelope<RateLimitErrorDetails> {
  return (
    isErrorEnvelope(envelope) &&
    typeof envelope.error.details === 'object' &&
    envelope.error.details !== null &&
    typeof (envelope.error.details as RateLimitErrorDetails).limit === 'number' &&
    typeof (envelope.error.details as RateLimitErrorDetails).remaining === 'number' &&
    typeof (envelope.error.details as RateLimitErrorDetails).reset_time === 'string'
  );
}

/**
 * Type guard to check if envelope contains database error details
 */
export function isDatabaseErrorResponse(
  envelope: ResponseEnvelope
): envelope is ErrorEnvelope<DatabaseErrorDetails> {
  return (
    isErrorEnvelope(envelope) &&
    typeof envelope.error.details === 'object' &&
    envelope.error.details !== null &&
    typeof (envelope.error.details as DatabaseErrorDetails).operation === 'string' &&
    typeof (envelope.error.details as DatabaseErrorDetails).connection_status === 'string'
  );
}

/**
 * Safe extractor for memory store data
 */
export function extractMemoryStoreData(envelope: ResponseEnvelope): MemoryStoreResult | null {
  return isMemoryStoreResponse(envelope) ? envelope.data : null;
}

/**
 * Safe extractor for memory find data
 */
export function extractMemoryFindData(envelope: ResponseEnvelope): MemoryFindResult | null {
  return isMemoryFindResponse(envelope) ? envelope.data : null;
}

/**
 * Safe extractor for system status data
 */
export function extractSystemStatusData(envelope: ResponseEnvelope): SystemStatusResult | null {
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
  return isRateLimitErrorResponse(envelope) ? envelope.error.details || null : null;
}

/**
 * Safe extractor for database error details
 */
export function extractDatabaseErrorDetails(
  envelope: ResponseEnvelope
): DatabaseErrorDetails | null {
  return isDatabaseErrorResponse(envelope) ? envelope.error.details || null : null;
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
    },
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

// ============================================================================
// Runtime Validation Utilities
// ============================================================================

/**
 * Validate response envelope structure at runtime
 */
export function validateResponseEnvelope(obj: unknown): obj is ResponseEnvelope {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const envelope = obj as Record<string, unknown>;

  // Check required properties
  if (typeof envelope.success !== 'boolean') {
    return false;
  }

  // If success is true, must have data property
  if (envelope.success && envelope.data === undefined) {
    return false;
  }

  // If success is false, must have error property
  if (!envelope.success && envelope.error === undefined) {
    return false;
  }

  // Optional properties validation
  if (envelope.timestamp !== undefined && typeof envelope.timestamp !== 'string') {
    return false;
  }

  if (envelope.correlationId !== undefined && typeof envelope.correlationId !== 'string') {
    return false;
  }

  if (envelope.metadata !== undefined && (
    typeof envelope.metadata !== 'object' || envelope.metadata === null || Array.isArray(envelope.metadata)
  )) {
    return false;
  }

  return true;
}

/**
 * Validate MCP tool response structure at runtime
 */
export function validateMcpToolResponse(obj: unknown): boolean {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const response = obj as Record<string, unknown>;

  // Must have content array
  if (!Array.isArray(response.content)) {
    return false;
  }

  // Content array must not be empty
  if (response.content.length === 0) {
    return false;
  }

  // Validate each content block
  for (const block of response.content) {
    if (!block || typeof block !== 'object') {
      return false;
    }

    const blockObj = block as Record<string, unknown>;
    if (typeof blockObj.type !== 'string') {
      return false;
    }

    // Text content blocks must have text
    if (blockObj.type === 'text' && typeof blockObj.text !== 'string') {
      return false;
    }
  }

  // isError must be boolean if present
  if (response.isError !== undefined && typeof response.isError !== 'boolean') {
    return false;
  }

  // _meta must be object if present
  if (response._meta !== undefined && (
    typeof response._meta !== 'object' || response._meta === null || Array.isArray(response._meta)
  )) {
    return false;
  }

  return true;
}

/**
 * Safe response envelope validation with error reporting
 */
export function safeValidateResponseEnvelope(obj: unknown): {
  isValid: boolean;
  envelope?: ResponseEnvelope;
  errors: string[];
} {
  const errors: string[] = [];

  if (!obj || typeof obj !== 'object') {
    errors.push('Response must be an object');
    return { isValid: false, errors };
  }

  const envelope = obj as Record<string, unknown>;

  // Check success property
  if (typeof envelope.success !== 'boolean') {
    errors.push('Missing or invalid success property (must be boolean)');
  }

  // Check data property for success responses
  if (envelope.success === true && envelope.data === undefined) {
    errors.push('Success responses must have data property');
  }

  // Check error property for error responses
  if (envelope.success === false && envelope.error === undefined) {
    errors.push('Error responses must have error property');
  }

  // Validate error structure if present
  if (envelope.error !== undefined) {
    const error = envelope.error;
    if (!error || typeof error !== 'object') {
      errors.push('Error property must be an object');
    } else {
      const errorObj = error as Record<string, unknown>;
      if (typeof errorObj.code !== 'string' && typeof errorObj.code !== 'number') {
        errors.push('Error object must have code property');
      }
      if (typeof errorObj.message !== 'string') {
        errors.push('Error object must have message property');
      }
    }
  }

  return {
    isValid: errors.length === 0,
    envelope: errors.length === 0 ? envelope as unknown as ResponseEnvelope : undefined,
    errors,
  };
}

/**
 * Runtime type guard for content blocks
 */
export function isContentBlock(obj: unknown): obj is { type: string; text?: string } {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const block = obj as Record<string, unknown>;

  if (typeof block.type !== 'string') {
    return false;
  }

  // Text blocks must have text property
  if (block.type === 'text' && typeof block.text !== 'string') {
    return false;
  }

  return true;
}

/**
 * Validate array of content blocks
 */
export function validateContentBlocks(blocks: unknown): blocks is { type: string; text?: string }[] {
  if (!Array.isArray(blocks)) {
    return false;
  }

  return blocks.every(isContentBlock);
}
