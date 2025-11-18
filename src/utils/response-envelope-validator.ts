/**
 * MCP Response Envelope Validator
 *
 * Validation utilities for response envelopes to ensure type safety
 * and compliance with expected response patterns.
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

import {
  type MemoryFindResult,
  type MemoryStoreResult,
  type SystemStatusResult,
} from '../types/mcp-response-data.types';
import {
  type ErrorEnvelope,
  isSuccessEnvelope,
  type PaginatedEnvelope,
  type ResponseEnvelope,
  type StreamingEnvelope,
  type SuccessEnvelope,
} from '../types/response-envelope.types';

/**
 * Validation result interface
 */
export interface ValidationResult {
  /**
   * Whether validation passed
   */
  valid: boolean;

  /**
   * Validation errors, if any
   */
  errors: string[];

  /**
   * Validation warnings, if any
   */
  warnings: string[];
}

/**
 * Response envelope validator
 */
export class ResponseEnvelopeValidator {
  /**
   * Validate a response envelope structure
   */
  static validateEnvelope(envelope: unknown): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Check if envelope is an object
    if (!envelope || typeof envelope !== 'object') {
      errors.push('Response envelope must be an object');
      return { valid: false, errors, warnings };
    }

    const env = envelope as Record<string, unknown>;

    // Check required fields
    if (!env.type || typeof env.type !== 'string') {
      errors.push('Missing or invalid "type" field');
    }

    if (!env.timestamp || typeof env.timestamp !== 'string') {
      errors.push('Missing or invalid "timestamp" field');
    } else {
      // Validate timestamp format
      const timestamp = new Date(env.timestamp);
      if (isNaN(timestamp.getTime())) {
        errors.push('Invalid "timestamp" format - must be ISO 8601');
      }
    }

    if (!env.request_id || typeof env.request_id !== 'string') {
      errors.push('Missing or invalid "request_id" field');
    }

    if (!env.api_version || typeof env.api_version !== 'string') {
      errors.push('Missing or invalid "api_version" field');
    }

    if (!env.meta || typeof env.meta !== 'object') {
      errors.push('Missing or invalid "meta" field');
    }

    // Type-specific validation
    if (env.type === 'success') {
      const successValidation = this.validateSuccessEnvelope(env as unknown as SuccessEnvelope);
      errors.push(...successValidation.errors);
      warnings.push(...successValidation.warnings);
    } else if (env.type === 'error') {
      const errorValidation = this.validateErrorEnvelope(env as unknown as ErrorEnvelope);
      errors.push(...errorValidation.errors);
      warnings.push(...errorValidation.warnings);
    } else if (env.type === 'paginated') {
      const paginatedValidation = this.validatePaginatedEnvelope(
        env as unknown as PaginatedEnvelope
      );
      errors.push(...paginatedValidation.errors);
      warnings.push(...paginatedValidation.warnings);
    } else if (env.type === 'streaming') {
      const streamingValidation = this.validateStreamingEnvelope(
        env as unknown as StreamingEnvelope
      );
      errors.push(...streamingValidation.errors);
      warnings.push(...streamingValidation.warnings);
    } else {
      errors.push(`Unknown envelope type: ${env.type}`);
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Validate success envelope
   */
  private static validateSuccessEnvelope(envelope: SuccessEnvelope): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (envelope.success !== true) {
      errors.push('Success envelope must have success: true');
    }

    if (envelope.data === undefined) {
      errors.push('Success envelope must have data field');
    }

    // Validate rate limit if present
    if (envelope.rate_limit) {
      if (typeof envelope.rate_limit.allowed !== 'boolean') {
        errors.push('rate_limit.allowed must be a boolean');
      }
      if (typeof envelope.rate_limit.remaining !== 'number') {
        errors.push('rate_limit.remaining must be a number');
      }
      if (typeof envelope.rate_limit.reset_time !== 'string') {
        errors.push('rate_limit.reset_time must be a string');
      }
      if (typeof envelope.rate_limit.identifier !== 'string') {
        errors.push('rate_limit.identifier must be a string');
      }
    }

    return { valid: errors.length === 0, errors, warnings };
  }

  /**
   * Validate error envelope
   */
  private static validateErrorEnvelope(envelope: ErrorEnvelope): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (envelope.success !== false) {
      errors.push('Error envelope must have success: false');
    }

    if (envelope.data !== null) {
      errors.push('Error envelope must have data: null');
    }

    if (!envelope.error || typeof envelope.error !== 'object') {
      errors.push('Error envelope must have error object');
      return { valid: false, errors, warnings };
    }

    const error = envelope.error;

    if (!error.code || typeof error.code !== 'string') {
      errors.push('Error must have a code string');
    }

    if (!error.message || typeof error.message !== 'string') {
      errors.push('Error must have a message string');
    }

    if (!error.type || typeof error.type !== 'string') {
      errors.push('Error must have a type string');
    }

    if (typeof error.retryable !== 'boolean') {
      errors.push('Error.retryable must be a boolean');
    }

    if (error.retryable && error.retry_after_ms && typeof error.retry_after_ms !== 'number') {
      errors.push('Error.retry_after_ms must be a number when retryable is true');
    }

    if (!envelope.error_id || typeof envelope.error_id !== 'string') {
      errors.push('Error envelope must have error_id string');
    }

    return { valid: errors.length === 0, errors, warnings };
  }

  /**
   * Validate paginated envelope
   */
  private static validatePaginatedEnvelope(envelope: PaginatedEnvelope): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (envelope.success !== true) {
      errors.push('Paginated envelope must have success: true');
    }

    if (!Array.isArray(envelope.data)) {
      errors.push('Paginated envelope data must be an array');
    }

    if (!envelope.pagination || typeof envelope.pagination !== 'object') {
      errors.push('Paginated envelope must have pagination object');
      return { valid: false, errors, warnings };
    }

    const pagination = envelope.pagination;

    if (typeof pagination.page !== 'number' || pagination.page < 1) {
      errors.push('pagination.page must be a number >= 1');
    }

    if (typeof pagination.per_page !== 'number' || pagination.per_page < 1) {
      errors.push('pagination.per_page must be a number >= 1');
    }

    if (typeof pagination.total !== 'number' || pagination.total < 0) {
      errors.push('pagination.total must be a number >= 0');
    }

    if (typeof pagination.total_pages !== 'number' || pagination.total_pages < 1) {
      errors.push('pagination.total_pages must be a number >= 1');
    }

    if (typeof pagination.has_next !== 'boolean') {
      errors.push('pagination.has_next must be a boolean');
    }

    if (typeof pagination.has_prev !== 'boolean') {
      errors.push('pagination.has_prev must be a boolean');
    }

    // Check consistency
    if (pagination.page > pagination.total_pages) {
      errors.push('pagination.page cannot be greater than pagination.total_pages');
    }

    if (envelope.data.length > pagination.per_page) {
      warnings.push('Data array length exceeds per_page limit');
    }

    return { valid: errors.length === 0, errors, warnings };
  }

  /**
   * Validate streaming envelope
   */
  private static validateStreamingEnvelope(envelope: StreamingEnvelope): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (envelope.success !== true) {
      errors.push('Streaming envelope must have success: true');
    }

    if (!envelope.stream || typeof envelope.stream !== 'object') {
      errors.push('Streaming envelope must have stream object');
      return { valid: false, errors, warnings };
    }

    const stream = envelope.stream;

    if (!stream.stream_id || typeof stream.stream_id !== 'string') {
      errors.push('stream.stream_id must be a string');
    }

    if (typeof stream.chunk_number !== 'number' || stream.chunk_number < 0) {
      errors.push('stream.chunk_number must be a number >= 0');
    }

    if (
      stream.total_chunks !== undefined &&
      (typeof stream.total_chunks !== 'number' || stream.total_chunks < 1)
    ) {
      errors.push('stream.total_chunks must be a number >= 1 when provided');
    }

    if (typeof stream.is_final !== 'boolean') {
      errors.push('stream.is_final must be a boolean');
    }

    const validStatuses = ['active', 'completed', 'error', 'timeout'];
    if (!validStatuses.includes(stream.status)) {
      errors.push(`stream.status must be one of: ${validStatuses.join(', ')}`);
    }

    // Check consistency
    if (stream.is_final && stream.status !== 'completed' && stream.status !== 'error') {
      warnings.push('Final chunk should have status "completed" or "error"');
    }

    if (stream.total_chunks !== undefined && stream.chunk_number > stream.total_chunks) {
      errors.push('stream.chunk_number cannot be greater than stream.total_chunks');
    }

    return { valid: errors.length === 0, errors, warnings };
  }

  /**
   * Validate memory store result data
   */
  static validateMemoryStoreResult(data: unknown): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!data || typeof data !== 'object') {
      errors.push('Memory store result must be an object');
      return { valid: false, errors, warnings };
    }

    const result = data as MemoryStoreResult;

    if (!Array.isArray(result.stored_items)) {
      errors.push('stored_items must be an array');
    }

    if (!Array.isArray(result.failed_items)) {
      errors.push('failed_items must be an array');
    }

    if (!result.summary || typeof result.summary !== 'object') {
      errors.push('summary must be an object');
    } else {
      const summary = result.summary;
      if (typeof summary.total_attempted !== 'number' || summary.total_attempted < 0) {
        errors.push('summary.total_attempted must be a number >= 0');
      }
      if (typeof summary.total_stored !== 'number' || summary.total_stored < 0) {
        errors.push('summary.total_stored must be a number >= 0');
      }
      if (typeof summary.total_failed !== 'number' || summary.total_failed < 0) {
        errors.push('summary.total_failed must be a number >= 0');
      }
      if (
        typeof summary.success_rate !== 'number' ||
        summary.success_rate < 0 ||
        summary.success_rate > 1
      ) {
        errors.push('summary.success_rate must be a number between 0 and 1');
      }

      // Check consistency
      if (summary.total_attempted !== summary.total_stored + summary.total_failed) {
        errors.push('summary.total_attempted must equal total_stored + total_failed');
      }
    }

    return { valid: errors.length === 0, errors, warnings };
  }

  /**
   * Validate memory find result data
   */
  static validateMemoryFindResult(data: unknown): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!data || typeof data !== 'object') {
      errors.push('Memory find result must be an object');
      return { valid: false, errors, warnings };
    }

    const result = data as MemoryFindResult;

    if (typeof result.query !== 'string') {
      errors.push('query must be a string');
    }

    if (typeof result.strategy !== 'string') {
      errors.push('strategy must be a string');
    }

    if (typeof result.confidence !== 'number' || result.confidence < 0 || result.confidence > 1) {
      errors.push('confidence must be a number between 0 and 1');
    }

    if (typeof result.total !== 'number' || result.total < 0) {
      errors.push('total must be a number >= 0');
    }

    if (!Array.isArray(result.items)) {
      errors.push('items must be an array');
    }

    if (!result.search_id || typeof result.search_id !== 'string') {
      errors.push('search_id must be a string');
    }

    // Check consistency
    if (result.items.length > result.total) {
      warnings.push('Returned items count exceeds total results');
    }

    return { valid: errors.length === 0, errors, warnings };
  }

  /**
   * Validate system status result data
   */
  static validateSystemStatusResult(data: unknown): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!data || typeof data !== 'object') {
      errors.push('System status result must be an object');
      return { valid: false, errors, warnings };
    }

    const result = data as SystemStatusResult;

    const validStatuses = ['healthy', 'degraded', 'unhealthy', 'maintenance'];
    if (!validStatuses.includes(result.status)) {
      errors.push(`status must be one of: ${validStatuses.join(', ')}`);
    }

    if (!result.components || typeof result.components !== 'object') {
      errors.push('components must be an object');
    }

    if (!result.metrics || typeof result.metrics !== 'object') {
      errors.push('metrics must be an object');
    }

    if (!result.version || typeof result.version !== 'object') {
      errors.push('version must be an object');
    }

    if (!result.capabilities || typeof result.capabilities !== 'object') {
      errors.push('capabilities must be an object');
    }

    return { valid: errors.length === 0, errors, warnings };
  }

  /**
   * Validate response envelope for specific operation type
   */
  static validateOperationResponse<T>(
    envelope: ResponseEnvelope<T>,
    operationType: 'memory_store' | 'memory_find' | 'system_status'
  ): ValidationResult {
    // First validate the envelope structure
    const envelopeValidation = this.validateEnvelope(envelope);
    if (!envelopeValidation.valid) {
      return envelopeValidation;
    }

    const errors: string[] = [...envelopeValidation.errors];
    const warnings: string[] = [...envelopeValidation.warnings];

    // If it's a success envelope, validate the data based on operation type
    if (isSuccessEnvelope(envelope)) {
      switch (operationType) {
        case 'memory_store':
          const memoryStoreValidation = this.validateMemoryStoreResult(envelope.data);
          errors.push(...memoryStoreValidation.errors);
          warnings.push(...memoryStoreValidation.warnings);
          break;

        case 'memory_find':
          const memoryFindValidation = this.validateMemoryFindResult(envelope.data);
          errors.push(...memoryFindValidation.errors);
          warnings.push(...memoryFindValidation.warnings);
          break;

        case 'system_status':
          const systemStatusValidation = this.validateSystemStatusResult(envelope.data);
          errors.push(...systemStatusValidation.errors);
          warnings.push(...systemStatusValidation.warnings);
          break;

        default:
          warnings.push(`Unknown operation type: ${operationType}`);
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }
}

/**
 * Utility function to validate and throw if invalid
 */
export function validateEnvelopeOrThrow(envelope: unknown): ResponseEnvelope {
  const validation = ResponseEnvelopeValidator.validateEnvelope(envelope);

  if (!validation.valid) {
    throw new Error(`Invalid response envelope: ${validation.errors.join(', ')}`);
  }

  if (validation.warnings.length > 0) {
    console.warn(`Response envelope validation warnings: ${validation.warnings.join(', ')}`);
  }

  return envelope as ResponseEnvelope;
}

/**
 * Utility function to validate operation response and throw if invalid
 */
export function validateOperationResponseOrThrow<T>(
  envelope: ResponseEnvelope<T>,
  operationType: 'memory_store' | 'memory_find' | 'system_status'
): ResponseEnvelope<T> {
  const validation = ResponseEnvelopeValidator.validateOperationResponse(envelope, operationType);

  if (!validation.valid) {
    throw new Error(`Invalid ${operationType} response: ${validation.errors.join(', ')}`);
  }

  if (validation.warnings.length > 0) {
    console.warn(
      `${operationType} response validation warnings: ${validation.warnings.join(', ')}`
    );
  }

  return envelope;
}
