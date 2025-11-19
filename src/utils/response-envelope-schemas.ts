/**
 * MCP Response Envelope Zod Schemas
 *
 * Runtime validation schemas for all response envelope types to ensure
 * type safety and provide comprehensive validation error reporting.
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

import { z } from 'zod';

import type { UnifiedResponseMeta } from '../types/unified-response.interface';

/**
 * Zod schema for UnifiedResponseMeta
 */
export const UnifiedResponseMetaSchema = z.object({
  strategy: z.enum(['auto', 'deep', 'semantic', 'fallback', 'hybrid', 'fast', 'keyword']).default('auto'),
  vector_used: z.boolean(),
  degraded: z.boolean(),
  source: z.string(),
  execution_time_ms: z.number().optional(),
  confidence_score: z.number().optional(),
  truncated: z.boolean(),
  truncation_details: z.array(z.object({
    result_index: z.number(),
    reason: z.string(),
    content_length: z.number(),
    content_type: z.string().optional(),
  })).optional(),
  total_chars_removed: z.number().optional(),
  total_tokens_removed: z.number().optional(),
  warnings: z.array(z.string()).optional(),
});

/**
 * Zod schema for rate limit information
 */
export const RateLimitSchema = z.object({
  allowed: z.boolean(),
  remaining: z.number(),
  reset_time: z.string(),
  identifier: z.string(),
});

/**
 * Zod schema for error details
 */
export const ErrorDetailsSchema = z.object({
  code: z.string(),
  message: z.string(),
  type: z.string(),
  stack: z.string().optional(),
  details: z.unknown().optional(),
  retryable: z.boolean(),
  retry_after_ms: z.number().optional(),
});

/**
 * Zod schema for pagination information
 */
export const PaginationSchema = z.object({
  page: z.number(),
  per_page: z.number(),
  total: z.number(),
  total_pages: z.number(),
  has_next: z.boolean(),
  has_prev: z.boolean(),
  next_cursor: z.string().optional(),
  prev_cursor: z.string().optional(),
});

/**
 * Zod schema for stream information
 */
export const StreamSchema = z.object({
  stream_id: z.string(),
  chunk_number: z.number(),
  total_chunks: z.number().optional(),
  is_final: z.boolean(),
  status: z.enum(['active', 'completed', 'error', 'timeout']),
});

/**
 * Zod schema for stream metadata
 */
export const StreamMetadataSchema = z.object({
  content_type: z.string().optional(),
  estimated_size_bytes: z.number().optional(),
  progress: z.number().optional(),
});

/**
 * Base schema for all response envelopes
 */
const BaseEnvelopeSchema = z.object({
  timestamp: z.string(),
  request_id: z.string(),
  operation_id: z.string().optional(),
  api_version: z.string(),
});

/**
 * Zod schema for success envelopes
 */
export const SuccessEnvelopeSchema = <TData>() => BaseEnvelopeSchema.extend({
  type: z.literal('success'),
  success: z.literal(true),
  data: z.unknown(), // Will be refined with specific data type
  message: z.string().optional(),
  meta: UnifiedResponseMetaSchema.optional(),
  rate_limit: RateLimitSchema.optional(),
});

/**
 * Zod schema for error envelopes
 */
export const ErrorEnvelopeSchema = <TErrorData>() => BaseEnvelopeSchema.extend({
  type: z.literal('error'),
  success: z.literal(false),
  data: z.literal(null),
  error: ErrorDetailsSchema,
  error_id: z.string(),
  rate_limit: RateLimitSchema.optional(),
});

/**
 * Zod schema for paginated envelopes
 */
export const PaginatedEnvelopeSchema = <TData>() => BaseEnvelopeSchema.extend({
  type: z.literal('paginated'),
  success: z.literal(true),
  data: z.array(z.unknown()), // Will be refined with specific data type
  pagination: PaginationSchema,
  summary: z.record(z.unknown()).optional(),
  meta: UnifiedResponseMetaSchema.optional(),
  rate_limit: RateLimitSchema.optional(),
});

/**
 * Zod schema for streaming envelopes
 */
export const StreamingEnvelopeSchema = <TData>() => BaseEnvelopeSchema.extend({
  type: z.literal('streaming'),
  success: z.literal(true),
  data: z.unknown(), // Will be refined with specific data type
  stream: StreamSchema,
  stream_metadata: StreamMetadataSchema.optional(),
  meta: UnifiedResponseMetaSchema.optional(),
  rate_limit: RateLimitSchema.optional(),
});

/**
 * Union schema for all response envelope types
 */
export const ResponseEnvelopeSchema = <TData = unknown, TErrorData = unknown>() =>
  z.union([
    SuccessEnvelopeSchema<TData>(),
    ErrorEnvelopeSchema<TErrorData>(),
    PaginatedEnvelopeSchema<TData>(),
    StreamingEnvelopeSchema<TData>(),
  ]);

/**
 * Runtime validator for response envelopes
 */
export function validateResponseEnvelope<TData = unknown, TErrorData = unknown>(
  envelope: unknown,
  dataType?: z.ZodSchema<TData>,
  errorDataType?: z.ZodSchema<TErrorData>
): { success: true; data: unknown }
    | { success: false; errors: string[] } {
  try {
    const schema = ResponseEnvelopeSchema<TData, TErrorData>();
    const result = schema.parse(envelope);
    return { success: true, data: result };
  } catch (error) {
    if (error instanceof z.ZodError) {
      const errors = error.errors.map(err =>
        `${err.path.join('.')}: ${err.message}`
      );
      return { success: false, errors };
    }
    return { success: false, errors: ['Unknown validation error'] };
  }
}

/**
 * Runtime validator that throws on invalid envelopes
 */
export function validateResponseEnvelopeOrThrow<TData = unknown, TErrorData = unknown>(
  envelope: unknown,
  dataType?: z.ZodSchema<TData>,
  errorDataType?: z.ZodSchema<TErrorData>
): unknown {
  const result = validateResponseEnvelope<TData, TErrorData>(envelope, dataType, errorDataType);

  if (!result.success) {
    throw new Error(`Response envelope validation failed: ${(result as any).errors.join(', ')}`);
  }

  return result.data;
}

/**
 * Type guard with runtime validation
 */
export function isResponseEnvelope<TData = unknown, TErrorData = unknown>(
  envelope: unknown,
  dataType?: z.ZodSchema<TData>,
  errorDataType?: z.ZodSchema<TErrorData>
): envelope is unknown {
  return validateResponseEnvelope<TData, TErrorData>(envelope, dataType, errorDataType).success;
}

/**
 * Extract safe data from unknown envelope with validation
 */
export function extractEnvelopeData<TData = unknown>(
  envelope: unknown,
  dataType?: z.ZodSchema<TData>
): { success: true; data: TData } | { success: false; error: string } {
  try {
    const validation = validateResponseEnvelope(envelope, dataType);
    if (!validation.success) {
      return { success: false, error: (validation as any).errors.join(', ') };
    }

    const env = validation.data as any;
    if (env.type === 'success' || env.type === 'streaming') {
      return { success: true, data: env.data as TData };
    } else if (env.type === 'paginated') {
      return { success: true, data: env.data as unknown as TData };
    } else {
      return { success: false, error: 'Envelope does not contain data' };
    }
  } catch (error) {
    return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
  }
}

/**
 * Extract error information with validation
 */
export function extractEnvelopeError<TErrorData = unknown>(
  envelope: unknown,
  errorDataType?: z.ZodSchema<TErrorData>
): { success: true; error: z.infer<typeof ErrorDetailsSchema> & { details?: TErrorData } }
    | { success: false; error: string } {
  try {
    const validation = validateResponseEnvelope(envelope, undefined, errorDataType);
    if (!validation.success) {
      return { success: false, error: (validation as any).errors.join(', ') };
    }

    const env = validation.data as any;
    if (env.type === 'error') {
      return { success: true, error: env.error };
    } else {
      return { success: false, error: 'Envelope is not an error envelope' };
    }
  } catch (error) {
    return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
  }
}