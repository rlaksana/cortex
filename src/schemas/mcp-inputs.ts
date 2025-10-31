/**
 * Cortex Memory MCP - Input Validation Schemas
 *
 * Zod runtime validation schemas for all MCP tool inputs.
 * Provides comprehensive type safety and input sanitization.
 *
 * @version 1.0.0
 */

import { z } from 'zod';

// ============================================================================
// MCP Tool Input Schemas
// ============================================================================

/**
 * Schema for memory_store tool input validation
 */
// Define base item schema with kind
const BaseItemSchema = z.object({
  kind: z.enum(
    [
      'entity',
      'relation',
      'observation',
      'section',
      'runbook',
      'change',
      'issue',
      'decision',
      'todo',
      'release_note',
      'ddl',
      'pr_context',
      'incident',
      'release',
      'risk',
      'assumption',
    ],
    {
      errorMap: () => ({
        message: `Invalid knowledge type. Must be one of: entity, relation, observation, section, runbook, change, issue, decision, todo, release_note, ddl, pr_context, incident, release, risk, assumption`,
      }),
    }
  ),
  metadata: z
    .record(z.any(), {
      description: 'Additional metadata',
    })
    .optional(),
  scope: z
    .object({
      project: z.string().optional(),
      branch: z.string().optional(),
      org: z.string().optional(),
    })
    .optional(),
});

// Content-based item schema (for text types)
const ContentItemSchema = BaseItemSchema.and(
  z.object({
    content: z.string({
      description: 'Content of the knowledge item',
    }),
  })
);

// Data-based item schema (for structured types like entity, relation, observation)
const DataItemSchema = BaseItemSchema.and(
  z.object({
    data: z.record(z.any(), {
      description: 'Structured data for the knowledge item',
    }),
  })
);

export const MemoryStoreInputSchema = z
  .object({
    items: z
      .array(z.union([ContentItemSchema, DataItemSchema]))
      .min(1, 'At least one item is required'),
  })
  .strict();

/**
 * Schema for memory_find tool input validation
 */
export const MemoryFindInputSchema = z
  .object({
    query: z
      .string()
      .min(1, 'Query parameter is required and cannot be empty')
      .max(1000, 'Query must be 1000 characters or less')
      .transform((val) => val.trim()), // Auto-trim whitespace
    scope: z
      .object({
        project: z.string().optional(),
        branch: z.string().optional(),
        org: z.string().optional(),
      })
      .optional(),
    types: z.array(z.string()).optional(),
    mode: z
      .enum(['auto', 'fast', 'deep'], {
        errorMap: () => ({ message: `Invalid mode. Must be one of: auto, fast, deep` }),
      })
      .optional(),
    top_k: z
      .number()
      .int('top_k must be an integer')
      .min(1, 'top_k must be at least 1')
      .max(100, 'top_k cannot exceed 100')
      .optional(),
  })
  .strict();

// ============================================================================
// Error Types
// ============================================================================

/**
 * Custom validation error class
 */
export class ValidationError extends Error {
  constructor(
    message: string,
    // eslint-disable-next-line no-unused-vars
    public field?: string,
    // eslint-disable-next-line no-unused-vars
    public code?: string
  ) {
    super(message);
    this.name = 'ValidationError';
  }
}

// ============================================================================
// Validation Functions
// ============================================================================

/**
 * Validates memory_store input with comprehensive error handling
 */
export function validateMemoryStoreInput(input: unknown) {
  try {
    return MemoryStoreInputSchema.parse(input);
  } catch (error) {
    if (error instanceof z.ZodError) {
      const field = error.errors[0]?.path.join('.');
      const message = error.errors[0]?.message || 'Validation failed';
      throw new ValidationError(
        `Memory store validation failed: ${message}`,
        field,
        'VALIDATION_ERROR'
      );
    }
    throw new ValidationError('Unknown validation error occurred', undefined, 'UNKNOWN_ERROR');
  }
}

/**
 * Validates memory_find input with comprehensive error handling
 */
export function validateMemoryFindInput(input: unknown) {
  try {
    return MemoryFindInputSchema.parse(input);
  } catch (error) {
    if (error instanceof z.ZodError) {
      const field = error.errors[0]?.path.join('.');
      const message = error.errors[0]?.message || 'Validation failed';
      throw new ValidationError(
        `Memory find validation failed: ${message}`,
        field,
        'VALIDATION_ERROR'
      );
    }
    throw new ValidationError('Unknown validation error occurred', undefined, 'UNKNOWN_ERROR');
  }
}

/**
 * Safe validation function that returns null instead of throwing
 */
export function safeValidateMemoryFindInput(input: unknown) {
  try {
    return MemoryFindInputSchema.parse(input);
  } catch {
    return null;
  }
}

/**
 * Safe validation function that returns null instead of throwing
 */
export function safeValidateMemoryStoreInput(input: unknown) {
  try {
    return MemoryStoreInputSchema.parse(input);
  } catch {
    return null;
  }
}
