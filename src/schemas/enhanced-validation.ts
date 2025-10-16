import { z } from 'zod';

/**
 * Enhanced Zod schemas with comprehensive validation to prevent database constraint violations
 * Based on issues discovered during comprehensive testing
 */

// Base scope filter with proper validation
export const ScopeFilterSchema = z
  .object({
    project: z.string().min(1, 'Project name is required').max(100, 'Project name too long'),
    branch: z
      .string()
      .min(1, 'Branch name is required')
      .max(100, 'Branch name too long')
      .optional(),
    org: z
      .string()
      .min(1, 'Organization name is required')
      .max(100, 'Organization name too long')
      .optional(),
  })
  .strict();

// Enhanced section data schema preventing constraint violations
export const SectionDataSchema = z
  .object({
    id: z.string().uuid().optional(),
    title: z
      .string()
      .min(1, 'Title is required and cannot be empty')
      .max(500, 'Title cannot exceed 500 characters (database constraint)')
      .regex(/^[^\\s]/, 'Title cannot start with whitespace')
      .trim(),
    heading: z
      .string()
      .min(1, 'Heading is required')
      .max(300, 'Heading cannot exceed 300 characters (database constraint)')
      .optional(),
    body_md: z.string().max(1000000, 'Markdown content too large').optional(),
    body_text: z.string().max(1000000, 'Text content too large').optional(),
  })
  .refine((data) => data.body_md || data.body_text || data.heading || data.title, {
    message: 'Section must have at least one of: title, heading, body_md, or body_text',
    path: ['root'],
  });

// Decision data schema with ADR-specific validation
export const DecisionDataSchema = z
  .object({
    id: z.string().uuid().optional(),
    component: z.string().min(1, 'Component is required').max(200, 'Component name too long'),
    status: z.enum(['proposed', 'accepted', 'deprecated', 'superseded'], {
      errorMap: () => ({
        message: 'Status must be one of: proposed, accepted, deprecated, superseded',
      }),
    }),
    title: z
      .string()
      .min(1, 'Decision title is required')
      .max(500, 'Title cannot exceed 500 characters')
      .trim(),
    rationale: z
      .string()
      .min(10, 'Rationale must be at least 10 characters')
      .max(50000, 'Rationale too long'),
    alternatives_considered: z.array(z.string().min(1)).max(20, 'Too many alternatives').optional(),
    consequences: z.string().max(10000, 'Consequences description too long').optional(),
    supersedes: z.string().uuid().optional(),
  })
  .refine((data) => data.status !== 'accepted' || data.rationale.length >= 50, {
    message: 'Accepted decisions must have detailed rationale (at least 50 characters)',
    path: ['rationale'],
  });

// Issue data schema
export const IssueDataSchema = z.object({
  id: z.string().uuid().optional(),
  tracker: z.string().min(1, 'Tracker is required').max(100, 'Tracker name too long'),
  external_id: z.string().min(1, 'External ID is required').max(100, 'External ID too long'),
  title: z
    .string()
    .min(1, 'Issue title is required')
    .max(500, 'Title cannot exceed 500 characters')
    .trim(),
  description: z.string().max(50000, 'Description too long'),
  severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  status: z.enum(['open', 'in_progress', 'resolved', 'closed']).optional(),
});

// Todo data schema
export const TodoDataSchema = z.object({
  id: z.string().uuid().optional(),
  title: z
    .string()
    .min(1, 'Todo title is required')
    .max(500, 'Title cannot exceed 500 characters')
    .trim(),
  description: z.string().max(5000, 'Description too long').optional(),
  status: z.enum(['pending', 'in_progress', 'completed', 'cancelled']),
  priority: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  due_date: z.string().datetime().optional(),
});

// Enhanced knowledge item schema with discriminators
export const EnhancedKnowledgeItemSchema = z
  .object({
    kind: z.enum(
      [
        'section',
        'decision',
        'issue',
        'todo',
        'runbook',
        'change',
        'release_note',
        'ddl',
        'pr_context',
        'entity',
        'relation',
        'observation',
        'incident',
        'release',
        'risk',
        'assumption',
      ],
      {
        errorMap: () => ({
          message: 'Invalid knowledge kind. Must be one of the 16 supported types',
        }),
      }
    ),
    scope: ScopeFilterSchema.optional(),
    data: z.any(), // Will be refined by specific schemas
    tags: z.record(z.unknown()).optional(),
    source: z
      .object({
        actor: z.string().max(200, 'Actor name too long').optional(),
        timestamp: z.string().datetime().optional(),
      })
      .optional(),
    idempotency_key: z.string().max(255, 'Idempotency key too long').optional(),
  })
  .refine((item) => (item.kind === 'section' ? item.scope : true), {
    message: 'Section items must have a scope defined',
    path: ['scope'],
  });

// Discriminated union for different knowledge types
export const KnowledgeItemDiscriminator = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('section'),
    scope: ScopeFilterSchema,
    data: SectionDataSchema,
  }),
  z.object({
    kind: z.literal('decision'),
    scope: ScopeFilterSchema.optional(),
    data: DecisionDataSchema,
  }),
  z.object({
    kind: z.literal('issue'),
    scope: ScopeFilterSchema.optional(),
    data: IssueDataSchema,
  }),
  z.object({
    kind: z.literal('todo'),
    scope: ScopeFilterSchema.optional(),
    data: TodoDataSchema,
  }),
  // Add other types as needed
]);

// Memory store request schema
export const MemoryStoreRequestSchema = z
  .object({
    items: z
      .array(EnhancedKnowledgeItemSchema)
      .min(1, 'At least one item is required')
      .max(100, 'Cannot process more than 100 items in a single request'),
  })
  .refine(
    (request) => {
      const ids = request.items.filter((item) => item.data.id).map((item) => item.data.id);
      return new Set(ids).size === ids.length;
    },
    {
      message: 'Duplicate item IDs found in request',
      path: ['items'],
    }
  );

// Enhanced validation function with detailed error reporting
export function validateKnowledgeItems(items: unknown[]) {
  const results = {
    valid: [] as any[],
    errors: [] as Array<{
      index: number;
      field: string;
      message: string;
      code: string;
    }>,
    warnings: [] as Array<{
      index: number;
      field: string;
      message: string;
    }>,
  };

  items.forEach((item, index) => {
    const result = KnowledgeItemDiscriminator.safeParse(item);

    if (result.success) {
      results.valid.push({
        ...result.data,
        // Add computed fields
        content_hash: generateContentHash(result.data),
        validation_warnings: getValidationWarnings(result.data),
      });
    } else {
      result.error.errors.forEach((error) => {
        results.errors.push({
          index,
          field: error.path.join('.'),
          message: error.message,
          code: error.code || 'VALIDATION_ERROR',
        });
      });
    }
  });

  return results;
}

// Helper function to generate content hash
function generateContentHash(item: any): string {
  const crypto = require('crypto');
  const content = JSON.stringify({
    kind: item.kind,
    scope: item.scope,
    data: item.data,
  });
  return crypto.createHash('sha256').update(content).digest('hex');
}

// Helper function to get validation warnings
function getValidationWarnings(item: any): string[] {
  const warnings: string[] = [];

  if (item.kind === 'section' && item.data.body_md && item.data.body_md.length > 50000) {
    warnings.push('Large markdown content may impact performance');
  }

  if (item.data.title && item.data.title.length > 200) {
    warnings.push('Long titles may be truncated in some displays');
  }

  return warnings;
}

export type EnhancedSectionData = z.infer<typeof SectionDataSchema>;
export type EnhancedDecisionData = z.infer<typeof DecisionDataSchema>;
export type EnhancedKnowledgeItem = z.infer<typeof KnowledgeItemDiscriminator>;
export type MemoryStoreRequest = z.infer<typeof MemoryStoreRequestSchema>;
