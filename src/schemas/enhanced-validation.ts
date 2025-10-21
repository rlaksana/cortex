import { z } from 'zod';
import * as crypto from 'crypto';
import {
  ReleaseNoteDataSchema,
  DDLDataSchema,
  PRContextDataSchema,
  EntityDataSchema,
  RelationDataSchema,
  ObservationDataSchema,
  IncidentDataSchema,
  ReleaseDataSchema,
  RiskDataSchema,
  AssumptionDataSchema,
  ScopeSchema,
} from './knowledge-types.js';

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
  .refine((data) => data.body_md ?? data.body_text ?? data.heading ?? data.title, {
    message: 'Section must have at least one of: title, heading, body_md, or body_text',
    path: ['root'],
  });

// Decision data schema with ADR-specific validation
export const DecisionDataSchema = z
  .object({
    id: z.string().uuid().optional(),
    component: z.string().min(1, 'Component is required').max(200, 'Component name too long'),
    status: z.enum(['proposed', 'accepted', 'rejected', 'deprecated', 'superseded'], {
      errorMap: () => ({
        message: 'Status must be one of: proposed, accepted, rejected, deprecated, superseded',
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

// PRISMA SCHEMA COMPLIANT Issue data schema
// Uses direct database fields: tracker, external_id, labels, url, assignee
// NO metadata/tags workarounds for database fields
export const IssueDataSchema = z.object({
  id: z.string().uuid().optional(),
  // Direct database fields (Prisma Schema compliance)
  tracker: z.string().max(100, 'Tracker name too long').optional(),
  external_id: z.string().max(100, 'External ID too long').optional(),
  title: z
    .string()
    .min(1, 'Issue title is required')
    .max(500, 'Title cannot exceed 500 characters')
    .trim(),
  description: z.string().max(50000, 'Description too long').optional(),
  severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  status: z.enum(['open', 'in_progress', 'resolved', 'closed']).optional(),
  // Additional direct fields from Prisma schema
  labels: z.array(z.any()).optional(),
  url: z.string().max(2000, 'URL too long').optional(),
  assignee: z.string().max(200, 'Assignee name too long').optional(),
  // Additional properties for validation (NOT for database storage)
  metadata: z.record(z.unknown()).optional(),
  tags: z.record(z.unknown()).optional(),
}).refine((data) => {
  // PRISMA SCHEMA COMPLIANCE: Ensure no metadata workaround usage
  // All database fields must use direct field access
  if (data.metadata) {
    const forbiddenFields = ['tracker', 'external_id', 'url', 'assignee', 'labels'];
    for (const field of forbiddenFields) {
      if (field in data.metadata) {
        return false;
      }
    }
  }
  if (data.tags) {
    const forbiddenFields = ['tracker', 'external_id', 'url', 'assignee', 'labels'];
    for (const field of forbiddenFields) {
      if (field in data.tags) {
        return false;
      }
    }
  }
  return true;
}, {
  message: 'PRISMA SCHEMA VIOLATION: Use direct fields (tracker, external_id, url, assignee, labels) instead of metadata/tags workarounds',
  path: ['root'],
});

// Todo data schema - aligned with database service expectations
export const TodoDataSchema = z.object({
  todo_type: z.enum(['task', 'bug', 'epic', 'story', 'spike']),
  text: z.string().min(1, 'text is required'),
  status: z.enum(['open', 'in_progress', 'done', 'cancelled', 'archived']),
  priority: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  assignee: z.string().optional(),
  due_date: z.string().datetime().optional(),
});

// Change data schema
export const ChangeDataSchema = z.object({
  change_type: z.enum(['feature_add', 'feature_modify', 'feature_remove', 'bugfix', 'refactor', 'config_change', 'dependency_update']),
  subject_ref: z.string().min(1, 'subject_ref is required').max(200, 'subject_ref must be 200 characters or less'),
  summary: z.string().min(1, 'summary is required'),
  details: z.string().optional(),
  affected_files: z.array(z.string()).optional(),
  author: z.string().optional(),
  commit_sha: z.string().optional(),
});

// Runbook data schema
export const RunbookDataSchema = z.object({
  service: z.string().min(1, 'service is required').max(200, 'service must be 200 characters or less'),
  title: z.string().min(1, 'title is required').max(500, 'title must be 500 characters or less'),
  description: z.string().optional(),
  steps: z.array(z.object({
    step_number: z.number().int().positive(),
    description: z.string().min(1, 'step description is required'),
    command: z.string().optional(),
    expected_outcome: z.string().optional(),
  })).min(1, 'At least one step is required'),
  triggers: z.array(z.string()).optional(),
  last_verified_at: z.string().datetime().optional(),
});

// Incident, Release, Risk, and Assumption data schemas are now imported from knowledge-types.js
// to avoid schema duplication and validation conflicts

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
    scope: ScopeSchema,
    data: SectionDataSchema,
  }),
  z.object({
    kind: z.literal('decision'),
    scope: ScopeSchema.optional(),
    data: DecisionDataSchema,
  }),
  z.object({
    kind: z.literal('issue'),
    scope: ScopeSchema.optional(),
    data: IssueDataSchema,
  }),
  z.object({
    kind: z.literal('todo'),
    scope: ScopeSchema.optional(),
    data: TodoDataSchema,
  }),
  z.object({
    kind: z.literal('change'),
    scope: ScopeSchema.optional(),
    data: ChangeDataSchema,
  }),
  z.object({
    kind: z.literal('runbook'),
    scope: ScopeSchema.optional(),
    data: RunbookDataSchema,
  }),
  z.object({
    kind: z.literal('incident'),
    scope: ScopeSchema.optional(),
    data: IncidentDataSchema,
  }),
  z.object({
    kind: z.literal('release'),
    scope: ScopeSchema.optional(),
    data: ReleaseDataSchema,
  }),
  z.object({
    kind: z.literal('risk'),
    scope: ScopeSchema.optional(),
    data: RiskDataSchema,
  }),
  z.object({
    kind: z.literal('assumption'),
    scope: ScopeSchema.optional(),
    data: AssumptionDataSchema,
  }),
  // Missing schemas added during comprehensive testing
  z.object({
    kind: z.literal('release_note'),
    scope: ScopeSchema.optional(),
    data: ReleaseNoteDataSchema,
  }),
  z.object({
    kind: z.literal('ddl'),
    scope: ScopeSchema.optional(),
    data: DDLDataSchema,
  }),
  z.object({
    kind: z.literal('pr_context'),
    scope: ScopeSchema.optional(),
    data: PRContextDataSchema,
  }),
  z.object({
    kind: z.literal('entity'),
    scope: ScopeSchema.optional(),
    data: EntityDataSchema,
  }),
  z.object({
    kind: z.literal('relation'),
    scope: ScopeSchema.optional(),
    data: RelationDataSchema,
  }),
  z.object({
    kind: z.literal('observation'),
    scope: ScopeSchema.optional(),
    data: ObservationDataSchema,
  }),
]);

// Schema for delete operations
export const DeleteOperationSchema = z.object({
  operation: z.literal('delete'),
  kind: z.enum(['section', 'decision', 'issue', 'todo', 'change', 'runbook', 'incident', 'release', 'risk', 'assumption', 'release_note', 'ddl', 'pr_context', 'entity', 'relation', 'observation']),
  id: z.string().min(1, 'ID is required'),
  scope: ScopeSchema,
  cascade_relations: z.boolean().optional().default(false),
});

// Combined schema for all operations (create + delete)
export const AnyKnowledgeItemSchema = z.union([
  // Create operations (discriminated by kind)
  KnowledgeItemDiscriminator,
  // Delete operations
  DeleteOperationSchema,
]);

// Memory store request schema
export const MemoryStoreRequestSchema = z
  .object({
    items: z
      .array(AnyKnowledgeItemSchema)
      .min(1, 'At least one item is required')
      .max(100, 'Cannot process more than 100 items in a single request'),
  })
  .refine(
    (request) => {
      const ids = request.items
        .filter((item) => {
          // For create operations, check data.id (only applies to sections)
          if ('data' in item && 'id' in item.data && item.data?.id) return true;
          // For delete operations, check id directly (using type guard)
          if (isDeleteOperation(item) && item.id) return true;
          return false;
        })
        .map((item) => {
          // For create operations, return data.id (only sections have IDs)
          if ('data' in item && 'id' in item.data && item.data?.id) return item.data.id;
          // For delete operations, return id directly (using type guard)
          if (isDeleteOperation(item) && item.id) return item.id;
          return null;
        })
        .filter(Boolean);
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
    // Try validating with new combined schema first
    const result = AnyKnowledgeItemSchema.safeParse(item);

    if (result.success) {
      const validatedData = result.data;

      // Check if this is a delete operation
      const isDeleteOperation = 'operation' in validatedData && validatedData.operation === 'delete';

      results.valid.push({
        ...validatedData,
        // Add computed fields only for create operations (not delete)
        ...(!isDeleteOperation && {
          content_hash: generateContentHash(validatedData),
          validation_warnings: getValidationWarnings(validatedData),
        }),
      });
    } else {
      result.error.errors.forEach((error) => {
        results.errors.push({
          index,
          field: error.path.join('.'),
          message: error.message,
          code: error.code ?? 'VALIDATION_ERROR',
        });
      });
    }
  });

  return results;
}

// Helper function to generate content hash
function generateContentHash(item: Record<string, unknown>): string {
  const content = JSON.stringify({
    kind: item.kind,
    scope: item.scope,
    data: item.data,
  });
  return crypto.createHash('sha256').update(content).digest('hex');
}

// Helper function to validate array depth
function validateArrayDepth(obj: unknown, currentDepth: number = 0, maxDepth: number = 3): { valid: boolean; message?: string } {
  if (currentDepth > maxDepth) {
    return { valid: false, message: `Array depth exceeds maximum allowed (${maxDepth} levels)` };
  }

  if (Array.isArray(obj)) {
    for (const element of obj) {
      const result = validateArrayDepth(element, currentDepth + 1, maxDepth);
      if (!result.valid) {
        return result;
      }
    }
  } else if (obj && typeof obj === 'object') {
    for (const [, value] of Object.entries(obj)) {
      const result = validateArrayDepth(value, currentDepth, maxDepth);
      if (!result.valid) {
        return result;
      }
    }
  }

  return { valid: true };
}

// Helper function to get validation warnings
function getValidationWarnings(item: Record<string, unknown>): string[] {
  const warnings: string[] = [];

  // Validate array depth to prevent performance issues
  const arrayValidation = validateArrayDepth(item.data);
  if (!arrayValidation.valid && arrayValidation.message) {
    warnings.push(arrayValidation.message);
  }

  if (
    item.kind === 'section' &&
    item.data &&
    typeof item.data === 'object' &&
    'body_md' in item.data &&
    typeof item.data.body_md === 'string' &&
    item.data.body_md.length > 1000000
  ) {
    warnings.push('Content exceeds 1MB limit and may be truncated');
  }

  if (
    item.data &&
    typeof item.data === 'object' &&
    'title' in item.data &&
    typeof item.data.title === 'string' &&
    item.data.title.length > 200
  ) {
    warnings.push('Long titles may be truncated in some displays');
  }

  return warnings;
}

export type EnhancedSectionData = z.infer<typeof SectionDataSchema>;
export type EnhancedDecisionData = z.infer<typeof DecisionDataSchema>;
// Type guard for delete operations
function isDeleteOperation(item: unknown): item is z.infer<typeof DeleteOperationSchema> {
  return typeof item === 'object' && item !== null && 'operation' in item && item.operation === 'delete';
}

export type EnhancedKnowledgeItem = z.infer<typeof AnyKnowledgeItemSchema>;
export type MemoryStoreRequest = z.infer<typeof MemoryStoreRequestSchema>;
