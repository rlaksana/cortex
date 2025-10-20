import { z } from 'zod';
import * as crypto from 'crypto';

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

// Incident data schema - aligned with session-logs service
export const IncidentDataSchema = z.object({
  title: z.string().min(1, 'title is required').max(500, 'title must be 500 characters or less'),
  severity: z.enum(['low', 'medium', 'high', 'critical']),
  impact: z.string().min(1, 'impact is required'),
  timeline: z.array(z.object({
    timestamp: z.string(),
    event: z.string(),
    actor: z.string().optional(),
  })).optional(),
  root_cause_analysis: z.string().optional(),
  resolution_status: z.enum(['open', 'investigating', 'resolved', 'closed']),
  affected_services: z.array(z.string()).optional(),
  business_impact: z.string().optional(),
  recovery_actions: z.array(z.string()).optional(),
  follow_up_required: z.boolean().optional(),
  incident_commander: z.string().optional(),
});

// Release data schema - aligned with session-logs service
export const ReleaseDataSchema = z.object({
  version: z.string().min(1, 'version is required'),
  release_type: z.enum(['major', 'minor', 'patch', 'hotfix']),
  scope: z.string().min(1, 'scope is required'),
  release_date: z.string().datetime().optional(),
  status: z.enum(['planned', 'in_progress', 'completed', 'rolled_back']),
  ticket_references: z.array(z.string()).optional(),
  included_changes: z.array(z.string()).optional(),
  deployment_strategy: z.string().optional(),
  rollback_plan: z.string().optional(),
  testing_status: z.string().optional(),
  approvers: z.array(z.string()).optional(),
  release_notes: z.string().optional(),
  post_release_actions: z.array(z.string()).optional(),
});

// Risk data schema - aligned with session-logs service
export const RiskDataSchema = z.object({
  title: z.string().min(1, 'title is required').max(500, 'title must be 500 characters or less'),
  category: z.enum(['technical', 'business', 'operational', 'security', 'compliance']),
  risk_level: z.enum(['critical', 'high', 'medium', 'low']),
  probability: z.enum(['very_likely', 'likely', 'possible', 'unlikely', 'very_unlikely']),
  impact_description: z.string().min(1, 'impact description is required'),
  trigger_events: z.array(z.string()).optional(),
  mitigation_strategies: z.array(z.string()).optional(),
  owner: z.string().optional(),
  review_date: z.string().optional(),
  status: z.enum(['active', 'mitigated', 'accepted', 'closed']),
  related_decisions: z.array(z.string()).optional(),
  monitoring_indicators: z.array(z.string()).optional(),
  contingency_plans: z.string().optional(),
});

// Assumption data schema - aligned with session-logs service
export const AssumptionDataSchema = z.object({
  title: z.string().min(1, 'title is required').max(500, 'title must be 500 characters or less'),
  description: z.string().min(1, 'description is required'),
  category: z.enum(['technical', 'business', 'user', 'market', 'resource']),
  validation_status: z.enum(['validated', 'assumed', 'invalidated', 'needs_validation']),
  impact_if_invalid: z.string().min(1, 'impact if invalid is required'),
  validation_criteria: z.array(z.string()).optional(),
  validation_date: z.string().datetime().optional(),
  owner: z.string().optional(),
  related_assumptions: z.array(z.string()).optional(),
  dependencies: z.array(z.string()).optional(),
  monitoring_approach: z.string().optional(),
  review_frequency: z.enum(['daily', 'weekly', 'monthly', 'quarterly', 'as_needed']).optional(),
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
  z.object({
    kind: z.literal('change'),
    scope: ScopeFilterSchema.optional(),
    data: ChangeDataSchema,
  }),
  z.object({
    kind: z.literal('runbook'),
    scope: ScopeFilterSchema.optional(),
    data: RunbookDataSchema,
  }),
  z.object({
    kind: z.literal('incident'),
    scope: ScopeFilterSchema.optional(),
    data: IncidentDataSchema,
  }),
  z.object({
    kind: z.literal('release'),
    scope: ScopeFilterSchema.optional(),
    data: ReleaseDataSchema,
  }),
  z.object({
    kind: z.literal('risk'),
    scope: ScopeFilterSchema.optional(),
    data: RiskDataSchema,
  }),
  z.object({
    kind: z.literal('assumption'),
    scope: ScopeFilterSchema.optional(),
    data: AssumptionDataSchema,
  }),
]);

// Schema for delete operations
export const DeleteOperationSchema = z.object({
  operation: z.literal('delete'),
  kind: z.enum(['section', 'decision', 'issue', 'todo', 'change', 'runbook', 'incident', 'release', 'risk', 'assumption']),
  id: z.string().uuid(),
  scope: ScopeFilterSchema,
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
