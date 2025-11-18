// LAST ABSOLUTE FINAL EMERGENCY ROLLBACK: Complete the systematic rollback

/**
 * Cortex Memory MCP - Unified Knowledge Type Validator System
 *
 * Comprehensive type validation system providing:
 * - Single source of truth for all knowledge type schemas
 * - Consistent error handling and messaging
 * - Runtime type checking with Zod integration
 * - Business rule validation
 * - Performance-optimized validation patterns
 *
 * @version 2.0.0 - T20 Implementation
 */

import { z, type ZodError, type ZodSchema } from 'zod';

import type {
  KnowledgeItem,
  MemoryFindRequest,
  MemoryStoreRequest,
  StoreError,
} from '../types/core-interfaces.js';
import type {
  JSONValue,
  Metadata,
  Tags,
} from '../types/base-types.js';
import {
  hasPropertySimple,
  isString as isStringType,
  isBoolean,
  isNumber,
  isUnknown,
  isObject,
} from '../utils/type-guards.js';

// ============================================================================
// Safe Property Access Helpers for JSONValue
// ============================================================================

/**
 * Safely access a string property from a JSONValue object
 */
function safeString(obj: JSONValue, property: string): string | undefined {
  return hasPropertySimple(obj, property) && isStringType(obj[property]) ? obj[property] : undefined;
}

/**
 * Safely access a boolean property from a JSONValue object
 */
function safeBoolean(obj: JSONValue, property: string): boolean | undefined {
  return hasPropertySimple(obj, property) && isBoolean(obj[property]) ? obj[property] : undefined;
}

/**
 * Safely access a number property from a JSONValue object
 */
function safeNumber(obj: JSONValue, property: string): number | undefined {
  return hasPropertySimple(obj, property) && isNumber(obj[property]) ? obj[property] : undefined;
}

/**
 * Safely access an object property from a JSONValue object
 */
function safeObject(obj: JSONValue, property: string): Record<string, unknown> | undefined {
  return hasPropertySimple(obj, property) && isObject(obj[property]) ? obj[property] : undefined;
}

/**
 * Safely access an array property from a JSONValue object
 */
function safeArray(obj: JSONValue, property: string): unknown[] | undefined {
  return hasPropertySimple(obj, property) && Array.isArray(obj[property]) ? obj[property] : undefined;
}

// Re-export JSONValue, Metadata, and Tags for external use
export type { JSONValue, Metadata, Tags } from '../types/base-types.js';

// ============================================================================
// Type-Safe Validation Interfaces
// ============================================================================

/**
 * Branded type for validated data to ensure type safety
 */
export type ValidatedData<T = JSONValue> = {
  readonly data: T;
  readonly validatedAt: string;
  readonly schemaVersion: string;
};

/**
 * Type-safe validation rule interface
 */
export interface TypedValidationRule<T = JSONValue> {
  name: string;
  validator: (data: T) => ValidationErrorDetail[];
  priority: number;
  description?: string;
}

/**
 * Type-safe validation context
 */
export interface TypedValidationContext<T = JSONValue> {
  data: T;
  schema: ZodSchema<T>;
  options: ValidationOptions;
  businessRules?: TypedValidationRule<T>[];
}

// ============================================================================
// Error Handling System
// ============================================================================

export enum ValidationErrorCategory {
  SCHEMA = 'SCHEMA',
  BUSINESS_RULE = 'BUSINESS_RULE',
  SYSTEM = 'SYSTEM',
  PERFORMANCE = 'PERFORMANCE',
}

export enum ValidationErrorSeverity {
  ERROR = 'ERROR',
  WARNING = 'WARNING',
  INFO = 'INFO',
}

export interface ValidationErrorDetail {
  code: string;
  message: string;
  field?: string;
  path?: string[];
  category: ValidationErrorCategory;
  severity: ValidationErrorSeverity;
  suggestion?: string;
  context?: Record<string, JSONValue>;
}

export interface ValidationResult<T = JSONValue> {
  valid: boolean;
  errors: ValidationErrorDetail[];
  warnings: ValidationErrorDetail[];
  data?: ValidatedData<T>;
  metadata: {
    validationTimeMs: number;
    validatorVersion: string;
    schemaVersion: string;
    validationMode: ValidationMode;
  };
}

export const ValidationMode = {
  STRICT: 'STRICT' as const,
  LENIENT: 'LENIENT' as const,
  BUSINESS_RULES_ONLY: 'BUSINESS_RULES_ONLY' as const,
  SCHEMA_ONLY: 'SCHEMA_ONLY' as const,
} as const;

export type ValidationMode = (typeof ValidationMode)[keyof typeof ValidationMode];

export interface ValidationOptions<T = JSONValue> {
  mode?: ValidationMode;
  includeWarnings?: boolean;
  maxErrors?: number;
  timeout?: number;
  enablePerformanceChecks?: boolean;
  customRules?: CustomValidationRule<T>[];
}

export interface CustomValidationRule<T = JSONValue> {
  name: string;
  validator: (data: T) => ValidationErrorDetail[];
  priority: number;
  description?: string;
}

// ============================================================================
// Base Schemas (Single Source of Truth)
// ============================================================================

export const BaseScopeSchema = z
  .object({
    org: z
      .string()
      .min(1, 'Organization name is required')
      .max(100, 'Organization name too long')
      .optional(),
    project: z.string().min(1, 'Project name is required').max(100, 'Project name too long'),
    branch: z
      .string()
      .min(1, 'Branch name is required')
      .max(100, 'Branch name too long')
      .optional(),
    service: z.string().max(100, 'Service name too long').optional(),
    sprint: z.string().max(50, 'Sprint name too long').optional(),
    tenant: z.string().max(50, 'Tenant name too long').optional(),
    environment: z.string().max(50, 'Environment name too long').optional(),
  })
  .strict();

export const BaseSourceSchema = z
  .object({
    actor: z.string().max(200, 'Actor name too long').optional(),
    tool: z.string().max(100, 'Tool name too long').optional(),
    timestamp: z.string().datetime().optional(),
  })
  .strict();

export const BaseMetadataSchema = z.record(z.unknown()).optional();

// ============================================================================
// Knowledge Type Data Schemas
// ============================================================================

export const SectionDataSchema = z
  .object({
    id: z.string().uuid().optional(),
    title: z.string().min(1, 'Title is required').max(500, 'Title cannot exceed 500 characters'),
    heading: z
      .string()
      .min(1, 'Heading is required')
      .max(300, 'Heading cannot exceed 300 characters')
      .optional(),
    body_md: z.string().max(1000000, 'Markdown content too large').optional(),
    body_text: z.string().max(1000000, 'Text content too large').optional(),
    document_id: z.string().uuid().optional(),
    citation_count: z.number().int().nonnegative().optional(),
  })
  .strict()
  .refine((data) => data.body_md || data.body_text || data.title, {
    message: 'Section must have content (body_md, body_text, or title)',
    path: ['content'],
  });

export const DecisionDataSchema = z
  .object({
    id: z.string().uuid().optional(),
    component: z.string().min(1, 'Component is required').max(200, 'Component name too long'),
    status: z.enum(['proposed', 'accepted', 'rejected', 'deprecated', 'superseded']),
    title: z.string().min(1, 'Title is required').max(500, 'Title cannot exceed 500 characters'),
    rationale: z
      .string()
      .min(10, 'Rationale must be at least 10 characters')
      .max(50000, 'Rationale too long'),
    alternatives_considered: z.array(z.string().min(1)).max(20, 'Too many alternatives').optional(),
    consequences: z.string().max(10000, 'Consequences description too long').optional(),
    supersedes: z.string().uuid().optional(),
    acceptance_date: z.string().datetime().optional(),
  })
  .strict();

export const IssueDataSchema = z
  .object({
    id: z.string().uuid().optional(),
    tracker: z.string().max(100, 'Tracker name too long').optional(),
    external_id: z.string().max(100, 'External ID too long').optional(),
    title: z
      .string()
      .min(1, 'Issue title is required')
      .max(500, 'Title cannot exceed 500 characters'),
    description: z.string().max(50000, 'Description too long').optional(),
    severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
    status: z
      .enum(['open', 'in_progress', 'resolved', 'closed', 'wont_fix', 'duplicate'])
      .optional(),
    assignee: z.string().max(200, 'Assignee name too long').optional(),
    labels: z.array(z.string()).optional(),
    url: z.string().max(2000, 'URL too long').optional(),
    metadata: z.record(z.unknown()).optional(),
    tags: z.record(z.unknown()).optional(),
  })
  .strict();

export const TodoDataSchema = z
  .object({
    id: z.string().optional(),
    scope: z.string().max(200, 'Scope too long').optional(),
    todo_type: z.enum(['task', 'bug', 'epic', 'story', 'spike']),
    text: z.string().min(1, 'Todo text is required'),
    status: z.enum(['open', 'in_progress', 'done', 'cancelled', 'archived']),
    priority: z.enum(['low', 'medium', 'high', 'critical']).optional(),
    assignee: z.string().max(200, 'Assignee name too long').optional(),
    due_date: z.string().datetime().optional(),
    closed_at: z.string().datetime().optional(),
  })
  .strict();

export const RunbookDataSchema = z
  .object({
    service: z.string().min(1, 'Service is required').max(200, 'Service name too long'),
    title: z.string().min(1, 'Title is required').max(500, 'Title must be 500 characters or less'),
    description: z.string().optional(),
    steps: z
      .array(
        z.object({
          step_number: z.number().int().positive(),
          description: z.string().min(1, 'Step description is required'),
          command: z.string().optional(),
          expected_outcome: z.string().optional(),
        })
      )
      .min(1, 'At least one step is required'),
    triggers: z.array(z.string()).optional(),
    owner: z.string().max(200, 'Owner name too long').optional(),
    last_verified_at: z.string().datetime().optional(),
  })
  .strict();

export const ChangeDataSchema = z
  .object({
    change_type: z.enum([
      'feature_add',
      'feature_modify',
      'feature_remove',
      'bugfix',
      'refactor',
      'config_change',
      'dependency_update',
    ]),
    subject_ref: z
      .string()
      .min(1, 'Subject reference is required')
      .max(200, 'Subject reference too long'),
    summary: z.string().min(1, 'Summary is required'),
    details: z.string().optional(),
    affected_files: z.array(z.string()).optional(),
    author: z.string().max(200, 'Author name too long').optional(),
    commit_sha: z.string().max(100, 'Commit SHA too long').optional(),
  })
  .strict();

export const ReleaseNoteDataSchema = z
  .object({
    id: z.string().uuid().optional(),
    version: z.string().min(1, 'Version is required').max(100, 'Version too long'),
    release_date: z.string().datetime(),
    summary: z.string().min(1, 'Summary is required'),
    breaking_changes: z.array(z.string()).optional(),
    new_features: z.array(z.string()).optional(),
    bug_fixes: z.array(z.string()).optional(),
    deprecations: z.array(z.string()).optional(),
  })
  .strict();

export const DDLDataSchema = z
  .object({
    id: z.string().uuid().optional(),
    migration_id: z.string().min(1, 'Migration ID is required').max(200, 'Migration ID too long'),
    ddl_text: z.string().min(1, 'DDL text is required'),
    checksum: z.string().max(64, 'Checksum too long').optional(),
    description: z.string().optional(),
  })
  .strict();

export const PRContextDataSchema = z
  .object({
    id: z.string().uuid().optional(),
    pr_number: z.number().int().positive(),
    title: z.string().min(1, 'Title is required').max(500, 'Title too long'),
    description: z.string().optional(),
    author: z.string().min(1, 'Author is required').max(200, 'Author name too long'),
    status: z.enum(['open', 'merged', 'closed', 'draft']),
    base_branch: z.string().min(1, 'Base branch is required').max(200, 'Base branch too long'),
    head_branch: z.string().min(1, 'Head branch is required').max(200, 'Head branch too long'),
    merged_at: z.string().datetime().optional(),
  })
  .strict();

export const EntityDataSchema = z
  .object({
    entity_type: z.string().min(1, 'Entity type is required').max(100, 'Entity type too long'),
    name: z.string().min(1, 'Entity name is required').max(500, 'Entity name too long'),
    data: z.record(z.unknown()),
  })
  .strict();

export const RelationDataSchema = z
  .object({
    source: z.string().uuid('Source ID must be a valid UUID'),
    target: z.string().uuid('Target ID must be a valid UUID'),
    type: z.string().min(1, 'Relation type is required').max(100, 'Relation type too long'),
    metadata: z.record(z.unknown()).optional(),
  })
  .strict();

export const ObservationDataSchema = z
  .object({
    content: z.string().min(1, 'Content is required'),
    observation_type: z.string().max(100, 'Observation type too long').optional(),
    metadata: z.record(z.unknown()).optional(),
  })
  .strict();

export const IncidentDataSchema = z
  .object({
    id: z.string().uuid().optional(),
    title: z.string().min(1, 'Title is required').max(500, 'Title too long'),
    description: z.string().optional(),
    severity: z.enum(['critical', 'high', 'medium', 'low']),
    status: z.string().max(50, 'Status too long').optional(),
    impact: z.string().min(1, 'Impact is required'),
    impact_level: z.string().max(50, 'Impact level too long').optional(),
    timeline: z.array(z.any()).optional(),
    incident_type: z.string().max(100, 'Incident type too long').optional(),
    affected_services: z.array(z.string()).optional(),
    root_cause: z.string().optional(),
    root_cause_analysis: z.string().optional(),
    resolution: z.string().optional(),
    lessons_learned: z.string().optional(),
    recovery_actions: z.array(z.string()).optional(),
    created_at: z.string().datetime().optional(),
    updated_at: z.string().datetime().optional(),
  })
  .strict();

export const ReleaseDataSchema = z
  .object({
    id: z.string().uuid().optional(),
    version: z.string().min(1, 'Version is required').max(100, 'Version too long'),
    title: z.string().max(500, 'Title too long').optional(),
    description: z.string().optional(),
    status: z.string().max(50, 'Status too long').optional(),
    deployment_strategy: z.string().max(100, 'Deployment strategy too long').optional(),
    release_date: z.string().datetime().optional(),
    release_notes: z.array(z.string()).optional(),
    features: z.array(z.string()).optional(),
    bug_fixes: z.array(z.string()).optional(),
    breaking_changes: z.array(z.string()).optional(),
    rollback_plan: z.string().optional(),
    created_at: z.string().datetime().optional(),
    updated_at: z.string().datetime().optional(),
  })
  .strict();

export const RiskDataSchema = z
  .object({
    id: z.string().uuid().optional(),
    title: z.string().min(1, 'Title is required').max(500, 'Title too long'),
    description: z.string().min(1, 'Description is required'),
    probability: z.enum(['very_likely', 'likely', 'possible', 'unlikely', 'very_unlikely']),
    impact: z.string().min(1, 'Impact is required'),
    risk_level: z.string().max(50, 'Risk level too long').optional(),
    category: z.string().min(1, 'Category is required').max(100, 'Category too long'),
    mitigation: z.string().optional(),
    contingency_plan: z.string().optional(),
    risk_owner: z.string().max(200, 'Risk owner too long').optional(),
    review_date: z.string().optional(),
    identified_date: z.string().optional(),
    created_at: z.string().datetime().optional(),
    updated_at: z.string().datetime().optional(),
  })
  .strict();

export const AssumptionDataSchema = z
  .object({
    id: z.string().uuid().optional(),
    title: z.string().min(1, 'Title is required').max(500, 'Title too long'),
    description: z.string().min(1, 'Description is required'),
    category: z.string().min(1, 'Category is required').max(100, 'Category too long'),
    validation_status: z.string().max(50, 'Validation status too long').optional(),
    impact_if_invalid: z.string().min(1, 'Impact description is required'),
    validation_method: z.string().max(100, 'Validation method too long').optional(),
    validation_date: z.string().optional(),
    owner: z.string().max(200, 'Owner too long').optional(),
    dependencies: z.array(z.string()).optional(),
    expiry_date: z.string().optional(),
    created_at: z.string().datetime().optional(),
    updated_at: z.string().datetime().optional(),
  })
  .strict();

// ============================================================================
// Complete Knowledge Item Schema
// ============================================================================

const KnowledgeItemKindSchema = z.enum([
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
]);

export const BaseKnowledgeItemSchema = z
  .object({
    id: z.string().uuid().optional(),
    kind: KnowledgeItemKindSchema,
    content: z.string().optional(),
    scope: BaseScopeSchema,
    data: z.any(), // Will be refined by discriminated union
    metadata: BaseMetadataSchema,
    created_at: z.string().datetime().optional(),
    updated_at: z.string().datetime().optional(),
    expiry_at: z.string().datetime().optional(),
    source: BaseSourceSchema.optional(),
    idempotency_key: z.string().max(255, 'Idempotency key too long').optional(),
  })
  .strict();

export const KnowledgeItemSchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('section'), data: SectionDataSchema }).merge(BaseKnowledgeItemSchema),
  z
    .object({ kind: z.literal('decision'), data: DecisionDataSchema })
    .merge(BaseKnowledgeItemSchema),
  z.object({ kind: z.literal('issue'), data: IssueDataSchema }).merge(BaseKnowledgeItemSchema),
  z.object({ kind: z.literal('todo'), data: TodoDataSchema }).merge(BaseKnowledgeItemSchema),
  z.object({ kind: z.literal('runbook'), data: RunbookDataSchema }).merge(BaseKnowledgeItemSchema),
  z.object({ kind: z.literal('change'), data: ChangeDataSchema }).merge(BaseKnowledgeItemSchema),
  z
    .object({ kind: z.literal('release_note'), data: ReleaseNoteDataSchema })
    .merge(BaseKnowledgeItemSchema),
  z.object({ kind: z.literal('ddl'), data: DDLDataSchema }).merge(BaseKnowledgeItemSchema),
  z
    .object({ kind: z.literal('pr_context'), data: PRContextDataSchema })
    .merge(BaseKnowledgeItemSchema),
  z.object({ kind: z.literal('entity'), data: EntityDataSchema }).merge(BaseKnowledgeItemSchema),
  z
    .object({ kind: z.literal('relation'), data: RelationDataSchema })
    .merge(BaseKnowledgeItemSchema),
  z
    .object({ kind: z.literal('observation'), data: ObservationDataSchema })
    .merge(BaseKnowledgeItemSchema),
  z
    .object({ kind: z.literal('incident'), data: IncidentDataSchema })
    .merge(BaseKnowledgeItemSchema),
  z.object({ kind: z.literal('release'), data: ReleaseDataSchema }).merge(BaseKnowledgeItemSchema),
  z.object({ kind: z.literal('risk'), data: RiskDataSchema }).merge(BaseKnowledgeItemSchema),
  z
    .object({ kind: z.literal('assumption'), data: AssumptionDataSchema })
    .merge(BaseKnowledgeItemSchema),
]);

// ============================================================================
// Request/Response Schemas
// ============================================================================

export const MemoryStoreRequestSchema = z
  .object({
    items: z
      .array(KnowledgeItemSchema)
      .min(1, 'At least one item is required')
      .max(100, 'Cannot process more than 100 items in a single request'),
  })
  .strict();

export const MemoryFindRequestSchema = z
  .object({
    query: z.string().min(1, 'Query is required'),
    scope: BaseScopeSchema.optional(),
    types: z.array(z.string()).optional(),
    mode: z.enum(['auto', 'fast', 'deep']).optional().default('auto'),
    limit: z.number().int().min(1).max(1000).optional().default(50),
    expand: z.enum(['relations', 'parents', 'children', 'none']).optional().default('none'),
  })
  .strict();

export const DeleteRequestSchema = z
  .object({
    id: z.string().min(1, 'ID is required'),
    kind: KnowledgeItemKindSchema,
    scope: BaseScopeSchema,
    cascade_relations: z.boolean().optional().default(false),
  })
  .strict();

// ============================================================================
// Business Rule Validators
// ============================================================================

export class BusinessRuleValidator {
  private static rules: Map<string, (data: JSONValue) => ValidationErrorDetail[]> = new Map([
    ['section', BusinessRuleValidator.validateSection],
    ['decision', BusinessRuleValidator.validateDecision],
    ['issue', BusinessRuleValidator.validateIssue],
    ['todo', BusinessRuleValidator.validateTodo],
    ['runbook', BusinessRuleValidator.validateRunbook],
    ['change', BusinessRuleValidator.validateChange],
    ['release_note', BusinessRuleValidator.validateReleaseNote],
    ['ddl', BusinessRuleValidator.validateDDL],
    ['pr_context', BusinessRuleValidator.validatePRContext],
    ['entity', BusinessRuleValidator.validateEntity],
    ['relation', BusinessRuleValidator.validateRelation],
    ['observation', BusinessRuleValidator.validateObservation],
    ['incident', BusinessRuleValidator.validateIncident],
    ['release', BusinessRuleValidator.validateRelease],
    ['risk', BusinessRuleValidator.validateRisk],
    ['assumption', BusinessRuleValidator.validateAssumption],
  ]);

  private static validateSection(data: JSONValue): ValidationErrorDetail[] {
    const errors: ValidationErrorDetail[] = [];

    const title = safeString(data, 'title');
    const bodyMd = safeString(data, 'body_md');
    const bodyText = safeString(data, 'body_text');

    if (!bodyMd && !bodyText && title && title.length > 200) {
      errors.push({
        code: 'SECTION_TITLE_TOO_LONG',
        message: 'Section title is very long without body content',
        field: 'title',
        category: ValidationErrorCategory.BUSINESS_RULE,
        severity: ValidationErrorSeverity.WARNING,
        suggestion: 'Consider adding body content or shortening the title',
      });
    }

    return errors;
  }

  private static validateDecision(data: JSONValue): ValidationErrorDetail[] {
    const errors: ValidationErrorDetail[] = [];

    if (!hasPropertySimple(data, 'status')) {
      return errors;
    }

    const record = data as Record<string, unknown>;

    if (record.status === 'accepted') {
      if (!hasPropertySimple(record, 'rationale') || typeof record.rationale !== 'string' || record.rationale.length < 50) {
        errors.push({
          code: 'DECISION_INSUFFICIENT_RATIONALE',
          message: 'Accepted decisions must have detailed rationale (at least 50 characters)',
          path: ['rationale'],
          category: ValidationErrorCategory.BUSINESS_RULE,
          severity: ValidationErrorSeverity.ERROR,
          suggestion: 'Add detailed rationale explaining the decision',
        });
      }
    }

    if (hasPropertySimple(record, 'acceptance_date')) {
      if (!hasPropertySimple(record, 'rationale') || typeof record.rationale !== 'string' || record.rationale.length < 30) {
        errors.push({
          code: 'DECISION_ACCEPTANCE_MISSING_RATIONALE',
          message: 'Decisions with acceptance date must have rationale explaining acceptance',
          path: ['rationale'],
          category: ValidationErrorCategory.BUSINESS_RULE,
          severity: ValidationErrorSeverity.WARNING,
          suggestion: 'Add rationale explaining why this was accepted',
        });
      }
    }

    return errors;
  }

  private static validateIssue(data: JSONValue): ValidationErrorDetail[] {
    const errors: ValidationErrorDetail[] = [];
    const record = data as Record<string, unknown>;

    if (hasPropertySimple(record, 'tracker') && record.tracker && !hasPropertySimple(record, 'external_id')) {
      errors.push({
        code: 'ISSUE_TRACKER_WITHOUT_ID',
        message: 'Issue has tracker but missing external ID',
        field: 'external_id',
        category: ValidationErrorCategory.BUSINESS_RULE,
        severity: ValidationErrorSeverity.WARNING,
        suggestion: 'Add external ID for proper tracker integration',
      });
    }

    if (hasPropertySimple(record, 'severity') && record.severity === 'critical' && !hasPropertySimple(record, 'description')) {
      errors.push({
        code: 'CRITICAL_ISSUE_NO_DESCRIPTION',
        message: 'Critical issues should have detailed descriptions',
        field: 'description',
        category: ValidationErrorCategory.BUSINESS_RULE,
        severity: ValidationErrorSeverity.WARNING,
        suggestion: 'Add description to explain the critical issue',
      });
    }

    return errors;
  }

  private static validateTodo(data: JSONValue): ValidationErrorDetail[] {
    const errors: ValidationErrorDetail[] = [];
    const record = data as Record<string, unknown>;

    if (hasPropertySimple(record, 'due_date') && record.due_date && 
        hasPropertySimple(record, 'status') && record.status === 'done' && 
        !hasPropertySimple(record, 'closed_at')) {
      errors.push({
        code: 'TODO_DONE_WITHOUT_CLOSE_DATE',
        message: 'Todo is marked done but missing closed date',
        field: 'closed_at',
        category: ValidationErrorCategory.BUSINESS_RULE,
        severity: ValidationErrorSeverity.WARNING,
        suggestion: 'Set closed date when marking todo as done',
      });
    }

    if (hasPropertySimple(record, 'priority') && record.priority === 'critical' && !hasPropertySimple(record, 'assignee')) {
      errors.push({
        code: 'CRITICAL_TODO_NO_ASSIGNEE',
        message: 'Critical todos should have assignees',
        field: 'assignee',
        category: ValidationErrorCategory.BUSINESS_RULE,
        severity: ValidationErrorSeverity.WARNING,
        suggestion: 'Assign this critical todo to someone',
      });
    }

    return errors;
  }

  private static validateRunbook(data: JSONValue): ValidationErrorDetail[] {
    const errors: ValidationErrorDetail[] = [];
    const record = data as Record<string, unknown>;

    if (hasPropertySimple(record, 'steps') && Array.isArray(record.steps) && record.steps.length > 50) {
      errors.push({
        code: 'RUNBOOK_TOO_MANY_STEPS',
        message: 'Runbook has too many steps (consider splitting)',
        field: 'steps',
        category: ValidationErrorCategory.BUSINESS_RULE,
        severity: ValidationErrorSeverity.WARNING,
        suggestion: 'Consider breaking this into multiple runbooks',
      });
    }

    if (hasPropertySimple(record, 'service') && record.service && !hasPropertySimple(record, 'last_verified_at')) {
      errors.push({
        code: 'RUNBOOK_NOT_VERIFIED',
        message: 'Runbook has not been verified',
        field: 'last_verified_at',
        category: ValidationErrorCategory.BUSINESS_RULE,
        severity: ValidationErrorSeverity.INFO,
        suggestion: "Verify this runbook to ensure it's up to date",
      });
    }

    return errors;
  }

  private static validateChange(data: JSONValue): ValidationErrorDetail[] {
    const errors: ValidationErrorDetail[] = [];
    const record = data as Record<string, unknown>;

    if (hasPropertySimple(record, 'change_type') && 
        typeof record.change_type === 'string' && 
        record.change_type.startsWith('feature_') && 
        !hasPropertySimple(record, 'author')) {
      errors.push({
        code: 'FEATURE_CHANGE_NO_AUTHOR',
        message: 'Feature changes should have author attribution',
        field: 'author',
        category: ValidationErrorCategory.BUSINESS_RULE,
        severity: ValidationErrorSeverity.WARNING,
        suggestion: 'Add author to track feature change ownership',
      });
    }

    if (hasPropertySimple(record, 'affected_files') && 
        Array.isArray(record.affected_files) && 
        record.affected_files.length > 100) {
      errors.push({
        code: 'CHANGE_TOO_MANY_FILES',
        message: 'Change affects too many files (consider splitting)',
        field: 'affected_files',
        category: ValidationErrorCategory.BUSINESS_RULE,
        severity: ValidationErrorSeverity.WARNING,
        suggestion: 'Consider breaking this into smaller changes',
      });
    }

    return errors;
  }

  private static validateReleaseNote(data: JSONValue): ValidationErrorDetail[] {
    const errors: ValidationErrorDetail[] = [];
    const record = data as Record<string, unknown>;

    if (
      hasPropertySimple(record, 'breaking_changes') && 
      Array.isArray(record.breaking_changes) &&
      record.breaking_changes.length > 0 &&
      hasPropertySimple(record, 'summary') && 
      typeof record.summary === 'string' &&
      !record.summary.toLowerCase().includes('breaking')
    ) {
      errors.push({
        code: 'BREAKING_CHANGES_NOT_IN_SUMMARY',
        message: "Release has breaking changes but summary doesn't indicate this",
        field: 'summary',
        category: ValidationErrorCategory.BUSINESS_RULE,
        severity: ValidationErrorSeverity.WARNING,
        suggestion: 'Add "BREAKING" to summary to highlight breaking changes',
      });
    }

    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 30); // 30 days from now
    if (hasPropertySimple(record, 'release_date') && 
        typeof record.release_date === 'string' &&
        new Date(record.release_date) > futureDate) {
      errors.push({
        code: 'RELEASE_DATE_TOO_FAR',
        message: 'Release date is more than 30 days in the future',
        field: 'release_date',
        category: ValidationErrorCategory.BUSINESS_RULE,
        severity: ValidationErrorSeverity.WARNING,
        suggestion: 'Verify the release date is correct',
      });
    }

    return errors;
  }

  private static validateDDL(data: JSONValue): ValidationErrorDetail[] {
    const errors: ValidationErrorDetail[] = [];
    const record = data as Record<string, unknown>;

    if (
      hasPropertySimple(record, 'ddl_text') && 
      typeof record.ddl_text === 'string' &&
      !record.ddl_text.toLowerCase().includes('create') &&
      !record.ddl_text.toLowerCase().includes('alter') &&
      !record.ddl_text.toLowerCase().includes('drop')
    ) {
      errors.push({
        code: 'DDL_NO_OPERATION',
        message: "DDL text doesn't contain recognized DDL operations",
        field: 'ddl_text',
        category: ValidationErrorCategory.BUSINESS_RULE,
        severity: ValidationErrorSeverity.WARNING,
        suggestion: 'Verify this is actually a DDL statement',
      });
    }

    if (hasPropertySimple(record, 'migration_id') && 
        typeof record.migration_id === 'string' &&
        !/^[A-Z0-9_-]+$/i.test(record.migration_id)) {
      errors.push({
        code: 'DDL_INVALID_MIGRATION_ID',
        message: 'Migration ID should contain only alphanumeric characters, underscores, and hyphens',
        field: 'migration_id',
        category: ValidationErrorCategory.BUSINESS_RULE,
        severity: ValidationErrorSeverity.WARNING,
        suggestion: 'Use a standard migration ID format',
      });
    }

    return errors;
  }

  private static validatePRContext(data: JSONValue): ValidationErrorDetail[] {
    const errors: ValidationErrorDetail[] = [];
    const record = data as Record<string, unknown>;

    if (hasPropertySimple(record, 'status') && record.status === 'merged' && !hasPropertySimple(record, 'merged_at')) {
      errors.push({
        code: 'PR_MERGED_WITHOUT_DATE',
        message: 'PR is marked merged but missing merge date',
        field: 'merged_at',
        category: ValidationErrorCategory.BUSINESS_RULE,
        severity: ValidationErrorSeverity.WARNING,
        suggestion: 'Add merge date for proper tracking',
      });
    }

    if (hasPropertySimple(record, 'base_branch') && hasPropertySimple(record, 'head_branch') && 
        record.base_branch === record.head_branch) {
      errors.push({
        code: 'PR_SAME_BRANCH',
        message: 'PR base and head branches are the same',
        field: 'head_branch',
        category: ValidationErrorCategory.BUSINESS_RULE,
        severity: ValidationErrorSeverity.ERROR,
        suggestion: 'Verify the target branch is correct',
      });
    }

    return errors;
  }

  private static validateEntity(data: JSONValue): ValidationErrorDetail[] {
    const errors: ValidationErrorDetail[] = [];
    const record = data as Record<string, unknown>;

    if (hasPropertySimple(record, 'data') && 
        record.data && 
        typeof record.data === 'object' && 
        record.data !== null && 
        !Array.isArray(record.data) &&
        Object.keys(record.data as Record<string, unknown>).length > 1000) {
      errors.push({
        code: 'ENTITY_TOO_COMPLEX',
        message: 'Entity has too many data properties',
        field: 'data',
        category: ValidationErrorCategory.BUSINESS_RULE,
        severity: ValidationErrorSeverity.WARNING,
        suggestion: 'Consider simplifying the entity structure',
      });
    }

    return errors;
  }

  private static validateRelation(data: JSONValue): ValidationErrorDetail[] {
    const errors: ValidationErrorDetail[] = [];

    if (data.source === data.target) {
      errors.push({
        code: 'RELATION_SELF_REFERENCE',
        message: 'Relation references the same entity',
        field: 'target',
        category: ValidationErrorCategory.BUSINESS_RULE,
        severity: ValidationErrorSeverity.WARNING,
        suggestion: 'Verify this relation is intentional',
      });
    }

    return errors;
  }

  private static validateObservation(data: JSONValue): ValidationErrorDetail[] {
    const errors: ValidationErrorDetail[] = [];
    const record = data as Record<string, unknown>;

    if (hasPropertySimple(record, 'content') && 
        typeof record.content === 'string' &&
        record.content.length > 10000) {
      errors.push({
        code: 'OBSERVATION_TOO_LONG',
        message: 'Observation content is very long',
        field: 'content',
        category: ValidationErrorCategory.BUSINESS_RULE,
        severity: ValidationErrorSeverity.WARNING,
        suggestion: 'Consider making this more concise',
      });
    }

    return errors;
  }

  private static validateIncident(data: JSONValue): ValidationErrorDetail[] {
    const errors: ValidationErrorDetail[] = [];
    const record = data as Record<string, unknown>;

    if (hasPropertySimple(record, 'severity') && record.severity === 'critical' && !hasPropertySimple(record, 'root_cause_analysis')) {
      errors.push({
        code: 'CRITICAL_INCIDENT_NO_RCA',
        message: 'Critical incidents should have root cause analysis',
        field: 'root_cause_analysis',
        category: ValidationErrorCategory.BUSINESS_RULE,
        severity: ValidationErrorSeverity.WARNING,
        suggestion: 'Add root cause analysis for critical incidents',
      });
    }

    if (hasPropertySimple(record, 'affected_services') && Array.isArray(record.affected_services) && record.affected_services.length > 20) {
      errors.push({
        code: 'INCIDENT_TOO_MANY_SERVICES',
        message: 'Incident affects too many services',
        field: 'affected_services',
        category: ValidationErrorCategory.BUSINESS_RULE,
        severity: ValidationErrorSeverity.WARNING,
        suggestion: 'Verify all services are actually affected',
      });
    }

    return errors;
  }

  private static validateRelease(data: JSONValue): ValidationErrorDetail[] {
    const errors: ValidationErrorDetail[] = [];
    const record = data as Record<string, unknown>;

    if (hasPropertySimple(record, 'status') && record.status === 'completed' && !hasPropertySimple(record, 'release_date')) {
      errors.push({
        code: 'RELEASE_COMPLETED_WITHOUT_DATE',
        message: 'Release is marked completed but missing release date',
        field: 'release_date',
        category: ValidationErrorCategory.BUSINESS_RULE,
        severity: ValidationErrorSeverity.WARNING,
        suggestion: 'Add release date for completed releases',
      });
    }

    if (hasPropertySimple(record, 'deployment_strategy') && record.deployment_strategy && !hasPropertySimple(record, 'rollback_plan')) {
      errors.push({
        code: 'RELEASE_NO_ROLLBACK_PLAN',
        message: 'Release has deployment strategy but no rollback plan',
        field: 'rollback_plan',
        category: ValidationErrorCategory.BUSINESS_RULE,
        severity: ValidationErrorSeverity.WARNING,
        suggestion: 'Add rollback plan for safety',
      });
    }

    return errors;
  }

  private static validateRisk(data: JSONValue): ValidationErrorDetail[] {
    const errors: ValidationErrorDetail[] = [];
    const record = data as Record<string, unknown>;

    if (
      hasPropertySimple(record, 'probability') && record.probability === 'very_likely' &&
      hasPropertySimple(record, 'risk_level') && record.risk_level !== 'critical' && record.risk_level !== 'high'
    ) {
      errors.push({
        code: 'RISK_PROBABILITY_MISMATCH',
        message: 'Very likely probability should have high or critical risk level',
        field: 'risk_level',
        category: ValidationErrorCategory.BUSINESS_RULE,
        severity: ValidationErrorSeverity.WARNING,
        suggestion: 'Consider increasing the risk level',
      });
    }

    if (!hasPropertySimple(record, 'mitigation') && hasPropertySimple(record, 'risk_level') && record.risk_level === 'critical') {
      errors.push({
        code: 'CRITICAL_RISK_NO_MITIGATION',
        message: 'Critical risks should have mitigation strategies',
        field: 'mitigation',
        category: ValidationErrorCategory.BUSINESS_RULE,
        severity: ValidationErrorSeverity.WARNING,
        suggestion: 'Add mitigation strategy for critical risks',
      });
    }

    return errors;
  }

  private static validateAssumption(data: JSONValue): ValidationErrorDetail[] {
    const errors: ValidationErrorDetail[] = [];

    if (data.validation_status === 'invalidated' && !data.impact_if_invalid) {
      errors.push({
        code: 'INVALIDATED_ASSUMPTION_NO_IMPACT',
        message: 'Invalidated assumptions should have documented impact',
        field: 'impact_if_invalid',
        category: ValidationErrorCategory.BUSINESS_RULE,
        severity: ValidationErrorSeverity.WARNING,
        suggestion: 'Document the impact of this invalidated assumption',
      });
    }

    if (data.expiry_date && new Date(data.expiry_date) < new Date()) {
      errors.push({
        code: 'ASSUMPTION_EXPIRED',
        message: 'Assumption has expired',
        field: 'expiry_date',
        category: ValidationErrorCategory.BUSINESS_RULE,
        severity: ValidationErrorSeverity.WARNING,
        suggestion: 'Review and update this assumption',
      });
    }

    return errors;
  }

  static validate(kind: string, data: JSONValue): ValidationErrorDetail[] {
    const validator = this.rules.get(kind);
    return validator ? validator(data) : [];
  }
}

// ============================================================================
// Main Validator Class
// ============================================================================

export class UnifiedKnowledgeTypeValidator {
  private static instance: UnifiedKnowledgeTypeValidator;
  private readonly version = '2.0.0';
  private readonly schemaVersion = '2.0.0';

  static getInstance(): UnifiedKnowledgeTypeValidator {
    if (!UnifiedKnowledgeTypeValidator.instance) {
      UnifiedKnowledgeTypeValidator.instance = new UnifiedKnowledgeTypeValidator();
    }
    return UnifiedKnowledgeTypeValidator.instance;
  }

  /**
   * Validate a single knowledge item
   */
  async validateKnowledgeItem(
    item: unknown,
    options: ValidationOptions = {}
  ): Promise<ValidationResult> {
    const startTime = Date.now();
    const {
      mode = ValidationMode.STRICT,
      includeWarnings = true,
      maxErrors = 50,
      enablePerformanceChecks = true,
    } = options;

    const result: ValidationResult = {
      valid: true,
      errors: [],
      warnings: [],
      metadata: {
        validationTimeMs: 0,
        validatorVersion: this.version,
        schemaVersion: this.schemaVersion,
        validationMode: mode,
      },
    };

    try {
      // Skip schema validation for business rules only mode
      if (mode !== ValidationMode.BUSINESS_RULES_ONLY) {
        const schemaResult = KnowledgeItemSchema.safeParse(item);

        if (!schemaResult.success) {
          result.valid = false;
          result.errors.push(...this.convertZodErrors(schemaResult.error, maxErrors));

          if (mode === ValidationMode.STRICT) {
            return result;
          }
        } else {
          item = schemaResult.data;
        }
      }

      // Skip business rules for schema only mode
      if (mode !== ValidationMode.SCHEMA_ONLY && typeof item === 'object' && item !== null) {
        const businessRuleErrors = BusinessRuleValidator.validate(
          (item as unknown).kind,
          (item as unknown).data
        );

        if (businessRuleErrors.length > 0) {
          const actualErrors = businessRuleErrors.filter(
            (e) => e.severity === ValidationErrorSeverity.ERROR
          );
          const warnings = businessRuleErrors.filter(
            (e) => e.severity !== ValidationErrorSeverity.ERROR
          );

          if (actualErrors.length > 0) {
            result.valid = false;
            result.errors.push(...actualErrors);
          }

          if (includeWarnings) {
            result.warnings.push(...warnings);
          }
        }
      }

      // Performance checks
      if (enablePerformanceChecks && typeof item === 'object' && item !== null) {
        const performanceIssues = this.validatePerformanceConstraints(item);
        if (includeWarnings) {
          result.warnings.push(...performanceIssues);
        }
      }

      result.data = item;
    } catch (error) {
      result.valid = false;
      result.errors.push({
        code: 'VALIDATION_SYSTEM_ERROR',
        message: `Validation system error: ${error instanceof Error ? error.message : 'Unknown error'}`,
        category: ValidationErrorCategory.SYSTEM,
        severity: ValidationErrorSeverity.ERROR,
      });
    }

    result.metadata.validationTimeMs = Date.now() - startTime;
    return result;
  }

  /**
   * Validate memory store request
   */
  async validateMemoryStoreRequest(
    request: unknown,
    options: ValidationOptions = {}
  ): Promise<ValidationResult> {
    const startTime = Date.now();
    const { includeWarnings = true, maxErrors = 50 } = options;

    const result: ValidationResult = {
      valid: true,
      errors: [],
      warnings: [],
      metadata: {
        validationTimeMs: 0,
        validatorVersion: this.version,
        schemaVersion: this.schemaVersion,
        validationMode: options.mode || ValidationMode.STRICT,
      },
    };

    try {
      const schemaResult = MemoryStoreRequestSchema.safeParse(request);

      if (!schemaResult.success) {
        result.valid = false;
        result.errors.push(...this.convertZodErrors(schemaResult.error, maxErrors));
        return result;
      }

      const validatedRequest = schemaResult.data;

      // Validate each item
      for (let i = 0; i < validatedRequest.items.length; i++) {
        const itemResult = await this.validateKnowledgeItem(validatedRequest.items[i], options);

        if (!itemResult.valid) {
          result.valid = false;
          result.errors.push(
            ...itemResult.errors.map((error) => ({
              ...error,
              field: error.field ? `items[${i}].${error.field}` : `items[${i}]`,
            }))
          );
        }

        if (includeWarnings) {
          result.warnings.push(
            ...itemResult.warnings.map((warning) => ({
              ...warning,
              field: warning.field ? `items[${i}].${warning.field}` : `items[${i}]`,
            }))
          );
        }
      }

      // Check for duplicate IDs
      const itemsWithIds = validatedRequest.items.filter((item) => item.id);
      const duplicateIds = itemsWithIds
        .map((item) => item.id)
        .filter((id, index, ids) => ids.indexOf(id) !== index);

      if (duplicateIds.length > 0) {
        result.valid = false;
        result.errors.push({
          code: 'DUPLICATE_ITEM_IDS',
          message: `Duplicate item IDs found: ${duplicateIds.join(', ')}`,
          category: ValidationErrorCategory.BUSINESS_RULE,
          severity: ValidationErrorSeverity.ERROR,
        });
      }

      result.data = validatedRequest;
    } catch (error) {
      result.valid = false;
      result.errors.push({
        code: 'VALIDATION_SYSTEM_ERROR',
        message: `Validation system error: ${error instanceof Error ? error.message : 'Unknown error'}`,
        category: ValidationErrorCategory.SYSTEM,
        severity: ValidationErrorSeverity.ERROR,
      });
    }

    result.metadata.validationTimeMs = Date.now() - startTime;
    return result;
  }

  /**
   * Validate memory find request
   */
  async validateMemoryFindRequest(
    request: unknown,
    options: ValidationOptions = {}
  ): Promise<ValidationResult> {
    const startTime = Date.now();

    const result: ValidationResult = {
      valid: true,
      errors: [],
      warnings: [],
      metadata: {
        validationTimeMs: 0,
        validatorVersion: this.version,
        schemaVersion: this.schemaVersion,
        validationMode: options.mode || ValidationMode.STRICT,
      },
    };

    try {
      const schemaResult = MemoryFindRequestSchema.safeParse(request);

      if (!schemaResult.success) {
        result.valid = false;
        result.errors.push(...this.convertZodErrors(schemaResult.error));
        return result;
      }

      const validatedRequest = schemaResult.data;

      // Additional business rule validation
      if (validatedRequest.limit > 100) {
        result.warnings.push({
          code: 'LARGE_RESULT_SET',
          message: 'Large result set requested (>100 items). Consider using pagination.',
          field: 'limit',
          category: ValidationErrorCategory.PERFORMANCE,
          severity: ValidationErrorSeverity.WARNING,
          suggestion: 'Use pagination for better performance',
        });
      }

      if (validatedRequest.query.length > 1000) {
        result.warnings.push({
          code: 'LONG_QUERY',
          message: 'Query is very long (>1000 characters). Consider simplifying.',
          field: 'query',
          category: ValidationErrorCategory.PERFORMANCE,
          severity: ValidationErrorSeverity.WARNING,
          suggestion: 'Shorten the query for better performance',
        });
      }

      result.data = validatedRequest;
    } catch (error) {
      result.valid = false;
      result.errors.push({
        code: 'VALIDATION_SYSTEM_ERROR',
        message: `Validation system error: ${error instanceof Error ? error.message : 'Unknown error'}`,
        category: ValidationErrorCategory.SYSTEM,
        severity: ValidationErrorSeverity.ERROR,
      });
    }

    result.metadata.validationTimeMs = Date.now() - startTime;
    return result;
  }

  /**
   * Validate delete request
   */
  async validateDeleteRequest(
    request: unknown,
    options: ValidationOptions = {}
  ): Promise<ValidationResult> {
    const startTime = Date.now();

    const result: ValidationResult = {
      valid: true,
      errors: [],
      warnings: [],
      metadata: {
        validationTimeMs: 0,
        validatorVersion: this.version,
        schemaVersion: this.schemaVersion,
        validationMode: options.mode || ValidationMode.STRICT,
      },
    };

    try {
      const schemaResult = DeleteRequestSchema.safeParse(request);

      if (!schemaResult.success) {
        result.valid = false;
        result.errors.push(...this.convertZodErrors(schemaResult.error));
        return result;
      }

      const validatedRequest = schemaResult.data;

      if (validatedRequest.cascade_relations) {
        result.warnings.push({
          code: 'CASCADE_DELETE',
          message: 'Cascade delete will remove all related entities',
          field: 'cascade_relations',
          category: ValidationErrorCategory.BUSINESS_RULE,
          severity: ValidationErrorSeverity.WARNING,
          suggestion: 'Ensure you want to delete all related entities',
        });
      }

      result.data = validatedRequest;
    } catch (error) {
      result.valid = false;
      result.errors.push({
        code: 'VALIDATION_SYSTEM_ERROR',
        message: `Validation system error: ${error instanceof Error ? error.message : 'Unknown error'}`,
        category: ValidationErrorCategory.SYSTEM,
        severity: ValidationErrorSeverity.ERROR,
      });
    }

    result.metadata.validationTimeMs = Date.now() - startTime;
    return result;
  }

  /**
   * Convert Zod errors to ValidationErrorDetail format
   */
  private convertZodErrors(zodError: ZodError, maxErrors: number = 50): ValidationErrorDetail[] {
    return zodError.errors.slice(0, maxErrors).map((error) => ({
      code: error.code || 'SCHEMA_VALIDATION_ERROR',
      message: error.message,
      field: error.path.join('.'),
      category: ValidationErrorCategory.SCHEMA,
      severity: ValidationErrorSeverity.ERROR,
      context: {
        code: error.code,
        path: error.path,
        message: error.message,
      },
    }));
  }

  /**
   * Validate performance constraints
   */
  private validatePerformanceConstraints(item: JSONValue): ValidationErrorDetail[] {
    const warnings: ValidationErrorDetail[] = [];

    try {
      const jsonString = JSON.stringify(item);
      const size = Buffer.byteLength(jsonString, 'utf8');

      if (size > 1024 * 1024) {
        // 1MB
        warnings.push({
          code: 'LARGE_ITEM_SIZE',
          message: `Knowledge item is very large (${(size / 1024 / 1024).toFixed(2)}MB)`,
          category: ValidationErrorCategory.PERFORMANCE,
          severity: ValidationErrorSeverity.WARNING,
          suggestion: 'Consider reducing item size for better performance',
          context: { sizeBytes: size },
        });
      }

      // Check depth
      const depth = this.getObjectDepth(item);
      if (depth > 10) {
        warnings.push({
          code: 'DEEP_NESTING',
          message: `Knowledge item has deep nesting (${depth} levels)`,
          category: ValidationErrorCategory.PERFORMANCE,
          severity: ValidationErrorSeverity.WARNING,
          suggestion: 'Consider flattening the structure',
          context: { depth },
        });
      }
    } catch (error) {
      // Ignore serialization errors
    }

    return warnings;
  }

  /**
   * Calculate object depth
   */
  private getObjectDepth(obj: JSONValue, currentDepth = 0): number {
    if (currentDepth > 20) return currentDepth; // Prevent infinite recursion

    if (Array.isArray(obj)) {
      return Math.max(...obj.map((item) => this.getObjectDepth(item, currentDepth + 1)));
    }

    if (obj && typeof obj === 'object') {
      const depths = Object.values(obj).map((value) =>
        this.getObjectDepth(value, currentDepth + 1)
      );
      return depths.length > 0 ? Math.max(...depths) : currentDepth;
    }

    return currentDepth;
  }
}

// ============================================================================
// Convenience Functions
// ============================================================================

export const validator = UnifiedKnowledgeTypeValidator.getInstance();

export async function validateKnowledgeItem(
  item: unknown,
  options?: ValidationOptions
): Promise<ValidationResult> {
  return validator.validateKnowledgeItem(item, options);
}

export async function validateMemoryStoreRequest(
  request: unknown,
  options?: ValidationOptions
): Promise<ValidationResult> {
  return validator.validateMemoryStoreRequest(request, options);
}

export async function validateMemoryFindRequest(
  request: unknown,
  options?: ValidationOptions
): Promise<ValidationResult> {
  return validator.validateMemoryFindRequest(request, options);
}

export async function validateDeleteRequest(
  request: unknown,
  options?: ValidationOptions
): Promise<ValidationResult> {
  return validator.validateDeleteRequest(request, options);
}

// ============================================================================
// Type Exports
// ============================================================================

export type {
  ValidationResult as IValidationResult,
  KnowledgeItem,
  MemoryFindRequest,
  MemoryStoreRequest,
  StoreError,
};

// ValidationMode already exported above
