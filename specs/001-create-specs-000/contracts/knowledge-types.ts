/**
 * Cortex Memory MCP - Knowledge Type Schemas
 *
 * Zod runtime validation schemas for all 9 knowledge types.
 * Uses discriminated union pattern for type-safe parsing.
 *
 * Constitutional Requirements:
 * - Type Safety (Principle VII): Compile-time + runtime validation
 * - Minimal API (Principle I): 9 core types, extensible via tags
 * - Immutability (Principle IV): ADR content immutable, approved specs write-locked
 *
 * @version 1.0.0
 */

import { z } from 'zod';

// ============================================================================
// Shared Schemas
// ============================================================================

export const ScopeSchema = z.object({
  org: z.string().optional(),
  project: z.string().min(1, 'project is required'),
  service: z.string().optional(),
  branch: z.string().min(1, 'branch is required'),
  sprint: z.string().optional(),
  tenant: z.string().optional(),
}).strict();

export const SourceSchema = z.object({
  actor: z.string().optional(),
  tool: z.string().optional(),
  timestamp: z.string().datetime().optional(),
}).strict();

export const TTLPolicySchema = z.enum(['default', 'short', 'long', 'permanent']);

// ============================================================================
// Knowledge Type: section
// ============================================================================

export const SectionDataSchema = z.object({
  title: z.string().min(1, 'title is required'),
  body_md: z.string().optional(),
  body_text: z.string().optional(),
  heading: z.string().optional(),
  document_id: z.string().uuid().optional(),
  citation_count: z.number().int().nonnegative().optional(),
}).strict().refine(
  data => data.body_md || data.body_text,
  { message: 'Either body_md or body_text must be provided' }
);

export const SectionSchema = z.object({
  kind: z.literal('section'),
  scope: ScopeSchema,
  data: SectionDataSchema,
  tags: z.record(z.unknown()).optional(),
  source: SourceSchema.optional(),
  idempotency_key: z.string().max(256).optional(),
  ttl_policy: TTLPolicySchema.optional(),
}).strict();

// ============================================================================
// Knowledge Type: runbook
// ============================================================================

export const RunbookDataSchema = z.object({
  service: z.string().min(1, 'service is required'),
  steps: z.array(z.object({
    step_number: z.number().int().positive(),
    description: z.string().min(1),
    command: z.string().optional(),
    expected_outcome: z.string().optional(),
  })).min(1, 'At least one step is required'),
  title: z.string().min(1, 'title is required'),
  description: z.string().optional(),
  triggers: z.array(z.string()).optional(),
  last_verified_at: z.string().datetime().optional(),
}).strict();

export const RunbookSchema = z.object({
  kind: z.literal('runbook'),
  scope: ScopeSchema,
  data: RunbookDataSchema,
  tags: z.record(z.unknown()).optional(),
  source: SourceSchema.optional(),
  idempotency_key: z.string().max(256).optional(),
  ttl_policy: TTLPolicySchema.optional(),
}).strict();

// ============================================================================
// Knowledge Type: change
// ============================================================================

export const ChangeDataSchema = z.object({
  change_type: z.enum([
    'feature_add',
    'feature_modify',
    'feature_remove',
    'bugfix',
    'refactor',
    'config_change',
    'dependency_update',
  ]),
  subject_ref: z.string().min(1, 'subject_ref is required (e.g., commit SHA, PR number)'),
  summary: z.string().min(1, 'summary is required'),
  details: z.string().optional(),
  affected_files: z.array(z.string()).optional(),
  author: z.string().optional(),
  commit_sha: z.string().optional(),
}).strict();

export const ChangeSchema = z.object({
  kind: z.literal('change'),
  scope: ScopeSchema,
  data: ChangeDataSchema,
  tags: z.record(z.unknown()).optional(),
  source: SourceSchema.optional(),
  idempotency_key: z.string().max(256).optional(),
  ttl_policy: TTLPolicySchema.optional(),
}).strict();

// ============================================================================
// Knowledge Type: issue
// ============================================================================

export const IssueDataSchema = z.object({
  tracker: z.string().min(1, 'tracker is required (e.g., github, jira, linear)'),
  external_id: z.string().min(1, 'external_id is required (e.g., GH-123, PROJ-456)'),
  title: z.string().min(1, 'title is required'),
  status: z.enum(['open', 'in_progress', 'resolved', 'closed', 'wont_fix']),
  description: z.string().optional(),
  assignee: z.string().optional(),
  labels: z.array(z.string()).optional(),
  url: z.string().url().optional(),
}).strict();

export const IssueSchema = z.object({
  kind: z.literal('issue'),
  scope: ScopeSchema,
  data: IssueDataSchema,
  tags: z.record(z.unknown()).optional(),
  source: SourceSchema.optional(),
  idempotency_key: z.string().max(256).optional(),
  ttl_policy: TTLPolicySchema.optional(),
}).strict();

// ============================================================================
// Knowledge Type: decision (ADR)
// ============================================================================

export const DecisionDataSchema = z.object({
  component: z.string().min(1, 'component is required'),
  status: z.enum(['proposed', 'accepted', 'rejected', 'deprecated', 'superseded']),
  title: z.string().min(1, 'title is required'),
  rationale: z.string().min(1, 'rationale is required'),
  alternatives_considered: z.array(z.string()).optional(),
  consequences: z.string().optional(),
  supersedes: z.string().uuid().optional(),
}).strict();

export const DecisionSchema = z.object({
  kind: z.literal('decision'),
  scope: ScopeSchema,
  data: DecisionDataSchema,
  tags: z.record(z.unknown()).optional(),
  source: SourceSchema.optional(),
  idempotency_key: z.string().max(256).optional(),
  ttl_policy: TTLPolicySchema.optional(),
}).strict();

// ============================================================================
// Knowledge Type: todo
// ============================================================================

export const TodoDataSchema = z.object({
  scope: z.string().min(1, 'scope is required (e.g., task, epic, story)'),
  todo_type: z.enum(['task', 'bug', 'epic', 'story', 'spike']),
  text: z.string().min(1, 'text is required'),
  status: z.enum(['open', 'in_progress', 'done', 'cancelled', 'archived']),
  priority: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  assignee: z.string().optional(),
  due_date: z.string().datetime().optional(),
  closed_at: z.string().datetime().optional(),
}).strict();

export const TodoSchema = z.object({
  kind: z.literal('todo'),
  scope: ScopeSchema,
  data: TodoDataSchema,
  tags: z.record(z.unknown()).optional(),
  source: SourceSchema.optional(),
  idempotency_key: z.string().max(256).optional(),
  ttl_policy: TTLPolicySchema.optional(),
}).strict();

// ============================================================================
// Knowledge Type: release_note
// ============================================================================

export const ReleaseNoteDataSchema = z.object({
  version: z.string().min(1, 'version is required (e.g., 1.2.3, v2024.10.09)'),
  release_date: z.string().datetime(),
  summary: z.string().min(1, 'summary is required'),
  breaking_changes: z.array(z.string()).optional(),
  new_features: z.array(z.string()).optional(),
  bug_fixes: z.array(z.string()).optional(),
  deprecations: z.array(z.string()).optional(),
}).strict();

export const ReleaseNoteSchema = z.object({
  kind: z.literal('release_note'),
  scope: ScopeSchema,
  data: ReleaseNoteDataSchema,
  tags: z.record(z.unknown()).optional(),
  source: SourceSchema.optional(),
  idempotency_key: z.string().max(256).optional(),
  ttl_policy: TTLPolicySchema.optional(),
}).strict();

// ============================================================================
// Knowledge Type: ddl
// ============================================================================

export const DDLDataSchema = z.object({
  migration_id: z.string().min(1, 'migration_id is required (e.g., 001_initial_schema)'),
  ddl_text: z.string().min(1, 'ddl_text is required (SQL DDL statements)'),
  checksum: z.string().min(1, 'checksum is required (SHA-256 hash for integrity)'),
  applied_at: z.string().datetime().optional(),
  description: z.string().optional(),
}).strict();

export const DDLSchema = z.object({
  kind: z.literal('ddl'),
  scope: ScopeSchema,
  data: DDLDataSchema,
  tags: z.record(z.unknown()).optional(),
  source: SourceSchema.optional(),
  idempotency_key: z.string().max(256).optional(),
  ttl_policy: TTLPolicySchema.optional(),
}).strict();

// ============================================================================
// Knowledge Type: pr_context
// ============================================================================

export const PRContextDataSchema = z.object({
  pr_number: z.number().int().positive(),
  title: z.string().min(1, 'title is required'),
  description: z.string().optional(),
  author: z.string().min(1, 'author is required'),
  status: z.enum(['open', 'merged', 'closed', 'draft']),
  base_branch: z.string().min(1, 'base_branch is required'),
  head_branch: z.string().min(1, 'head_branch is required'),
  merged_at: z.string().datetime().optional(),
  expires_at: z.string().datetime().optional(), // TTL: 30d post-merge
}).strict();

export const PRContextSchema = z.object({
  kind: z.literal('pr_context'),
  scope: ScopeSchema,
  data: PRContextDataSchema,
  tags: z.record(z.unknown()).optional(),
  source: SourceSchema.optional(),
  idempotency_key: z.string().max(256).optional(),
  ttl_policy: TTLPolicySchema.optional(),
}).strict();

// ============================================================================
// Discriminated Union
// ============================================================================

export const KnowledgeItemSchema = z.discriminatedUnion('kind', [
  SectionSchema,
  RunbookSchema,
  ChangeSchema,
  IssueSchema,
  DecisionSchema,
  TodoSchema,
  ReleaseNoteSchema,
  DDLSchema,
  PRContextSchema,
]);

export type KnowledgeItem = z.infer<typeof KnowledgeItemSchema>;
export type SectionItem = z.infer<typeof SectionSchema>;
export type RunbookItem = z.infer<typeof RunbookSchema>;
export type ChangeItem = z.infer<typeof ChangeSchema>;
export type IssueItem = z.infer<typeof IssueSchema>;
export type DecisionItem = z.infer<typeof DecisionSchema>;
export type TodoItem = z.infer<typeof TodoSchema>;
export type ReleaseNoteItem = z.infer<typeof ReleaseNoteSchema>;
export type DDLItem = z.infer<typeof DDLSchema>;
export type PRContextItem = z.infer<typeof PRContextSchema>;

// ============================================================================
// Validation Helpers
// ============================================================================

/**
 * Validate and parse a knowledge item with detailed error reporting
 *
 * @param input - Raw input object
 * @returns Parsed knowledge item or throws ZodError with validation details
 *
 * @example
 * try {
 *   const item = validateKnowledgeItem(rawInput);
 *   // item is now type-safe KnowledgeItem
 * } catch (err) {
 *   if (err instanceof z.ZodError) {
 *     console.error(err.errors); // Detailed validation errors
 *   }
 * }
 */
export function validateKnowledgeItem(input: unknown): KnowledgeItem {
  return KnowledgeItemSchema.parse(input);
}

/**
 * Safe validation with error details
 *
 * @param input - Raw input object
 * @returns { success: true, data } or { success: false, error }
 */
export function safeValidateKnowledgeItem(input: unknown) {
  return KnowledgeItemSchema.safeParse(input);
}

/**
 * Immutability enforcement check for ADR (decision kind)
 *
 * Constitutional Requirement (Principle IV):
 * Once an ADR status is 'accepted', its content (rationale, title, component) is IMMUTABLE.
 * Only metadata updates (tags, supersedes) are permitted.
 *
 * @param existing - Existing ADR from database
 * @param incoming - New update attempt
 * @returns true if immutability violated, false if update is allowed
 */
export function violatesADRImmutability(
  existing: DecisionItem,
  incoming: DecisionItem
): boolean {
  if (existing.data.status !== 'accepted') {
    return false; // Not yet immutable
  }

  // Check if content fields changed
  const contentFields: (keyof DecisionDataSchema['_type'])[] = [
    'title',
    'rationale',
    'component',
    'alternatives_considered',
    'consequences',
  ];

  return contentFields.some(
    field => existing.data[field] !== incoming.data[field]
  );
}

/**
 * Write-lock check for approved specifications (section kind with approved=true tag)
 *
 * Constitutional Requirement (Principle IV):
 * Once a spec is tagged as approved, the body_md/body_text is write-locked.
 * Only metadata (tags, citation_count) may be updated.
 *
 * @param existing - Existing section from database
 * @param incoming - New update attempt
 * @returns true if write-lock violated, false if update is allowed
 */
export function violatesSpecWriteLock(
  existing: SectionItem,
  incoming: SectionItem
): boolean {
  const isApproved = existing.tags?.approved === true;
  if (!isApproved) {
    return false; // Not write-locked
  }

  // Check if content changed
  return (
    existing.data.body_md !== incoming.data.body_md ||
    existing.data.body_text !== incoming.data.body_text ||
    existing.data.title !== incoming.data.title
  );
}
