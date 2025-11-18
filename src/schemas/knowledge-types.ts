// LAST ABSOLUTE FINAL EMERGENCY ROLLBACK: Complete the systematic rollback

/**
 * Cortex Memory MCP - Knowledge Type Schemas
 *
 * Zod runtime validation schemas for all 16 knowledge types.
 * Uses discriminated union pattern for type-safe parsing.
 *
 * Constitutional Requirements:
 * - Type Safety (Principle VII): Compile-time + runtime validation
 * - Minimal API (Principle I): 16 core types, extensible via tags
 * - Immutability (Principle IV): ADR content immutable, approved specs write-locked
 *
 * @version 2.1.0 - Updated for qdrant 18 schema alignment with 8-LOG SYSTEM
 */

import { z } from 'zod';

// ============================================================================
// Shared Schemas
// ============================================================================

export const ScopeSchema = z
  .object({
    org: z.string().optional(),
    project: z.string().min(1, 'project is required'),
    service: z.string().optional(),
    branch: z.string().min(1, 'branch is required'),
    sprint: z.string().optional(),
    tenant: z.string().optional(),
    environment: z.string().optional(),
  })
  .strict();

export const SourceSchema = z
  .object({
    actor: z.string().optional(),
    tool: z.string().optional(),
    timestamp: z.string().datetime().optional(),
  })
  .strict();

export const TTLPolicySchema = z.enum(['default', 'short', 'long', 'permanent']);

// ============================================================================
// Knowledge Type: section
// ============================================================================

export const SectionDataSchema = z
  .object({
    id: z.string().uuid().optional(), // For update operations
    title: z.string().min(1, 'title is required').max(500, 'title must be 500 characters or less'),
    body_md: z.string().optional(),
    body_text: z.string().optional(),
    heading: z
      .string()
      .min(1, 'heading is required')
      .max(300, 'heading must be 300 characters or less'),
    document_id: z.string().uuid().optional(),
    citation_count: z.number().int().nonnegative().optional(),
  })
  .strict()
  .refine((data) => data.body_md ?? data.body_text, {
    message: 'Either body_md or body_text must be provided',
  });

export const SectionSchema = z
  .object({
    kind: z.literal('section'),
    scope: ScopeSchema,
    data: SectionDataSchema,
    tags: z.record(z.unknown()).optional(),
    source: SourceSchema.optional(),
    idempotency_key: z.string().max(256).optional(),
    ttl_policy: TTLPolicySchema.optional(),
  })
  .strict();

// ============================================================================
// Knowledge Type: runbook
// ============================================================================

export const RunbookDataSchema = z
  .object({
    service: z
      .string()
      .min(1, 'service is required')
      .max(200, 'service must be 200 characters or less'),
    steps: z
      .array(
        z.object({
          step_number: z.number().int().positive(),
          description: z.string().min(1),
          command: z.string().optional(),
          expected_outcome: z.string().optional(),
        })
      )
      .min(1, 'At least one step is required'),
    title: z.string().min(1, 'title is required').max(500, 'title must be 500 characters or less'),
    description: z.string().optional(),
    triggers: z.array(z.string()).optional(),
    last_verified_at: z.string().datetime().optional(),
  })
  .strict();

export const RunbookSchema = z
  .object({
    kind: z.literal('runbook'),
    scope: ScopeSchema,
    data: RunbookDataSchema,
    tags: z.record(z.unknown()).optional(),
    source: SourceSchema.optional(),
    idempotency_key: z.string().max(256).optional(),
    ttl_policy: TTLPolicySchema.optional(),
  })
  .strict();

// ============================================================================
// Knowledge Type: change
// ============================================================================

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
      .min(1, 'subject_ref is required (e.g., commit SHA, PR number)')
      .max(200, 'subject_ref must be 200 characters or less'),
    summary: z.string().min(1, 'summary is required'),
    details: z.string().optional(),
    affected_files: z.array(z.string()).optional(),
    author: z.string().optional(),
    commit_sha: z.string().optional(),
  })
  .strict();

export const ChangeSchema = z
  .object({
    kind: z.literal('change'),
    scope: ScopeSchema,
    data: ChangeDataSchema,
    tags: z.record(z.unknown()).optional(),
    source: SourceSchema.optional(),
    idempotency_key: z.string().max(256).optional(),
    ttl_policy: TTLPolicySchema.optional(),
  })
  .strict();

// ============================================================================
// Knowledge Type: issue
// ============================================================================

export const IssueDataSchema = z
  .object({
    tracker: z
      .string()
      .min(1, 'tracker is required (e.g., github, jira, linear)')
      .max(100, 'tracker must be 100 characters or less'),
    external_id: z
      .string()
      .min(1, 'external_id is required (e.g., GH-123, PROJ-456)')
      .max(100, 'external_id must be 100 characters or less'),
    title: z.string().min(1, 'title is required').max(500, 'title must be 500 characters or less'),
    status: z.enum(['open', 'in_progress', 'resolved', 'closed', 'wont_fix', 'duplicate']),
    description: z.string().max(5000, 'description must be 5000 characters or less').optional(),
    severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
    issue_type: z.enum(['bug', 'feature_request', 'improvement', 'task', 'question']).optional(),
    assignee: z.string().optional(),
    reporter: z.string().optional(),
    labels: z.array(z.string()).optional(),
    url: z.string().url().optional(),
    affected_components: z.array(z.string()).optional(),
    created_at: z.string().datetime().optional(),
    updated_at: z.string().datetime().optional(),
    resolution: z.string().optional(),
  })
  .strict();

export const IssueSchema = z
  .object({
    kind: z.literal('issue'),
    scope: ScopeSchema,
    data: IssueDataSchema,
    tags: z.record(z.unknown()).optional(),
    source: SourceSchema.optional(),
    idempotency_key: z.string().max(256).optional(),
    ttl_policy: TTLPolicySchema.optional(),
  })
  .strict();

// ============================================================================
// Knowledge Type: decision (ADR)
// ============================================================================

export const DecisionDataSchema = z
  .object({
    id: z.string().uuid().optional(), // For update operations
    component: z
      .string()
      .min(1, 'component is required')
      .max(200, 'component must be 200 characters or less'),
    status: z.enum(['proposed', 'accepted', 'rejected', 'deprecated', 'superseded']),
    title: z.string().min(1, 'title is required').max(500, 'title must be 500 characters or less'),
    rationale: z.string().min(1, 'rationale is required'),
    alternatives_considered: z.array(z.string()).optional(),
    consequences: z.string().optional(),
    supersedes: z.string().uuid().optional(),
  })
  .strict();

export const DecisionSchema = z
  .object({
    kind: z.literal('decision'),
    scope: ScopeSchema,
    data: DecisionDataSchema,
    tags: z.record(z.unknown()).optional(),
    source: SourceSchema.optional(),
    idempotency_key: z.string().max(256).optional(),
    ttl_policy: TTLPolicySchema.optional(),
  })
  .strict();

// ============================================================================
// Knowledge Type: todo
// ============================================================================

export const TodoDataSchema = z
  .object({
    // P5-T5.3: Made fields optional and aligned with business validator expectations
    scope: z.string().max(200, 'scope must be 200 characters or less').optional(),
    todo_type: z.enum(['task', 'bug', 'epic', 'story', 'spike']).optional(),
    title: z.string().max(1000, 'title must be 1000 characters or less').optional(), // Changed from 'text' to 'title' for business validation
    status: z.enum(['pending', 'in_progress', 'done', 'blocked', 'cancelled']).optional(), // Aligned with business validator
    priority: z.enum(['low', 'medium', 'high', 'critical']).optional(),
    assignee: z.string().optional(),
    due_date: z.string().datetime().optional(),
    closed_at: z.string().datetime().optional(),
    // P5-T5.3: Added fields used in business validation tests
    id: z.string().optional(),
    dependencies: z.array(z.string()).optional(),
  })
  .strict();

export const TodoSchema = z
  .object({
    kind: z.literal('todo'),
    scope: ScopeSchema,
    data: TodoDataSchema,
    tags: z.record(z.unknown()).optional(),
    source: SourceSchema.optional(),
    idempotency_key: z.string().max(256).optional(),
    ttl_policy: TTLPolicySchema.optional(),
  })
  .strict();

// ============================================================================
// Knowledge Type: release_note
// ============================================================================

export const ReleaseNoteDataSchema = z
  .object({
    version: z
      .string()
      .min(1, 'version is required (e.g., 1.2.3, v2024.10.09)')
      .max(100, 'version must be 100 characters or less'),
    release_date: z.string().datetime(),
    summary: z.string().min(1, 'summary is required'),
    breaking_changes: z.array(z.string()).optional(),
    new_features: z.array(z.string()).optional(),
    bug_fixes: z.array(z.string()).optional(),
    deprecations: z.array(z.string()).optional(),
  })
  .strict();

export const ReleaseNoteSchema = z
  .object({
    kind: z.literal('release_note'),
    scope: ScopeSchema,
    data: ReleaseNoteDataSchema,
    tags: z.record(z.unknown()).optional(),
    source: SourceSchema.optional(),
    idempotency_key: z.string().max(256).optional(),
    ttl_policy: TTLPolicySchema.optional(),
  })
  .strict();

// ============================================================================
// Knowledge Type: ddl
// ============================================================================

export const DDLDataSchema = z
  .object({
    // P5-T5.3: Made fields optional and aligned with business validator expectations
    migration_id: z.string().max(200, 'migration_id must be 200 characters or less').optional(),
    sql: z.string().optional(), // Changed from 'ddl_text' to 'sql' for business validation
    database: z.string().max(100, 'database name must be 100 characters or less').optional(),
    checksum: z.string().max(64, 'checksum must be 64 characters (SHA-256 hash)').optional(),
    applied_at: z.string().datetime().optional(),
    description: z.string().optional(),
    // P5-T5.3: Added fields used in business validation tests
    duplicate_migration_id_detected: z.boolean().optional(),
    existing_ddl_id: z.string().optional(),
  })
  .strict();

export const DDLSchema = z
  .object({
    kind: z.literal('ddl'),
    scope: ScopeSchema,
    data: DDLDataSchema,
    tags: z.record(z.unknown()).optional(),
    source: SourceSchema.optional(),
    idempotency_key: z.string().max(256).optional(),
    ttl_policy: TTLPolicySchema.optional(),
  })
  .strict();

// ============================================================================
// Knowledge Type: pr_context
// ============================================================================

export const PRContextDataSchema = z
  .object({
    pr_number: z.number().int().positive(),
    title: z.string().min(1, 'title is required').max(500, 'title must be 500 characters or less'),
    description: z.string().optional(),
    author: z
      .string()
      .min(1, 'author is required')
      .max(200, 'author must be 200 characters or less'),
    status: z.enum(['open', 'merged', 'closed', 'draft']),
    base_branch: z
      .string()
      .min(1, 'base_branch is required')
      .max(200, 'base_branch must be 200 characters or less'),
    head_branch: z
      .string()
      .min(1, 'head_branch is required')
      .max(200, 'head_branch must be 200 characters or less'),
    merged_at: z.string().datetime().optional(),
    expires_at: z.string().datetime().optional(), // TTL: 30d post-merge
  })
  .strict();

export const PRContextSchema = z
  .object({
    kind: z.literal('pr_context'),
    scope: ScopeSchema,
    data: PRContextDataSchema,
    tags: z.record(z.unknown()).optional(),
    source: SourceSchema.optional(),
    idempotency_key: z.string().max(256).optional(),
    ttl_policy: TTLPolicySchema.optional(),
  })
  .strict();

// ============================================================================
// Knowledge Type: entity (GRAPH EXTENSION - Flexible entity storage)
// ============================================================================

export const EntityDataSchema = z
  .object({
    entity_type: z
      .string()
      .min(1, 'entity_type is required (e.g., user, organization, goal, preference)')
      .max(100, 'entity_type must be 100 characters or less'),
    name: z
      .string()
      .min(1, 'name is required (unique identifier within entity_type)')
      .max(500, 'name must be 500 characters or less'),
    data: z.record(z.unknown()), // Flexible schema - no validation constraints
  })
  .strict();

export const EntitySchema = z
  .object({
    kind: z.literal('entity'),
    scope: ScopeSchema,
    data: EntityDataSchema,
    tags: z.record(z.unknown()).optional(),
    source: SourceSchema.optional(),
    idempotency_key: z.string().max(256).optional(),
    ttl_policy: TTLPolicySchema.optional(),
  })
  .strict();

// ============================================================================
// Knowledge Type: relation (GRAPH EXTENSION - Entity relationships)
// ============================================================================

export const RelationDataSchema = z
  .object({
    from_entity_type: z
      .string()
      .min(1, 'from_entity_type is required (e.g., decision, section, entity)')
      .max(100, 'from_entity_type must be 100 characters or less'),
    from_entity_id: z.string().uuid('from_entity_id must be a valid UUID'),
    to_entity_type: z
      .string()
      .min(1, 'to_entity_type is required')
      .max(100, 'to_entity_type must be 100 characters or less'),
    to_entity_id: z.string().uuid('to_entity_id must be a valid UUID'),
    relation_type: z
      .string()
      .min(1, 'relation_type is required (e.g., resolves, supersedes, references, implements)')
      .max(100, 'relation_type must be 100 characters or less'),
    metadata: z.record(z.unknown()).optional(), // Optional: { weight: 1.0, confidence: 0.85, since: "2025-01-01" }
  })
  .strict();

export const RelationSchema = z
  .object({
    kind: z.literal('relation'),
    scope: ScopeSchema,
    data: RelationDataSchema,
    tags: z.record(z.unknown()).optional(),
    source: SourceSchema.optional(),
    idempotency_key: z.string().max(256).optional(),
    ttl_policy: TTLPolicySchema.optional(),
  })
  .strict();

// ============================================================================
// Knowledge Type: observation (GRAPH EXTENSION - Fine-grained facts)
// ============================================================================

export const ObservationDataSchema = z
  .object({
    entity_type: z
      .string()
      .min(1, 'entity_type is required (e.g., decision, section, entity)')
      .max(100, 'entity_type must be 100 characters or less'),
    entity_id: z.string().uuid('entity_id must be a valid UUID'),
    observation: z
      .string()
      .min(1, 'observation is required (e.g., "status: completed", "progress: 50%")'),
    observation_type: z.string().optional(), // Optional: "status", "progress", "note", "metric"
    metadata: z.record(z.unknown()).optional(), // Optional: { source: "user", confidence: 0.9 }
  })
  .strict();

export const ObservationSchema = z
  .object({
    kind: z.literal('observation'),
    scope: ScopeSchema,
    data: ObservationDataSchema,
    tags: z.record(z.unknown()).optional(),
    source: SourceSchema.optional(),
    idempotency_key: z.string().max(256).optional(),
    ttl_policy: TTLPolicySchema.optional(),
  })
  .strict();

// ============================================================================
// Knowledge Type: incident (8-LOG SYSTEM - Incident Management)
// ============================================================================

export const IncidentDataSchema = z
  .object({
    // P5-T5.3: Made title and severity optional to allow business rule validation
    title: z.string().max(500, 'title must be 500 characters or less').optional(),
    severity: z.enum(['critical', 'high', 'medium', 'low']).optional(),
    impact: z.string().optional(),
    timeline: z
      .array(
        z.object({
          timestamp: z.string().datetime(),
          event: z.string(),
          actor: z.string().optional(),
        })
      )
      .optional(),
    root_cause_analysis: z.string().optional(),
    resolution_status: z.enum(['open', 'investigating', 'resolved', 'closed']),
    affected_services: z.array(z.string()).optional(),
    business_impact: z.string().optional(),
    recovery_actions: z.array(z.string()).optional(),
    follow_up_required: z.boolean().optional(),
    incident_commander: z.string().optional(),
  })
  .strict();

export const IncidentSchema = z
  .object({
    kind: z.literal('incident'),
    scope: ScopeSchema,
    data: IncidentDataSchema,
    tags: z.record(z.unknown()).optional(),
    source: SourceSchema.optional(),
    idempotency_key: z.string().max(256).optional(),
    ttl_policy: TTLPolicySchema.optional(),
  })
  .strict();

// ============================================================================
// Knowledge Type: release (8-LOG SYSTEM - Release Management)
// ============================================================================

export const ReleaseDataSchema = z
  .object({
    version: z
      .string()
      .min(1, 'release version is required')
      .max(100, 'version must be 100 characters or less'),
    release_type: z.enum(['major', 'minor', 'patch', 'hotfix']),
    scope: z.string().min(1, 'release scope description is required'),
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
  })
  .strict();

export const ReleaseSchema = z
  .object({
    kind: z.literal('release'),
    scope: ScopeSchema,
    data: ReleaseDataSchema,
    tags: z.record(z.unknown()).optional(),
    source: SourceSchema.optional(),
    idempotency_key: z.string().max(256).optional(),
    ttl_policy: TTLPolicySchema.optional(),
  })
  .strict();

// ============================================================================
// Knowledge Type: risk (8-LOG SYSTEM - Risk Management)
// ============================================================================

export const RiskDataSchema = z
  .object({
    // P5-T5.3: Made title, category, risk_level, and impact_description optional to allow business rule validation
    title: z.string().max(500, 'title must be 500 characters or less').optional(),
    category: z.enum(['technical', 'business', 'operational', 'security', 'compliance']).optional(),
    risk_level: z.enum(['critical', 'high', 'medium', 'low']).optional(),
    probability: z
      .enum(['very_likely', 'likely', 'possible', 'unlikely', 'very_unlikely'])
      .optional(),
    impact_description: z.string().optional(),
    trigger_events: z.array(z.string()).optional(),
    mitigation_strategies: z.array(z.string()).optional(),
    owner: z.string().optional(),
    review_date: z.string().datetime().optional(),
    status: z.enum(['active', 'mitigated', 'accepted', 'closed']),
    related_decisions: z.array(z.string().uuid()).optional(),
    monitoring_indicators: z.array(z.string()).optional(),
    contingency_plans: z.string().optional(),
  })
  .strict();

export const RiskSchema = z
  .object({
    kind: z.literal('risk'),
    scope: ScopeSchema,
    data: RiskDataSchema,
    tags: z.record(z.unknown()).optional(),
    source: SourceSchema.optional(),
    idempotency_key: z.string().max(256).optional(),
    ttl_policy: TTLPolicySchema.optional(),
  })
  .strict();

// ============================================================================
// Knowledge Type: assumption (8-LOG SYSTEM - Assumption Management)
// ============================================================================

export const AssumptionDataSchema = z
  .object({
    title: z
      .string()
      .min(1, 'assumption title is required')
      .max(500, 'title must be 500 characters or less'),
    description: z.string().min(1, 'assumption description is required'),
    category: z.enum(['technical', 'business', 'user', 'market', 'resource']),
    validation_status: z.enum(['validated', 'assumed', 'invalidated', 'needs_validation']),
    impact_if_invalid: z.string().min(1, 'impact description is required'),
    validation_criteria: z.array(z.string()).optional(),
    validation_date: z.string().datetime().optional(),
    owner: z.string().optional(),
    related_assumptions: z.array(z.string().uuid()).optional(),
    dependencies: z.array(z.string()).optional(),
    monitoring_approach: z.string().optional(),
    review_frequency: z.enum(['daily', 'weekly', 'monthly', 'quarterly', 'as_needed']).optional(),
  })
  .strict();

export const AssumptionSchema = z
  .object({
    kind: z.literal('assumption'),
    scope: ScopeSchema,
    data: AssumptionDataSchema,
    tags: z.record(z.unknown()).optional(),
    source: SourceSchema.optional(),
    idempotency_key: z.string().max(256).optional(),
    ttl_policy: TTLPolicySchema.optional(),
  })
  .strict();

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
  EntitySchema, // 10th knowledge type - flexible entity storage
  RelationSchema, // 11th knowledge type - entity relationships
  ObservationSchema, // 12th knowledge type - fine-grained facts
  IncidentSchema, // 13th knowledge type - incident management (8-LOG SYSTEM)
  ReleaseSchema, // 14th knowledge type - release management (8-LOG SYSTEM)
  RiskSchema, // 15th knowledge type - risk management (8-LOG SYSTEM)
  AssumptionSchema, // 16th knowledge type - assumption management (8-LOG SYSTEM)
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
export type EntityItem = z.infer<typeof EntitySchema>;
export type RelationItem = z.infer<typeof RelationSchema>;
export type ObservationItem = z.infer<typeof ObservationSchema>;
export type IncidentItem = z.infer<typeof IncidentSchema>;
export type ReleaseItem = z.infer<typeof ReleaseSchema>;
export type RiskItem = z.infer<typeof RiskSchema>;
export type AssumptionItem = z.infer<typeof AssumptionSchema>;

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
export function violatesADRImmutability(existing: DecisionItem, incoming: DecisionItem): boolean {
  if (existing.data.status !== 'accepted') {
    return false; // Not yet immutable
  }

  // Check if content fields changed
  const contentFields = [
    'title',
    'rationale',
    'component',
    'alternatives_considered',
    'consequences',
  ] as const;

  return contentFields.some(
    (field) => (existing.data as unknown)[field] !== (incoming.data as unknown)[field]
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
export function violatesSpecWriteLock(existing: SectionItem, incoming: SectionItem): boolean {
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
