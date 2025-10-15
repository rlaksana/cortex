import {
  pgTable,
  uuid,
  text,
  jsonb,
  timestamp,
  bigserial,
  index,
  check,
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';

/**
 * T012: Drizzle schema definitions for all 11 tables
 *
 * Constitutional Requirements:
 * - Single SoT (Principle II): PostgreSQL 18+ exclusive source
 * - Type Safety (Principle VII): Generated TypeScript types from schema
 * - Immutability (Principle IV): Triggers enforce ADR/spec locks
 */

// Helper function for uuidv7() default (requires pgcrypto extension)
const uuidv7 = sql`gen_random_uuid()`;

// 1. document - Container for specifications and guides
export const document = pgTable(
  'document',
  {
    id: uuid('id').primaryKey().default(uuidv7),
    type: text('type').notNull(), // spec|doc|guide|other
    title: text('title').notNull(),
    tags: jsonb('tags')
      .notNull()
      .default(sql`'{}'::jsonb`),
    approved_at: timestamp('approved_at', { withTimezone: true }),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    typeCheck: check(
      'document_type_check',
      sql`${table.type} IN ('spec', 'doc', 'guide', 'other')`
    ),
  })
);

// 2. section - Documentation chunks with FTS
export const section = pgTable(
  'section',
  {
    id: uuid('id').primaryKey().default(uuidv7),
    document_id: uuid('document_id').references(() => document.id, { onDelete: 'cascade' }),
    heading: text('heading'),
    body_jsonb: jsonb('body_jsonb').notNull(),
    body_text: text('body_text'), // Generated column
    content_hash: text('content_hash').notNull(),
    tags: jsonb('tags')
      .notNull()
      .default(sql`'{}'::jsonb`),
    citation_count: bigserial('citation_count', { mode: 'number' }).default(0),
    last_verified_at: timestamp('last_verified_at', { withTimezone: true }),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    tagsIdx: index('section_tags_gin').on(table.tags),
    bodyIdx: index('section_body_gin').on(table.body_jsonb),
  })
);

// 3. runbook - Operational procedures
export const runbook = pgTable(
  'runbook',
  {
    id: uuid('id').primaryKey().default(uuidv7),
    service: text('service').notNull(),
    steps_jsonb: jsonb('steps_jsonb').notNull(),
    last_verified_at: timestamp('last_verified_at', { withTimezone: true }),
    owner: text('owner'),
    tags: jsonb('tags')
      .notNull()
      .default(sql`'{}'::jsonb`),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    tagsIdx: index('runbook_tags_gin').on(table.tags),
  })
);

// 4. pr_context - Pull request metadata (TTL: 30d post-merge)
export const pr_context = pgTable('pr_context', {
  id: uuid('id').primaryKey().default(uuidv7),
  pr_number: bigserial('pr_number', { mode: 'number' }).notNull(),
  title: text('title').notNull(),
  description: text('description'),
  author: text('author').notNull(),
  status: text('status').notNull(), // open|merged|closed|draft
  base_branch: text('base_branch').notNull(),
  head_branch: text('head_branch').notNull(),
  merged_at: timestamp('merged_at', { withTimezone: true }),
  expires_at: timestamp('expires_at', { withTimezone: true }),
  tags: jsonb('tags')
    .notNull()
    .default(sql`'{}'::jsonb`),
  created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

// 5. ddl_history - Migration tracking
export const ddl_history = pgTable('ddl_history', {
  id: uuid('id').primaryKey().default(uuidv7),
  migration_id: text('migration_id').notNull().unique(),
  ddl_text: text('ddl_text').notNull(),
  checksum: text('checksum').notNull(),
  applied_at: timestamp('applied_at', { withTimezone: true }).notNull().defaultNow(),
  description: text('description'),
});

// 6. release_note - Version releases
export const release_note = pgTable('release_note', {
  id: uuid('id').primaryKey().default(uuidv7),
  version: text('version').notNull(),
  release_date: timestamp('release_date', { withTimezone: true }).notNull(),
  summary: text('summary').notNull(),
  breaking_changes: jsonb('breaking_changes'),
  new_features: jsonb('new_features'),
  bug_fixes: jsonb('bug_fixes'),
  deprecations: jsonb('deprecations'),
  tags: jsonb('tags')
    .notNull()
    .default(sql`'{}'::jsonb`),
  created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

// 7. change_log - Code changes
export const change_log = pgTable(
  'change_log',
  {
    id: uuid('id').primaryKey().default(uuidv7),
    change_type: text('change_type').notNull(), // feature_add|feature_modify|feature_remove|bugfix|refactor|config_change|dependency_update
    subject_ref: text('subject_ref').notNull(),
    summary: text('summary').notNull(),
    details: text('details'),
    content_hash: text('content_hash').notNull(),
    affected_files: jsonb('affected_files'),
    author: text('author'),
    commit_sha: text('commit_sha'),
    tags: jsonb('tags')
      .notNull()
      .default(sql`'{}'::jsonb`),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    tagsIdx: index('change_log_tags_gin').on(table.tags),
  })
);

// 8. issue_log - Bug/task tracking
export const issue_log = pgTable(
  'issue_log',
  {
    id: uuid('id').primaryKey().default(uuidv7),
    tracker: text('tracker').notNull(),
    external_id: text('external_id').notNull(),
    title: text('title').notNull(),
    status: text('status').notNull(), // open|in_progress|resolved|closed|wont_fix
    description: text('description'),
    assignee: text('assignee'),
    labels: jsonb('labels'),
    url: text('url'),
    tags: jsonb('tags')
      .notNull()
      .default(sql`'{}'::jsonb`),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    trackerExternalIdx: index('issue_log_tracker_external').on(table.tracker, table.external_id),
    tagsIdx: index('issue_log_tags_gin').on(table.tags),
  })
);

// 9. adr_decision - Architecture Decision Records
export const adr_decision = pgTable(
  'adr_decision',
  {
    id: uuid('id').primaryKey().default(uuidv7),
    component: text('component').notNull(),
    status: text('status').notNull(), // proposed|accepted|rejected|deprecated|superseded
    title: text('title').notNull(),
    rationale: text('rationale').notNull(),
    alternatives_considered: jsonb('alternatives_considered'),
    consequences: text('consequences'),
    supersedes: uuid('supersedes'),
    tags: jsonb('tags')
      .notNull()
      .default(sql`'{}'::jsonb`),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    tagsIdx: index('adr_decision_tags_gin').on(table.tags),
  })
);

// 10. todo_log - Task tracking
export const todo_log = pgTable(
  'todo_log',
  {
    id: uuid('id').primaryKey().default(uuidv7),
    scope: text('scope').notNull(),
    todo_type: text('todo_type').notNull(), // task|bug|epic|story|spike
    text: text('text').notNull(),
    status: text('status').notNull(), // open|in_progress|done|cancelled|archived
    priority: text('priority'), // low|medium|high|critical
    assignee: text('assignee'),
    due_date: timestamp('due_date', { withTimezone: true }),
    closed_at: timestamp('closed_at', { withTimezone: true }),
    tags: jsonb('tags')
      .notNull()
      .default(sql`'{}'::jsonb`),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    tagsIdx: index('todo_log_tags_gin').on(table.tags),
  })
);

// 11. event_audit - Immutable audit trail
export const event_audit = pgTable(
  'event_audit',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    entity_type: text('entity_type').notNull(),
    entity_id: uuid('entity_id').notNull(),
    operation: text('operation').notNull(), // INSERT|UPDATE|DELETE
    actor: text('actor'),
    change_summary: jsonb('change_summary'),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    entityIdx: index('event_audit_entity_idx').on(table.entity_type, table.entity_id),
    createdAtIdx: index('event_audit_created_at_idx').on(table.created_at),
  })
);

// ============================================================================
// GRAPH EXTENSION - Knowledge Graph Capabilities
// ============================================================================

// 12. knowledge_entity - Flexible entity storage (10th knowledge type)
export const knowledge_entity = pgTable(
  'knowledge_entity',
  {
    id: uuid('id').primaryKey().default(uuidv7),
    entity_type: text('entity_type').notNull(), // user-defined: "user", "organization", "project", etc.
    name: text('name').notNull(),
    data: jsonb('data').notNull(), // flexible schema: { key: value, ... }
    tags: jsonb('tags')
      .notNull()
      .default(sql`'{}'::jsonb`), // scope: {org, project, branch, ...}
    content_hash: text('content_hash').notNull(), // SHA-256(entity_type + name + data) for deduplication
    deleted_at: timestamp('deleted_at', { withTimezone: true }), // soft delete
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    nameIdx: index('knowledge_entity_name_idx').on(table.name),
    typeIdx: index('knowledge_entity_type_idx').on(table.entity_type),
    tagsIdx: index('knowledge_entity_tags_gin').on(table.tags),
    dataIdx: index('knowledge_entity_data_gin').on(table.data),
    contentHashIdx: index('knowledge_entity_content_hash_idx').on(table.content_hash),
    deletedAtIdx: index('knowledge_entity_deleted_at_idx').on(table.deleted_at),
    uniqueActiveEntity: index('knowledge_entity_unique_active')
      .on(table.entity_type, table.name)
      .where(sql`deleted_at IS NULL`),
  })
);

// 13. knowledge_relation - Entity relationships (directed edges)
export const knowledge_relation = pgTable(
  'knowledge_relation',
  {
    id: uuid('id').primaryKey().default(uuidv7),
    from_entity_type: text('from_entity_type').notNull(), // "section" | "decision" | "entity" | ...
    from_entity_id: uuid('from_entity_id').notNull(),
    to_entity_type: text('to_entity_type').notNull(),
    to_entity_id: uuid('to_entity_id').notNull(),
    relation_type: text('relation_type').notNull(), // "resolves", "supersedes", "references", "implements", etc.
    metadata: jsonb('metadata'), // optional: { weight: 1.0, confidence: 0.85, since: "2025-01-01" }
    tags: jsonb('tags')
      .notNull()
      .default(sql`'{}'::jsonb`), // scope: {org, project, branch, ...}
    deleted_at: timestamp('deleted_at', { withTimezone: true }), // soft delete
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    fromIdx: index('knowledge_relation_from_idx').on(table.from_entity_type, table.from_entity_id),
    toIdx: index('knowledge_relation_to_idx').on(table.to_entity_type, table.to_entity_id),
    relationTypeIdx: index('knowledge_relation_type_idx').on(table.relation_type),
    tagsIdx: index('knowledge_relation_tags_gin').on(table.tags),
    metadataIdx: index('knowledge_relation_metadata_gin').on(table.metadata),
    deletedAtIdx: index('knowledge_relation_deleted_at_idx').on(table.deleted_at),
    uniqueActiveRelation: index('knowledge_relation_unique_active')
      .on(
        table.from_entity_type,
        table.from_entity_id,
        table.to_entity_type,
        table.to_entity_id,
        table.relation_type
      )
      .where(sql`deleted_at IS NULL`),
  })
);

// 14. knowledge_observation - Fine-grained facts attached to entities
export const knowledge_observation = pgTable(
  'knowledge_observation',
  {
    id: uuid('id').primaryKey().default(uuidv7),
    entity_type: text('entity_type').notNull(), // "section" | "decision" | "entity" | ...
    entity_id: uuid('entity_id').notNull(),
    observation: text('observation').notNull(), // key:value format or free text
    observation_type: text('observation_type'), // optional: "status", "progress", "note", "metric"
    metadata: jsonb('metadata'), // optional: { source: "user", confidence: 0.9 }
    deleted_at: timestamp('deleted_at', { withTimezone: true }), // soft delete
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    entityIdx: index('knowledge_observation_entity_idx').on(table.entity_type, table.entity_id),
    typeIdx: index('knowledge_observation_type_idx').on(table.observation_type),
    metadataIdx: index('knowledge_observation_metadata_gin').on(table.metadata),
    createdAtIdx: index('knowledge_observation_created_at_idx').on(table.created_at),
    deletedAtIdx: index('knowledge_observation_deleted_at_idx').on(table.deleted_at),
  })
);
