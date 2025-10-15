/**
 * Database Row Type Definitions
 * Auto-generated to fix @typescript-eslint/no-unsafe-* errors
 */

export interface DocumentRow {
  id: string;
  type: 'spec' | 'doc' | 'guide' | 'other';
  title: string;
  tags: Record<string, unknown>;
  approved_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

export interface SectionRow {
  id: string;
  document_id: string | null;
  heading: string | null;
  body_jsonb: { text: string };
  body_text: string;
  content_hash: string;
  tags: Record<string, unknown>;
  citation_count: number;
  last_verified_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

export interface RunbookRow {
  id: string;
  service: string;
  steps_jsonb: Array<{ step: number; action: string }>;
  last_verified_at: Date | null;
  owner: string | null;
  tags: Record<string, unknown>;
  created_at: Date;
  updated_at: Date;
}

export interface PRContextRow {
  id: string;
  pr_number: number;
  title: string;
  description: string | null;
  author: string;
  status: 'open' | 'merged' | 'closed' | 'draft';
  base_branch: string;
  head_branch: string;
  merged_at: Date | null;
  expires_at: Date | null;
  tags: Record<string, unknown>;
  created_at: Date;
  updated_at: Date;
}

export interface DDLHistoryRow {
  id: string;
  migration_id: string;
  ddl_text: string;
  checksum: string;
  applied_at: Date;
  description: string | null;
}

export interface ReleaseNoteRow {
  id: string;
  version: string;
  release_date: Date;
  summary: string;
  breaking_changes: unknown;
  new_features: unknown;
  bug_fixes: unknown;
  deprecations: unknown;
  tags: Record<string, unknown>;
  created_at: Date;
}

export interface ChangeLogRow {
  id: string;
  change_type:
    | 'feature_add'
    | 'feature_modify'
    | 'feature_remove'
    | 'bugfix'
    | 'refactor'
    | 'config_change'
    | 'dependency_update';
  subject_ref: string;
  summary: string;
  details: string | null;
  content_hash: string;
  affected_files: unknown;
  author: string | null;
  commit_sha: string | null;
  tags: Record<string, unknown>;
  created_at: Date;
  updated_at: Date;
}

export interface IssueLogRow {
  id: string;
  tracker: string;
  external_id: string;
  title: string;
  status: 'open' | 'in_progress' | 'resolved' | 'closed' | 'wont_fix';
  description: string | null;
  assignee: string | null;
  labels: unknown;
  url: string | null;
  tags: Record<string, unknown>;
  created_at: Date;
  updated_at: Date;
}

export interface ADRDecisionRow {
  id: string;
  component: string;
  status: 'proposed' | 'accepted' | 'rejected' | 'deprecated' | 'superseded';
  title: string;
  rationale: string;
  alternatives_considered: unknown;
  consequences: string | null;
  supersedes: string | null;
  tags: Record<string, unknown>;
  created_at: Date;
  updated_at: Date;
}

export interface TodoLogRow {
  id: string;
  scope: string;
  todo_type: 'task' | 'bug' | 'epic' | 'story' | 'spike';
  text: string;
  status: 'open' | 'in_progress' | 'done' | 'cancelled' | 'archived';
  priority: 'low' | 'medium' | 'high' | 'critical' | null;
  assignee: string | null;
  due_date: Date | null;
  closed_at: Date | null;
  tags: Record<string, unknown>;
  created_at: Date;
  updated_at: Date;
}

export interface EventAuditRow {
  id: number;
  entity_type: string;
  entity_id: string;
  operation: 'INSERT' | 'UPDATE' | 'DELETE';
  actor: string | null;
  change_summary: unknown;
  created_at: Date;
}

export interface KnowledgeEntityRow {
  id: string;
  entity_type: string;
  name: string;
  data: Record<string, unknown>;
  tags: Record<string, unknown>;
  content_hash: string;
  deleted_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

export interface KnowledgeRelationRow {
  id: string;
  from_entity_type: string;
  from_entity_id: string;
  to_entity_type: string;
  to_entity_id: string;
  relation_type: string;
  metadata: Record<string, unknown> | null;
  tags: Record<string, unknown>;
  deleted_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

export interface KnowledgeObservationRow {
  id: string;
  entity_type: string;
  entity_id: string;
  observation: string;
  observation_type: string | null;
  metadata: Record<string, unknown> | null;
  deleted_at: Date | null;
  created_at: Date;
}

export interface PurgeMetadataRow {
  id: number;
  last_purge_at: Date;
  operations_since_purge: number;
  time_threshold_hours: number;
  operation_threshold: number;
  deleted_counts: Record<string, number>;
  last_duration_ms: number | null;
  enabled: boolean;
  created_at: Date;
  updated_at: Date;
}

// Generic query result row for counts/stats
export interface CountRow {
  count: string;
  total?: string;
}

export interface StatsRow {
  entity_type: string;
  count: string;
}
