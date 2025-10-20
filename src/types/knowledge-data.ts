/**
 * Type definitions for knowledge item data structures
 * Used by knowledge handler functions for type safety
 */

export interface ScopeFilter {
  branch?: string;
  project?: string;
  [key: string]: string | undefined;
}

export interface SectionData {
  id?: string;
  document_id?: string;
  title?: string;
  heading?: string;
  body_md?: string;
  body_text?: string;
  body_jsonb?: Record<string, unknown>;
  citation_count?: number;
}

export interface RunbookData {
  service: string;
  steps: unknown;
  title?: string;
  description?: string;
  triggers?: unknown;
  owner?: string;
  last_verified_at?: string;
}

export interface ChangeData {
  change_type: string;
  subject_ref: string;
  summary: string;
  details?: string;
  affected_files?: unknown;
  author?: string;
  commit_sha?: string;
}

export interface IssueData {
  tracker: string;
  external_id: string;
  title: string;
  status: string;
  description?: string;
  assignee?: string;
  labels?: unknown;
  url?: string;
}

export interface DecisionData {
  id?: string;
  component: string;
  status: string;
  title: string;
  rationale: string;
  alternatives_considered?: unknown;
  consequences?: string;
  supersedes?: string;
}

export interface TodoData {
  scope?: string;
  todo_type: 'task' | 'bug' | 'epic' | 'story' | 'spike';
  text: string;
  status: 'open' | 'in_progress' | 'done' | 'cancelled' | 'archived';
  priority?: 'low' | 'medium' | 'high' | 'critical';
  assignee?: string;
  due_date?: string | Date;
  closed_at?: string | Date;
}

export interface ReleaseNoteData {
  version: string;
  release_date: string | Date;
  summary: string;
  breaking_changes?: unknown;
  new_features?: unknown;
  bug_fixes?: unknown;
  deprecations?: unknown;
}

export interface PRContextData {
  pr_number: number;
  title: string;
  description?: string;
  author: string;
  status: string;
  base_branch: string;
  head_branch: string;
  merged_at?: string | Date | null;
}

export interface DDLData {
  migration_id: string;
  ddl_text: string;
  checksum?: string;
  description?: string;
}
