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
  tracker?: string;
  external_id?: string;
  title: string;
  status: string;
  description?: string;
  assignee?: string;
  labels?: unknown;
  url?: string;
  // Additional properties for validation (NOT for database storage)
  metadata?: Record<string, unknown>;
  tags?: Record<string, unknown>;
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
  id?: string;
  version: string;
  release_date: string | Date;
  summary: string;
  breaking_changes?: unknown;
  new_features?: unknown;
  bug_fixes?: unknown;
  deprecations?: unknown;
}

export interface PRContextData {
  id?: string;
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
  id?: string;
  migration_id: string;
  ddl_text: string;
  checksum?: string;
  description?: string;
}

export interface AssumptionData {
  id?: string;
  title: string;
  description: string;
  category: string;
  validation_status?: string;
  impact_if_invalid?: string;
  validation_method?: string;
  validation_date?: string;
  owner?: string;
  dependencies?: unknown;
  expiry_date?: string;
  created_at?: Date;
  updated_at?: Date;
}

export interface IncidentData {
  id?: string;
  title: string;
  description?: string;
  severity: string;
  status?: string;
  impact: string;
  impact_level?: string;
  timeline?: unknown;
  incident_type?: string;
  affected_services?: unknown;
  root_cause?: string;
  root_cause_analysis?: string;
  resolution?: string;
  lessons_learned?: string;
  recovery_actions?: unknown;
  created_at?: Date;
  updated_at?: Date;
}

export interface ReleaseData {
  id?: string;
  version: string;
  title?: string;
  description?: string;
  status?: string;
  deployment_strategy?: string;
  release_date?: string | Date;
  release_notes?: unknown;
  features?: unknown;
  bug_fixes?: unknown;
  breaking_changes?: unknown;
  rollback_plan?: string;
  created_at?: Date;
  updated_at?: Date;
}

export interface RiskData {
  id?: string;
  title: string;
  description: string;
  probability: 'very_likely' | 'likely' | 'possible' | 'unlikely' | 'very_unlikely';
  impact: string;
  risk_level?: string;
  category: string;
  mitigation?: string;
  contingency_plan?: string;
  risk_owner?: string;
  review_date?: string;
  identified_date?: string;
  created_at?: Date;
  updated_at?: Date;
}
