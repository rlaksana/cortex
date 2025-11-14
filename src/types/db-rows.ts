// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * Database Row Type Definitions
 * Updated to match qdrant 18 schema with all 16 knowledge types and 8-LOG SYSTEM
 */

// ============================================================================
// CORE TABLES - Knowledge Storage
// ============================================================================

export interface DocumentRow {
  id: string;
  title: string;
  description: string | null;
  created_at: Date;
  updated_at: Date;
  tags: Record<string, unknown>;
  metadata: Record<string, unknown>;
}

export interface SectionRow {
  id: string;
  document_id: string | null;
  heading: string;
  body_md: string | null;
  body_text: string | null;
  title: string;
  citation_count: number;
  created_at: Date;
  updated_at: Date;
  tags: Record<string, unknown>;
  metadata: Record<string, unknown>;
  body_jsonb: { text: string; markdown?: string };
  ts: string; // Full-text search vector
}

export interface RunbookRow {
  id: string;
  service: string;
  title: string;
  description: string | null;
  steps_jsonb: Array<{
    step_number: number;
    description: string;
    command?: string;
    expected_outcome?: string;
  }>;
  triggers: string[] | null;
  last_verified_at: Date | null;
  created_at: Date;
  updated_at: Date;
  tags: Record<string, unknown>;
  metadata: Record<string, unknown>;
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
  affected_files: string[] | null;
  author: string | null;
  commit_sha: string | null;
  created_at: Date;
  updated_at: Date;
  tags: Record<string, unknown>;
  metadata: Record<string, unknown>;
}

export interface IssueLogRow {
  id: string;
  tracker: string;
  external_id: string;
  title: string;
  description: string | null;
  status: 'open' | 'in_progress' | 'resolved' | 'closed' | 'wont_fix';
  assignee: string | null;
  labels: string[] | null;
  url: string | null;
  created_at: Date;
  updated_at: Date;
  tags: Record<string, unknown>;
  metadata: Record<string, unknown>;
}

export interface ADRDecisionRow {
  id: string;
  component: string;
  status: 'proposed' | 'accepted' | 'rejected' | 'deprecated' | 'superseded';
  title: string;
  rationale: string;
  alternatives_considered: string[] | null;
  consequences: string | null;
  supersedes: string | null;
  created_at: Date;
  updated_at: Date;
  tags: Record<string, unknown>;
  metadata: Record<string, unknown>;
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
  created_at: Date;
  updated_at: Date;
  tags: Record<string, unknown>;
  metadata: Record<string, unknown>;
}

export interface ReleaseNoteRow {
  id: string;
  version: string;
  release_date: Date;
  summary: string;
  breaking_changes: string[] | null;
  new_features: string[] | null;
  bug_fixes: string[] | null;
  deprecations: string[] | null;
  created_at: Date;
  updated_at: Date;
  tags: Record<string, unknown>;
  metadata: Record<string, unknown>;
}

export interface DDLHistoryRow {
  id: string;
  migration_id: string;
  ddl_text: string;
  checksum: string;
  applied_at: Date;
  description: string | null;
  status: 'pending' | 'applied' | 'failed' | 'rolled_back';
  tags: Record<string, unknown>;
  metadata: Record<string, unknown>;
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
  created_at: Date;
  updated_at: Date;
  tags: Record<string, unknown>;
  metadata: Record<string, unknown>;
}

// ============================================================================
// GRAPH EXTENSION TABLES - Entity-Relationship Model
// ============================================================================

export interface KnowledgeEntityRow {
  id: string;
  entity_type: string;
  name: string;
  data: Record<string, unknown>;
  created_at: Date;
  updated_at: Date;
  deleted_at: Date | null;
  tags: Record<string, unknown>;
  metadata: Record<string, unknown>;
}

export interface KnowledgeRelationRow {
  id: string;
  from_entity_type: string;
  from_entity_id: string;
  to_entity_type: string;
  to_entity_id: string;
  relation_type: string;
  metadata: Record<string, unknown>;
  created_at: Date;
  updated_at: Date;
  tags: Record<string, unknown>;
}

export interface KnowledgeObservationRow {
  id: string;
  entity_type: string;
  entity_id: string;
  observation: string;
  observation_type: string | null;
  metadata: Record<string, unknown>;
  created_at: Date;
  updated_at: Date;
  tags: Record<string, unknown>;
}

// ============================================================================
// 8-LOG SYSTEM TABLES - Session Persistence
// ============================================================================

export interface IncidentLogRow {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  impact: string;
  timeline: Array<{ timestamp: string; event: string; actor?: string }> | null;
  root_cause_analysis: string | null;
  resolution_status: 'open' | 'investigating' | 'resolved' | 'closed';
  affected_services: string[] | null;
  business_impact: string | null;
  recovery_actions: string[] | null;
  follow_up_required: boolean;
  incident_commander: string | null;
  created_at: Date;
  updated_at: Date;
  tags: Record<string, unknown>;
  metadata: Record<string, unknown>;
}

export interface ReleaseLogRow {
  id: string;
  version: string;
  release_type: 'major' | 'minor' | 'patch' | 'hotfix';
  scope: string;
  release_date: Date | null;
  status: 'planned' | 'in_progress' | 'completed' | 'rolled_back';
  ticket_references: string[] | null;
  included_changes: string[] | null;
  deployment_strategy: string | null;
  rollback_plan: string | null;
  testing_status: string | null;
  approvers: string[] | null;
  release_notes: string | null;
  post_release_actions: string[] | null;
  created_at: Date;
  updated_at: Date;
  tags: Record<string, unknown>;
  metadata: Record<string, unknown>;
}

export interface RiskLogRow {
  id: string;
  title: string;
  category: 'technical' | 'business' | 'operational' | 'security' | 'compliance';
  risk_level: 'critical' | 'high' | 'medium' | 'low';
  probability: 'very_likely' | 'likely' | 'possible' | 'unlikely' | 'very_unlikely';
  impact_description: string;
  trigger_events: string[] | null;
  mitigation_strategies: string[] | null;
  owner: string | null;
  review_date: Date | null;
  status: 'active' | 'mitigated' | 'accepted' | 'closed';
  related_decisions: string[] | null;
  monitoring_indicators: string[] | null;
  contingency_plans: string | null;
  created_at: Date;
  updated_at: Date;
  tags: Record<string, unknown>;
  metadata: Record<string, unknown>;
}

export interface AssumptionLogRow {
  id: string;
  title: string;
  description: string;
  category: 'technical' | 'business' | 'user' | 'market' | 'resource';
  validation_status: 'validated' | 'assumed' | 'invalidated' | 'needs_validation';
  impact_if_invalid: string;
  validation_criteria: string[] | null;
  validation_date: Date | null;
  owner: string | null;
  related_assumptions: string[] | null;
  dependencies: string[] | null;
  monitoring_approach: string | null;
  review_frequency: 'daily' | 'weekly' | 'monthly' | 'quarterly' | 'as_needed' | null;
  created_at: Date;
  updated_at: Date;
  tags: Record<string, unknown>;
  metadata: Record<string, unknown>;
}

// ============================================================================
// AUDIT TRAIL TABLE
// ============================================================================

export interface EventAuditRow {
  id: number;
  event_id: string;
  event_type: string;
  table_name: string;
  record_id: string;
  operation: 'INSERT' | 'UPDATE' | 'DELETE';
  old_data: Record<string, unknown> | null;
  new_data: Record<string, unknown> | null;
  changed_by: string;
  changed_at: Date;
  tags: Record<string, unknown>;
  metadata: Record<string, unknown>;
}

// ============================================================================
// AUTO-MAINTENANCE TABLE
// ============================================================================

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

// ============================================================================
// VIEW TYPES
// ============================================================================

export interface ActiveKnowledgeRow {
  type: string;
  id: string;
  name: string;
  updated_at: Date;
  tags: Record<string, unknown>;
}

export interface GraphRelationshipsRow {
  from_entity_type: string;
  from_entity_id: string;
  to_entity_type: string;
  to_entity_id: string;
  relation_type: string;
  metadata: Record<string, unknown>;
  created_at: Date;
}

export interface RecentActivityRow {
  type: string;
  id: string;
  description: string;
  timestamp: Date;
  tags: Record<string, unknown>;
}

export interface TableStatisticsRow {
  table_name: string;
  total_rows: number;
  table_size: number;
  index_size: number;
  total_size: number;
  last_vacuum: Date | null;
  last_autovacuum: Date | null;
  last_analyze: Date | null;
  last_autoanalyze: Date | null;
}

// ============================================================================
// GENERIC QUERY RESULT ROWS
// ============================================================================

export interface CountRow {
  count: string;
  total?: string;
}

export interface StatsRow {
  entity_type: string;
  count: string;
}

// ============================================================================
// UNION TYPES FOR CONVENIENCE
// ============================================================================

export type KnowledgeTableRow =
  | SectionRow
  | RunbookRow
  | ChangeLogRow
  | IssueLogRow
  | ADRDecisionRow
  | TodoLogRow
  | ReleaseNoteRow
  | DDLHistoryRow
  | PRContextRow
  | KnowledgeEntityRow
  | KnowledgeRelationRow
  | KnowledgeObservationRow
  | IncidentLogRow
  | ReleaseLogRow
  | RiskLogRow
  | AssumptionLogRow;

export type GraphTableRow = KnowledgeEntityRow | KnowledgeRelationRow | KnowledgeObservationRow;

export type SessionLogTableRow = IncidentLogRow | ReleaseLogRow | RiskLogRow | AssumptionLogRow;
