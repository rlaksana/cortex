/**
 * Type definitions for database query results
 * Used for type-safe database operations
 */

export interface SectionQueryResult {
  id: string;
  heading: string | null;
  body_jsonb: { text?: string } | null;
  fts_score: string;
  tags: Record<string, unknown> | null;
  updated_at: Date | string | null;
  citation_count: number | string | null;
}

export interface RunbookQueryResult {
  id: string;
  service: string | null;
  steps_jsonb: unknown;
  tags: Record<string, unknown> | null;
  updated_at: Date | string | null;
}

export interface ChangeQueryResult {
  id: string;
  subject_ref: string | null;
  summary: string | null;
  details: string | null;
  tags: Record<string, unknown> | null;
  updated_at: Date | string | null;
}

export interface IssueQueryResult {
  id: string;
  title: string | null;
  description: string | null;
  tags: Record<string, unknown> | null;
  updated_at: Date | string | null;
}

export interface DecisionQueryResult {
  id: string;
  title: string | null;
  rationale: string | null;
  component: string | null;
  tags: Record<string, unknown> | null;
  updated_at: Date | string | null;
}

export interface TodoQueryResult {
  id: string;
  text: string | null;
  scope: string | null;
  tags: Record<string, unknown> | null;
  updated_at: Date | string | null;
}

export interface ReleaseNoteQueryResult {
  id: string;
  version: string | null;
  summary: string | null;
  tags: Record<string, unknown> | null;
  created_at: Date | string | null;
}

export interface PRContextQueryResult {
  id: string;
  title: string | null;
  description: string | null;
  pr_number: number | string;
  tags: Record<string, unknown> | null;
  updated_at: Date | string | null;
}

export interface DDLQueryResult {
  id: string;
  migration_id: string | null;
  description: string | null;
  applied_at: Date | string | null;
}
