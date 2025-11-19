/**
 * Enhanced Database Result Types with Type Safety
 *
 * Provides typed interfaces for database operations and results,
 * replacing unknown types with proper type guards and validation.
 */

import type { KnowledgeItem } from './core-interfaces.js';
import type { AssumptionData, ChangeData, DDLData, DecisionData, IncidentData, IssueData, PRContextData, ReleaseData, ReleaseNoteData, RiskData,RunbookData, SectionData, TodoData } from './knowledge-data.js';

// ============================================================================
// Core Database Result Interface
// ============================================================================

/** @deprecated Use DatabaseResult<T> from './database-generics.js' instead */
/** @deprecated Use DatabaseResult<T> from './database-generics.js' instead */
export interface DatabaseResult<T = Record<string, any>> {
  rows: T[];
  rowCount: number;
  command: string;
}

// ============================================================================
// Typed Database Row Interfaces
// ============================================================================

export interface SectionRow {
  id: string;
  title: string;
  heading: string;
  body_md?: string;
  body_text?: string;
  body_jsonb: Record<string, any>;
  content_hash?: string;
  created_at: Date;
  updated_at: Date;
  tags: Record<string, any>;
  metadata: Record<string, any>;
}

export interface AuditEventRow {
  id: string;
  table_name: string;
  operation: string;
  user_id?: string;
  old_data?: Record<string, any>;
  new_data?: Record<string, any>;
  created_at: Date;
}

// ============================================================================
// Enhanced Knowledge Entity Row Types
// ============================================================================

export interface KnowledgeEntityRow<T = Record<string, any>> {
  id: string;
  kind: string;
  content?: string;
  scope_project?: string;
  scope_branch?: string;
  scope_org?: string;
  data: T;
  metadata?: Record<string, any>;
  created_at: Date;
  updated_at: Date;
  expiry_at?: Date;
  vector_id?: string;
  content_hash?: string;
  embedding?: number[];
}

export interface SectionEntityRow extends KnowledgeEntityRow<SectionData> {
  kind: 'section';
}

export interface RunbookEntityRow extends KnowledgeEntityRow<RunbookData> {
  kind: 'runbook';
}

export interface ChangeEntityRow extends KnowledgeEntityRow<ChangeData> {
  kind: 'change';
}

export interface IssueEntityRow extends KnowledgeEntityRow<IssueData> {
  kind: 'issue';
}

export interface DecisionEntityRow extends KnowledgeEntityRow<DecisionData> {
  kind: 'decision';
}

export interface TodoEntityRow extends KnowledgeEntityRow<TodoData> {
  kind: 'todo';
}

export interface ReleaseNoteEntityRow extends KnowledgeEntityRow<ReleaseNoteData> {
  kind: 'release_note';
}

export interface PRContextEntityRow extends KnowledgeEntityRow<PRContextData> {
  kind: 'pr_context';
}

export interface DDLEntityRow extends KnowledgeEntityRow<DDLData> {
  kind: 'ddl';
}

export interface AssumptionEntityRow extends KnowledgeEntityRow<AssumptionData> {
  kind: 'assumption';
}

export interface IncidentEntityRow extends KnowledgeEntityRow<IncidentData> {
  kind: 'incident';
}

export interface ReleaseEntityRow extends KnowledgeEntityRow<ReleaseData> {
  kind: 'release';
}

export interface RiskEntityRow extends KnowledgeEntityRow<RiskData> {
  kind: 'risk';
}

// Union type for all knowledge entity rows
export type AnyKnowledgeEntityRow =
  | SectionEntityRow
  | RunbookEntityRow
  | ChangeEntityRow
  | IssueEntityRow
  | DecisionEntityRow
  | TodoEntityRow
  | ReleaseNoteEntityRow
  | PRContextEntityRow
  | DDLEntityRow
  | AssumptionEntityRow
  | IncidentEntityRow
  | ReleaseEntityRow
  | RiskEntityRow;

// ============================================================================
// Enhanced Query Result Types
// ============================================================================

export type QueryResult<T> = DatabaseResult<T>;
export type PoolQueryResult<T> = Promise<DatabaseResult<T>>;

export type KnowledgeQueryResult = DatabaseResult<KnowledgeEntityRow>;
export type SectionQueryResult = DatabaseResult<SectionEntityRow>;
export type RunbookQueryResult = DatabaseResult<RunbookEntityRow>;
export type ChangeQueryResult = DatabaseResult<ChangeEntityRow>;
export type IssueQueryResult = DatabaseResult<IssueEntityRow>;
export type DecisionQueryResult = DatabaseResult<DecisionEntityRow>;
export type TodoQueryResult = DatabaseResult<TodoEntityRow>;
export type ReleaseNoteQueryResult = DatabaseResult<ReleaseNoteEntityRow>;
export type PRContextQueryResult = DatabaseResult<PRContextEntityRow>;
export type DDLQueryResult = DatabaseResult<DDLEntityRow>;
export type AssumptionQueryResult = DatabaseResult<AssumptionEntityRow>;
export type IncidentQueryResult = DatabaseResult<IncidentEntityRow>;
export type ReleaseQueryResult = DatabaseResult<ReleaseEntityRow>;
export type RiskQueryResult = DatabaseResult<RiskEntityRow>;

// ============================================================================
// Type Guard Functions for Database Rows
// ============================================================================

export function isKnowledgeEntityRow(obj: unknown): obj is KnowledgeEntityRow {
  if (!obj || typeof obj !== 'object') return false;
  const row = obj as Record<string, unknown>;

  return (
    typeof row.id === 'string' &&
    typeof row.kind === 'string' &&
    (row.content === undefined || typeof row.content === 'string') &&
    typeof row.created_at === 'object' && // Date
    typeof row.updated_at === 'object' && // Date
    (row.data === undefined || typeof row.data === 'object')
  );
}

export function isSectionEntityRow(obj: unknown): obj is SectionEntityRow {
  if (!isKnowledgeEntityRow(obj)) return false;
  const row = obj as KnowledgeEntityRow;
  return row.kind === 'section';
}

export function isRunbookEntityRow(obj: unknown): obj is RunbookEntityRow {
  if (!isKnowledgeEntityRow(obj)) return false;
  const row = obj as KnowledgeEntityRow;
  return row.kind === 'runbook';
}

export function isChangeEntityRow(obj: unknown): obj is ChangeEntityRow {
  if (!isKnowledgeEntityRow(obj)) return false;
  const row = obj as KnowledgeEntityRow;
  return row.kind === 'change';
}

export function isIssueEntityRow(obj: unknown): obj is IssueEntityRow {
  if (!isKnowledgeEntityRow(obj)) return false;
  const row = obj as KnowledgeEntityRow;
  return row.kind === 'issue';
}

export function isDecisionEntityRow(obj: unknown): obj is DecisionEntityRow {
  if (!isKnowledgeEntityRow(obj)) return false;
  const row = obj as KnowledgeEntityRow;
  return row.kind === 'decision';
}

export function isTodoEntityRow(obj: unknown): obj is TodoEntityRow {
  if (!isKnowledgeEntityRow(obj)) return false;
  const row = obj as KnowledgeEntityRow;
  return row.kind === 'todo';
}

export function isReleaseNoteEntityRow(obj: unknown): obj is ReleaseNoteEntityRow {
  if (!isKnowledgeEntityRow(obj)) return false;
  const row = obj as KnowledgeEntityRow;
  return row.kind === 'release_note';
}

export function isPRContextEntityRow(obj: unknown): obj is PRContextEntityRow {
  if (!isKnowledgeEntityRow(obj)) return false;
  const row = obj as KnowledgeEntityRow;
  return row.kind === 'pr_context';
}

export function isDDLEntityRow(obj: unknown): obj is DDLEntityRow {
  if (!isKnowledgeEntityRow(obj)) return false;
  const row = obj as KnowledgeEntityRow;
  return row.kind === 'ddl';
}

export function isAssumptionEntityRow(obj: unknown): obj is AssumptionEntityRow {
  if (!isKnowledgeEntityRow(obj)) return false;
  const row = obj as KnowledgeEntityRow;
  return row.kind === 'assumption';
}

export function isIncidentEntityRow(obj: unknown): obj is IncidentEntityRow {
  if (!isKnowledgeEntityRow(obj)) return false;
  const row = obj as KnowledgeEntityRow;
  return row.kind === 'incident';
}

export function isReleaseEntityRow(obj: unknown): obj is ReleaseEntityRow {
  if (!isKnowledgeEntityRow(obj)) return false;
  const row = obj as KnowledgeEntityRow;
  return row.kind === 'release';
}

export function isRiskEntityRow(obj: unknown): obj is RiskEntityRow {
  if (!isKnowledgeEntityRow(obj)) return false;
  const row = obj as KnowledgeEntityRow;
  return row.kind === 'risk';
}

// ============================================================================
// Type Guard Functions for Knowledge Data
// ============================================================================

export function isSectionData(obj: unknown): obj is SectionData {
  if (!obj || typeof obj !== 'object') return false;
  const data = obj as Record<string, unknown>;

  return (
    (data.id === undefined || typeof data.id === 'string') &&
    (data.title === undefined || typeof data.title === 'string') &&
    (data.heading === undefined || typeof data.heading === 'string') &&
    (data.body_md === undefined || typeof data.body_md === 'string') &&
    (data.body_text === undefined || typeof data.body_text === 'string') &&
    (data.body_jsonb === undefined || typeof data.body_jsonb === 'object') &&
    (data.content_hash === undefined || typeof data.content_hash === 'string')
  );
}

export function isRunbookData(obj: unknown): obj is RunbookData {
  if (!obj || typeof obj !== 'object') return false;
  const data = obj as Record<string, unknown>;

  return (
    typeof data.service === 'string' &&
    (data.title === undefined || typeof data.title === 'string') &&
    (data.description === undefined || typeof data.description === 'string') &&
    (data.owner === undefined || typeof data.owner === 'string') &&
    (data.last_verified_at === undefined || typeof data.last_verified_at === 'string')
  );
}

export function isIssueData(obj: unknown): obj is IssueData {
  if (!obj || typeof obj !== 'object') return false;
  const data = obj as Record<string, unknown>;

  return (
    typeof data.title === 'string' &&
    typeof data.status === 'string' &&
    (data.tracker === undefined || typeof data.tracker === 'string') &&
    (data.external_id === undefined || typeof data.external_id === 'string') &&
    (data.description === undefined || typeof data.description === 'string') &&
    (data.assignee === undefined || typeof data.assignee === 'string') &&
    (data.url === undefined || typeof data.url === 'string')
  );
}

export function isDecisionData(obj: unknown): obj is DecisionData {
  if (!obj || typeof obj !== 'object') return false;
  const data = obj as Record<string, unknown>;

  return (
    typeof data.component === 'string' &&
    typeof data.status === 'string' &&
    typeof data.title === 'string' &&
    typeof data.rationale === 'string' &&
    (data.id === undefined || typeof data.id === 'string') &&
    (data.alternatives_considered === undefined || data.alternatives_considered !== undefined) &&
    (data.consequences === undefined || typeof data.consequences === 'string') &&
    (data.supersedes === undefined || typeof data.supersedes === 'string')
  );
}

export function isTodoData(obj: unknown): obj is TodoData {
  if (!obj || typeof obj !== 'object') return false;
  const data = obj as Record<string, unknown>;

  return (
    typeof data.todo_type === 'string' &&
    typeof data.text === 'string' &&
    typeof data.status === 'string' &&
    (data.scope === undefined || typeof data.scope === 'string') &&
    (data.priority === undefined || typeof data.priority === 'string') &&
    (data.assignee === undefined || typeof data.assignee === 'string') &&
    (data.due_date === undefined || typeof data.due_date === 'string' || data.due_date instanceof Date) &&
    (data.closed_at === undefined || typeof data.closed_at === 'string' || data.closed_at instanceof Date)
  );
}

export function isIncidentData(obj: unknown): obj is IncidentData {
  if (!obj || typeof obj !== 'object') return false;
  const data = obj as Record<string, unknown>;

  return (
    typeof data.title === 'string' &&
    typeof data.severity === 'string' &&
    typeof data.impact === 'string' &&
    (data.description === undefined || typeof data.description === 'string') &&
    (data.status === undefined || typeof data.status === 'string') &&
    (data.impact_level === undefined || typeof data.impact_level === 'string') &&
    (data.incident_type === undefined || typeof data.incident_type === 'string') &&
    (data.root_cause === undefined || typeof data.root_cause === 'string') &&
    (data.resolution === undefined || typeof data.resolution === 'string')
  );
}

export function isRiskData(obj: unknown): obj is RiskData {
  if (!obj || typeof obj !== 'object') return false;
  const data = obj as Record<string, unknown>;

  return (
    typeof data.title === 'string' &&
    typeof data.description === 'string' &&
    typeof data.probability === 'string' &&
    typeof data.impact === 'string' &&
    typeof data.category === 'string' &&
    (data.risk_level === undefined || typeof data.risk_level === 'string') &&
    (data.mitigation === undefined || typeof data.mitigation === 'string') &&
    (data.contingency_plan === undefined || typeof data.contingency_plan === 'string') &&
    (data.risk_owner === undefined || typeof data.risk_owner === 'string')
  );
}

// ============================================================================
// Database Result Type Guards
// ============================================================================

export function isDatabaseResult<T>(
  obj: unknown,
  rowGuard: (row: unknown) => row is T
): obj is DatabaseResult<T> {
  if (!obj || typeof obj !== 'object') return false;
  const result = obj as Record<string, unknown>;

  return (
    Array.isArray(result.rows) &&
    result.rows.every(rowGuard) &&
    typeof result.rowCount === 'number' &&
    typeof result.command === 'string'
  );
}

export function isKnowledgeQueryResult(obj: unknown): obj is KnowledgeQueryResult {
  return isDatabaseResult(obj, isKnowledgeEntityRow);
}

export function isSectionQueryResult(obj: unknown): obj is SectionQueryResult {
  return isDatabaseResult(obj, isSectionEntityRow);
}

export function isRunbookQueryResult(obj: unknown): obj is RunbookQueryResult {
  return isDatabaseResult(obj, isRunbookEntityRow);
}

export function isIssueQueryResult(obj: unknown): obj is IssueQueryResult {
  return isDatabaseResult(obj, isIssueEntityRow);
}

export function isDecisionQueryResult(obj: unknown): obj is DecisionQueryResult {
  return isDatabaseResult(obj, isDecisionEntityRow);
}

export function isTodoQueryResult(obj: unknown): obj is TodoQueryResult {
  return isDatabaseResult(obj, isTodoEntityRow);
}

export function isIncidentQueryResult(obj: unknown): obj is IncidentQueryResult {
  return isDatabaseResult(obj, isIncidentEntityRow);
}

export function isRiskQueryResult(obj: unknown): obj is RiskQueryResult {
  return isDatabaseResult(obj, isRiskEntityRow);
}

// ============================================================================
// Data Transformation Utilities
// ============================================================================

export function knowledgeEntityRowToKnowledgeItem(row: KnowledgeEntityRow): KnowledgeItem {
  return {
    id: row.id,
    kind: row.kind,
    content: row.content,
    scope: {
      project: row.scope_project,
      branch: row.scope_branch,
      org: row.scope_org,
    },
    data: row.data,
    metadata: row.metadata,
    created_at: row.created_at.toISOString(),
    updated_at: row.updated_at.toISOString(),
    expiry_at: row.expiry_at?.toISOString(),
  };
}

export function knowledgeItemToEntityRow(item: KnowledgeItem): KnowledgeEntityRow {
  return {
    id: item.id || '',
    kind: item.kind,
    content: item.content,
    scope_project: item.scope.project,
    scope_branch: item.scope.branch,
    scope_org: item.scope.org,
    data: item.data,
    metadata: item.metadata,
    created_at: new Date(item.created_at || Date.now()),
    updated_at: new Date(item.updated_at || Date.now()),
    expiry_at: item.expiry_at ? new Date(item.expiry_at) : undefined,
  };
}

// ============================================================================
// Generic Database Query Builder Helper Types
// ============================================================================

export interface TypedDatabaseQuery<T = Record<string, any>> {
  sql: string;
  parameters?: any[];
  transform?: (row: any) => T;
  rowGuard?: (row: any) => row is T;
}

export interface TypedQueryResult<T = Record<string, any>> {
  success: boolean;
  data?: T[];
  error?: string;
  rowCount: number;
  metadata?: Record<string, any>;
}

export class TypedQueryBuilder {
  static createQuery<T>(
    sql: string,
    rowGuard: (row: unknown) => row is T,
    transform?: (row: unknown) => T
  ): TypedDatabaseQuery<T> {
    return {
      sql,
      parameters: [],
      transform,
      rowGuard,
    };
  }

  static validateResult<T>(
    result: unknown,
    query: TypedDatabaseQuery<T>
  ): TypedQueryResult<T> {
    if (!result || typeof result !== 'object') {
      return {
        success: false,
        data: undefined,
        error: 'Invalid database result',
        rowCount: 0,
      };
    }

    const dbResult = result as Record<string, unknown>;

    if (!Array.isArray(dbResult.rows)) {
      return {
        success: false,
        data: undefined,
        error: 'Result rows is not an array',
        rowCount: 0,
      };
    }

    if (!query.rowGuard) {
      return {
        success: true,
        data: dbResult.rows as T[],
        rowCount: dbResult.rowCount as number || dbResult.rows.length,
      };
    }

    const validRows: T[] = [];
    const errors: string[] = [];

    for (const row of dbResult.rows) {
      if (query.rowGuard(row)) {
        validRows.push(query.transform ? query.transform(row) : row);
      } else {
        errors.push(`Invalid row: ${JSON.stringify(row)}`);
      }
    }

    return {
      success: errors.length === 0,
      data: validRows,
      error: errors.length > 0 ? errors.join('; ') : undefined,
      rowCount: validRows.length,
    };
  }
}
