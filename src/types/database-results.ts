// Auto-generated database result types
export interface DatabaseResult<T = unknown> {
  rows: T[];
  rowCount: number;
  command: string;
}

export interface SectionRow {
  id: string;
  title: string;
  heading: string;
  body_md?: string;
  body_text?: string;
  body_jsonb: Record<string, unknown>;
  content_hash?: string;
  created_at: Date;
  updated_at: Date;
  tags: Record<string, unknown>;
  metadata: Record<string, unknown>;
}

export interface AuditEventRow {
  id: string;
  table_name: string;
  operation: string;
  user_id?: string;
  old_data?: Record<string, unknown>;
  new_data?: Record<string, unknown>;
  created_at: Date;
}

export type QueryResult<T> = DatabaseResult<T>;
export type PoolQueryResult<T> = Promise<DatabaseResult<T>>;
