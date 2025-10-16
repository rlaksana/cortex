// Auto-generated database result types
export interface DatabaseResult<T = any> {
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

export type QueryResult<T> = DatabaseResult<T>;
export type PoolQueryResult<T> = Promise<DatabaseResult<T>>;
