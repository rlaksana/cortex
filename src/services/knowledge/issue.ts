import { Pool } from 'pg';
import type { IssueData, ScopeFilter } from '../../types/knowledge-data.js';

export async function storeIssue(pool: Pool, data: IssueData, scope: ScopeFilter): Promise<string> {
  const existing = await pool.query<{ id: string }>(
    'SELECT id FROM issue_log WHERE tracker = $1 AND external_id = $2',
    [data.tracker, data.external_id]
  );
  if (existing.rows.length > 0) return existing.rows[0].id;

  const result = await pool.query<{ id: string }>(
    `INSERT INTO issue_log (tracker, external_id, title, status, description, assignee, labels, url, tags)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
    [
      data.tracker,
      data.external_id,
      data.title,
      data.status,
      data.description,
      data.assignee,
      JSON.stringify(data.labels),
      data.url,
      JSON.stringify(scope),
    ]
  );
  return result.rows[0].id;
}
