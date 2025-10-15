import { Pool } from 'pg';
import type { PRContextData, ScopeFilter } from '../../types/knowledge-data.js';

export async function storePRContext(
  pool: Pool,
  data: PRContextData,
  scope: ScopeFilter
): Promise<string> {
  const expiresAt = data.merged_at
    ? new Date(new Date(data.merged_at).getTime() + 30 * 24 * 60 * 60 * 1000).toISOString()
    : null;

  const result = await pool.query<{ id: string }>(
    `INSERT INTO pr_context (pr_number, title, description, author, status, base_branch, head_branch, merged_at, expires_at, tags)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`,
    [
      data.pr_number,
      data.title,
      data.description,
      data.author,
      data.status,
      data.base_branch,
      data.head_branch,
      data.merged_at,
      expiresAt,
      JSON.stringify(scope),
    ]
  );
  return result.rows[0].id;
}
