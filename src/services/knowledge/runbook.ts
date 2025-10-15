import { Pool } from 'pg';
import type { RunbookData, ScopeFilter } from '../../types/knowledge-data.js';

export async function storeRunbook(
  pool: Pool,
  data: RunbookData,
  scope: ScopeFilter
): Promise<string> {
  const result = await pool.query<{ id: string }>(
    `INSERT INTO runbook (service, steps_jsonb, owner, tags)
     VALUES ($1, $2, $3, $4) RETURNING id`,
    [data.service, JSON.stringify(data.steps), data.owner, JSON.stringify(scope)]
  );
  return result.rows[0].id;
}
