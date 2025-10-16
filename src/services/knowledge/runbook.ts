import { Pool } from 'pg';
import type { RunbookData, ScopeFilter } from '../../types/knowledge-data.js';
import { logger } from '../../utils/logger.js';

export async function storeRunbook(
  pool: Pool,
  data: RunbookData,
  scope: ScopeFilter
): Promise<string> {
  const result = await pool.query<{ id: string }>(
    `INSERT INTO runbook (service, title, description, steps_jsonb, triggers, tags, metadata)
     VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
    [
      data.service,
      data.title,
      data.description ?? null,
      JSON.stringify(data.steps),
      data.triggers ?? [],
      JSON.stringify(scope),
      JSON.stringify({}),
    ]
  );

  logger.info(
    { runbookId: result.rows[0].id, service: data.service },
    'Runbook stored successfully'
  );
  return result.rows[0].id;
}

export async function updateRunbook(
  pool: Pool,
  id: string,
  data: Partial<RunbookData>
): Promise<void> {
  const updates: string[] = [];
  const values: unknown[] = [];
  let paramIndex = 1;

  if (data.service !== undefined) {
    updates.push(`service = $${paramIndex++}`);
    values.push(data.service);
  }
  if (data.title !== undefined) {
    updates.push(`title = $${paramIndex++}`);
    values.push(data.title);
  }
  if (data.description !== undefined) {
    updates.push(`description = $${paramIndex++}`);
    values.push(data.description);
  }
  if (data.steps !== undefined) {
    updates.push(`steps_jsonb = $${paramIndex++}`);
    values.push(JSON.stringify(data.steps));
  }
  if (data.triggers !== undefined) {
    updates.push(`triggers = $${paramIndex++}`);
    values.push(data.triggers);
  }
  if (data.last_verified_at !== undefined) {
    updates.push(`last_verified_at = $${paramIndex++}`);
    values.push(data.last_verified_at);
  }

  if (updates.length === 0) {
    return; // No updates to perform
  }

  updates.push(`updated_at = CURRENT_TIMESTAMP`);
  values.push(id);

  await pool.query(`UPDATE runbook SET ${updates.join(', ')} WHERE id = $${paramIndex}`, values);
  logger.info({ runbookId: id, updates: updates.length }, 'Runbook updated successfully');
}

export async function findRunbooks(
  pool: Pool,
  criteria: {
    service?: string;
    limit?: number;
    offset?: number;
  }
): Promise<
  Array<{
    id: string;
    service: string;
    title: string;
    description: string;
    steps_jsonb: unknown;
    triggers: string[];
    last_verified_at: Date;
    created_at: Date;
    updated_at: Date;
  }>
> {
  const conditions: string[] = [];
  const values: unknown[] = [];
  let paramIndex = 1;

  if (criteria.service) {
    conditions.push(`service ILIKE $${paramIndex}`);
    values.push(`%${criteria.service}%`);
    paramIndex++;
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const limitClause = criteria.limit ? `LIMIT $${paramIndex++}` : '';
  const offsetClause = criteria.offset ? `OFFSET $${paramIndex++}` : '';

  if (criteria.limit) values.push(criteria.limit);
  if (criteria.offset) values.push(criteria.offset);

  const result = await pool.query<{
    id: string;
    service: string;
    title: string;
    description: string;
    steps_jsonb: unknown;
    triggers: string[];
    last_verified_at: Date;
    created_at: Date;
    updated_at: Date;
  }>(
    `SELECT id, service, title, description, steps_jsonb, triggers, last_verified_at, created_at, updated_at
     FROM runbook ${whereClause}
     ORDER BY updated_at DESC ${limitClause} ${offsetClause}`,
    values
  );

  return result.rows;
}
