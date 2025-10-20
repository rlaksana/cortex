import { Pool } from 'pg';
import type { DecisionData, ScopeFilter } from '../../types/knowledge-data.js';
import { validateADRImmutability } from '../../utils/immutability.js';

export async function storeDecision(
  pool: Pool,
  data: DecisionData,
  scope: ScopeFilter
): Promise<string> {
  const result = await pool.query<{ id: string }>(
    `INSERT INTO adr_decision (component, status, title, rationale, alternatives_considered, consequences, supersedes, tags)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
    [
      data.component,
      data.status,
      data.title,
      data.rationale,
      data.alternatives_considered || [],
      data.consequences,
      data.supersedes,
      JSON.stringify(scope),
    ]
  );
  return result.rows[0].id;
}

/**
 * Update existing ADR with immutability checks
 *
 * @throws ImmutabilityViolationError if ADR status is 'accepted'
 */
export async function updateDecision(
  pool: Pool,
  id: string,
  data: Partial<DecisionData>
): Promise<void> {
  // Check immutability before allowing update
  await validateADRImmutability(pool, id);

  const updates: string[] = [];
  const values: unknown[] = [];
  let paramIndex = 1;

  if (data.component !== undefined) {
    updates.push(`component = $${paramIndex++}`);
    values.push(data.component);
  }
  if (data.status !== undefined) {
    updates.push(`status = $${paramIndex++}`);
    values.push(data.status);
  }
  if (data.title !== undefined) {
    updates.push(`title = $${paramIndex++}`);
    values.push(data.title);
  }
  if (data.rationale !== undefined) {
    updates.push(`rationale = $${paramIndex++}`);
    values.push(data.rationale);
  }
  if (data.alternatives_considered !== undefined) {
    updates.push(`alternatives_considered = $${paramIndex++}`);
    values.push(data.alternatives_considered || []);
  }
  if (data.consequences !== undefined) {
    updates.push(`consequences = $${paramIndex++}`);
    values.push(data.consequences);
  }

  if (updates.length === 0) {
    return; // No updates to perform
  }

  values.push(id);
  await pool.query(
    `UPDATE adr_decision SET ${updates.join(', ')} WHERE id = $${paramIndex}`,
    values
  );
}
