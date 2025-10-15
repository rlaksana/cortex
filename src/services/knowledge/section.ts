import { Pool } from 'pg';
import type { SectionData, ScopeFilter } from '../../types/knowledge-data.js';
import { validateSpecWriteLock } from '../../utils/immutability.js';

/**
 * Update existing section with write-lock checks
 *
 * @throws ImmutabilityViolationError if section is in approved document
 */
export async function updateSection(
  pool: Pool,
  id: string,
  data: Partial<SectionData>,
  scope?: ScopeFilter
): Promise<void> {
  // Check write-lock before allowing update
  await validateSpecWriteLock(pool, id);

  const updates: string[] = [];
  const values: unknown[] = [];
  let paramIndex = 1;

  if (data.title !== undefined) {
    updates.push(`heading = $${paramIndex++}`);
    values.push(data.title);
  }
  if (data.body_md !== undefined || data.body_text !== undefined) {
    updates.push(`body_jsonb = $${paramIndex++}`);
    values.push({ text: data.body_md || data.body_text });
  }
  if (scope !== undefined) {
    updates.push(`tags = $${paramIndex++}`);
    values.push(JSON.stringify(scope));
  }

  if (updates.length === 0) {
    return; // No updates to perform
  }

  updates.push(`updated_at = CURRENT_TIMESTAMP`);
  values.push(id);

  await pool.query(`UPDATE section SET ${updates.join(', ')} WHERE id = $${paramIndex}`, values);
}
