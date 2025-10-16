import { Pool } from 'pg';
import type { SectionData, ScopeFilter } from '../../types/knowledge-data.js';
import { validateSpecWriteLock } from '../../utils/immutability.js';
import { logger } from '../../utils/logger.js';

/**
 * Store a new section in the database
 */
export async function storeSection(
  pool: Pool,
  data: SectionData,
  scope?: ScopeFilter
): Promise<string> {
  const result = await pool.query<{ id: string }>(
    `INSERT INTO section (heading, title, body_md, body_text, body_jsonb, tags, metadata)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     RETURNING id`,
    [
      data.heading,
      data.title,
      data.body_md ?? null,
      data.body_text ?? null,
      { text: data.body_text ?? data.body_md, markdown: data.body_md },
      JSON.stringify(scope ?? {}),
      JSON.stringify({}),
    ]
  );

  logger.info({ sectionId: result.rows[0].id, title: data.title }, 'Section stored successfully');
  return result.rows[0].id;
}

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
    updates.push(`title = $${paramIndex++}`);
    values.push(data.title);
  }
  if (data.heading !== undefined) {
    updates.push(`heading = $${paramIndex++}`);
    values.push(data.heading);
  }
  if (data.body_md !== undefined) {
    updates.push(`body_md = $${paramIndex++}`);
    values.push(data.body_md);
  }
  if (data.body_text !== undefined) {
    updates.push(`body_text = $${paramIndex++}`);
    values.push(data.body_text);
  }
  if (data.body_md !== undefined || data.body_text !== undefined) {
    updates.push(`body_jsonb = $${paramIndex++}`);
    values.push({ text: data.body_text ?? data.body_md, markdown: data.body_md });
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
  logger.info({ sectionId: id, updates: updates.length }, 'Section updated successfully');
}

/**
 * Find sections by various criteria
 */
export async function findSections(
  pool: Pool,
  criteria: {
    title?: string;
    documentId?: string;
    limit?: number;
    offset?: number;
  }
): Promise<
  Array<{
    id: string;
    title: string;
    heading: string;
    body_text: string;
    body_md: string;
    citation_count: number;
    created_at: Date;
    updated_at: Date;
  }>
> {
  const conditions: string[] = [];
  const values: unknown[] = [];
  let paramIndex = 1;

  if (criteria.title) {
    conditions.push(`(title ILIKE $${paramIndex} OR heading ILIKE $${paramIndex})`);
    values.push(`%${criteria.title}%`);
    paramIndex++;
  }

  if (criteria.documentId) {
    conditions.push(`document_id = $${paramIndex}`);
    values.push(criteria.documentId);
    paramIndex++;
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const limitClause = criteria.limit ? `LIMIT $${paramIndex++}` : '';
  const offsetClause = criteria.offset ? `OFFSET $${paramIndex++}` : '';

  if (criteria.limit) values.push(criteria.limit);
  if (criteria.offset) values.push(criteria.offset);

  const result = await pool.query<{
    id: string;
    title: string;
    heading: string;
    body_text: string;
    body_md: string;
    citation_count: number;
    created_at: Date;
    updated_at: Date;
  }>(
    `SELECT id, title, heading, body_text, body_md, citation_count, created_at, updated_at
     FROM section ${whereClause}
     ORDER BY updated_at DESC ${limitClause} ${offsetClause}`,
    values
  );

  return result.rows;
}
