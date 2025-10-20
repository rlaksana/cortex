import { Pool } from 'pg';
import { computeContentHash } from '../../utils/hash.js';
import type { ChangeData, ScopeFilter } from '../../types/knowledge-data.js';

export async function storeChange(
  pool: Pool,
  data: ChangeData,
  scope: ScopeFilter
): Promise<string> {
  const hash = computeContentHash(data.summary);
  const result = await pool.query<{ id: string }>(
    `INSERT INTO change_log (change_type, subject_ref, summary, details, content_hash, affected_files, author, commit_sha, tags)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
    [
      data.change_type,
      data.subject_ref,
      data.summary,
      data.details,
      hash,
      data.affected_files || [],
      data.author,
      data.commit_sha,
      JSON.stringify(scope),
    ]
  );
  return result.rows[0].id;
}
