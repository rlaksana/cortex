import { Pool } from 'pg';
import type { ReleaseNoteData, ScopeFilter } from '../../types/knowledge-data.js';

export async function storeReleaseNote(
  pool: Pool,
  data: ReleaseNoteData,
  scope: ScopeFilter
): Promise<string> {
  const result = await pool.query<{ id: string }>(
    `INSERT INTO release_note (version, release_date, summary, breaking_changes, new_features, bug_fixes, deprecations, tags)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
    [
      data.version,
      data.release_date,
      data.summary,
      JSON.stringify(data.breaking_changes),
      JSON.stringify(data.new_features),
      JSON.stringify(data.bug_fixes),
      JSON.stringify(data.deprecations),
      JSON.stringify(scope),
    ]
  );
  return result.rows[0].id;
}
