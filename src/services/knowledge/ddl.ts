import { Pool } from 'pg';
import { createHash } from 'crypto';
import type { DDLData } from '../../types/knowledge-data.js';

export async function storeDDL(pool: Pool, data: DDLData): Promise<string> {
  const checksum = createHash('sha256').update(data.ddl_text).digest('hex');
  if (data.checksum && checksum !== data.checksum) {
    throw new Error('DDL checksum mismatch');
  }

  const result = await pool.query<{ id: string }>(
    `INSERT INTO ddl_history (migration_id, ddl_text, checksum, description)
     VALUES ($1, $2, $3, $4) RETURNING id`,
    [data.migration_id, data.ddl_text, checksum, data.description]
  );
  return result.rows[0].id;
}
