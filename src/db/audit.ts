import { Pool } from 'pg';

export async function auditLog(
  pool: Pool,
  entityType: string,
  entityId: string,
  operation: 'INSERT' | 'UPDATE' | 'DELETE',
  changeSummary?: Record<string, unknown>,
  actor?: string
): Promise<void> {
  await pool.query(
    `INSERT INTO event_audit (entity_type, entity_id, operation, actor, change_summary)
     VALUES ($1, $2, $3, $4, $5)`,
    [entityType, entityId, operation, actor, JSON.stringify(changeSummary || {})]
  );
}
