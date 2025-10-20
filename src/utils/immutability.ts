import { Pool } from 'pg';

export class ImmutabilityViolationError extends Error {
  constructor(
    message: string,
    // eslint-disable-next-line no-unused-vars
    public readonly errorCode: string,
    // eslint-disable-next-line no-unused-vars
    public readonly field?: string
  ) {
    super(message);
    this.name = 'ImmutabilityViolationError';
  }
}

/**
 * Check if ADR update violates immutability rules
 *
 * Rule: Once ADR status = 'accepted', content becomes immutable
 * Rationale: Accepted decisions are authoritative and should not be retroactively changed
 *
 * @param pool - Database connection pool
 * @param id - ADR UUID to check
 * @throws ImmutabilityViolationError if ADR is accepted
 */
export async function validateADRImmutability(pool: Pool, id: string): Promise<void> {
  const result = await pool.query(`SELECT status FROM adr_decision WHERE id = $1`, [id]);

  if (result.rows.length === 0) {
    throw new Error(`ADR with id ${id} not found`);
  }

  const currentStatus = (result.rows[0] as Record<string, unknown>).status;

  if (currentStatus === 'accepted') {
    throw new ImmutabilityViolationError(
      'Cannot modify accepted ADR. Create a new ADR with supersedes reference instead.',
      'IMMUTABILITY_VIOLATION',
      'status'
    );
  }
}

/**
 * Check if document update violates approved spec write-lock
 *
 * Rule: Once document.approved_at is set, all child sections become read-only
 * Rationale: Approved specs are authoritative and prevent drift
 *
 * @param pool - Database connection pool
 * @param sectionId - Section UUID to check
 * @throws ImmutabilityViolationError if parent document is approved
 */
export async function validateSpecWriteLock(pool: Pool, sectionId: string): Promise<void> {
  const result = await pool.query(
    `SELECT d.approved_at
     FROM section s
     JOIN document d ON s.document_id = d.id
     WHERE s.id = $1`,
    [sectionId]
  );

  if (result.rows.length === 0) {
    throw new Error(`Section with id ${sectionId} not found`);
  }

  const approvedAt = (result.rows[0] as Record<string, unknown>).approved_at;

  if (approvedAt !== null) {
    throw new ImmutabilityViolationError(
      `Cannot modify section in approved document (approved at ${approvedAt}). Create a new document version instead.`,
      'WRITE_LOCK_VIOLATION',
      'approved_at'
    );
  }
}

/**
 * Check if event_audit modification violates append-only policy
 *
 * Rule: Audit log is append-only - no updates or deletes
 * Rationale: Audit integrity requires immutable event history
 *
 * @throws ImmutabilityViolationError always (audit log is append-only)
 */
export function validateAuditAppendOnly(): void {
  throw new ImmutabilityViolationError(
    'Audit log is append-only. Cannot modify or delete existing audit entries.',
    'AUDIT_APPEND_ONLY_VIOLATION'
  );
}

/**
 * Check if operation would violate any immutability constraints
 *
 * @param entityType - Type of entity being modified
 * @param operation - Operation being performed (UPDATE, DELETE)
 * @returns Error code if violation, null if allowed
 */
export function checkImmutabilityConstraint(
  entityType: string,
  operation: 'UPDATE' | 'DELETE'
): string | null {
  // Audit log is always append-only
  if (entityType === 'event_audit' && (operation === 'UPDATE' || operation === 'DELETE')) {
    return 'AUDIT_APPEND_ONLY_VIOLATION';
  }

  return null;
}
