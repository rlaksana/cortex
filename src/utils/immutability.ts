import { getQdrantClient } from '../db/qdrant.js';

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
 * @param id - ADR UUID to check
 * @throws ImmutabilityViolationError if ADR is accepted
 */
export async function validateADRImmutability(id: string): Promise<void> {
  const qdrant = getQdrantClient();

  const decision = await qdrant.adrDecision.findUnique({
    where: { id },
    select: { status: true },
  });

  if (!decision) {
    throw new Error(`ADR with id ${id} not found`);
  }

  if (decision.status === 'accepted') {
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
 * Note: Document functionality not implemented in current schema - this is a placeholder
 * for future document approval workflow implementation.
 *
 * @param sectionId - Section UUID to check
 * @throws ImmutabilityViolationError if parent document is approved
 */
export async function validateSpecWriteLock(sectionId: string): Promise<void> {
  const qdrant = getQdrantClient();

  // First get the section to verify it exists
  const section = await qdrant.section.findUnique({
    where: { id: sectionId },
    select: { id: true },
  });

  if (!section) {
    throw new Error(`Section with id ${sectionId} not found`);
  }

  // Document approval workflow not implemented in current schema
  // This function serves as a placeholder for future document approval features
  // Currently, all sections are editable as there is no document concept in the schema
  return;
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
 * @param entity_type - Type of entity being modified
 * @param operation - Operation being performed (UPDATE, DELETE)
 * @returns Error code if violation, null if allowed
 */
export function checkImmutabilityConstraint(
  entity_type: string,
  operation: 'UPDATE' | 'DELETE'
): string | null {
  // Audit log is always append-only
  if (entity_type === 'event_audit' && (operation === 'UPDATE' || operation === 'DELETE')) {
    return 'AUDIT_APPEND_ONLY_VIOLATION';
  }

  return null;
}
