import { logger } from './logger.js';

export class ImmutabilityViolationError extends Error {
  constructor(
    message: string,
    public readonly _errorCode: string,
    public readonly _field?: string
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
export async function validateADRImmutability(_id: string): Promise<void> {
  // Placeholder implementation - immutability checks would require database access
  // For now, we'll just log and allow the operation
  logger.debug({ id: _id }, 'ADR immutability check - placeholder implementation');

  // TODO: Implement actual immutability check when database interface is available
  // This would typically check if a decision with 'accepted' status exists
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
export async function validateSpecWriteLock(_sectionId: string): Promise<void> {
  // Placeholder implementation - document approval workflow not implemented
  logger.debug({ sectionId: _sectionId }, 'Section write-lock check - placeholder implementation');

  // TODO: Implement actual document approval workflow check
  // This would typically check if the parent document is approved
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
