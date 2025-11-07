/**
 * Audit Service Adapter
 *
 * Adapts the AuditService to implement the IAuditService interface.
 * Bridges interface gaps while maintaining backward compatibility.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import type { IAuditService } from '../service-interfaces.js';
import { auditService } from '../../services/audit/audit-service.js';

/**
 * Adapter for Audit service
 */
export class AuditServiceAdapter implements IAuditService {
  constructor(private service = auditService) {}

  /**
   * Log an audit event
   */
  async log(action: string, data: any): Promise<void> {
    // Map to the audit service's logSearchOperation method
    this.service.logSearchOperation(
      data.userId || 'anonymous',
      data.query || '',
      data.resultsFound || 0
    );
  }

  /**
   * Query audit events with filters
   */
  async query(filters: Record<string, any>): Promise<any[]> {
    const events = this.service.searchAuditEvents({
      userId: filters.userId,
      action: filters.eventType,
      resource: filters.operation,
      outcome: filters.success ? 'success' : 'failure',
      startDate: filters.startDate,
      endDate: filters.endDate,
    });

    return events;
  }

  /**
   * Archive audit events before a specified date
   */
  async archive(before: Date): Promise<number> {
    const result = this.service.cleanupOldEvents(before);
    return result;
  }
}
