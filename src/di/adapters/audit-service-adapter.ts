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
    await this.service.logSearchOperation(
      data.query || '',
      data.resultsFound || 0,
      data.strategy || 'unknown',
      data.scope,
      data.userId,
      data.duration
    );
  }

  /**
   * Query audit events with filters
   */
  async query(filters: Record<string, any>): Promise<any[]> {
    const searchResult = await this.service.searchAuditEvents({
      userId: filters.userId,
      eventType: filters.eventType,
      operation: filters.operation,
      startDate: filters.startDate,
      endDate: filters.endDate,
      success: filters.success,
      limit: filters.limit,
      offset: filters.offset,
    });

    return searchResult.events;
  }

  /**
   * Archive audit events before a specified date
   */
  async archive(before: Date): Promise<number> {
    const retentionDays = Math.floor((Date.now() - before.getTime()) / (1000 * 60 * 60 * 24));
    const result = await this.service.cleanupOldEvents(retentionDays);
    return result.deletedCount;
  }
}
