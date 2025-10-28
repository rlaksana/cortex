/**
 * Auto-Purge Service
 *
 * Implements threshold-based automatic cleanup of old data.
 * Triggers when time threshold (24h) OR operation threshold (1000 ops) exceeded.
 *
 * Pattern: qdrant autovacuum-inspired opportunistic cleanup
 *
 * @module services/auto-purge
 */

import { logger } from '../utils/logger';
import { qdrant } from '../db/qdrant';
import { dbErrorHandler } from '../utils/db-error-handler';

export interface PurgeResult {
  deleted_counts: Record<string, number>;
  total_deleted: number;
  duration_ms: number;
  triggered_by: 'time_threshold' | 'operation_threshold' | 'manual';
  triggered_from: 'memory.store' | 'memory.find' | 'manual';
}

/**
 * Check if purge should run based on thresholds
 * Increments operation counter on every call
 *
 * @param source - Tool that triggered the check
 */
export async function checkAndPurge(source: 'memory.store' | 'memory.find'): Promise<void> {
  try {
    // Update operation counter with error handling
    const updateResult = await dbErrorHandler.executeWithRetry(
      () =>
        qdrant.getClient().purgeMetadata.update({
          where: { id: 1 },
          data: {
            operations_since_purge: { increment: 1 },
          },
        }),
      'auto-purge.update-counter',
      { maxRetries: 2, baseDelayMs: 500 }
    );

    if (!updateResult.success) {
      logger.warn(
        { error: updateResult.error, source },
        'Failed to update purge counter, skipping purge check'
      );
      return;
    }

    // Get current state
    const meta = await qdrant.getClient().purgeMetadata.findUnique({
      where: { id: 1 },
    });

    if (!meta) {
      logger.error('Purge metadata not found, creating initial record');
      await qdrant.getClient().purgeMetadata.create({
        data: {
          id: 1,
          time_threshold_hours: 24,
          operation_threshold: 1000,
        },
      });
      return;
    }

    // Check if purge is enabled
    if (!meta.enabled) {
      return;
    }

    // Calculate time elapsed since last purge
    const hoursSince = (Date.now() - new Date(meta.last_purge_at).getTime()) / 3600000;

    // Check thresholds
    const timeThresholdExceeded = hoursSince >= meta.time_threshold_hours;
    const operation_thresholdExceeded = meta.operations_since_purge >= meta.operation_threshold;

    if (!timeThresholdExceeded && !operation_thresholdExceeded) {
      // No purge needed
      return;
    }

    const triggeredBy = timeThresholdExceeded ? 'time_threshold' : 'operation_threshold';

    logger.info(
      {
        hours_since: hoursSince.toFixed(2),
        operations_since: meta.operations_since_purge,
        triggered_by: triggeredBy,
        triggered_from: source,
      },
      'Auto-purge triggered'
    );

    // Run purge asynchronously (non-blocking)
    runPurge(triggeredBy, source).catch((err: unknown) => {
      logger.error({ err, source }, 'Auto-purge failed');
    });
  } catch (error) {
    logger.error({ error, source }, 'Auto-purge check failed');
  }
}

/**
 * Execute purge of old data based on TTL policies
 *
 * TTL Policies (from constitution.md):
 * - todo_log: 90 days after closure
 * - change_log: 90 days after creation
 * - pr_context: 30 days after merge
 * - issue_log: 90 days after closure
 * - knowledge_entity: 90 days after soft delete
 * - knowledge_relation: 90 days after soft delete
 * - knowledge_observation: 90 days after soft delete
 * - incident_log: 90 days after resolution
 * - release_log: 90 days after completion
 * - risk_log: 90 days after closure
 * - assumption_log: 90 days after validation
 *
 * @param triggeredBy - Which threshold was exceeded
 * @param source - Tool that triggered purge
 */
async function runPurge(
  triggeredBy: 'time_threshold' | 'operation_threshold' | 'manual',
  source: 'memory.store' | 'memory.find' | 'manual'
): Promise<PurgeResult> {
  const startTime = Date.now();
  const deleted_counts: Record<string, number> = {};
  const ninetyDaysAgo = new Date();
  ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90);
  const thirtyDaysAgo = new Date();
  thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

  try {
    // Rule 1: Delete closed todos > 90 days
    const r1 = await qdrant.getClient().todoLog.deleteMany({
      where: {
        status: { in: ['done', 'cancelled'] },
        closed_at: { lt: ninetyDaysAgo },
      },
    });
    deleted_counts.todo = r1.count;

    // Rule 2: Delete old changes > 90 days
    const r2 = await qdrant.getClient().changeLog.deleteMany({
      where: {
        created_at: { lt: ninetyDaysAgo },
      },
    });
    deleted_counts.change = r2.count;

    // Rule 3: Delete merged PRs > 30 days
    const r3 = await qdrant.getClient().prContext.deleteMany({
      where: {
        status: 'merged',
        merged_at: { lt: thirtyDaysAgo },
      },
    });
    deleted_counts.pr_context = r3.count;

    // Rule 4: Delete closed issues > 90 days
    const r4 = await qdrant.getClient().issueLog.deleteMany({
      where: {
        status: { in: ['closed', 'wont_fix'] },
        updated_at: { lt: ninetyDaysAgo },
      },
    });
    deleted_counts.issue = r4.count;

    // Rule 5: Hard delete soft-deleted graph entities > 90 days
    const r5 = await qdrant.getClient().knowledgeEntity.deleteMany({
      where: {
        deleted_at: { lt: ninetyDaysAgo },
      },
    });
    deleted_counts.entity = r5.count;

    // Rule 6: Hard delete soft-deleted relations > 90 days
    const r6 = await qdrant.getClient().knowledgeRelation.deleteMany({
      where: {
        deleted_at: { lt: ninetyDaysAgo },
      },
    });
    deleted_counts.relation = r6.count;

    // Rule 7: Hard delete soft-deleted observations > 90 days
    const r7 = await qdrant.getClient().knowledgeObservation.deleteMany({
      where: {
        deleted_at: { lt: ninetyDaysAgo },
      },
    });
    deleted_counts.observation = r7.count;

    // Rule 8: Delete resolved incidents > 90 days
    const r8 = await qdrant.getClient().incidentLog.deleteMany({
      where: {
        resolution_status: { in: ['resolved', 'closed'] },
        updated_at: { lt: ninetyDaysAgo },
      },
    });
    deleted_counts.incident = r8.count;

    // Rule 9: Delete completed releases > 90 days
    const r9 = await qdrant.getClient().releaseLog.deleteMany({
      where: {
        status: { in: ['completed', 'rolled_back'] },
        updated_at: { lt: ninetyDaysAgo },
      },
    });
    deleted_counts.release = r9.count;

    // Rule 10: Delete closed risks > 90 days
    const r10 = await qdrant.getClient().riskLog.deleteMany({
      where: {
        status: { in: ['closed', 'accepted'] },
        updated_at: { lt: ninetyDaysAgo },
      },
    });
    deleted_counts.risk = r10.count;

    // Rule 11: Delete validated assumptions > 90 days
    const r11 = await qdrant.getClient().assumptionLog.deleteMany({
      where: {
        validation_status: 'validated',
        updated_at: { lt: ninetyDaysAgo },
      },
    });
    deleted_counts.assumption = r11.count;

    const durationMs = Date.now() - startTime;
    const totalDeleted = Object.values(deleted_counts).reduce((sum, n) => sum + n, 0);

    // Update purge metadata
    await qdrant.getClient().purgeMetadata.update({
      where: { id: 1 },
      data: {
        last_purge_at: new Date(),
        operations_since_purge: 0,
        deleted_counts,
        last_duration_ms: durationMs,
      },
    });

    logger.info(
      {
        deleted_counts,
        total_deleted: totalDeleted,
        duration_ms: durationMs,
        triggered_by: triggeredBy,
        source,
      },
      'Auto-purge completed successfully'
    );

    return {
      deleted_counts,
      total_deleted: totalDeleted,
      duration_ms: durationMs,
      triggered_by: triggeredBy,
      triggered_from: source,
    };
  } catch (err) {
    logger.error({ err, source, triggered_by: triggeredBy }, 'Auto-purge encountered error');
    throw err;
  }
}

/**
 * Manually trigger purge (for admin/debug purposes)
 *
 * @returns Purge result
 */
export async function manualPurge(): Promise<PurgeResult> {
  logger.info('Manual purge triggered');
  return await runPurge('manual', 'manual');
}

/**
 * Get current purge status and statistics
 *
 * @returns Purge metadata
 */
export async function getPurgeStatus() {
  const meta = await qdrant.getClient().purgeMetadata.findUnique({
    where: { id: 1 },
  });

  if (!meta) {
    throw new Error('Purge metadata not found');
  }

  const hoursSince = (Date.now() - new Date(meta.last_purge_at).getTime()) / 3600000;

  return {
    enabled: meta.enabled,
    last_purge_at: meta.last_purge_at,
    hours_since_purge: hoursSince.toFixed(2),
    operations_since_purge: meta.operations_since_purge,
    time_threshold_hours: meta.time_threshold_hours,
    operation_threshold: meta.operation_threshold,
    last_deleted_counts: meta.deleted_counts,
    last_duration_ms: meta.last_duration_ms,
    next_purge_estimate: estimateNextPurge(meta, hoursSince),
  };
}

function estimateNextPurge(meta: any, hoursSince: number): string {
  const hoursRemaining = meta.time_threshold_hours - hoursSince;
  const opsRemaining = meta.operation_threshold - meta.operations_since_purge;

  if (hoursRemaining <= 0 || opsRemaining <= 0) {
    return 'imminent';
  }

  if (hoursRemaining < opsRemaining / 100) {
    // Assuming ~100 ops/hour
    return `~${Math.ceil(hoursRemaining)} hours (time threshold)`;
  } else {
    return `~${opsRemaining} operations (operation threshold)`;
  }
}
