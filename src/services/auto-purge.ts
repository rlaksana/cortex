/**
 * Auto-Purge Service
 *
 * Implements threshold-based automatic cleanup of old data.
 * Triggers when time threshold (24h) OR operation threshold (1000 ops) exceeded.
 *
 * Pattern: PostgreSQL autovacuum-inspired opportunistic cleanup
 *
 * @module services/auto-purge
 */

import type { Pool } from 'pg';
import { logger } from '../utils/logger.js';

interface PurgeMetadata {
  id: number;
  last_purge_at: Date;
  operations_since_purge: number;
  time_threshold_hours: number;
  operation_threshold: number;
  deleted_counts: Record<string, number>;
  last_duration_ms: number | null;
  enabled: boolean;
  created_at: Date;
  updated_at: Date;
}

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
 * @param pool - PostgreSQL connection pool
 * @param source - Tool that triggered the check
 */
export async function checkAndPurge(
  pool: Pool,
  source: 'memory.store' | 'memory.find'
): Promise<void> {
  // Increment operation counter
  await pool.query(
    'UPDATE purge_metadata SET operations_since_purge = operations_since_purge + 1 WHERE id = 1'
  );

  // Get current state
  const result = await pool.query<PurgeMetadata>('SELECT * FROM purge_metadata WHERE id = 1');
  const meta = result.rows[0] as unknown as PurgeMetadata;

  if (!meta) {
    logger.error('Purge metadata not found, skipping purge check');
    return;
  }

  // Check if purge is enabled
  if (!meta.enabled) {
    return;
  }

  // Calculate time elapsed since last purge
  const hoursSince = (Date.now() - new Date(meta.last_purge_at).getTime()) / 3600000;

  // Check thresholds
  const timeThresholdExceeded = hoursSince >= (meta.time_threshold_hours as number);
  const operationThresholdExceeded = (meta.operations_since_purge as number) >= (meta.operation_threshold as number);

  if (!timeThresholdExceeded && !operationThresholdExceeded) {
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
  runPurge(pool, triggeredBy, source).catch((err: unknown) => {
    logger.error({ err, source }, 'Auto-purge failed');
  });
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
 * @param pool - PostgreSQL connection pool
 * @param triggeredBy - Which threshold was exceeded
 * @param source - Tool that triggered purge
 */
async function runPurge(
  pool: Pool,
  triggeredBy: 'time_threshold' | 'operation_threshold' | 'manual',
  source: 'memory.store' | 'memory.find' | 'manual'
): Promise<PurgeResult> {
  const startTime = Date.now();
  const deletedCounts: Record<string, number> = {};

  try {
    // Rule 1: Delete closed todos > 90 days
    const r1 = await pool.query(`
      DELETE FROM todo_log
      WHERE status IN ('done', 'cancelled')
        AND closed_at IS NOT NULL
        AND closed_at < NOW() - INTERVAL '90 days'
      RETURNING id
    `);
    deletedCounts.todo = r1.rowCount ?? 0;

    // Rule 2: Delete old changes > 90 days
    const r2 = await pool.query(`
      DELETE FROM change_log
      WHERE created_at < NOW() - INTERVAL '90 days'
      RETURNING id
    `);
    deletedCounts.change = r2.rowCount ?? 0;

    // Rule 3: Delete merged PRs > 30 days
    const r3 = await pool.query(`
      DELETE FROM pr_context
      WHERE status = 'merged'
        AND merged_at IS NOT NULL
        AND merged_at < NOW() - INTERVAL '30 days'
      RETURNING id
    `);
    deletedCounts.pr_context = r3.rowCount ?? 0;

    // Rule 4: Delete closed issues > 90 days
    const r4 = await pool.query(`
      DELETE FROM issue_log
      WHERE status IN ('closed', 'wont_fix')
        AND updated_at < NOW() - INTERVAL '90 days'
      RETURNING id
    `);
    deletedCounts.issue = r4.rowCount ?? 0;

    // Rule 5: Hard delete soft-deleted graph entities > 90 days
    const r5 = await pool.query(`
      DELETE FROM knowledge_entity
      WHERE deleted_at IS NOT NULL
        AND deleted_at < NOW() - INTERVAL '90 days'
      RETURNING id
    `);
    deletedCounts.entity = r5.rowCount ?? 0;

    // Rule 6: Hard delete soft-deleted relations > 90 days
    const r6 = await pool.query(`
      DELETE FROM knowledge_relation
      WHERE deleted_at IS NOT NULL
        AND deleted_at < NOW() - INTERVAL '90 days'
      RETURNING id
    `);
    deletedCounts.relation = r6.rowCount ?? 0;

    // Rule 7: Hard delete soft-deleted observations > 90 days
    const r7 = await pool.query(`
      DELETE FROM knowledge_observation
      WHERE deleted_at IS NOT NULL
        AND deleted_at < NOW() - INTERVAL '90 days'
      RETURNING id
    `);
    deletedCounts.observation = r7.rowCount ?? 0;

    // Rule 8: Delete resolved incidents > 90 days
    const r8 = await pool.query(`
      DELETE FROM incident_log
      WHERE resolution_status IN ('resolved', 'closed')
        AND updated_at < NOW() - INTERVAL '90 days'
      RETURNING id
    `);
    deletedCounts.incident = r8.rowCount ?? 0;

    // Rule 9: Delete completed releases > 90 days
    const r9 = await pool.query(`
      DELETE FROM release_log
      WHERE status IN ('completed', 'rolled_back')
        AND updated_at < NOW() - INTERVAL '90 days'
      RETURNING id
    `);
    deletedCounts.release = r9.rowCount ?? 0;

    // Rule 10: Delete closed risks > 90 days
    const r10 = await pool.query(`
      DELETE FROM risk_log
      WHERE status IN ('closed', 'accepted')
        AND updated_at < NOW() - INTERVAL '90 days'
      RETURNING id
    `);
    deletedCounts.risk = r10.rowCount ?? 0;

    // Rule 11: Delete validated assumptions > 90 days
    const r11 = await pool.query(`
      DELETE FROM assumption_log
      WHERE validation_status = 'validated'
        AND updated_at < NOW() - INTERVAL '90 days'
      RETURNING id
    `);
    deletedCounts.assumption = r11.rowCount ?? 0;

    const durationMs = Date.now() - startTime;
    const totalDeleted = Object.values(deletedCounts).reduce((sum, n) => sum + n, 0);

    // Update purge metadata
    await pool.query(
      `UPDATE purge_metadata
       SET last_purge_at = NOW(),
           operations_since_purge = 0,
           deleted_counts = $1,
           last_duration_ms = $2
       WHERE id = 1`,
      [JSON.stringify(deletedCounts), durationMs]
    );

    logger.info(
      {
        deleted_counts: deletedCounts,
        total_deleted: totalDeleted,
        duration_ms: durationMs,
        triggered_by: triggeredBy,
        source,
      },
      'Auto-purge completed successfully'
    );

    return {
      deleted_counts: deletedCounts,
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
 * @param pool - PostgreSQL connection pool
 * @returns Purge result
 */
export async function manualPurge(pool: Pool): Promise<PurgeResult> {
  logger.info('Manual purge triggered');
  return await runPurge(pool, 'manual', 'manual');
}

/**
 * Get current purge status and statistics
 *
 * @param pool - PostgreSQL connection pool
 * @returns Purge metadata
 */
export async function getPurgeStatus(pool: Pool) {
  const result = await pool.query<PurgeMetadata>('SELECT * FROM purge_metadata WHERE id = 1');
  const meta = result.rows[0] as unknown as PurgeMetadata;

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

function estimateNextPurge(meta: PurgeMetadata, hoursSince: number): string {
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
