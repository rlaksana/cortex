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

import { logger } from '@/utils/logger.js';
import { QdrantOnlyDatabaseLayer, QdrantDatabaseConfig } from '../db/unified-database-layer-v2.js';
import { Environment } from '../config/environment.js';

export interface PurgeResult {
  deleted_counts: Record<string, number>;
  total_deleted: number;
  duration_ms: number;
  triggered_by: 'time_threshold' | 'operation_threshold' | 'manual';
  triggered_from: 'memory.store' | 'memory.find' | 'manual';
}

// Get database instance
let dbInstance: QdrantOnlyDatabaseLayer | null = null;

function getDatabase(): QdrantOnlyDatabaseLayer {
  if (!dbInstance) {
    const env = Environment.getInstance();
    const rawConfig = env.getRawConfig();
    const qdrantConfig: any = {
      url: rawConfig.QDRANT_URL || 'http://localhost:6333',
      collectionName: 'knowledge',
      timeout: 30000,
      batchSize: 100,
      maxRetries: 3,
    };

    // Only add apiKey if it exists (exactOptionalPropertyTypes compatibility)
    if (rawConfig.QDRANT_API_KEY) {
      qdrantConfig.apiKey = rawConfig.QDRANT_API_KEY;
    }

    const config: QdrantDatabaseConfig = {
      type: 'qdrant',
      qdrant: qdrantConfig,
    };
    dbInstance = new QdrantOnlyDatabaseLayer(config);
  }
  return dbInstance;
}

// Simple in-memory store for purge metadata (in production, use persistent storage)
const purgeMetadata: {
  enabled: boolean;
  last_purge_at: Date;
  operations_since_purge: number;
  time_threshold_hours: number;
  operation_threshold: number;
  deleted_counts: Record<string, number>;
  last_duration_ms: number;
} = {
  enabled: true,
  last_purge_at: new Date(),
  operations_since_purge: 0,
  time_threshold_hours: 24,
  operation_threshold: 1000,
  deleted_counts: {},
  last_duration_ms: 0,
};

/**
 * Check if purge should run based on thresholds
 * Increments operation counter on every call
 *
 * @param source - Tool that triggered the check
 */
export async function checkAndPurge(source: 'memory.store' | 'memory.find'): Promise<void> {
  try {
    // Update operation counter
    purgeMetadata.operations_since_purge += 1;

    // Check if purge is enabled
    if (!purgeMetadata.enabled) {
      return;
    }

    // Calculate time elapsed since last purge
    const hoursSince = (Date.now() - purgeMetadata.last_purge_at.getTime()) / 3600000;

    // Check thresholds
    const timeThresholdExceeded = hoursSince >= purgeMetadata.time_threshold_hours;
    const operation_thresholdExceeded =
      purgeMetadata.operations_since_purge >= purgeMetadata.operation_threshold;

    if (!timeThresholdExceeded && !operation_thresholdExceeded) {
      // No purge needed
      return;
    }

    const triggeredBy = timeThresholdExceeded ? 'time_threshold' : 'operation_threshold';

    logger.info(
      {
        hours_since: hoursSince.toFixed(2),
        operations_since: purgeMetadata.operations_since_purge,
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
    const db = getDatabase();

    // Rule 1: Delete closed todos > 90 days
    const todoFilter = {
      kind: 'todo',
      before: ninetyDaysAgo.toISOString(),
      scope: { metadata: { status: { in: ['done', 'cancelled'] } } },
    };
    const r1 = await db.bulkDelete(todoFilter);
    deleted_counts.todo = r1.deleted;

    // Rule 2: Delete old changes > 90 days
    const changeFilter = {
      kind: 'change',
      before: ninetyDaysAgo.toISOString(),
    };
    const r2 = await db.bulkDelete(changeFilter);
    deleted_counts.change = r2.deleted;

    // Rule 3: Delete merged PRs > 30 days
    const prFilter = {
      kind: 'pr_context',
      before: thirtyDaysAgo.toISOString(),
      scope: { metadata: { status: 'merged' } },
    };
    const r3 = await db.bulkDelete(prFilter);
    deleted_counts.pr_context = r3.deleted;

    // Rule 4: Delete closed issues > 90 days
    const issueFilter = {
      kind: 'issue',
      before: ninetyDaysAgo.toISOString(),
      scope: { metadata: { status: { in: ['closed', 'wont_fix'] } } },
    };
    const r4 = await db.bulkDelete(issueFilter);
    deleted_counts.issue = r4.deleted;

    // Rule 5: Hard delete soft-deleted graph entities > 90 days
    const entityFilter = {
      kind: 'entity',
      before: ninetyDaysAgo.toISOString(),
      scope: { metadata: { deleted_at: { exists: true } } },
    };
    const r5 = await db.bulkDelete(entityFilter);
    deleted_counts.entity = r5.deleted;

    // Rule 6: Hard delete soft-deleted relations > 90 days
    const relationFilter = {
      kind: 'relation',
      before: ninetyDaysAgo.toISOString(),
      scope: { metadata: { deleted_at: { exists: true } } },
    };
    const r6 = await db.bulkDelete(relationFilter);
    deleted_counts.relation = r6.deleted;

    // Rule 7: Hard delete soft-deleted observations > 90 days
    const observationFilter = {
      kind: 'observation',
      before: ninetyDaysAgo.toISOString(),
      scope: { metadata: { deleted_at: { exists: true } } },
    };
    const r7 = await db.bulkDelete(observationFilter);
    deleted_counts.observation = r7.deleted;

    // Rule 8: Delete resolved incidents > 90 days
    const incidentFilter = {
      kind: 'incident',
      before: ninetyDaysAgo.toISOString(),
      scope: { metadata: { resolution_status: { in: ['resolved', 'closed'] } } },
    };
    const r8 = await db.bulkDelete(incidentFilter);
    deleted_counts.incident = r8.deleted;

    // Rule 9: Delete completed releases > 90 days
    const releaseFilter = {
      kind: 'release',
      before: ninetyDaysAgo.toISOString(),
      scope: { metadata: { status: { in: ['completed', 'rolled_back'] } } },
    };
    const r9 = await db.bulkDelete(releaseFilter);
    deleted_counts.release = r9.deleted;

    // Rule 10: Delete closed risks > 90 days
    const riskFilter = {
      kind: 'risk',
      before: ninetyDaysAgo.toISOString(),
      scope: { metadata: { status: { in: ['closed', 'accepted'] } } },
    };
    const r10 = await db.bulkDelete(riskFilter);
    deleted_counts.risk = r10.deleted;

    // Rule 11: Delete validated assumptions > 90 days
    const assumptionFilter = {
      kind: 'assumption',
      before: ninetyDaysAgo.toISOString(),
      scope: { metadata: { validation_status: 'validated' } },
    };
    const r11 = await db.bulkDelete(assumptionFilter);
    deleted_counts.assumption = r11.deleted;

    const durationMs = Date.now() - startTime;
    const totalDeleted = Object.values(deleted_counts).reduce((sum, n) => sum + n, 0);

    // Update purge metadata
    purgeMetadata.last_purge_at = new Date();
    purgeMetadata.operations_since_purge = 0;
    purgeMetadata.deleted_counts = deleted_counts;
    purgeMetadata.last_duration_ms = durationMs;

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
  const hoursSince = (Date.now() - purgeMetadata.last_purge_at.getTime()) / 3600000;

  return {
    enabled: purgeMetadata.enabled,
    last_purge_at: purgeMetadata.last_purge_at,
    hours_since_purge: hoursSince.toFixed(2),
    operations_since_purge: purgeMetadata.operations_since_purge,
    time_threshold_hours: purgeMetadata.time_threshold_hours,
    operation_threshold: purgeMetadata.operation_threshold,
    last_deleted_counts: purgeMetadata.deleted_counts,
    last_duration_ms: purgeMetadata.last_duration_ms,
    next_purge_estimate: estimateNextPurge(purgeMetadata, hoursSince),
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

// Note: The bulkDelete method is added to QdrantOnlyDatabaseLayer for compatibility
// In a real implementation, this would be part of the adapter interface
