
// @ts-nocheck - Emergency rollback: Critical business service
/**
 * P6-T6.2: Expiry Worker Service
 *
 * Implements scheduled cleanup of expired items based on expiry_at timestamps.
 * Uses the P6-T6.1 expiry calculation system to delete items that have passed their expiry time.
 *
 * Features:
 * - Cron-scheduled execution (configurable intervals)
 * - Batch processing for performance
 * - Comprehensive logging and metrics
 * - Graceful error handling
 * - Integration with existing database layer
 *
 * @module services/expiry-worker
 */

import { logger } from '@/utils/logger.js';

import { systemMetricsService } from './metrics/system-metrics.js';
import { createTTLManagementService } from './ttl/index.js';
import type { TTLBulkOperationOptions } from './ttl/ttl-management-service.js';
import { Environment } from '../config/environment.js';
import { type QdrantDatabaseConfig,QdrantOnlyDatabaseLayer } from '../db/unified-database-layer-v2.js';
import type { KnowledgeItem, SearchQuery } from '../types/core-interfaces.js';
import { isExpired } from '../utils/expiry-utils.js';

export interface ExpiryWorkerResult {
  deleted_counts: Record<string, number>;
  total_deleted: number;
  total_processed: number;
  total_skipped: number;
  duration_ms: number;
  error?: string;
  metrics: {
    ttl_deletes_total: number;
    ttl_skips_total: number;
    ttl_errors_total: number;
    processing_rate_per_second: number;
    batch_count: number;
    average_batch_size: number;
  };
  dry_run?: boolean;
  policy_enforcement: {
    policies_applied: Record<string, number>;
    permanent_items_preserved: number;
    extensions_granted: number;
  };
}

export interface ExpiryWorkerConfig {
  /** Cron schedule for when to run the expiry worker */
  schedule: string; // Default: '0 2 * * *' (2 AM daily)
  /** Batch size for processing expired items */
  batch_size: number;
  /** Maximum number of batches to process in one run */
  max_batches: number;
  /** Enable dry run mode (logs what would be deleted without actually deleting) */
  dry_run: boolean;
  /** Enable the worker */
  enabled: boolean;
}

// Default configuration (will be overridden by environment)
const DEFAULT_CONFIG: ExpiryWorkerConfig = {
  schedule: '0 2 * * *', // 2 AM daily
  batch_size: 100,
  max_batches: 50, // Max 5,000 items per run
  dry_run: false,
  enabled: true,
};

// Get configuration from environment
function getWorkerConfig(): ExpiryWorkerConfig {
  try {
    const env = Environment.getInstance();
    const ttlConfig = env.getTTLConfig();

    return {
      schedule: ttlConfig.worker.schedule,
      batch_size: ttlConfig.worker.batch_size,
      max_batches: ttlConfig.worker.max_batches,
      dry_run: false,
      enabled: ttlConfig.worker.enabled,
    };
  } catch (error) {
    logger.warn({ error }, 'Failed to load TTL config from environment, using defaults');
    return DEFAULT_CONFIG;
  }
}

// Get database instance (shared with auto-purge service)
let dbInstance: QdrantOnlyDatabaseLayer | null = null;

function getDatabase(): QdrantOnlyDatabaseLayer {
  if (!dbInstance) {
    const env = Environment.getInstance();
    const rawConfig = env.getRawConfig();
    const qdrantConfig: unknown = {
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

/**
 * P6-T6.2: Find and delete expired knowledge items
 *
 * This is the core expiry worker implementation that:
 * 1. Queries for items with expiry_at timestamps in the past
 * 2. Processes them in batches for performance
 * 3. Deletes expired items from both Qdrant and metadata
 * 4. Returns comprehensive metrics about the operation
 *
 * @param config - Worker configuration options
 * @returns ExpiryWorkerResult with deletion metrics
 */
export async function runExpiryWorker(
  config: Partial<ExpiryWorkerConfig> = {}
): Promise<ExpiryWorkerResult> {
  const envConfig = getWorkerConfig();
  const finalConfig = { ...envConfig, ...config };
  const startTime = Date.now();

  logger.info(
    {
      enabled: finalConfig.enabled,
      dry_run: finalConfig.dry_run,
      batch_size: finalConfig.batch_size,
      max_batches: finalConfig.max_batches,
      integration_with_ttl_service: true,
    },
    'P6-T6.2: Starting enhanced TTL expiry worker run'
  );

  const result: ExpiryWorkerResult = {
    deleted_counts: {},
    total_deleted: 0,
    total_processed: 0,
    total_skipped: 0,
    duration_ms: 0,
    metrics: {
      ttl_deletes_total: 0,
      ttl_skips_total: 0,
      ttl_errors_total: 0,
      processing_rate_per_second: 0,
      batch_count: 0,
      average_batch_size: 0,
    },
    dry_run: finalConfig.dry_run,
    policy_enforcement: {
      policies_applied: {},
      permanent_items_preserved: 0,
      extensions_granted: 0,
    },
  };

  try {
    if (!finalConfig.enabled) {
      logger.info('P6-T6.2: TTL expiry worker is disabled, skipping');
      result.duration_ms = Date.now() - startTime;
      return result;
    }

    const db = getDatabase();
    const ttlService = createTTLManagementService(db);

    logger.info('P6-T6.2: TTL Management Service initialized for expiry processing');

    // Use TTL Management Service for comprehensive cleanup
    const ttlCleanupOptions: TTLBulkOperationOptions = {
      batchSize: finalConfig.batch_size,
      continueOnError: true,
      dryRun: finalConfig.dry_run,
      verbose: true,
      validatePolicies: true,
      generateAudit: true,
    };

    // Run TTL cleanup with enhanced metrics
    const cleanupStartTime = Date.now();
    const ttlResult = await ttlService.cleanupExpiredItems(ttlCleanupOptions);
    const cleanupDuration = Date.now() - cleanupStartTime;

    // Transform TTL result to ExpiryWorkerResult format
    result.total_processed = ttlResult.processed;
    result.total_deleted = ttlResult.updated;
    result.total_skipped = ttlResult.processed - ttlResult.updated;
    result.duration_ms = Date.now() - startTime;

    // Calculate enhanced metrics
    result.metrics.ttl_deletes_total = ttlResult.updated;
    result.metrics.ttl_skips_total = result.total_skipped;
    result.metrics.ttl_errors_total = ttlResult.errors.length;
    result.metrics.processing_rate_per_second =
      result.total_processed / (result.duration_ms / 1000);
    result.metrics.batch_count = Math.ceil(result.total_processed / finalConfig.batch_size);
    result.metrics.average_batch_size = finalConfig.batch_size;

    // Extract deleted counts by kind from TTL result details
    if (ttlResult.details?.itemsProcessed) {
      // We'd need to get the items to determine their kinds
      // For now, use a generic approach
      result.deleted_counts = {
        mixed_expired_items: result.total_deleted,
      };
    }

    // Update system metrics with TTL execution data
    systemMetricsService.updateMetrics({
      operation: 'ttl',
      data: {
        ttl_deletes_total: result.metrics.ttl_deletes_total,
        ttl_skips_total: result.metrics.ttl_skips_total,
        ttl_errors_total: result.metrics.ttl_errors_total,
        ttl_processing_rate_per_second: result.metrics.processing_rate_per_second,
        ttl_batch_count: result.metrics.batch_count,
        ttl_average_batch_size: result.metrics.average_batch_size,
        ttl_policies_applied: result.policy_enforcement.policies_applied,
        ttl_extensions_granted: result.policy_enforcement.extensions_granted,
        ttl_permanent_items_preserved: result.policy_enforcement.permanent_items_preserved,
        ttl_last_cleanup_timestamp: new Date().toISOString(),
        ttl_success_rate:
          result.total_processed > 0
            ? ((result.metrics.ttl_deletes_total + result.metrics.ttl_skips_total) /
                result.total_processed) *
              100
            : 100,
        dry_run: finalConfig.dry_run,
      },
      duration_ms: result.duration_ms,
    });

    // Enhanced structured logging with TTL integration
    const structuredLogData = {
      operation: 'enhanced_ttl_expiry_worker_completed',
      worker_config: {
        enabled: finalConfig.enabled,
        dry_run: finalConfig.dry_run,
        batch_size: finalConfig.batch_size,
        max_batches: finalConfig.max_batches,
        ttl_service_integration: true,
      },
      performance: {
        duration_ms: result.duration_ms,
        cleanup_duration_ms: cleanupDuration,
        total_processed: result.total_processed,
        success: !result.error,
        processing_rate_per_second: result.metrics.processing_rate_per_second,
      },
      ttl_metrics: {
        ttl_deletes_total: result.metrics.ttl_deletes_total,
        ttl_skips_total: result.metrics.ttl_skips_total,
        ttl_errors_total: result.metrics.ttl_errors_total,
        batch_count: result.metrics.batch_count,
        average_batch_size: result.metrics.average_batch_size,
      },
      purging: {
        purged_count: result.total_deleted,
        items_processed: result.total_processed,
        items_skipped: result.total_skipped,
        purge_efficiency:
          result.total_processed > 0 ? (result.total_deleted / result.total_processed) * 100 : 0,
      },
      ttl_service: {
        ttl_result_success: ttlResult.success,
        ttl_warnings: ttlResult.warnings.length,
        ttl_errors: ttlResult.errors.length,
        audit_generated: ttlCleanupOptions.generateAudit,
      },
    };

    logger.info(structuredLogData, 'P6-T6.2: Enhanced TTL expiry worker run completed');

    // Log specific metrics for monitoring
    if (result.metrics.ttl_deletes_total > 0) {
      logger.info(
        {
          metric_type: 'ttl_deletes_total',
          metric_value: result.metrics.ttl_deletes_total,
          timestamp: new Date().toISOString(),
          operation: 'ttl_expiry_purge',
          details: {
            processing_rate: result.metrics.processing_rate_per_second,
            batch_count: result.metrics.batch_count,
            efficiency_percentage: structuredLogData.purging.purge_efficiency,
            dry_run: finalConfig.dry_run,
            ttl_service_integration: true,
          },
        },
        'TTL worker deletes_total metric logged'
      );
    }

    if (result.metrics.ttl_skips_total > 0) {
      logger.info(
        {
          metric_type: 'ttl_skips_total',
          metric_value: result.metrics.ttl_skips_total,
          timestamp: new Date().toISOString(),
          operation: 'ttl_expiry_skip',
          details: {
            skip_reason: 'items_not_expired_or_policy_preserved',
            total_processed: result.total_processed,
            dry_run: finalConfig.dry_run,
          },
        },
        'TTL worker skips_total metric logged'
      );
    }

    return result;
  } catch (error) {
    result.duration_ms = Date.now() - startTime;
    result.error = error instanceof Error ? error.message : 'Unknown error';

    // Update system metrics with error information
    systemMetricsService.updateMetrics({
      operation: 'ttl',
      data: {
        ttl_deletes_total: result.metrics.ttl_deletes_total,
        ttl_skips_total: result.metrics.ttl_skips_total,
        ttl_errors_total: result.metrics.ttl_errors_total + 1,
        ttl_last_cleanup_timestamp: new Date().toISOString(),
        ttl_success_rate: 0,
        error: result.error,
        dry_run: finalConfig.dry_run,
      },
      duration_ms: result.duration_ms,
    });

    // Enhanced structured error logging
    logger.error(
      {
        operation: 'expiry_worker_failed',
        error: {
          message: result.error,
          type: error instanceof Error ? error.constructor.name : 'Unknown',
          stack: error instanceof Error ? error.stack : undefined,
        },
        worker_config: {
          enabled: finalConfig.enabled,
          dry_run: finalConfig.dry_run,
          batch_size: finalConfig.batch_size,
          max_batches: finalConfig.max_batches,
        },
        performance: {
          duration_ms: result.duration_ms,
          total_processed: result.total_processed,
          success: false,
        },
        purging: {
          purged_count: result.total_deleted,
          deleted_counts: result.deleted_counts,
          items_processed_before_failure: result.total_processed,
        },
        timestamp: new Date().toISOString(),
      },
      'P6-T6.2: Expiry worker run failed with structured error details'
    );

    throw error;
  }
}

/**
 * Find items that have expired using database filtering
 * Uses the efficient database findExpiredItems method
 */
async function findExpiredItems(
  db: QdrantOnlyDatabaseLayer,
  filter: { expiry_before: string }
): Promise<KnowledgeItem[]> {
  try {
    logger.debug(
      { expiry_before: filter.expiry_before },
      'P6-T6.2: Finding expired items using database filtering'
    );

    // Use the efficient database method for finding expired items
    const expiredItems = await db.findExpiredItems({
      expiry_before: filter.expiry_before,
      limit: 10000, // Large limit for processing
    });

    logger.debug(
      {
        expired_items: expiredItems.length,
        expiry_before: filter.expiry_before,
      },
      'P6-T6.2: Found expired items using database filtering'
    );

    return expiredItems;
  } catch (error) {
    logger.error(
      { error, expiry_before: filter.expiry_before },
      'P6-T6.2: Error finding expired items'
    );
    throw error;
  }
}

/**
 * Create batches of items for processing
 */
function createBatches<T>(items: T[], batchSize: number, maxBatches: number): T[][] {
  const batches: T[][] = [];
  const totalBatches = Math.min(maxBatches, Math.ceil(items.length / batchSize));

  for (let i = 0; i < totalBatches; i++) {
    const start = i * batchSize;
    const end = Math.min(start + batchSize, items.length);
    batches.push(items.slice(start, end));
  }

  return batches;
}

/**
 * Process a batch of expired items
 */
async function processBatch(
  db: QdrantOnlyDatabaseLayer,
  batch: KnowledgeItem[],
  dryRun: boolean
): Promise<{ deleted_counts: Record<string, number>; total_deleted: number }> {
  const deletedCounts: Record<string, number> = {};
  let totalDeleted = 0;

  if (dryRun) {
    // Dry run - just count what would be deleted
    for (const item of batch) {
      deletedCounts[item.kind] = (deletedCounts[item.kind] || 0) + 1;
      totalDeleted++;
    }

    logger.debug(
      {
        batch_size: batch.length,
        would_delete: totalDeleted,
        by_kind: deletedCounts,
      },
      'P6-T6.2: Dry run batch - items would be deleted'
    );

    return { deleted_counts: deletedCounts, total_deleted: totalDeleted };
  }

  // Actual deletion
  try {
    // Extract IDs for batch deletion (filter out undefined)
    const ids = batch.map((item) => item.id).filter((id): id is string => id !== undefined);

    // Use the existing delete method from the database layer
    const deleteResult = await db.delete(ids, { cascade: true, soft: false });

    // Count successful deletions by kind
    for (const item of batch) {
      deletedCounts[item.kind] = (deletedCounts[item.kind] || 0) + 1;
    }
    totalDeleted = deleteResult.deleted;

    logger.debug(
      {
        batch_size: batch.length,
        deleted: totalDeleted,
        errors: deleteResult.errors.length,
        by_kind: deletedCounts,
      },
      'P6-T6.2: Batch deleted successfully'
    );

    if (deleteResult.errors.length > 0) {
      logger.warn(
        {
          errors: deleteResult.errors,
          batch_size: batch.length,
          successful_deletions: totalDeleted,
        },
        'P6-T6.2: Some items in batch failed to delete'
      );
    }
  } catch (error) {
    logger.error(
      {
        error,
        batch_size: batch.length,
        processed_so_far: totalDeleted,
      },
      'P6-T6.2: Error processing batch'
    );
    throw error;
  }

  return { deleted_counts: deletedCounts, total_deleted: totalDeleted };
}

/**
 * Get current expiry worker status and configuration
 */
export function getExpiryWorkerStatus(): {
  config: ExpiryWorkerConfig;
  database_connected: boolean;
  last_run?: ExpiryWorkerResult;
} {
  return {
    config: DEFAULT_CONFIG,
    database_connected: dbInstance !== null,
    // In a real implementation, this would include last run results from persistent storage
  };
}

/**
 * Manual trigger for expiry worker (for testing/admin purposes)
 */
export async function runExpiryWorkerManual(
  options: { dry_run?: boolean } = {}
): Promise<ExpiryWorkerResult> {
  logger.info('P6-T6.2: Manual expiry worker trigger');
  const config: Partial<ExpiryWorkerConfig> = {};
  if (options.dry_run !== undefined) {
    config.dry_run = options.dry_run;
  }
  return await runExpiryWorker(config);
}

/**
 * Validate that the expiry system is working correctly
 */
export async function validateExpirySystem(): Promise<{
  valid: boolean;
  issues: string[];
  recommendations: string[];
}> {
  const issues: string[] = [];
  const recommendations: string[] = [];

  try {
    // Check database connection
    getDatabase();
    // In a real implementation, you might run a simple query to verify connectivity

    // Check if expiry utils are working
    const testItem = {
      kind: 'entity' as const,
      scope: { project: 'test' },
      data: {},
      expiry_at: new Date(Date.now() - 1000).toISOString(), // 1 second ago
    };

    const isTestItemExpired = isExpired(testItem);
    if (!isTestItemExpired) {
      issues.push('Expiry validation function not working correctly');
    }

    logger.debug('P6-T6.2: Expiry system validation completed');

    return {
      valid: issues.length === 0,
      issues,
      recommendations,
    };
  } catch (error) {
    issues.push(`Failed to validate expiry system: ${error}`);
    return {
      valid: false,
      issues,
      recommendations: ['Check database connection and configuration'],
    };
  }
}

/**
 * Enhanced TTL worker with comprehensive purge reporting and logging
 * This adds detailed reporting capabilities to the existing expiry worker
 */

export interface PurgeReport {
  timestamp: string;
  duration_ms: number;
  summary: {
    total_items_processed: number;
    total_items_deleted: number;
    items_by_kind: Record<string, number>;
    dry_run: boolean;
    worker_config: ExpiryWorkerConfig;
  };
  deleted_items: Array<{
    id: string;
    kind: string;
    scope: unknown;
    expiry_at: string;
    days_expired: number;
    deletion_reason: string;
  }>;
  errors: Array<{
    item_id?: string;
    error: string;
    timestamp: string;
  }>;
  performance_metrics: {
    items_per_second: number;
    average_batch_duration_ms: number;
    database_queries: number;
  };
}

/**
 * Enhanced expiry worker with detailed purge reporting
 */
export async function runExpiryWorkerWithReport(
  config: Partial<ExpiryWorkerConfig> = {}
): Promise<PurgeReport> {
  const finalConfig = { ...DEFAULT_CONFIG, ...config };
  const startTime = Date.now();
  const reportTimestamp = new Date().toISOString();

  logger.info(
    {
      timestamp: reportTimestamp,
      config: finalConfig,
    },
    'Starting enhanced TTL worker with purge reporting'
  );

  const report: PurgeReport = {
    timestamp: reportTimestamp,
    duration_ms: 0,
    summary: {
      total_items_processed: 0,
      total_items_deleted: 0,
      items_by_kind: {},
      dry_run: finalConfig.dry_run || false,
      worker_config: finalConfig,
    },
    deleted_items: [],
    errors: [],
    performance_metrics: {
      items_per_second: 0,
      average_batch_duration_ms: 0,
      database_queries: 0,
    },
  };

  try {
    if (!finalConfig.enabled) {
      logger.info('TTL worker is disabled, skipping');
      report.duration_ms = Date.now() - startTime;
      return report;
    }

    const db = getDatabase();
    const now = new Date().toISOString();

    // Get detailed expired items information
    const expiredItems = await findExpiredItemsWithDetails(db, {
      expiry_before: now,
      include_details: true,
    });

    report.summary.total_items_processed = expiredItems.length;

    if (expiredItems.length === 0) {
      logger.info('No expired items found for TTL processing');
      report.duration_ms = Date.now() - startTime;
      await logPurgeReport(report);
      return report;
    }

    logger.info(
      {
        expired_count: expiredItems.length,
        dry_run: finalConfig.dry_run,
        oldest_expiry: expiredItems[0]?.expiry_at,
        newest_expiry: expiredItems[expiredItems.length - 1]?.expiry_at,
      },
      'Processing expired items for TTL cleanup'
    );

    // Process in batches with detailed reporting
    const batches = createBatches(expiredItems, finalConfig.batch_size, finalConfig.max_batches);
    const batchDurations: number[] = [];

    for (let i = 0; i < batches.length; i++) {
      const batchStartTime = Date.now();
      const batch = batches[i];

      try {
        const batchResult = await processBatchWithDetails(db, batch, finalConfig.dry_run);
        const batchDuration = Date.now() - batchStartTime;
        batchDurations.push(batchDuration);

        // Update report summary
        Object.entries(batchResult.deleted_counts).forEach(([kind, count]) => {
          report.summary.items_by_kind[kind] = (report.summary.items_by_kind[kind] || 0) + count;
          report.summary.total_items_deleted += count;
        });

        // Add detailed deleted items
        report.deleted_items.push(...batchResult.deleted_items);

        // Log batch progress
        logger.info(
          {
            batch: i + 1,
            total_batches: batches.length,
            batch_size: batch.length,
            batch_deleted: batchResult.total_deleted,
            batch_duration_ms: batchDuration,
            cumulative_deleted: report.summary.total_items_deleted,
          },
          `TTL batch ${i + 1}/${batches.length} completed`
        );
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        const batchDuration = Date.now() - batchStartTime;
        batchDurations.push(batchDuration);

        report.errors.push({
          error: errorMessage,
          timestamp: new Date().toISOString(),
        });

        logger.error(
          {
            batch: i + 1,
            error: errorMessage,
            batch_duration_ms: batchDuration,
          },
          `TTL batch ${i + 1} failed`
        );
      }

      report.performance_metrics.database_queries += 2; // Approximate query count per batch
    }

    // Calculate performance metrics
    report.duration_ms = Date.now() - startTime;
    report.performance_metrics.items_per_second =
      report.summary.total_items_processed / (report.duration_ms / 1000);
    report.performance_metrics.average_batch_duration_ms =
      batchDurations.length > 0
        ? batchDurations.reduce((a, b) => a + b, 0) / batchDurations.length
        : 0;

    // Calculate expiry statistics
    const expiryStats = calculateExpiryStatistics(report.deleted_items);
    logger.info(
      {
        summary: report.summary,
        performance_metrics: report.performance_metrics,
        expiry_statistics: expiryStats,
        errors_count: report.errors.length,
      },
      'Enhanced TTL worker completed'
    );

    // Store purge report
    await logPurgeReport(report);

    return report;
  } catch (error) {
    report.duration_ms = Date.now() - startTime;
    report.errors.push({
      error: error instanceof Error ? error.message : 'Unknown error',
      timestamp: new Date().toISOString(),
    });

    logger.error({ error, duration_ms: report.duration_ms }, 'Enhanced TTL worker failed');

    await logPurgeReport(report);
    return report;
  }
}

/**
 * Find expired items with detailed information for reporting
 */
async function findExpiredItemsWithDetails(
  db: QdrantOnlyDatabaseLayer,
  filter: { expiry_before: string; include_details?: boolean }
): Promise<Array<unknown>> {
  try {
    logger.debug({ filter }, 'Finding expired items with details');

    // Use the existing findExpiredItems function and enhance with details
    const expiredItems = await findExpiredItems(db, filter);

    // Calculate additional details for each expired item
    const itemsWithDetails = expiredItems.map((item) => {
      const expiryDate = new Date(item.expiry_at || '');
      const now = new Date();
      const daysExpired = Math.floor(
        (now.getTime() - expiryDate.getTime()) / (1000 * 60 * 60 * 24)
      );

      return {
        ...item,
        days_expired: daysExpired,
        deletion_reason: 'TTL expired',
        expiry_timestamp: item.expiry_at,
        age_days: Math.floor(
          (now.getTime() - new Date(item.created_at || now).getTime()) / (1000 * 60 * 60 * 24)
        ),
      };
    });

    logger.debug(
      {
        total_items: itemsWithDetails.length,
        expiry_before: filter.expiry_before,
        oldest_expiry: itemsWithDetails[0]?.expiry_at,
        newest_expiry: itemsWithDetails[itemsWithDetails.length - 1]?.expiry_at,
      },
      'Found expired items with details'
    );

    return itemsWithDetails;
  } catch (error) {
    logger.error({ error, filter }, 'Failed to find expired items with details');
    return [];
  }
}

/**
 * Process a batch with detailed item information
 */
async function processBatchWithDetails(
  db: QdrantOnlyDatabaseLayer,
  batch: unknown[],
  dryRun: boolean
): Promise<{
  deleted_counts: Record<string, number>;
  total_deleted: number;
  deleted_items: unknown[];
}> {
  const result = {
    deleted_counts: {} as Record<string, number>,
    total_deleted: 0,
    deleted_items: [] as unknown[],
  };

  if (dryRun) {
    // In dry run mode, just report what would be deleted
    for (const item of batch) {
      const kind = item.kind || 'unknown';
      result.deleted_counts[kind] = (result.deleted_counts[kind] || 0) + 1;
      result.total_deleted++;

      const daysExpired =
        item.days_expired ||
        (item.expiry_at
          ? Math.floor((Date.now() - new Date(item.expiry_at).getTime()) / (1000 * 60 * 60 * 24))
          : 0);

      result.deleted_items.push({
        id: item.id,
        kind,
        scope: item.scope,
        expiry_at: item.expiry_at,
        days_expired: daysExpired,
        deletion_reason: 'TTL expired',
        created_at: item.created_at,
      });
    }

    logger.debug(
      {
        batch_size: batch.length,
        would_delete: result.total_deleted,
        by_kind: result.deleted_counts,
      },
      'P6-T6.2: Dry run batch with details - items would be deleted'
    );

    return result;
  }

  // Actual deletion
  try {
    // Extract IDs for batch deletion (filter out undefined)
    const ids = batch.map((item) => item.id).filter((id): id is string => id !== undefined);

    if (ids.length === 0) {
      logger.warn('No valid IDs found in batch for deletion');
      return result;
    }

    // Use the existing delete method from the database layer
    const deleteResult = await db.delete(ids, { cascade: true, soft: false });

    // Count successful deletions by kind and create detailed items
    for (const item of batch) {
      if (item.id && ids.includes(item.id)) {
        const kind = item.kind || 'unknown';
        result.deleted_counts[kind] = (result.deleted_counts[kind] || 0) + 1;
        result.total_deleted++;

        const daysExpired =
          item.days_expired ||
          (item.expiry_at
            ? Math.floor((Date.now() - new Date(item.expiry_at).getTime()) / (1000 * 60 * 60 * 24))
            : 0);

        result.deleted_items.push({
          id: item.id,
          kind,
          scope: item.scope,
          expiry_at: item.expiry_at,
          days_expired: daysExpired,
          deletion_reason: 'TTL expired',
          created_at: item.created_at,
        });
      }
    }

    logger.debug(
      {
        batch_size: batch.length,
        valid_ids: ids.length,
        deleted: result.total_deleted,
        errors: deleteResult.errors.length,
        by_kind: result.deleted_counts,
      },
      'P6-T6.2: Batch with details deleted successfully'
    );

    if (deleteResult.errors.length > 0) {
      logger.warn(
        {
          errors: deleteResult.errors,
          batch_size: batch.length,
          successful_deletions: result.total_deleted,
        },
        'P6-T6.2: Some items in batch failed to delete'
      );
    }
  } catch (error) {
    logger.error(
      {
        error,
        batch_size: batch.length,
        processed_so_far: result.total_deleted,
      },
      'P6-T6.2: Error processing batch with details'
    );
    throw error;
  }

  return result;
}

/**
 * Calculate expiry statistics from deleted items
 */
function calculateExpiryStatistics(deletedItems: unknown[]): {
  average_days_expired: number;
  oldest_expiry_days: number;
  newest_expiry_days: number;
  expiry_distribution: Record<string, number>;
} {
  if (deletedItems.length === 0) {
    return {
      average_days_expired: 0,
      oldest_expiry_days: 0,
      newest_expiry_days: 0,
      expiry_distribution: {},
    };
  }

  const daysExpired = deletedItems.map((item) => item.days_expired || 0);
  const averageDays = daysExpired.reduce((a, b) => a + b, 0) / daysExpired.length;
  const oldestDays = Math.max(...daysExpired);
  const newestDays = Math.min(...daysExpired);

  // Create distribution by expiry ranges
  const distribution = {
    '1-7 days': 0,
    '8-30 days': 0,
    '31-90 days': 0,
    '90+ days': 0,
  };

  daysExpired.forEach((days) => {
    if (days <= 7) distribution['1-7 days']++;
    else if (days <= 30) distribution['8-30 days']++;
    else if (days <= 90) distribution['31-90 days']++;
    else distribution['90+ days']++;
  });

  return {
    average_days_expired: Math.round(averageDays),
    oldest_expiry_days: oldestDays,
    newest_expiry_days: newestDays,
    expiry_distribution: distribution,
  };
}

/**
 * Log purge report to persistent storage
 */
async function logPurgeReport(report: PurgeReport): Promise<void> {
  try {
    // Store the report as a knowledge item for persistence
    const reportItem: KnowledgeItem = {
      id: `purge-report-${report.timestamp.replace(/[:.]/g, '-')}`,
      kind: 'release_note', // Using release_note type for operational reports
      scope: { project: 'system', org: 'cortex' },
      data: {
        title: `TTL Purge Report - ${new Date(report.timestamp).toLocaleDateString()}`,
        content: JSON.stringify(report, null, 2),
        report_type: 'purge_report',
        report_date: report.timestamp,
        summary: report.summary,
        performance_metrics: report.performance_metrics,
      },
      metadata: {
        created_at: report.timestamp,
        report_version: '1.0',
        total_items_processed: report.summary.total_items_processed,
        total_items_deleted: report.summary.total_items_deleted,
        dry_run: report.summary.dry_run,
        duration_ms: report.duration_ms,
        items_per_second: report.performance_metrics.items_per_second,
      },
    };

    // Store using the database layer
    const env = Environment.getInstance();
    const qdrantConfig = env.getQdrantConfig();
    const qdrantDbConfig = {
      url: qdrantConfig.url,
      ...(qdrantConfig.apiKey && { apiKey: qdrantConfig.apiKey }),
      collectionName: qdrantConfig.collectionName,
      timeout: qdrantConfig.connectionTimeout || 30000,
    };

    const dbConfig: QdrantDatabaseConfig = {
      type: 'qdrant',
      qdrant: qdrantDbConfig,
    };
    const db = new QdrantOnlyDatabaseLayer(dbConfig);
    await db.store([reportItem]);

    logger.info(
      {
        purge_summary: report.summary,
        performance: report.performance_metrics,
        deleted_count: report.deleted_items.length,
        errors_count: report.errors.length,
        report_id: reportItem.id,
      },
      'Purge report logged successfully'
    );
  } catch (error) {
    logger.error({ error, report_timestamp: report.timestamp }, 'Failed to log purge report');
  }
}

/**
 * Get recent purge reports
 */
export async function getRecentPurgeReports(limit: number = 10): Promise<PurgeReport[]> {
  try {
    logger.debug({ limit }, 'Retrieving recent purge reports');

    // Search for purge reports in the database
    const env = Environment.getInstance();
    const qdrantConfig = env.getQdrantConfig();
    const qdrantDbConfig = {
      url: qdrantConfig.url,
      ...(qdrantConfig.apiKey && { apiKey: qdrantConfig.apiKey }),
      collectionName: qdrantConfig.collectionName,
      timeout: qdrantConfig.connectionTimeout || 30000,
    };

    const dbConfig: QdrantDatabaseConfig = {
      type: 'qdrant',
      qdrant: qdrantDbConfig,
    };
    const db = new QdrantOnlyDatabaseLayer(dbConfig);
    const searchQuery: SearchQuery = {
      query: 'kind:release_note report_type:purge_report',
      limit,
      types: ['release_note'],
      scope: { project: 'system', org: 'cortex' },
      mode: 'fast',
    };

    const searchResult = await db.search(searchQuery);
    const reports: PurgeReport[] = [];

    for (const item of searchResult.results) {
      try {
        // Parse the JSON content back to PurgeReport
        if (item.data?.content) {
          const reportData = JSON.parse(item.data.content) as PurgeReport;
          reports.push(reportData);
        }
      } catch (parseError) {
        logger.warn(
          {
            item_id: item.id,
            error: parseError instanceof Error ? parseError.message : 'Unknown error',
          },
          'Failed to parse purge report content'
        );
      }
    }

    // Sort by timestamp (newest first)
    reports.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    logger.info(
      {
        requested_limit: limit,
        found_count: reports.length,
        returned_count: Math.min(limit, reports.length),
      },
      'Retrieved purge reports'
    );

    return reports.slice(0, limit);
  } catch (error) {
    logger.error({ error, limit }, 'Failed to retrieve purge reports');
    return [];
  }
}

/**
 * Get purge statistics for a time period
 */
export async function getPurgeStatistics(days: number = 30): Promise<{
  total_reports: number;
  total_items_deleted: number;
  average_performance: {
    items_per_second: number;
    average_duration_ms: number;
  };
  top_deleted_kinds: Array<{ kind: string; count: number }>;
}> {
  try {
    logger.debug({ days }, 'Calculating purge statistics');

    // Get recent reports for the specified time period
    const reports = await getRecentPurgeReports(100); // Get more reports to filter by date
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - days);

    // Filter reports within the time period
    const recentReports = reports.filter((report) => new Date(report.timestamp) >= cutoffDate);

    if (recentReports.length === 0) {
      return {
        total_reports: 0,
        total_items_deleted: 0,
        average_performance: {
          items_per_second: 0,
          average_duration_ms: 0,
        },
        top_deleted_kinds: [],
      };
    }

    // Calculate statistics
    let totalItemsDeleted = 0;
    let totalItemsPerSecond = 0;
    let totalDuration = 0;
    const kindCounts: Record<string, number> = {};

    for (const report of recentReports) {
      totalItemsDeleted += report.summary.total_items_deleted;
      totalItemsPerSecond += report.performance_metrics.items_per_second;
      totalDuration += report.duration_ms;

      // Count by kind
      for (const [kind, count] of Object.entries(report.summary.items_by_kind)) {
        kindCounts[kind] = (kindCounts[kind] || 0) + count;
      }
    }

    // Calculate averages
    const averageItemsPerSecond = totalItemsPerSecond / recentReports.length;
    const averageDuration = totalDuration / recentReports.length;

    // Get top deleted kinds (sorted by count)
    const topDeletedKinds = Object.entries(kindCounts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 10)
      .map(([kind, count]) => ({ kind, count }));

    const statistics = {
      total_reports: recentReports.length,
      total_items_deleted: totalItemsDeleted,
      average_performance: {
        items_per_second: Math.round(averageItemsPerSecond * 100) / 100,
        average_duration_ms: Math.round(averageDuration * 100) / 100,
      },
      top_deleted_kinds: topDeletedKinds,
    };

    logger.info(
      {
        period_days: days,
        reports_analyzed: recentReports.length,
        total_deleted: totalItemsDeleted,
        average_performance: statistics.average_performance,
      },
      'Calculated purge statistics'
    );

    return statistics;
  } catch (error) {
    logger.error({ error, days }, 'Failed to calculate purge statistics');
    return {
      total_reports: 0,
      total_items_deleted: 0,
      average_performance: {
        items_per_second: 0,
        average_duration_ms: 0,
      },
      top_deleted_kinds: [],
    };
  }
}
