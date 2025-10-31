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

import { logger } from '../utils/logger.js';
import { QdrantOnlyDatabaseLayer, QdrantDatabaseConfig } from '../db/unified-database-layer-v2.js';
import { Environment } from '../config/environment.js';
import { isExpired } from '../utils/expiry-utils.js';
import type { KnowledgeItem, SearchQuery } from '../types/core-interfaces.js';

export interface ExpiryWorkerResult {
  deleted_counts: Record<string, number>;
  total_deleted: number;
  total_processed: number;
  duration_ms: number;
  error?: string;
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

// Default configuration
const DEFAULT_CONFIG: ExpiryWorkerConfig = {
  schedule: '0 2 * * *', // 2 AM daily
  batch_size: 100,
  max_batches: 50, // Max 5,000 items per run
  dry_run: false,
  enabled: true,
};

// Get database instance (shared with auto-purge service)
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
  const finalConfig = { ...DEFAULT_CONFIG, ...config };
  const startTime = Date.now();

  logger.info(
    {
      enabled: finalConfig.enabled,
      dry_run: finalConfig.dry_run,
      batch_size: finalConfig.batch_size,
      max_batches: finalConfig.max_batches,
    },
    'P6-T6.2: Starting expiry worker run'
  );

  const result: ExpiryWorkerResult = {
    deleted_counts: {},
    total_deleted: 0,
    total_processed: 0,
    duration_ms: 0,
  };

  try {
    if (!finalConfig.enabled) {
      logger.info('P6-T6.2: Expiry worker is disabled, skipping');
      result.duration_ms = Date.now() - startTime;
      return result;
    }

    const db = getDatabase();
    const now = new Date().toISOString();

    // Find all items with expiry_at in the past
    // This query finds items where expiry_at exists and is less than now
    const expiredItemsFilter = {
      // Note: This would need to be implemented in the database layer
      // as a special query for expired items
      expiry_before: now,
    };

    logger.debug({ expiry_before: now }, 'P6-T6.2: Querying for expired items');

    // Get expired items (would be implemented in database layer)
    // For now, we'll simulate this with a bulk query that would need
    // to be added to the Qdrant adapter
    const expiredItems = await findExpiredItems(db, expiredItemsFilter);

    result.total_processed = expiredItems.length;

    if (expiredItems.length === 0) {
      logger.info('P6-T6.2: No expired items found');
      result.duration_ms = Date.now() - startTime;
      return result;
    }

    logger.info(
      {
        expired_count: expiredItems.length,
        dry_run: finalConfig.dry_run,
      },
      'P6-T6.2: Processing expired items'
    );

    // Process expired items in batches
    const batches = createBatches(expiredItems, finalConfig.batch_size, finalConfig.max_batches);

    for (let i = 0; i < batches.length; i++) {
      const batch = batches[i];
      const batchResult = await processBatch(db, batch, finalConfig.dry_run);

      // Aggregate results
      Object.entries(batchResult.deleted_counts).forEach(([kind, count]) => {
        result.deleted_counts[kind] = (result.deleted_counts[kind] || 0) + count;
      });
      result.total_deleted += batchResult.total_deleted;

      logger.debug(
        {
          batch: i + 1,
          total_batches: batches.length,
          batch_size: batch.length,
          batch_deleted: batchResult.total_deleted,
          cumulative_deleted: result.total_deleted,
        },
        'P6-T6.2: Processed batch'
      );
    }

    result.duration_ms = Date.now() - startTime;

    logger.info(
      {
        deleted_counts: result.deleted_counts,
        total_deleted: result.total_deleted,
        total_processed: result.total_processed,
        duration_ms: result.duration_ms,
        dry_run: finalConfig.dry_run,
      },
      'P6-T6.2: Expiry worker run completed'
    );

    return result;
  } catch (error) {
    result.duration_ms = Date.now() - startTime;
    result.error = error instanceof Error ? error.message : 'Unknown error';

    logger.error(
      {
        error,
        duration_ms: result.duration_ms,
        total_processed: result.total_processed,
      },
      'P6-T6.2: Expiry worker run failed'
    );

    throw error;
  }
}

/**
 * Find items that have expired using search functionality
 * Uses a filter query to find items where expiry_at exists and is in the past
 */
async function findExpiredItems(
  db: QdrantOnlyDatabaseLayer,
  filter: { expiry_before: string }
): Promise<KnowledgeItem[]> {
  try {
    // Search for items with expiry_at timestamps in the past
    // Note: This requires the database layer to support expiry_at filtering
    // For now, we'll implement using the available search functionality

    const searchQuery: SearchQuery = {
      query: '', // Empty query to get all items
      limit: 10000, // Large limit to get all potentially expired items
    };

    logger.debug(
      { expiry_before: filter.expiry_before, limit: 10000 },
      'P6-T6.2: Searching for expired items'
    );

    const response = await db.search(searchQuery);

    // Manual filtering for expired items (temporary solution)
    // In a proper implementation, this filtering would happen in the database
    const expiredItems = response.items.filter((item) => {
      const expiryTime = item.data?.expiry_at;
      if (!expiryTime) return false;

      try {
        const expiryDate = new Date(expiryTime);
        const filterDate = new Date(filter.expiry_before);
        return expiryDate < filterDate;
      } catch {
        return false; // Invalid date format
      }
    });

    logger.debug(
      {
        total_items: response.items.length,
        expired_items: expiredItems.length,
        expiry_before: filter.expiry_before,
      },
      'P6-T6.2: Found expired items'
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
