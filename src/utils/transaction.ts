/**
 * Transaction utilities for Qdrant Client
 *
 * Provides transaction safety and performance optimization for database operations.
 * Replaces manual transaction handling with Qdrant's transaction patterns.
 *
 * @module utils/transaction
 */

import { qdrant } from '../db/qdrant-client.js';
import { logger } from './logger.js';
import { dbErrorHandler, DbOperationResult } from './db-error-handler.js';

export interface TransactionOptions {
  timeout?: number; // Transaction timeout in milliseconds (default: 30000)
  isolationLevel?: 'ReadUncommitted' | 'ReadCommitted' | 'RepeatableRead' | 'Serializable';
  maxRetries?: number; // Maximum retry attempts for transaction conflicts (default: 3)
}

/**
 * Execute a function within a Qdrant transaction with automatic retry and error handling
 *
 * @param callback - Function to execute within the transaction
 * @param options - Transaction options
 * @returns Result of the transaction
 */
export async function executeTransaction<T>(
  callback: (tx: any) => Promise<T>,
  options: TransactionOptions = {}
): Promise<DbOperationResult<T>> {
  const { timeout = 30000, maxRetries = 3 } = options;

  let lastError: unknown;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      logger.debug({ attempt, maxRetries }, 'Starting transaction attempt');

      const startTime = Date.now();

      // Use Qdrant's $transaction API
      const result = await qdrant.getClient().$transaction(
        async (tx) => {
          return await callback(tx);
        },
        {
          timeout,
          isolationLevel: options.isolationLevel || 'ReadCommitted',
        }
      );

      const duration = Date.now() - startTime;

      logger.debug({ duration, attempt }, 'Transaction completed successfully');

      return {
        success: true,
        data: result,
        retryAttempts: attempt - 1,
      };

    } catch (error) {
      lastError = error;

      const errorType = dbErrorHandler.categorizeError(error);
      const errorMessage = error instanceof Error ? error.message : String(error);

      logger.warn({
        attempt,
        maxRetries,
        errorType,
        error: errorMessage,
      }, 'Transaction attempt failed');

      // Don't retry on certain error types
      if (shouldNotRetry(errorType) || attempt >= maxRetries) {
        break;
      }

      // Exponential backoff for retries
      const delay = Math.min(1000 * Math.pow(2, attempt - 1), 5000);
      logger.debug({ delay, attempt }, 'Waiting before retry');
      await sleep(delay);
    }
  }

  // All attempts failed
  const errorType = dbErrorHandler.categorizeError(lastError);
  const errorMessage = lastError instanceof Error ? lastError.message : String(lastError);

  return {
    success: false,
    error: {
      type: errorType,
      message: `Transaction failed after ${maxRetries} attempts: ${errorMessage}`,
      originalError: lastError,
    },
    retryAttempts: maxRetries - 1,
  };
}

/**
 * Execute a function within a transaction and throw on error (simplified API)
 *
 * @param callback - Function to execute within the transaction
 * @param options - Transaction options
 * @returns Result of the transaction
 */
export async function transaction<T>(
  callback: (tx: any) => Promise<T>,
  options: TransactionOptions = {}
): Promise<T> {
  const result = await executeTransaction(callback, options);

  if (!result.success) {
    throw new Error(result.error?.message || 'Transaction failed');
  }

  return result.data!;
}

/**
 * Execute multiple operations in parallel within separate transactions
 *
 * @param operations - Array of operations to execute
 * @param options - Transaction options for each operation
 * @returns Array of results
 */
export async function executeParallelTransactions<T>(
  operations: Array<() => Promise<T>>,
  options: TransactionOptions = {}
): Promise<DbOperationResult<T>[]> {
  logger.debug({ operationCount: operations.length }, 'Starting parallel transactions');

  const promises = operations.map((operation, index) =>
    executeTransaction(async (_tx) => {
      // Note: Each operation gets its own transaction
      // If you need true parallel operations within a single transaction,
      // use Promise.all inside the transaction callback
      return await operation();
    }, options).catch((error) => {
      logger.error({ index, error }, 'Parallel transaction failed');
      return {
        success: false,
        error: {
          type: 'UNKNOWN_ERROR' as any,
          message: error instanceof Error ? error.message : String(error),
          originalError: error,
        },
      } as DbOperationResult<T>;
    })
  );

  const results = await Promise.all(promises);

  const successCount = results.filter(r => r.success).length;
  const failureCount = results.length - successCount;

  logger.debug({
    total: results.length,
    successCount,
    failureCount
  }, 'Parallel transactions completed');

  return results;
}

/**
 * Batch operation with size limits to prevent memory issues
 *
 * @param items - Items to process
 * @param batchSize - Size of each batch (default: 100)
 * @param processor - Function to process each batch
 * @returns Results of all batches
 */
export async function batchOperation<T, R>(
  items: T[],
  batchSize: number,
  processor: (batch: T[], tx?: any) => Promise<R[]>
): Promise<R[]> {
  const results: R[] = [];

  logger.debug({
    totalItems: items.length,
    batchSize,
    batchCount: Math.ceil(items.length / batchSize)
  }, 'Starting batch operation');

  for (let i = 0; i < items.length; i += batchSize) {
    const batch = items.slice(i, i + batchSize);
    const batchNumber = Math.floor(i / batchSize) + 1;

    try {
      logger.debug({
        batchNumber,
        batchSize: batch.length,
        totalBatches: Math.ceil(items.length / batchSize)
      }, 'Processing batch');

      const batchResults = await transaction(async (tx) => {
        return await processor(batch, tx);
      });

      results.push(...batchResults);

    } catch (error) {
      logger.error({
        batchNumber,
        batchSize: batch.length,
        error: error instanceof Error ? error.message : String(error)
      }, 'Batch processing failed');

      // For batch operations, we might want to continue with other batches
      // depending on the error type and business requirements
      throw error;
    }
  }

  logger.debug({
    totalItems: items.length,
    processedItems: results.length
  }, 'Batch operation completed');

  return results;
}

/**
 * Optimistic lock helper for concurrent updates
 *
 * @param model - Qdrant model to update
 * @param id - ID of the record
 * @param data - Data to update
 * @param versionField - Field name for version tracking (default: 'updated_at')
 * @param expectedVersion - Expected version value
 * @returns Update result
 */
export async function optimisticUpdate<T>(
  model: any,
  id: string,
  data: any,
  versionField: string = 'updated_at',
  expectedVersion?: Date
): Promise<DbOperationResult<T>> {
  const updateData = { ...data };

  // Add version check if expected version is provided
  const whereClause: any = { id };
  if (expectedVersion) {
    whereClause[versionField] = expectedVersion;
  }

  return await executeTransaction(async (tx) => {
    const existing = await tx[model].findUnique({
      where: { id },
      select: { [versionField]: true },
    });

    if (!existing) {
      throw new Error(`Record with id ${id} not found`);
    }

    if (expectedVersion && existing[versionField].getTime() !== expectedVersion.getTime()) {
      throw new Error(`Record was modified by another process (version mismatch)`);
    }

    return await tx[model].update({
      where: whereClause,
      data: updateData,
    });
  });
}

/**
 * Check if error type should not be retried
 */
function shouldNotRetry(errorType: string): boolean {
  const nonRetryableErrors = [
    'CONSTRAINT_VIOLATION',
    'PERMISSION_ERROR',
    'SCHEMA_ERROR',
    'RECORD_NOT_FOUND',
  ];

  return nonRetryableErrors.includes(errorType);
}

/**
 * Sleep utility for retry delays
 */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Health check for transaction functionality
 */
export async function transactionHealthCheck(): Promise<{
  healthy: boolean;
  message: string;
  latency?: number;
}> {
  try {
    const startTime = Date.now();

    await transaction(async (tx) => {
      // Simple test operation within transaction
      await tx.$queryRaw`SELECT 1 as test`;
    }, { timeout: 5000 });

    const latency = Date.now() - startTime;

    return {
      healthy: true,
      message: 'Transaction system is healthy',
      latency,
    };

  } catch (error) {
    return {
      healthy: false,
      message: `Transaction health check failed: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}