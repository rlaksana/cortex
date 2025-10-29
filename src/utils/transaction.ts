/**
 * Transaction utilities for Vector Database Operations
 *
 * Note: Qdrant vector database does not support traditional SQL transactions.
 * This module provides retry logic and operation coordination for vector operations.
 * For true atomic operations, operations should be designed to be idempotent
 * and handle partial failures gracefully.
 *
 * @module utils/transaction
 */

import { logger } from './logger.js';
import { dbErrorHandler, DbOperationResult } from './db-error-handler.js';

export interface TransactionOptions {
  timeout?: number; // Operation timeout in milliseconds (default: 30000)
  maxRetries?: number; // Maximum retry attempts for conflicts (default: 3)
  ensureConsistency?: boolean; // Wait for write consistency (default: true)
}

export interface VectorTransactionContext {
  operationId: string;
  startTime: number;
  operations: Array<{
    type: string;
    data: any;
    timestamp: number;
  }>;
}

/**
 * Execute a function with retry logic and error handling for vector operations
 *
 * Note: This is not a true transaction but provides retry logic and operation tracking
 * for Qdrant vector operations which don't support ACID transactions.
 *
 * @param callback - Function to execute with operation context
 * @param options - Operation options
 * @returns Result of the operation
 */
export async function executeTransaction<T>(
  callback: (_ctx: VectorTransactionContext) => Promise<T>,
  options: TransactionOptions = {}
): Promise<DbOperationResult<T>> {
  const { timeout = 30000, maxRetries = 3 } = options;
  const operationId = `tx_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

  let lastError: unknown;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      logger.debug({ operationId, attempt, maxRetries }, 'Starting vector operation attempt');

      const startTime = Date.now();
      const ctx: VectorTransactionContext = {
        operationId,
        startTime,
        operations: [],
      };

      // Execute the callback with timeout
      const result = await Promise.race([
        callback(ctx),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error(`Operation timeout after ${timeout}ms`)), timeout)
        ),
      ]);

      const duration = Date.now() - startTime;

      logger.debug(
        {
          operationId,
          duration,
          attempt,
          operationCount: ctx.operations.length,
        },
        'Vector operation completed successfully'
      );

      return {
        success: true,
        data: result,
        retryAttempts: attempt - 1,
      };
    } catch (error) {
      lastError = error;

      const errorType = dbErrorHandler.categorizeError(error);
      const errorMessage = error instanceof Error ? error.message : String(error);

      logger.warn(
        {
          operationId,
          attempt,
          maxRetries,
          errorType,
          error: errorMessage,
        },
        'Vector operation attempt failed'
      );

      // Don't retry on certain error types
      if (shouldNotRetry(errorType) || attempt >= maxRetries) {
        break;
      }

      // Exponential backoff for retries
      const delay = Math.min(1000 * Math.pow(2, attempt - 1), 5000);
      logger.debug({ operationId, delay, attempt }, 'Waiting before retry');
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
      message: `Vector operation failed after ${maxRetries} attempts: ${errorMessage}`,
      originalError: lastError,
    },
    retryAttempts: maxRetries - 1,
  };
}

/**
 * Execute a function with retry logic and throw on error (simplified API)
 *
 * @param callback - Function to execute with operation context
 * @param options - Operation options
 * @returns Result of the operation
 */
export async function transaction<T>(
  callback: (_ctx: VectorTransactionContext) => Promise<T>,
  options: TransactionOptions = {}
): Promise<T> {
  const result = await executeTransaction(callback, options);

  if (!result.success) {
    throw new Error(result.error?.message || 'Vector operation failed');
  }

  return result.data!;
}

/**
 * Execute multiple operations in parallel with retry logic
 *
 * @param operations - Array of operations to execute
 * @param options - Operation options for each operation
 * @returns Array of results
 */
export async function executeParallelTransactions<T>(
  operations: Array<() => Promise<T>>,
  options: TransactionOptions = {}
): Promise<DbOperationResult<T>[]> {
  logger.debug({ operationCount: operations.length }, 'Starting parallel vector operations');

  const promises = operations.map((operation, index) =>
    executeTransaction(async (_ctx) => {
      // Note: Each operation gets its own retry logic and context
      // Vector operations don't support true ACID transactions
      return await operation();
    }, options).catch((error) => {
      logger.error({ index, error }, 'Parallel vector operation failed');
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

  const successCount = results.filter((r) => r.success).length;
  const failureCount = results.length - successCount;

  logger.debug(
    {
      total: results.length,
      successCount,
      failureCount,
    },
    'Parallel vector operations completed'
  );

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
  processor: (_batch: T[], _ctx?: VectorTransactionContext) => Promise<R[]>
): Promise<R[]> {
  const results: R[] = [];

  logger.debug(
    {
      totalItems: items.length,
      batchSize,
      batchCount: Math.ceil(items.length / batchSize),
    },
    'Starting batch vector operation'
  );

  for (let i = 0; i < items.length; i += batchSize) {
    const batch = items.slice(i, i + batchSize);
    const batchNumber = Math.floor(i / batchSize) + 1;

    try {
      logger.debug(
        {
          batchNumber,
          batchSize: batch.length,
          totalBatches: Math.ceil(items.length / batchSize),
        },
        'Processing batch'
      );

      const batchResults = await transaction(async (ctx) => {
        return await processor(batch, ctx);
      });

      results.push(...batchResults);
    } catch (error) {
      logger.error(
        {
          batchNumber,
          batchSize: batch.length,
          error: error instanceof Error ? error.message : String(error),
        },
        'Batch vector operation failed'
      );

      // For batch operations, we might want to continue with other batches
      // depending on the error type and business requirements
      throw error;
    }
  }

  logger.debug(
    {
      totalItems: items.length,
      processedItems: results.length,
    },
    'Batch vector operation completed'
  );

  return results;
}

/**
 * Optimistic update helper for concurrent vector operations
 *
 * Note: This is a simplified optimistic locking mechanism for vector operations.
 * True optimistic locking would require version vectors or timestamps stored
 * as part of the vector metadata.
 *
 * @param updateFunction - Function that performs the update with version check
 * @param maxRetries - Maximum retry attempts for concurrent updates
 * @returns Update result
 */
export async function optimisticUpdate<T>(
  updateFunction: (_ctx: VectorTransactionContext) => Promise<T>,
  maxRetries: number = 3
): Promise<DbOperationResult<T>> {
  let lastError: unknown;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await executeTransaction(
        async (ctx) => {
          return await updateFunction(ctx);
        },
        { maxRetries: 1 }
      ); // Use nested retry logic
    } catch (error) {
      lastError = error;
      const errorType = dbErrorHandler.categorizeError(error);

      // Only retry on concurrency-related errors
      if (errorType !== 'UNKNOWN_ERROR' && attempt >= maxRetries) {
        break;
      }

      if (attempt < maxRetries) {
        const delay = Math.min(100 * Math.pow(2, attempt - 1), 1000);
        await sleep(delay);
      }
    }
  }

  const errorType = dbErrorHandler.categorizeError(lastError);
  const errorMessage = lastError instanceof Error ? lastError.message : String(lastError);

  return {
    success: false,
    error: {
      type: errorType,
      message: `Optimistic update failed after ${maxRetries} attempts: ${errorMessage}`,
      originalError: lastError,
    },
    retryAttempts: maxRetries - 1,
  };
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
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Health check for vector operation functionality
 */
export async function transactionHealthCheck(): Promise<{
  healthy: boolean;
  message: string;
  latency?: number;
}> {
  try {
    const startTime = Date.now();

    await transaction(
      async (ctx) => {
        // Simple test operation - just validate the transaction context works
        ctx.operations.push({
          type: 'health_check',
          data: { test: true },
          timestamp: Date.now(),
        });

        // Simulate a small delay to test timeout handling
        await new Promise((resolve) => setTimeout(resolve, 10));

        return { status: 'ok', operations: ctx.operations.length };
      },
      { timeout: 5000 }
    );

    const latency = Date.now() - startTime;

    return {
      healthy: true,
      message: 'Vector operation system is healthy',
      latency,
    };
  } catch {
    return {
      healthy: false,
      message: 'Vector operation health check failed',
    };
  }
}
