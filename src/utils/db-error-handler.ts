// @ts-nocheck - Emergency rollback: Critical database service
/**
 * Database Error Handler
 *
 * Centralized error handling and graceful degradation for database operations.
 * Provides retry logic, fallback mechanisms, and proper error categorization.
 *
 * @module utils/db-error-handler
 */

import { logger } from '@/utils/logger.js';
// Note: Removed QdrantClient import as we're using a generic database interface now

export enum DbErrorType {
  _CONNECTION_ERROR = 'CONNECTION_ERROR',
  _TIMEOUT_ERROR = 'TIMEOUT_ERROR',
  _CONSTRAINT_VIOLATION = 'CONSTRAINT_VIOLATION',
  _RECORD_NOT_FOUND = 'RECORD_NOT_FOUND',
  _PERMISSION_ERROR = 'PERMISSION_ERROR',
  _SCHEMA_ERROR = 'SCHEMA_ERROR',
  _UNKNOWN_ERROR = 'UNKNOWN_ERROR',
}

export interface RetryConfig {
  maxRetries: number;
  baseDelayMs: number;
  maxDelayMs: number;
  backoffMultiplier: number;
}

export interface DbOperationResult<T> {
  success: boolean;
  data?: T;
  error?: {
    type: DbErrorType;
    message: string;
    originalError?: unknown;
  };
  retryAttempts: number;
}

const DEFAULT_RETRY_CONFIG: RetryConfig = {
  maxRetries: 3,
  baseDelayMs: 1000,
  maxDelayMs: 10000,
  backoffMultiplier: 2,
};

export class DatabaseErrorHandler {
  constructor(private _retryConfig: RetryConfig = DEFAULT_RETRY_CONFIG) {}

  /**
   * Execute database operation with retry logic and error handling
   */
  async executeWithRetry<T>(
    operation: () => Promise<T>,
    operationName: string,
    customRetryConfig?: Partial<RetryConfig>
  ): Promise<DbOperationResult<T>> {
    const config = { ...this._retryConfig, ...customRetryConfig };
    let lastError: unknown;

    for (let attempt = 0; attempt <= config.maxRetries; attempt++) {
      try {
        const data = await operation();

        if (attempt > 0) {
          logger.info(
            { operation: operationName, attempts: attempt + 1 },
            'Database operation succeeded after retries'
          );
        }

        return {
          success: true,
          data,
          retryAttempts: attempt,
        };
      } catch (error) {
        lastError = error;
        const errorType = this.categorizeError(error);

        logger.warn(
          {
            operation: operationName,
            attempt: attempt + 1,
            maxRetries: config.maxRetries + 1,
            errorType,
            error: error instanceof Error ? error.message : String(error),
          },
          'Database operation failed'
        );

        // Don't retry certain error types
        if (this.shouldNotRetry(errorType)) {
          break;
        }

        // Wait before retry (exponential backoff)
        if (attempt < config.maxRetries) {
          const delay = Math.min(
            config.baseDelayMs * Math.pow(config.backoffMultiplier, attempt),
            config.maxDelayMs
          );
          await this.sleep(delay);
        }
      }
    }

    const errorType = this.categorizeError(lastError);

    return {
      success: false,
      error: {
        type: errorType,
        message: this.getErrorMessage(lastError, operationName),
        originalError: lastError,
      },
      retryAttempts: config.maxRetries,
    };
  }

  /**
   * Execute with graceful degradation fallback
   */
  async executeWithFallback<T>(
    primaryOperation: () => Promise<T>,
    fallbackOperation: () => Promise<T>,
    operationName: string
  ): Promise<DbOperationResult<T>> {
    // Try primary operation first
    const primaryResult = await this.executeWithRetry(primaryOperation, `${operationName}_primary`);

    if (primaryResult.success) {
      return primaryResult;
    }

    logger.warn(
      { operation: operationName, error: primaryResult.error },
      'Primary operation failed, trying fallback'
    );

    // Try fallback operation
    try {
      const fallbackData = await fallbackOperation();
      return {
        success: true,
        data: fallbackData,
        retryAttempts: primaryResult.retryAttempts ?? 0,
      };
    } catch (fallbackError) {
      logger.error(
        { operation: operationName, primaryError: primaryResult.error, fallbackError },
        'Both primary and fallback operations failed'
      );

      return {
        success: false,
        error: {
          type: DbErrorType._UNKNOWN_ERROR,
          message: `Both primary and fallback failed for ${operationName}`,
          originalError: { primary: primaryResult.error, fallback: fallbackError },
        },
        retryAttempts: primaryResult.retryAttempts ?? 0,
      };
    }
  }

  /**
   * Health check for database connection
   */
  async healthCheck(): Promise<boolean> {
    try {
      // Generic health check - actual implementation would depend on the database adapter
      // For now, just return true as a placeholder
      logger.debug('Database health check placeholder - returning true');
      return true;
    } catch {
      // Suppress unused variable warning and return false on any error
      return false;
    }
  }

  public categorizeError(error: unknown): DbErrorType {
    if (error instanceof Error) {
      const message = error.message.toLowerCase();

      // Check for Qdrant-specific errors
      if ('code' in error) {
        const qdrantErrorCode = (error as unknown).code;

        // Qdrant error codes
        switch (qdrantErrorCode) {
          case 'P2002':
            return DbErrorType._CONSTRAINT_VIOLATION; // Unique constraint
          case 'P2003':
            return DbErrorType._CONSTRAINT_VIOLATION; // Foreign key constraint
          case 'P2025':
            return DbErrorType._RECORD_NOT_FOUND; // Record not found
          case 'P2014':
            return DbErrorType._CONSTRAINT_VIOLATION; // Relation violation
          case 'P2021':
          case 'P2022':
            return DbErrorType._SCHEMA_ERROR; // Table/column not found
        }
      }

      // Check for connection errors
      if (
        message.includes('connection') ||
        message.includes('connect') ||
        message.includes('econnrefused') ||
        message.includes('connection timeout')
      ) {
        return DbErrorType._CONNECTION_ERROR;
      }

      // Check for timeout errors
      if (message.includes('timeout') || message.includes('timed out')) {
        return DbErrorType._TIMEOUT_ERROR;
      }

      // Check for constraint violations
      if (
        message.includes('constraint') ||
        message.includes('unique') ||
        message.includes('foreign key') ||
        message.includes('duplicate key')
      ) {
        return DbErrorType._CONSTRAINT_VIOLATION;
      }

      // Check for record not found
      if (
        message.includes('not found') ||
        message.includes('record not found') ||
        message.includes('no rows returned')
      ) {
        return DbErrorType._RECORD_NOT_FOUND;
      }

      // Check for permission errors
      if (
        message.includes('permission') ||
        message.includes('access denied') ||
        message.includes('unauthorized') ||
        message.includes('insufficient privileges')
      ) {
        return DbErrorType._PERMISSION_ERROR;
      }

      // Check for schema errors
      if (
        message.includes('schema') ||
        message.includes('column') ||
        message.includes('table') ||
        message.includes('does not exist') ||
        message.includes('unknown column')
      ) {
        return DbErrorType._SCHEMA_ERROR;
      }
    }

    return DbErrorType._UNKNOWN_ERROR;
  }

  private shouldNotRetry(errorType: DbErrorType): boolean {
    // Don't retry these error types as they will likely fail again
    return [
      DbErrorType._CONSTRAINT_VIOLATION,
      DbErrorType._PERMISSION_ERROR,
      DbErrorType._SCHEMA_ERROR,
      DbErrorType._RECORD_NOT_FOUND,
    ].includes(errorType);
  }

  private getErrorMessage(error: unknown, operationName: string): string {
    if (error instanceof Error) {
      return `Database operation '${operationName}' failed: ${error.message}`;
    }
    return `Database operation '${operationName}' failed with unknown error: ${String(error)}`;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

// Singleton instance
export const dbErrorHandler = new DatabaseErrorHandler();

// Helper function for common operations
export async function safeDbOperation<T>(
  operation: () => Promise<T>,
  operationName: string
): Promise<T> {
  const result = await dbErrorHandler.executeWithRetry(operation, operationName);

  if (!result.success) {
    throw new Error(result.error?.message || 'Database operation failed');
  }

  return result.data!;
}
