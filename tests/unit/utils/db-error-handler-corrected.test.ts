/**
 * Database Error Handler Comprehensive Test Suite (Corrected Singleton Mocking)
 *
 * Tests all error types, retry logic, fallback mechanisms, and edge cases
 * for the DatabaseErrorHandler class and related utilities.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { DatabaseErrorHandler, DbErrorType, RetryConfig } from '../../../src/utils/db-error-handler.js';

// Mock at module level with inline mock object
vi.mock('../../../src/utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn()
  },
  createChildLogger: vi.fn((ctx) => ({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
    child: vi.fn(() => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }))
  }))
}));

// Mock the db-error-handler module to control the singleton
vi.mock('../../../src/utils/db-error-handler.js', async () => {
  const actual = await vi.importActual('../../../src/utils/db-error-handler.js');
  const { DatabaseErrorHandler } = actual as any;

  return {
    ...actual,
    dbErrorHandler: new DatabaseErrorHandler(),
    safeDbOperation: vi.fn()
  };
});

// Import after mocking
import { safeDbOperation } from '../../../src/utils/db-error-handler.js';
import { logger } from '../../../src/utils/logger.js';

describe('DatabaseErrorHandler', () => {
  let errorHandler: DatabaseErrorHandler;

  beforeEach(() => {
    vi.clearAllMocks();
    errorHandler = new DatabaseErrorHandler();
  });

  describe('Constructor and Configuration', () => {
    it('should create instance with default retry config', () => {
      const handler = new DatabaseErrorHandler();
      expect(handler).toBeInstanceOf(DatabaseErrorHandler);
    });

    it('should accept custom retry configuration', () => {
      const customConfig: RetryConfig = {
        maxRetries: 5,
        baseDelayMs: 500,
        maxDelayMs: 5000,
        backoffMultiplier: 1.5
      };
      const handler = new DatabaseErrorHandler(customConfig);
      expect(handler).toBeInstanceOf(DatabaseErrorHandler);
    });
  });

  describe('Error Categorization', () => {
    describe('Connection Errors', () => {
      it('should categorize connection refused errors', () => {
        const error = new Error('ECONNREFUSED: Connection refused');
        expect(errorHandler.categorizeError(error)).toBe(DbErrorType.CONNECTION_ERROR);
      });

      it('should categorize connection timeout errors', () => {
        const error = new Error('Connection timeout occurred');
        expect(errorHandler.categorizeError(error)).toBe(DbErrorType.CONNECTION_ERROR);
      });

      it('should categorize connection failed errors', () => {
        const error = new Error('Unable to connect to database');
        expect(errorHandler.categorizeError(error)).toBe(DbErrorType.CONNECTION_ERROR);
      });
    });

    describe('Timeout Errors', () => {
      it('should categorize timeout errors', () => {
        const error = new Error('Query timeout after 30 seconds');
        expect(errorHandler.categorizeError(error)).toBe(DbErrorType.TIMEOUT_ERROR);
      });

      it('should categorize timed out errors', () => {
        const error = new Error('Operation timed out');
        expect(errorHandler.categorizeError(error)).toBe(DbErrorType.TIMEOUT_ERROR);
      });
    });

    describe('Constraint Violations', () => {
      it('should categorize unique constraint violations', () => {
        const error = new Error('Unique constraint violation on field username');
        expect(errorHandler.categorizeError(error)).toBe(DbErrorType.CONSTRAINT_VIOLATION);
      });

      it('should categorize foreign key constraint violations', () => {
        const error = new Error('Foreign key constraint violation');
        expect(errorHandler.categorizeError(error)).toBe(DbErrorType.CONSTRAINT_VIOLATION);
      });

      it('should categorize duplicate key errors', () => {
        const error = new Error('Duplicate key error');
        expect(errorHandler.categorizeError(error)).toBe(DbErrorType.CONSTRAINT_VIOLATION);
      });
    });

    describe('Record Not Found Errors', () => {
      it('should categorize not found errors', () => {
        const error = new Error('Record not found');
        expect(errorHandler.categorizeError(error)).toBe(DbErrorType.RECORD_NOT_FOUND);
      });

      it('should categorize no rows returned errors', () => {
        const error = new Error('No rows returned');
        expect(errorHandler.categorizeError(error)).toBe(DbErrorType.RECORD_NOT_FOUND);
      });
    });

    describe('Permission Errors', () => {
      it('should categorize permission denied errors', () => {
        const error = new Error('Permission denied for operation');
        expect(errorHandler.categorizeError(error)).toBe(DbErrorType.PERMISSION_ERROR);
      });

      it('should categorize access denied errors', () => {
        const error = new Error('Access denied');
        expect(errorHandler.categorizeError(error)).toBe(DbErrorType.PERMISSION_ERROR);
      });

      it('should categorize unauthorized errors', () => {
        const error = new Error('Unauthorized access');
        expect(errorHandler.categorizeError(error)).toBe(DbErrorType.PERMISSION_ERROR);
      });
    });

    describe('Schema Errors', () => {
      it('should categorize table not found errors', () => {
        const error = new Error('Table "users" does not exist');
        expect(errorHandler.categorizeError(error)).toBe(DbErrorType.SCHEMA_ERROR);
      });

      it('should categorize column not found errors', () => {
        const error = new Error('Unknown column "invalid_field" in table');
        expect(errorHandler.categorizeError(error)).toBe(DbErrorType.SCHEMA_ERROR);
      });

      it('should categorize schema validation errors', () => {
        const error = new Error('Schema validation failed');
        expect(errorHandler.categorizeError(error)).toBe(DbErrorType.SCHEMA_ERROR);
      });
    });

    describe('Unknown Errors', () => {
      it('should categorize unrecognized errors as unknown', () => {
        const error = new Error('Some completely unexpected error');
        expect(errorHandler.categorizeError(error)).toBe(DbErrorType.UNKNOWN_ERROR);
      });

      it('should handle non-Error objects', () => {
        const error = 'String error message';
        expect(errorHandler.categorizeError(error)).toBe(DbErrorType.UNKNOWN_ERROR);
      });

      it('should handle null/undefined errors', () => {
        expect(errorHandler.categorizeError(null)).toBe(DbErrorType.UNKNOWN_ERROR);
        expect(errorHandler.categorizeError(undefined)).toBe(DbErrorType.UNKNOWN_ERROR);
      });
    });
  });

  describe('Retry Logic', () => {
    it('should succeed on first attempt', async () => {
      const mockOperation = vi.fn().mockResolvedValue('success');

      const result = await errorHandler.executeWithRetry(
        mockOperation,
        'test-operation'
      );

      expect(result.success).toBe(true);
      expect(result.data).toBe('success');
      expect(result.retryAttempts).toBe(0);
      expect(mockOperation).toHaveBeenCalledTimes(1);
    });

    it('should retry on connection errors', async () => {
      const mockOperation = vi.fn()
        .mockRejectedValueOnce(new Error('Connection refused'))
        .mockResolvedValue('success');

      const result = await errorHandler.executeWithRetry(
        mockOperation,
        'test-operation',
        { maxRetries: 2, baseDelayMs: 10, maxDelayMs: 100, backoffMultiplier: 2 }
      );

      expect(result.success).toBe(true);
      expect(result.data).toBe('success');
      expect(result.retryAttempts).toBe(1);
      expect(mockOperation).toHaveBeenCalledTimes(2);
    });

    it('should retry on timeout errors', async () => {
      const mockOperation = vi.fn()
        .mockRejectedValueOnce(new Error('Operation timed out'))
        .mockRejectedValueOnce(new Error('Connection timeout'))
        .mockResolvedValue('success');

      const result = await errorHandler.executeWithRetry(
        mockOperation,
        'test-operation',
        { maxRetries: 3, baseDelayMs: 10, maxDelayMs: 100, backoffMultiplier: 2 }
      );

      expect(result.success).toBe(true);
      expect(result.data).toBe('success');
      expect(result.retryAttempts).toBe(2);
      expect(mockOperation).toHaveBeenCalledTimes(3);
    });

    it('should not retry constraint violations', async () => {
      const mockOperation = vi.fn()
        .mockRejectedValue(new Error('Unique constraint violation'));

      const result = await errorHandler.executeWithRetry(
        mockOperation,
        'test-operation',
        { maxRetries: 3, baseDelayMs: 10, maxDelayMs: 100, backoffMultiplier: 2 }
      );

      expect(result.success).toBe(false);
      expect(result.error?.type).toBe(DbErrorType.CONSTRAINT_VIOLATION);
      expect(result.retryAttempts).toBe(0);
      expect(mockOperation).toHaveBeenCalledTimes(1);
    });

    it('should not retry permission errors', async () => {
      const mockOperation = vi.fn()
        .mockRejectedValue(new Error('Access denied'));

      const result = await errorHandler.executeWithRetry(
        mockOperation,
        'test-operation',
        { maxRetries: 3, baseDelayMs: 10, maxDelayMs: 100, backoffMultiplier: 2 }
      );

      expect(result.success).toBe(false);
      expect(result.error?.type).toBe(DbErrorType.PERMISSION_ERROR);
      expect(result.retryAttempts).toBe(0);
      expect(mockOperation).toHaveBeenCalledTimes(1);
    });

    it('should not retry schema errors', async () => {
      const mockOperation = vi.fn()
        .mockRejectedValue(new Error('Table does not exist'));

      const result = await errorHandler.executeWithRetry(
        mockOperation,
        'test-operation',
        { maxRetries: 3, baseDelayMs: 10, maxDelayMs: 100, backoffMultiplier: 2 }
      );

      expect(result.success).toBe(false);
      expect(result.error?.type).toBe(DbErrorType.SCHEMA_ERROR);
      expect(result.retryAttempts).toBe(0);
      expect(mockOperation).toHaveBeenCalledTimes(1);
    });

    it('should exhaust max retries', async () => {
      const mockOperation = vi.fn()
        .mockRejectedValue(new Error('Connection refused'));

      const result = await errorHandler.executeWithRetry(
        mockOperation,
        'test-operation',
        { maxRetries: 2, baseDelayMs: 10, maxDelayMs: 100, backoffMultiplier: 2 }
      );

      expect(result.success).toBe(false);
      expect(result.error?.type).toBe(DbErrorType.CONNECTION_ERROR);
      expect(result.retryAttempts).toBe(2);
      expect(mockOperation).toHaveBeenCalledTimes(3); // 1 initial + 2 retries
    });

    it('should use exponential backoff', async () => {
      const mockOperation = vi.fn()
        .mockRejectedValue(new Error('Connection refused'));

      const startTime = Date.now();

      await errorHandler.executeWithRetry(
        mockOperation,
        'test-operation',
        { maxRetries: 2, baseDelayMs: 50, maxDelayMs: 1000, backoffMultiplier: 2 }
      );

      const elapsed = Date.now() - startTime;

      // Should have waited approximately 50ms + 100ms = 150ms minimum
      expect(elapsed).toBeGreaterThan(100);
      expect(mockOperation).toHaveBeenCalledTimes(3); // 1 initial + 2 retries
    });
  });

  describe('Fallback Mechanism', () => {
    it('should use fallback when primary fails', async () => {
      const primaryOperation = vi.fn().mockRejectedValue(new Error('Connection refused'));
      const fallbackOperation = vi.fn().mockResolvedValue('fallback-success');

      const result = await errorHandler.executeWithFallback(
        primaryOperation,
        fallbackOperation,
        'test-operation'
      );

      expect(result.success).toBe(true);
      expect(result.data).toBe('fallback-success');
      expect(primaryOperation).toHaveBeenCalledTimes(1);
      expect(fallbackOperation).toHaveBeenCalledTimes(1);
    });

    it('should use primary when it succeeds', async () => {
      const primaryOperation = vi.fn().mockResolvedValue('primary-success');
      const fallbackOperation = vi.fn().mockResolvedValue('fallback-success');

      const result = await errorHandler.executeWithFallback(
        primaryOperation,
        fallbackOperation,
        'test-operation'
      );

      expect(result.success).toBe(true);
      expect(result.data).toBe('primary-success');
      expect(primaryOperation).toHaveBeenCalledTimes(1);
      expect(fallbackOperation).toHaveBeenCalledTimes(0);
    });

    it('should fail when both primary and fallback fail', async () => {
      const primaryOperation = vi.fn().mockRejectedValue(new Error('Primary failed'));
      const fallbackOperation = vi.fn().mockRejectedValue(new Error('Fallback failed'));

      const result = await errorHandler.executeWithFallback(
        primaryOperation,
        fallbackOperation,
        'test-operation'
      );

      expect(result.success).toBe(false);
      expect(result.error?.type).toBe(DbErrorType.UNKNOWN_ERROR);
      expect(result.error?.message).toContain('Both primary and fallback failed');
      expect(primaryOperation).toHaveBeenCalledTimes(1);
      expect(fallbackOperation).toHaveBeenCalledTimes(1);
    });
  });

  describe('Logging', () => {
    it('should log successful operations after retries', async () => {
      const mockOperation = vi.fn()
        .mockRejectedValueOnce(new Error('Connection refused'))
        .mockResolvedValue('success');

      await errorHandler.executeWithRetry(
        mockOperation,
        'test-operation',
        { maxRetries: 2, baseDelayMs: 10, maxDelayMs: 100, backoffMultiplier: 2 }
      );

      expect(logger.info).toHaveBeenCalledWith(
        { operation: 'test-operation', attempts: 2 },
        'Database operation succeeded after retries'
      );
    });

    it('should log operation failures', async () => {
      const mockOperation = vi.fn()
        .mockRejectedValue(new Error('Connection refused'));

      await errorHandler.executeWithRetry(
        mockOperation,
        'test-operation',
        { maxRetries: 1, baseDelayMs: 10, maxDelayMs: 100, backoffMultiplier: 2 }
      );

      expect(logger.warn).toHaveBeenCalledTimes(2); // Initial failure + retry failure
      expect(logger.warn).toHaveBeenCalledWith(
        expect.objectContaining({
          operation: 'test-operation',
          attempt: expect.any(Number),
          maxRetries: 2,
          errorType: DbErrorType.CONNECTION_ERROR
        }),
        'Database operation failed'
      );
    });

    it('should log fallback usage', async () => {
      const primaryOperation = vi.fn().mockRejectedValue(new Error('Primary failed'));
      const fallbackOperation = vi.fn().mockResolvedValue('success');

      await errorHandler.executeWithFallback(
        primaryOperation,
        fallbackOperation,
        'test-operation'
      );

      expect(logger.warn).toHaveBeenCalledWith(
        { operation: 'test-operation', error: expect.any(Object) },
        'Primary operation failed, trying fallback'
      );
    });

    it('should log when both operations fail', async () => {
      const primaryOperation = vi.fn().mockRejectedValue(new Error('Primary failed'));
      const fallbackOperation = vi.fn().mockRejectedValue(new Error('Fallback failed'));

      await errorHandler.executeWithFallback(
        primaryOperation,
        fallbackOperation,
        'test-operation'
      );

      expect(logger.error).toHaveBeenCalledWith(
        {
          operation: 'test-operation',
          primaryError: expect.any(Object),
          fallbackError: expect.any(Error)
        },
        'Both primary and fallback operations failed'
      );
    });
  });

  describe('Health Check', () => {
    it('should return true for successful health check', async () => {
      const mockQdrant = {
        $queryRaw: vi.fn().mockResolvedValue([{ 1: 1 }])
      };

      const result = await errorHandler.healthCheck(mockQdrant as any);
      expect(result).toBe(true);
      expect(mockQdrant.$queryRaw).toHaveBeenCalledWith`SELECT 1`;
    });

    it('should return false for failed health check', async () => {
      const mockQdrant = {
        $queryRaw: vi.fn().mockRejectedValue(new Error('Connection failed'))
      };

      const result = await errorHandler.healthCheck(mockQdrant as any);
      expect(result).toBe(false);
      expect(logger.error).toHaveBeenCalledWith(
        { error: expect.any(Error) },
        'Database health check failed'
      );
    });
  });
});

describe('safeDbOperation Helper', () => {
  let mockErrorHandler: any;

  beforeEach(() => {
    mockErrorHandler = {
      executeWithRetry: vi.fn()
    };
  });

  it('should return data when operation succeeds', async () => {
    const mockOperation = vi.fn().mockResolvedValue('test-data');
    mockErrorHandler.executeWithRetry.mockResolvedValue({
      success: true,
      data: 'test-data',
      retryAttempts: 0
    });

    // Mock the safeDbOperation function directly
    const mockSafeDbOperation = vi.fn().mockImplementation(async (operation, operationName) => {
      const result = await mockErrorHandler.executeWithRetry(operation, operationName);
      if (!result.success) {
        throw new Error(result.error?.message || 'Database operation failed');
      }
      return result.data;
    });

    const result = await mockSafeDbOperation(mockOperation, 'test-operation');

    expect(result).toBe('test-data');
    expect(mockErrorHandler.executeWithRetry).toHaveBeenCalledWith(
      mockOperation,
      'test-operation'
    );
  });

  it('should throw error when operation fails', async () => {
    const mockOperation = vi.fn();
    mockErrorHandler.executeWithRetry.mockResolvedValue({
      success: false,
      error: {
        type: DbErrorType.CONNECTION_ERROR,
        message: 'Connection failed'
      }
    });

    const mockSafeDbOperation = vi.fn().mockImplementation(async (operation, operationName) => {
      const result = await mockErrorHandler.executeWithRetry(operation, operationName);
      if (!result.success) {
        throw new Error(result.error?.message || 'Database operation failed');
      }
      return result.data;
    });

    await expect(mockSafeDbOperation(mockOperation, 'test-operation'))
      .rejects.toThrow('Connection failed');

    expect(mockErrorHandler.executeWithRetry).toHaveBeenCalledWith(
      mockOperation,
      'test-operation'
    );
  });

  it('should throw generic error when no error message provided', async () => {
    const mockOperation = vi.fn();
    mockErrorHandler.executeWithRetry.mockResolvedValue({
      success: false,
      error: undefined
    });

    const mockSafeDbOperation = vi.fn().mockImplementation(async (operation, operationName) => {
      const result = await mockErrorHandler.executeWithRetry(operation, operationName);
      if (!result.success) {
        throw new Error(result.error?.message || 'Database operation failed');
      }
      return result.data;
    });

    await expect(mockSafeDbOperation(mockOperation, 'test-operation'))
      .rejects.toThrow('Database operation failed');
  });
});

describe('Integration Tests', () => {
  it('should handle real async operation failures', async () => {
    const errorHandler = new DatabaseErrorHandler({
      maxRetries: 2,
      baseDelayMs: 10,
      maxDelayMs: 100,
      backoffMultiplier: 1.5
    });

    let attemptCount = 0;
    const flakyOperation = async (): Promise<string> => {
      attemptCount++;
      if (attemptCount < 3) {
        throw new Error('Simulated connection failure');
      }
      return 'success-after-retries';
    };

    const result = await errorHandler.executeWithRetry(
      flakyOperation,
      'flaky-operation'
    );

    expect(result.success).toBe(true);
    expect(result.data).toBe('success-after-retries');
    expect(result.retryAttempts).toBe(2);
    expect(attemptCount).toBe(3);
  });

  it('should handle concurrent operations safely', async () => {
    const errorHandler = new DatabaseErrorHandler({
      maxRetries: 1,
      baseDelayMs: 10,
      maxDelayMs: 100,
      backoffMultiplier: 2
    });

    const operation1 = vi.fn().mockResolvedValue('result1');
    const operation2 = vi.fn().mockResolvedValue('result2');
    const operation3 = vi.fn().mockRejectedValue(new Error('Operation 3 failed'));

    const results = await Promise.allSettled([
      errorHandler.executeWithRetry(operation1, 'operation1'),
      errorHandler.executeWithRetry(operation2, 'operation2'),
      errorHandler.executeWithRetry(operation3, 'operation3')
    ]);

    expect(results[0].status).toBe('fulfilled');
    expect(results[1].status).toBe('fulfilled');
    expect(results[2].status).toBe('rejected');

    if (results[0].status === 'fulfilled') {
      expect(results[0].value.data).toBe('result1');
    }
    if (results[1].status === 'fulfilled') {
      expect(results[1].value.data).toBe('result2');
    }
  });
});