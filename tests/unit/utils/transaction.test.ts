/**
 * Comprehensive Unit Tests for Transaction Handling Utilities
 *
 * Tests transaction functionality including:
 * - Transaction execution with retry logic
 * - Error handling and categorization
 * - Parallel transaction processing
 * - Batch operations
 * - Optimistic locking
 * - Health checks and monitoring
 * - Performance and scalability
 */

import {
  executeTransaction,
  transaction,
  executeParallelTransactions,
  batchOperation,
  optimisticUpdate,
  transactionHealthCheck,
} from '../../src/utils/transaction';

// Mock the dependencies
vi.mock('../../src/db/prisma-client.js', () => ({
  prisma: {
    getClient: vi.fn(() => mockPrismaClient),
  },
}));

vi.mock('../../src/utils/logger.js', () => ({
  logger: {
    debug: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

vi.mock('../../src/utils/db-error-handler.js', () => ({
  dbErrorHandler: {
    categorizeError: vi.fn(),
  },
}));

// Mock Prisma client
const mockPrismaClient = {
  $transaction: vi.fn(),
  $queryRaw: vi.fn(),
  someModel: {
    findUnique: vi.fn(),
    update: vi.fn(),
  },
};

describe('Transaction Handling Utilities', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.resetAllMocks();

    // Default successful transaction mock
    mockPrismaClient.$transaction.mockImplementation(async (callback) => {
      return await callback(mockTx);
    });

    // Default successful error categorization
    const { dbErrorHandler } = require('../../src/utils/db-error-handler.js');
    dbErrorHandler.categorizeError.mockReturnValue('UNKNOWN_ERROR');
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // Mock transaction object
  const mockTx = {
    $queryRaw: vi.fn(),
    someModel: {
      findUnique: vi.fn(),
      update: vi.fn(),
      create: vi.fn(),
      delete: vi.fn(),
    },
  };

  describe('executeTransaction', () => {
    it('should execute transaction successfully', async () => {
      const callback = vi.fn().mockResolvedValue('success');
      const { dbErrorHandler } = require('../../src/utils/db-error-handler.js');

      dbErrorHandler.categorizeError.mockReturnValue('UNKNOWN_ERROR');

      const result = await executeTransaction(callback);

      expect(result.success).toBe(true);
      expect(result.data).toBe('success');
      expect(result.retryAttempts).toBe(0);
      expect(callback).toHaveBeenCalledWith(mockTx);
    });

    it('should use default options when none provided', async () => {
      const callback = vi.fn().mockResolvedValue('success');

      await executeTransaction(callback);

      expect(mockPrismaClient.$transaction).toHaveBeenCalledWith(
        expect.any(Function),
        {
          timeout: 30000,
          isolationLevel: 'ReadCommitted',
        }
      );
    });

    it('should use custom options when provided', async () => {
      const callback = vi.fn().mockResolvedValue('success');
      const options = {
        timeout: 60000,
        isolationLevel: 'Serializable' as const,
        maxRetries: 5,
      };

      await executeTransaction(callback, options);

      expect(mockPrismaClient.$transaction).toHaveBeenCalledWith(
        expect.any(Function),
        {
          timeout: 60000,
          isolationLevel: 'Serializable',
        }
      );
    });

    it('should retry on retryable errors', async () => {
      const { dbErrorHandler } = require('../../src/utils/db-error-handler.js');

      // First call fails, second succeeds
      const callback = vi.fn()
        .mockRejectedValueOnce(new Error('Connection conflict'))
        .mockResolvedValueOnce('success');

      // First error is retryable, second is not (for successful case)
      dbErrorHandler.categorizeError
        .mockReturnValueOnce('CONFLICT')
        .mockReturnValueOnce('UNKNOWN_ERROR');

      // Mock delay for retry
      const originalSetTimeout = global.setTimeout;
      const mockSetTimeout = vi.fn().mockImplementation((fn, delay) => {
        fn(); // Execute immediately for test
        return 1;
      });
      global.setTimeout = mockSetTimeout;

      const result = await executeTransaction(callback, { maxRetries: 2 });

      expect(result.success).toBe(true);
      expect(result.data).toBe('success');
      expect(result.retryAttempts).toBe(1);
      expect(callback).toHaveBeenCalledTimes(2);

      global.setTimeout = originalSetTimeout;
    });

    it('should fail after max retries exceeded', async () => {
      const { dbErrorHandler } = require('../../src/utils/db-error-handler.js');

      const callback = vi.fn().mockRejectedValue(new Error('Persistent error'));
      dbErrorHandler.categorizeError.mockReturnValue('CONFLICT');

      // Mock setTimeout to avoid delays in tests
      const originalSetTimeout = global.setTimeout;
      global.setTimeout = vi.fn().mockImplementation((fn) => {
        fn();
        return 1;
      });

      const result = await executeTransaction(callback, { maxRetries: 2 });

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.retryAttempts).toBe(2);
      expect(callback).toHaveBeenCalledTimes(3); // Initial + 2 retries

      global.setTimeout = originalSetTimeout;
    });

    it('should not retry on non-retryable errors', async () => {
      const { dbErrorHandler } = require('../../src/utils/db-error-handler.js');

      const callback = vi.fn().mockRejectedValue(new Error('Constraint violation'));
      dbErrorHandler.categorizeError.mockReturnValue('CONSTRAINT_VIOLATION');

      const result = await executeTransaction(callback, { maxRetries: 3 });

      expect(result.success).toBe(false);
      expect(result.retryAttempts).toBe(0);
      expect(callback).toHaveBeenCalledTimes(1); // Only initial call, no retries
    });

    it('should use exponential backoff for retries', async () => {
      const { dbErrorHandler } = require('../../src/utils/db-error-handler.js');

      const callback = vi.fn().mockRejectedValue(new Error('Retryable error'));
      dbErrorHandler.categorizeError.mockReturnValue('CONFLICT');

      const delays: number[] = [];
      const originalSetTimeout = global.setTimeout;
      global.setTimeout = vi.fn().mockImplementation((fn, delay) => {
        delays.push(delay);
        fn();
        return 1;
      });

      await executeTransaction(callback, { maxRetries: 3 });

      // Should use exponential backoff: 1000ms, 2000ms, 4000ms (capped at 5000ms)
      expect(delays).toEqual([1000, 2000, 4000]);

      global.setTimeout = originalSetTimeout;
    });

    it('should cap retry delay at maximum', async () => {
      const { dbErrorHandler } = require('../../src/utils/db-error-handler.js');

      const callback = vi.fn().mockRejectedValue(new Error('Retryable error'));
      dbErrorHandler.categorizeError.mockReturnValue('CONFLICT');

      const delays: number[] = [];
      const originalSetTimeout = global.setTimeout;
      global.setTimeout = vi.fn().mockImplementation((fn, delay) => {
        delays.push(delay);
        fn();
        return 1;
      });

      // Use more retries to hit the cap
      await executeTransaction(callback, { maxRetries: 10 });

      // Delays should be capped at 5000ms
      expect(delays.every(delay => delay <= 5000)).toBe(true);
      expect(delays).toContain(5000); // Should hit the cap

      global.setTimeout = originalSetTimeout;
    });

    it('should log debug information during execution', async () => {
      const { logger } = require('../../src/utils/logger.js');
      const callback = vi.fn().mockResolvedValue('success');

      await executeTransaction(callback);

      expect(logger.debug).toHaveBeenCalledWith(
        expect.objectContaining({ attempt: 1, maxRetries: 3 }),
        'Starting transaction attempt'
      );

      expect(logger.debug).toHaveBeenCalledWith(
        expect.objectContaining({ duration: expect.any(Number), attempt: 1 }),
        'Transaction completed successfully'
      );
    });

    it('should log warnings for failed attempts', async () => {
      const { logger, dbErrorHandler } = require('../../src/utils/db-error-handler.js');

      const callback = vi.fn().mockRejectedValue(new Error('Test error'));
      dbErrorHandler.categorizeError.mockReturnValue('CONFLICT');

      const originalSetTimeout = global.setTimeout;
      global.setTimeout = vi.fn().mockImplementation((fn) => {
        fn();
        return 1;
      });

      await executeTransaction(callback, { maxRetries: 1 });

      expect(logger.warn).toHaveBeenCalledWith(
        expect.objectContaining({
          attempt: 1,
          maxRetries: 1,
          errorType: 'CONFLICT',
        }),
        'Transaction attempt failed'
      );

      global.setTimeout = originalSetTimeout;
    });
  });

  describe('transaction', () => {
    it('should execute transaction and throw on error', async () => {
      const callback = vi.fn().mockResolvedValue('success');

      const result = await transaction(callback);

      expect(result).toBe('success');
      expect(callback).toHaveBeenCalledWith(mockTx);
    });

    it('should throw error when transaction fails', async () => {
      const callback = vi.fn().mockRejectedValue(new Error('Transaction failed'));

      await expect(transaction(callback)).rejects.toThrow('Transaction failed');
    });

    it('should use default options', async () => {
      const callback = vi.fn().mockResolvedValue('success');

      await transaction(callback);

      expect(mockPrismaClient.$transaction).toHaveBeenCalledWith(
        expect.any(Function),
        {
          timeout: 30000,
          isolationLevel: 'ReadCommitted',
        }
      );
    });

    it('should pass through custom options', async () => {
      const callback = vi.fn().mockResolvedValue('success');
      const options = {
        timeout: 45000,
        isolationLevel: 'RepeatableRead' as const,
      };

      await transaction(callback, options);

      expect(mockPrismaClient.$transaction).toHaveBeenCalledWith(
        expect.any(Function),
        {
          timeout: 45000,
          isolationLevel: 'RepeatableRead',
        }
      );
    });
  });

  describe('executeParallelTransactions', () => {
    it('should execute multiple transactions in parallel', async () => {
      const operations = [
        vi.fn().mockResolvedValue('result1'),
        vi.fn().mockResolvedValue('result2'),
        vi.fn().mockResolvedValue('result3'),
      ];

      const results = await executeParallelTransactions(operations);

      expect(results).toHaveLength(3);
      expect(results[0].success).toBe(true);
      expect(results[0].data).toBe('result1');
      expect(results[1].success).toBe(true);
      expect(results[1].data).toBe('result2');
      expect(results[2].success).toBe(true);
      expect(results[2].data).toBe('result3');
    });

    it('should handle mixed success and failure operations', async () => {
      const { dbErrorHandler } = require('../../src/utils/db-error-handler.js');

      const operations = [
        vi.fn().mockResolvedValue('result1'),
        vi.fn().mockRejectedValue(new Error('Operation failed')),
        vi.fn().mockResolvedValue('result3'),
      ];

      dbErrorHandler.categorizeError.mockReturnValue('UNKNOWN_ERROR');

      const results = await executeParallelTransactions(operations);

      expect(results).toHaveLength(3);
      expect(results[0].success).toBe(true);
      expect(results[1].success).toBe(false);
      expect(results[2].success).toBe(true);
    });

    it('should use options for all parallel transactions', async () => {
      const operations = [
        vi.fn().mockResolvedValue('result1'),
        vi.fn().mockResolvedValue('result2'),
      ];

      const options = {
        timeout: 60000,
        maxRetries: 5,
      };

      await executeParallelTransactions(operations, options);

      expect(mockPrismaClient.$transaction).toHaveBeenCalledTimes(2);
      // Each transaction should get the same options
      expect(mockPrismaClient.$transaction).toHaveBeenCalledWith(
        expect.any(Function),
        {
          timeout: 60000,
          isolationLevel: 'ReadCommitted',
        }
      );
    });

    it('should log parallel transaction statistics', async () => {
      const { logger } = require('../../src/utils/logger.js');

      const operations = [
        vi.fn().mockResolvedValue('result1'),
        vi.fn().mockResolvedValue('result2'),
        vi.fn().mockResolvedValue('result3'),
      ];

      await executeParallelTransactions(operations);

      expect(logger.debug).toHaveBeenCalledWith(
        expect.objectContaining({
          total: 3,
          successCount: 3,
          failureCount: 0,
        }),
        'Parallel transactions completed'
      );
    });

    it('should handle empty operations array', async () => {
      const results = await executeParallelTransactions([]);

      expect(results).toHaveLength(0);
    });

    it('should handle individual transaction errors gracefully', async () => {
      const { logger } = require('../../src/utils/logger.js');

      const operations = [
        vi.fn().mockRejectedValue(new Error('Individual error')),
      ];

      const results = await executeParallelTransactions(operations);

      expect(results[0].success).toBe(false);
      expect(results[0].error).toBeDefined();
      expect(logger.error).toHaveBeenCalledWith(
        expect.objectContaining({
          index: 0,
          error: expect.any(Error),
        }),
        'Parallel transaction failed'
      );
    });
  });

  describe('batchOperation', () => {
    it('should process items in batches', async () => {
      const items = Array.from({ length: 10 }, (_, i) => `item${i}`);
      const batchSize = 3;
      const processor = vi.fn().mockImplementation((batch) =>
        Promise.resolve(batch.map(item => `processed_${item}`))
      );

      const results = await batchOperation(items, batchSize, processor);

      expect(results).toHaveLength(10);
      expect(processor).toHaveBeenCalledTimes(4); // ceil(10/3) = 4 batches
      expect(processor).toHaveBeenNthCalledWith(1, ['item0', 'item1', 'item2'], expect.any(Object));
      expect(processor).toHaveBeenNthCalledWith(2, ['item3', 'item4', 'item5'], expect.any(Object));
      expect(processor).toHaveBeenNthCalledWith(3, ['item6', 'item7', 'item8'], expect.any(Object));
      expect(processor).toHaveBeenNthCalledWith(4, ['item9'], expect.any(Object));
    });

    it('should use default batch size', async () => {
      const items = Array.from({ length: 150 }, (_, i) => `item${i}`);
      const processor = vi.fn().mockResolvedValue([]);

      await batchOperation(items, undefined, processor);

      expect(processor).toHaveBeenCalledTimes(2); // ceil(150/100) = 2 batches
    });

    it('should process each batch within a transaction', async () => {
      const items = ['item1', 'item2', 'item3'];
      const processor = vi.fn().mockResolvedValue(['processed_item1', 'processed_item2', 'processed_item3']);

      await batchOperation(items, 2, processor);

      // Should create a transaction for each batch
      expect(mockPrismaClient.$transaction).toHaveBeenCalledTimes(2);
    });

    it('should log batch processing information', async () => {
      const { logger } = require('../../src/utils/logger.js');

      const items = Array.from({ length: 10 }, (_, i) => `item${i}`);
      const processor = vi.fn().mockResolvedValue([]);

      await batchOperation(items, 3, processor);

      expect(logger.debug).toHaveBeenCalledWith(
        expect.objectContaining({
          totalItems: 10,
          batchSize: 3,
          batchCount: 4,
        }),
        'Starting batch operation'
      );

      expect(logger.debug).toHaveBeenCalledWith(
        expect.objectContaining({
          batchNumber: 1,
          batchSize: 3,
          totalBatches: 4,
        }),
        'Processing batch'
      );
    });

    it('should log batch completion', async () => {
      const { logger } = require('../../src/utils/logger.js');

      const items = ['item1', 'item2'];
      const processor = vi.fn().mockResolvedValue(['processed1', 'processed2']);

      await batchOperation(items, 2, processor);

      expect(logger.debug).toHaveBeenCalledWith(
        expect.objectContaining({
          totalItems: 2,
          processedItems: 2,
        }),
        'Batch operation completed'
      );
    });

    it('should throw error when batch processing fails', async () => {
      const items = ['item1', 'item2'];
      const processor = vi.fn().mockRejectedValue(new Error('Batch failed'));

      await expect(batchOperation(items, 2, processor)).rejects.toThrow('Batch failed');
    });

    it('should handle empty items array', async () => {
      const processor = vi.fn();
      const results = await batchOperation([], 10, processor);

      expect(results).toEqual([]);
      expect(processor).not.toHaveBeenCalled();
    });

    it('should handle single item batch', async () => {
      const items = ['single_item'];
      const processor = vi.fn().mockResolvedValue(['processed_single']);

      const results = await batchOperation(items, 10, processor);

      expect(results).toEqual(['processed_single']);
      expect(processor).toHaveBeenCalledTimes(1);
      expect(processor).toHaveBeenCalledWith(['single_item'], expect.any(Object));
    });
  });

  describe('optimisticUpdate', () => {
    it('should update record successfully with version check', async () => {
      const model = 'someModel';
      const id = '123e4567-e89b-12d3-a456-426614174000';
      const data = { name: 'Updated Name' };
      const expectedVersion = new Date('2025-01-01T12:00:00Z');

      // Mock successful version check and update
      mockTx.someModel.findUnique.mockResolvedValue({
        id,
        updated_at: expectedVersion,
      });

      mockTx.someModel.update.mockResolvedValue({
        id,
        name: 'Updated Name',
        updated_at: new Date(),
      });

      const result = await optimisticUpdate(model, id, data, 'updated_at', expectedVersion);

      expect(result.success).toBe(true);
      expect(mockTx.someModel.findUnique).toHaveBeenCalledWith({
        where: { id },
        select: { updated_at: true },
      });

      expect(mockTx.someModel.update).toHaveBeenCalledWith({
        where: {
          id,
          updated_at: expectedVersion
        },
        data,
      });
    });

    it('should throw error when record not found', async () => {
      const model = 'someModel';
      const id = 'non-existent-id';
      const data = { name: 'Updated Name' };

      mockTx.someModel.findUnique.mockResolvedValue(null);

      const result = await optimisticUpdate(model, id, data);

      expect(result.success).toBe(false);
      expect(result.error?.message).toContain('not found');
    });

    it('should throw error when version mismatch', async () => {
      const model = 'someModel';
      const id = '123e4567-e89b-12d3-a456-426614174000';
      const data = { name: 'Updated Name' };
      const expectedVersion = new Date('2025-01-01T12:00:00Z');
      const actualVersion = new Date('2025-01-01T13:00:00Z'); // Different version

      mockTx.someModel.findUnique.mockResolvedValue({
        id,
        updated_at: actualVersion,
      });

      const result = await optimisticUpdate(model, id, data, 'updated_at', expectedVersion);

      expect(result.success).toBe(false);
      expect(result.error?.message).toContain('version mismatch');
    });

    it('should work without version check when expected version not provided', async () => {
      const model = 'someModel';
      const id = '123e4567-e89b-12d3-a456-426614174000';
      const data = { name: 'Updated Name' };

      mockTx.someModel.findUnique.mockResolvedValue({
        id,
        updated_at: new Date(),
      });

      mockTx.someModel.update.mockResolvedValue({
        id,
        name: 'Updated Name',
        updated_at: new Date(),
      });

      const result = await optimisticUpdate(model, id, data);

      expect(result.success).toBe(true);
      expect(mockTx.someModel.findUnique).toHaveBeenCalledWith({
        where: { id },
        select: { updated_at: true },
      });

      expect(mockTx.someModel.update).toHaveBeenCalledWith({
        where: { id }, // No version check
        data,
      });
    });

    it('should use custom version field', async () => {
      const model = 'someModel';
      const id = '123e4567-e89b-12d3-a456-426614174000';
      const data = { name: 'Updated Name' };
      const versionField = 'version_number';
      const expectedVersion = 5;

      mockTx.someModel.findUnique.mockResolvedValue({
        id,
        [versionField]: expectedVersion,
      });

      mockTx.someModel.update.mockResolvedValue({
        id,
        name: 'Updated Name',
        [versionField]: expectedVersion + 1,
      });

      const result = await optimisticUpdate(model, id, data, versionField, expectedVersion);

      expect(result.success).toBe(true);
      expect(mockTx.someModel.findUnique).toHaveBeenCalledWith({
        where: { id },
        select: { [versionField]: true },
      });

      expect(mockTx.someModel.update).toHaveBeenCalledWith({
        where: {
          id,
          [versionField]: expectedVersion
        },
        data,
      });
    });
  });

  describe('transactionHealthCheck', () => {
    it('should return healthy status when transaction works', async () => {
      mockTx.$queryRaw.mockResolvedValue([{ test: 1 }]);

      const result = await transactionHealthCheck();

      expect(result.healthy).toBe(true);
      expect(result.message).toBe('Transaction system is healthy');
      expect(result.latency).toBeGreaterThan(0);
      expect(result.latency).toBeLessThan(1000); // Should be fast
    });

    it('should return unhealthy status when transaction fails', async () => {
      mockTx.$queryRaw.mockRejectedValue(new Error('Connection failed'));

      const result = await transactionHealthCheck();

      expect(result.healthy).toBe(false);
      expect(result.message).toContain('Transaction health check failed');
      expect(result.latency).toBeUndefined();
    });

    it('should use timeout for health check', async () => {
      mockTx.$queryRaw.mockResolvedValue([{ test: 1 }]);

      await transactionHealthCheck();

      expect(mockPrismaClient.$transaction).toHaveBeenCalledWith(
        expect.any(Function),
        {
          timeout: 5000,
          isolationLevel: 'ReadCommitted',
        }
      );
    });

    it('should handle health check timeout gracefully', async () => {
      mockPrismaClient.$transaction.mockRejectedValue(new Error('Transaction timeout'));

      const result = await transactionHealthCheck();

      expect(result.healthy).toBe(false);
      expect(result.message).toContain('failed');
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle transaction timeout errors', async () => {
      const callback = vi.fn().mockRejectedValue(new Error('Transaction timeout'));
      const { dbErrorHandler } = require('../../src/utils/db-error-handler.js');

      dbErrorHandler.categorizeError.mockReturnValue('TIMEOUT_ERROR');

      const result = await executeTransaction(callback);

      expect(result.success).toBe(false);
      expect(result.error?.message).toContain('Transaction failed');
    });

    it('should handle deadlock errors', async () => {
      const callback = vi.fn().mockRejectedValue(new Error('Deadlock detected'));
      const { dbErrorHandler } = require('../../src/utils/db-error-handler.js');

      dbErrorHandler.categorizeError.mockReturnValue('DEADLOCK');

      const originalSetTimeout = global.setTimeout;
      global.setTimeout = vi.fn().mockImplementation((fn) => {
        fn();
        return 1;
      });

      const result = await executeTransaction(callback, { maxRetries: 2 });

      expect(result.retryAttempts).toBe(2); // Should retry deadlock errors
      expect(result.success).toBe(false);

      global.setTimeout = originalSetTimeout;
    });

    it('should handle connection pool exhaustion', async () => {
      const callback = vi.fn().mockRejectedValue(new Error('Connection pool exhausted'));
      const { dbErrorHandler } = require('../../src/utils/db-error-handler.js');

      dbErrorHandler.categorizeError.mockReturnValue('CONNECTION_ERROR');

      const result = await executeTransaction(callback);

      expect(result.success).toBe(false);
      expect(result.retryAttempts).toBe(0); // Don't retry connection errors
    });

    it('should handle callback throwing non-Error objects', async () => {
      const callback = vi.fn().mockRejectedValue('String error');

      const result = await executeTransaction(callback);

      expect(result.success).toBe(false);
      expect(result.error?.message).toBe('String error');
    });

    it('should handle null/undefined callbacks', async () => {
      await expect(executeTransaction(null as any)).rejects.toThrow();
      await expect(executeTransaction(undefined as any)).rejects.toThrow();
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle large batch operations efficiently', async () => {
      const items = Array.from({ length: 10000 }, (_, i) => `item${i}`);
      const processor = vi.fn().mockImplementation((batch) =>
        Promise.resolve(batch)
      );

      const startTime = performance.now();
      const results = await batchOperation(items, 1000, processor);
      const endTime = performance.now();

      expect(results).toHaveLength(10000);
      expect(endTime - startTime).toBeLessThan(5000); // Should complete in under 5 seconds
    });

    it('should handle many parallel transactions', async () => {
      const operations = Array.from({ length: 100 }, (_, i) =>
        vi.fn().mockResolvedValue(`result${i}`)
      );

      const startTime = performance.now();
      const results = await executeParallelTransactions(operations);
      const endTime = performance.now();

      expect(results).toHaveLength(100);
      expect(results.every(r => r.success)).toBe(true);
      expect(endTime - startTime).toBeLessThan(2000); // Should complete in under 2 seconds
    });

    it('should not leak memory during transaction operations', async () => {
      const initialMemory = process.memoryUsage().heapUsed;

      // Perform many transaction operations
      for (let i = 0; i < 1000; i++) {
        const callback = vi.fn().mockResolvedValue(`result${i}`);
        await executeTransaction(callback);
      }

      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;

      // Memory increase should be reasonable
      expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024); // Less than 50MB
    });
  });

  describe('Integration Scenarios', () => {
    it('should handle complete workflow with retry and batch processing', async () => {
      const { dbErrorHandler } = require('../../src/utils/db-error-handler.js');

      // Simulate a scenario where some operations need retry
      let attemptCount = 0;
      const processor = vi.fn().mockImplementation((batch) => {
        attemptCount++;
        if (attemptCount === 1) {
          throw new Error('Transient error');
        }
        return Promise.resolve(batch.map(item => `processed_${item}`));
      });

      // First call fails, second succeeds
      dbErrorHandler.categorizeError
        .mockReturnValueOnce('CONNECTION_ERROR') // Non-retryable for batch
        .mockReturnValueOnce('UNKNOWN_ERROR');

      const items = ['item1', 'item2', 'item3'];

      // This should fail on the first batch due to non-retryable error
      await expect(batchOperation(items, 2, processor)).rejects.toThrow('Transient error');
    });

    it('should handle complex transaction with multiple operations', async () => {
      const callback = vi.fn().mockImplementation(async (tx) => {
        // Simulate complex transaction logic
        await tx.$queryRaw`SELECT 1`;
        const result1 = await tx.someModel.findUnique({ where: { id: 'test' } });
        const result2 = await tx.someModel.update({
          where: { id: 'test' },
          data: { name: 'updated' }
        });
        return { result1, result2 };
      });

      mockTx.$queryRaw.mockResolvedValue([{ test: 1 }]);
      mockTx.someModel.findUnique.mockResolvedValue({ id: 'test', name: 'original' });
      mockTx.someModel.update.mockResolvedValue({ id: 'test', name: 'updated' });

      const result = await executeTransaction(callback);

      expect(result.success).toBe(true);
      expect(result.data).toEqual({
        result1: { id: 'test', name: 'original' },
        result2: { id: 'test', name: 'updated' },
      });
    });

    it('should handle nested transaction scenarios', async () => {
      const innerCallback = vi.fn().mockResolvedValue('inner result');
      const outerCallback = vi.fn().mockImplementation(async (tx) => {
        const innerResult = await transaction(innerCallback);
        return `outer + ${innerResult}`;
      });

      // This tests that nested transactions are handled correctly
      // In reality, Prisma doesn't support true nested transactions,
      // but this tests our wrapper behavior
      await expect(outerCallback()).resolves.toBe('outer + inner result');
    });
  });
});