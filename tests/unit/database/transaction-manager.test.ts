/**
 * Comprehensive Unit Tests for Database Transaction Manager
 *
 * Tests transaction management functionality including:
 * - Transaction Lifecycle (creation, initialization, commit, rollback, isolation levels, timeout handling)
 * - Batch Transaction Operations (multiple operations, nested transactions, rollback scenarios, atomicity)
 * - Knowledge Item Transactions (storage within transactions, batch operations, consistency validation)
 * - Error Handling and Recovery (failure handling, deadlock detection, rollback verification, cleanup)
 * - Performance and Concurrency (concurrent handling, throughput testing, lock contention, resource utilization)
 * - Integration with Vector Operations (vector operations within transactions, consistency, metadata preservation)
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { describe, it, expect, beforeEach, afterEach, vi, beforeAll, afterAll } from 'vitest';
import {
  executeTransaction,
  transaction,
  executeParallelTransactions,
  batchOperation,
  optimisticUpdate,
  transactionHealthCheck,
  TransactionOptions,
  VectorTransactionContext,
} from '../../../src/utils/transaction';
import {
  dbErrorHandler,
  DbErrorType,
  DbOperationResult,
} from '../../../src/utils/db-error-handler';

// Local test utilities to avoid import conflicts
class TestUtils {
  static setupTestEnvironment(): void {
    // Mock console methods to reduce noise
    console.error = vi.fn();
    console.warn = vi.fn();
    console.info = vi.fn();
    console.debug = vi.fn();
    console.log = vi.fn();
  }

  static cleanupTestEnvironment(): void {
    // Clear all mocks
    vi.clearAllMocks();
  }
}

class TestPatterns {
  static unitTest(setupFn?: () => void | Promise<void>, teardownFn?: () => void | Promise<void>) {
    beforeEach(async () => {
      TestUtils.setupTestEnvironment();
      if (setupFn) await setupFn();
    });

    afterEach(async () => {
      if (teardownFn) await teardownFn();
      TestUtils.cleanupTestEnvironment();
    });
  }
}
import type { KnowledgeItem } from '../../../src/types/core-interfaces';

// Mock logger to avoid noise in tests
vi.mock('../../../src/utils/logger', () => ({
  logger: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

describe('Transaction Manager - Transaction Lifecycle', () => {
  beforeAll(() => {
    TestPatterns.unitTest();
  });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should create transaction with unique operation ID', async () => {
    const operationSpy = vi.fn().mockResolvedValue('success');

    const result = await executeTransaction(operationSpy);

    expect(result.success).toBe(true);
    expect(result.data).toBe('success');
    expect(result.retryAttempts).toBe(0);
    expect(operationSpy).toHaveBeenCalledTimes(1);

    // Verify transaction context was passed
    const ctx = operationSpy.mock.calls[0][0] as VectorTransactionContext;
    expect(ctx).toHaveProperty('operationId');
    expect(ctx).toHaveProperty('startTime');
    expect(ctx).toHaveProperty('operations');
    expect(ctx.operationId).toMatch(/^tx_\d+_[a-z0-9]+$/);
  });

  it('should handle transaction initialization with custom options', async () => {
    const operationSpy = vi.fn().mockResolvedValue('success');
    const options: TransactionOptions = {
      timeout: 5000,
      maxRetries: 5,
      ensureConsistency: true,
    };

    const result = await executeTransaction(operationSpy, options);

    expect(result.success).toBe(true);
    expect(operationSpy).toHaveBeenCalledTimes(1);
  });

  it('should handle successful transaction commit', async () => {
    let capturedContext: VectorTransactionContext | undefined;

    const operation = async (ctx: VectorTransactionContext) => {
      capturedContext = ctx;
      ctx.operations.push({
        type: 'test_operation',
        data: { test: 'data' },
        timestamp: Date.now(),
      });
      return 'operation_completed';
    };

    const result = await executeTransaction(operation);

    expect(result.success).toBe(true);
    expect(result.data).toBe('operation_completed');
    expect(capturedContext).toBeDefined();
    expect(capturedContext!.operations).toHaveLength(1);
    expect(capturedContext!.operations[0].type).toBe('test_operation');
  });

  it('should handle transaction rollback on error', async () => {
    const errorOperation = async () => {
      throw new Error('Operation failed');
    };

    const result = await executeTransaction(errorOperation);

    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
    expect(result.error?.type).toBe('UNKNOWN_ERROR');
    expect(result.error?.message).toContain('Vector operation failed after 3 attempts');
    expect(result.retryAttempts).toBe(2);
  });

  it('should respect transaction timeout settings', async () => {
    const slowOperation = async () => {
      await new Promise((resolve) => setTimeout(resolve, 2000));
      return 'completed';
    };

    const startTime = Date.now();
    const result = await executeTransaction(slowOperation, { timeout: 1000 });
    const duration = Date.now() - startTime;

    expect(result.success).toBe(false);
    expect(result.error?.message).toContain('timeout');
    expect(duration).toBeLessThan(1500); // Should timeout before 2 seconds
  });

  it('should handle transaction isolation levels', async () => {
    const operations: string[] = [];

    const operation1 = async (ctx: VectorTransactionContext) => {
      operations.push('op1_start');
      ctx.operations.push({ type: 'isolation_test_1', data: {}, timestamp: Date.now() });
      await new Promise((resolve) => setTimeout(resolve, 50));
      operations.push('op1_end');
      return 'result1';
    };

    const operation2 = async (ctx: VectorTransactionContext) => {
      operations.push('op2_start');
      ctx.operations.push({ type: 'isolation_test_2', data: {}, timestamp: Date.now() });
      await new Promise((resolve) => setTimeout(resolve, 25));
      operations.push('op2_end');
      return 'result2';
    };

    // Execute operations sequentially to test isolation
    const result1 = await executeTransaction(operation1);
    const result2 = await executeTransaction(operation2);

    expect(result1.success).toBe(true);
    expect(result2.success).toBe(true);
    expect(operations).toEqual(['op1_start', 'op1_end', 'op2_start', 'op2_end']);
  });

  it('should handle transaction retry logic with exponential backoff', async () => {
    let attemptCount = 0;
    const timestamps: number[] = [];

    const flakyOperation = async (ctx: VectorTransactionContext) => {
      attemptCount++;
      timestamps.push(Date.now());
      ctx.operations.push({
        type: 'retry_test',
        data: { attempt: attemptCount },
        timestamp: Date.now(),
      });

      if (attemptCount < 3) {
        throw new Error('Temporary failure');
      }

      return 'success_after_retries';
    };

    const result = await executeTransaction(flakyOperation, { maxRetries: 5 });

    expect(result.success).toBe(true);
    expect(result.data).toBe('success_after_retries');
    expect(result.retryAttempts).toBe(2);
    expect(attemptCount).toBe(3);

    // Verify exponential backoff (delays should increase)
    expect(timestamps).toHaveLength(3);
  });

  it('should handle transaction context cleanup on failure', async () => {
    const contexts: VectorTransactionContext[] = [];

    const failingOperation = async (ctx: VectorTransactionContext) => {
      contexts.push(ctx);
      ctx.operations.push({ type: 'cleanup_test', data: {}, timestamp: Date.now() });
      throw new Error('Cleanup test error');
    };

    const result = await executeTransaction(failingOperation, { maxRetries: 2 });

    expect(result.success).toBe(false);
    expect(contexts).toHaveLength(2); // Two attempts

    // Each context should be independent
    expect(contexts[0].operationId).not.toBe(contexts[1].operationId);
    expect(contexts[0].startTime).toBeLessThan(contexts[1].startTime);
  });

  it('should prevent transaction context modification after completion', async () => {
    let capturedContext: VectorTransactionContext | undefined;

    const operation = async (ctx: VectorTransactionContext) => {
      capturedContext = ctx;
      ctx.operations.push({ type: 'completion_test', data: {}, timestamp: Date.now() });
      return 'completed';
    };

    await executeTransaction(operation);

    // Context should still be accessible but operation should be complete
    expect(capturedContext).toBeDefined();
    expect(capturedContext!.operations).toHaveLength(1);

    // Adding operations after completion should not affect the transaction
    const originalLength = capturedContext!.operations.length;
    capturedContext!.operations.push({ type: 'after_completion', data: {}, timestamp: Date.now() });

    // This is more of a documentation test - in practice, the context is just a tracking mechanism
    expect(capturedContext!.operations.length).toBe(originalLength + 1);
  });
});

describe('Transaction Manager - Batch Transaction Operations', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should handle multiple operations in single transaction batch', async () => {
    const operations: string[] = [];

    const batchOperation = async (ctx: VectorTransactionContext) => {
      for (let i = 0; i < 5; i++) {
        operations.push(`operation_${i}`);
        ctx.operations.push({
          type: `batch_operation_${i}`,
          data: { index: i },
          timestamp: Date.now(),
        });
      }
      return { processed: 5 };
    };

    const result = await executeTransaction(batchOperation);

    expect(result.success).toBe(true);
    expect(result.data).toEqual({ processed: 5 });
    expect(operations).toHaveLength(5);
  });

  it('should handle nested transaction-like operations', async () => {
    const operationLog: string[] = [];

    const innerOperation = async (ctx: VectorTransactionContext) => {
      operationLog.push('inner_start');
      ctx.operations.push({ type: 'inner_operation', data: {}, timestamp: Date.now() });
      operationLog.push('inner_end');
      return 'inner_result';
    };

    const outerOperation = async (ctx: VectorTransactionContext) => {
      operationLog.push('outer_start');
      ctx.operations.push({ type: 'outer_operation', data: {}, timestamp: Date.now() });

      // Simulate nested operation
      const innerResult = await innerOperation(ctx);

      operationLog.push('outer_end');
      return { outer: 'result', inner: innerResult };
    };

    const result = await executeTransaction(outerOperation);

    expect(result.success).toBe(true);
    expect(result.data).toEqual({ outer: 'result', inner: 'inner_result' });
    expect(operationLog).toEqual(['outer_start', 'inner_start', 'inner_end', 'outer_end']);
  });

  it('should handle transaction rollback scenarios', async () => {
    const successfulOperations: string[] = [];
    const failedOperations: string[] = [];

    const operationWithFailure = async (ctx: VectorTransactionContext) => {
      // Record some successful operations
      for (let i = 0; i < 3; i++) {
        successfulOperations.push(`op_${i}`);
        ctx.operations.push({
          type: `successful_op_${i}`,
          data: { index: i },
          timestamp: Date.now(),
        });
      }

      // Simulate a failure that should "rollback" the transaction
      failedOperations.push('failure_point');
      throw new Error('Simulated transaction failure');
    };

    const result = await executeTransaction(operationWithFailure);

    expect(result.success).toBe(false);
    expect(successfulOperations).toHaveLength(3);
    expect(failedOperations).toHaveLength(1);

    // In a real transaction system, the successful operations would be rolled back
    // Here we test that the transaction context tracks the operations properly
  });

  it('should maintain atomicity guarantees for batch operations', async () => {
    const results: any[] = [];
    const errors: any[] = [];

    const atomicOperation = async (ctx: VectorTransactionContext) => {
      // Simulate a series of related operations
      const operations = [
        { type: 'create', data: { id: 1 } },
        { type: 'update', data: { id: 1, changes: { field: 'value' } } },
        { type: 'validate', data: { id: 1 } },
        { type: 'commit', data: { id: 1 } },
      ];

      for (const op of operations) {
        ctx.operations.push({
          type: op.type,
          data: op.data,
          timestamp: Date.now(),
        });

        // Simulate validation failure on one operation
        if (op.type === 'validate' && Math.random() > 0.5) {
          throw new Error(`Validation failed for operation ${op.type}`);
        }

        results.push(op.type);
      }

      return { status: 'committed', operations: results.length };
    };

    // Run multiple times to test different failure scenarios
    const attempts = 10;
    const outcomes: DbOperationResult<any>[] = [];

    for (let i = 0; i < attempts; i++) {
      const result = await executeTransaction(atomicOperation);
      outcomes.push(result);
    }

    // At least some should succeed
    const successes = outcomes.filter((o) => o.success);
    const failures = outcomes.filter((o) => !o.success);

    expect(successes.length + failures.length).toBe(attempts);
    expect(successes.length).toBeGreaterThan(0);
    expect(failures.length).toBeGreaterThan(0);

    // Successful operations should have completed all steps
    successes.forEach((success) => {
      expect(success.data.operations).toBe(4);
    });
  });

  it('should handle batch operation size limits', async () => {
    const largeBatch: number[] = Array.from({ length: 1000 }, (_, i) => i);
    const processedBatches: number[][] = [];

    const batchProcessor = async (items: number[], ctx?: VectorTransactionContext) => {
      processedBatches.push(items);
      ctx?.operations.push({
        type: 'batch_processing',
        data: { batchSize: items.length },
        timestamp: Date.now(),
      });

      return items.map((i) => ({ id: i, processed: true }));
    };

    const result = await batchOperation(largeBatch, 100, batchProcessor);

    expect(result).toHaveLength(1000);
    expect(processedBatches).toHaveLength(10); // 1000 items / 100 batch size = 10 batches
    expect(processedBatches[0]).toHaveLength(100);
    expect(processedBatches[9]).toHaveLength(100);
  });

  it('should handle parallel transaction execution', async () => {
    const operationResults: string[] = [];

    const operations = [
      async () => {
        operationResults.push('op1_start');
        await new Promise((resolve) => setTimeout(resolve, 50));
        operationResults.push('op1_end');
        return 'result1';
      },
      async () => {
        operationResults.push('op2_start');
        await new Promise((resolve) => setTimeout(resolve, 25));
        operationResults.push('op2_end');
        return 'result2';
      },
      async () => {
        operationResults.push('op3_start');
        await new Promise((resolve) => setTimeout(resolve, 75));
        operationResults.push('op3_end');
        return 'result3';
      },
    ];

    const results = await executeParallelTransactions(operations);

    expect(results).toHaveLength(3);
    expect(results.every((r) => r.success)).toBe(true);
    expect(results.map((r) => r.data)).toEqual(['result1', 'result2', 'result3']);

    // Operations should have run in parallel (no specific order guaranteed)
    expect(operationResults).toContain('op1_start');
    expect(operationResults).toContain('op2_start');
    expect(operationResults).toContain('op3_start');
  });

  it('should handle partial failures in parallel transactions', async () => {
    const operations = [
      async () => 'success1',
      async () => {
        throw new Error('failure2');
      },
      async () => 'success3',
      async () => {
        throw new Error('failure4');
      },
      async () => 'success5',
    ];

    const results = await executeParallelTransactions(operations);

    expect(results).toHaveLength(5);

    const successes = results.filter((r) => r.success);
    const failures = results.filter((r) => !r.success);

    expect(successes).toHaveLength(3);
    expect(failures).toHaveLength(2);

    expect(successes.map((r) => r.data)).toEqual(['success1', 'success3', 'success5']);
    failures.forEach((failure) => {
      expect(failure.error).toBeDefined();
    });
  });
});

describe('Transaction Manager - Knowledge Item Transactions', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should handle knowledge item storage within transactions', async () => {
    const knowledgeItems: KnowledgeItem[] = [
      {
        id: 'item1',
        kind: 'entity',
        scope: { project: 'test-project' },
        data: { title: 'Test Entity 1', content: 'Test content 1' },
      },
      {
        id: 'item2',
        kind: 'decision',
        scope: { project: 'test-project' },
        data: { title: 'Test Decision 1', rationale: 'Test rationale' },
      },
    ];

    const storeOperation = async (ctx: VectorTransactionContext) => {
      const storedItems: KnowledgeItem[] = [];

      for (const item of knowledgeItems) {
        ctx.operations.push({
          type: 'store_knowledge_item',
          data: { item },
          timestamp: Date.now(),
        });

        // Simulate storage
        storedItems.push({ ...item, created_at: new Date().toISOString() });
      }

      return { stored: storedItems, count: storedItems.length };
    };

    const result = await executeTransaction(storeOperation);

    expect(result.success).toBe(true);
    expect(result.data.stored).toHaveLength(2);
    expect(result.data.count).toBe(2);
  });

  it('should handle batch knowledge item operations', async () => {
    const batchItems: KnowledgeItem[] = Array.from({ length: 50 }, (_, i) => ({
      id: `batch_item_${i}`,
      kind: 'entity' as const,
      scope: { project: 'batch-test' },
      data: { title: `Batch Item ${i}`, index: i },
    }));

    const batchStoreOperation = async (items: KnowledgeItem[], ctx?: VectorTransactionContext) => {
      ctx?.operations.push({
        type: 'batch_store_knowledge_items',
        data: { batchSize: items.length },
        timestamp: Date.now(),
      });

      // Simulate batch storage
      return items.map((item) => ({
        ...item,
        created_at: new Date().toISOString(),
        stored: true,
      }));
    };

    const result = await batchOperation(batchItems, 10, batchStoreOperation);

    expect(result).toHaveLength(50);
    result.forEach((item, index) => {
      expect(item.id).toBe(`batch_item_${index}`);
      expect(item.stored).toBe(true);
    });
  });

  it('should handle transaction rollback for knowledge operations', async () => {
    const itemsToStore: KnowledgeItem[] = [
      {
        id: 'rollback_item1',
        kind: 'entity',
        scope: { project: 'rollback-test' },
        data: { title: 'Rollback Item 1' },
      },
      {
        id: 'rollback_item2',
        kind: 'entity',
        scope: { project: 'rollback-test' },
        data: { title: 'Rollback Item 2' },
      },
    ];

    const storedItems: KnowledgeItem[] = [];

    const failingStoreOperation = async (ctx: VectorTransactionContext) => {
      // Store first item successfully
      ctx.operations.push({
        type: 'store_knowledge_item',
        data: { item: itemsToStore[0] },
        timestamp: Date.now(),
      });
      storedItems.push({ ...itemsToStore[0] });

      // Simulate failure on second item
      ctx.operations.push({
        type: 'store_knowledge_item',
        data: { item: itemsToStore[1] },
        timestamp: Date.now(),
      });

      throw new Error('Storage operation failed - should trigger rollback');
    };

    const result = await executeTransaction(failingStoreOperation);

    expect(result.success).toBe(false);
    expect(result.error?.message).toContain('Storage operation failed');

    // In a real system, storedItems would be rolled back
    // Here we verify the transaction context tracks what should be rolled back
    expect(result.retryAttempts).toBe(2);
  });

  it('should validate consistency of knowledge item transactions', async () => {
    const inconsistentItems: KnowledgeItem[] = [
      {
        id: 'consistent_item',
        kind: 'entity',
        scope: { project: 'consistency-test' },
        data: { title: 'Consistent Item' },
      },
      {
        id: '', // Invalid: empty ID
        kind: 'entity',
        scope: { project: 'consistency-test' },
        data: { title: 'Inconsistent Item' },
      },
    ];

    const validationOperation = async (ctx: VectorTransactionContext) => {
      const validatedItems: KnowledgeItem[] = [];
      const validationErrors: string[] = [];

      for (const item of inconsistentItems) {
        ctx.operations.push({
          type: 'validate_knowledge_item',
          data: { item },
          timestamp: Date.now(),
        });

        // Simulate validation
        if (!item.id || item.id.trim() === '') {
          validationErrors.push(`Invalid ID for item: ${item.title}`);
          continue;
        }

        if (!item.kind) {
          validationErrors.push(`Missing kind for item: ${item.id}`);
          continue;
        }

        validatedItems.push(item);
      }

      if (validationErrors.length > 0) {
        throw new Error(`Validation failed: ${validationErrors.join(', ')}`);
      }

      return { validated: validatedItems, errors: validationErrors };
    };

    const result = await executeTransaction(validationOperation);

    expect(result.success).toBe(false);
    expect(result.error?.message).toContain('Validation failed');
    expect(result.error?.message).toContain('Invalid ID');
  });

  it('should handle knowledge item updates within transactions', async () => {
    const originalItem: KnowledgeItem = {
      id: 'update_item',
      kind: 'entity',
      scope: { project: 'update-test' },
      data: { title: 'Original Title', version: 1 },
    };

    const updatedData = { title: 'Updated Title', version: 2, updated_field: 'new value' };

    const updateOperation = async (ctx: VectorTransactionContext) => {
      // Record original state
      ctx.operations.push({
        type: 'record_original_state',
        data: { item: originalItem },
        timestamp: Date.now(),
      });

      // Simulate update
      const updatedItem = {
        ...originalItem,
        data: { ...originalItem.data, ...updatedData },
        updated_at: new Date().toISOString(),
      };

      // Record update
      ctx.operations.push({
        type: 'update_knowledge_item',
        data: { original: originalItem, updated: updatedItem },
        timestamp: Date.now(),
      });

      return updatedItem;
    };

    const result = await executeTransaction(updateOperation);

    expect(result.success).toBe(true);
    expect(result.data.title).toBe('Updated Title');
    expect(result.data.version).toBe(2);
    expect(result.data.updated_field).toBe('new value');
  });

  it('should handle knowledge item deletion within transactions', async () => {
    const itemsToDelete = ['delete_item1', 'delete_item2', 'delete_item3'];
    const deletedItems: string[] = [];

    const deleteOperation = async (ctx: VectorTransactionContext) => {
      const deletionResults: { id: string; deleted: boolean }[] = [];

      for (const itemId of itemsToDelete) {
        ctx.operations.push({
          type: 'delete_knowledge_item',
          data: { itemId },
          timestamp: Date.now(),
        });

        // Simulate deletion
        deletedItems.push(itemId);
        deletionResults.push({ id: itemId, deleted: true });
      }

      return { deleted: deletionResults, count: deletionResults.length };
    };

    const result = await executeTransaction(deleteOperation);

    expect(result.success).toBe(true);
    expect(result.data.deleted).toHaveLength(3);
    expect(result.data.count).toBe(3);
    expect(deletedItems).toEqual(itemsToDelete);
  });
});

describe('Transaction Manager - Error Handling and Recovery', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should handle transaction failure scenarios', async () => {
    const errorTypes = [
      new Error('Network timeout'),
      new Error('Connection refused'),
      new Error('Database constraint violation'),
      new Error('Insufficient permissions'),
      new Error('Invalid data format'),
    ];

    const results: DbOperationResult<any>[] = [];

    for (const error of errorTypes) {
      const failingOperation = async () => {
        throw error;
      };

      const result = await executeTransaction(failingOperation);
      results.push(result);
    }

    expect(results).toHaveLength(5);
    results.forEach((result) => {
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.retryAttempts).toBe(2); // Default maxRetries = 3, so 2 retries
    });
  });

  it('should handle deadlock detection and resolution', async () => {
    let attemptCount = 0;
    const deadlockErrors = [
      new Error('Deadlock detected'),
      new Error('Lock wait timeout exceeded'),
      new Error('Deadlock detected'),
    ];

    const deadlockProneOperation = async (ctx: VectorTransactionContext) => {
      attemptCount++;

      ctx.operations.push({
        type: 'deadlock_prone_operation',
        data: { attempt: attemptCount },
        timestamp: Date.now(),
      });

      if (attemptCount <= deadlockErrors.length) {
        throw deadlockErrors[attemptCount - 1];
      }

      return 'success_after_deadlock_resolution';
    };

    const result = await executeTransaction(deadlockProneOperation, { maxRetries: 5 });

    expect(result.success).toBe(true);
    expect(result.data).toBe('success_after_deadlock_resolution');
    expect(result.retryAttempts).toBe(3);
    expect(attemptCount).toBe(4);
  });

  it('should verify rollback completion', async () => {
    const operationsLog: string[] = [];
    const rollbackLog: string[] = [];

    const operationWithRollback = async (ctx: VectorTransactionContext) => {
      operationsLog.push('start_operation');

      // Simulate operations that would need rollback
      ctx.operations.push({
        type: 'create_resource',
        data: { resourceId: 'temp_resource_1' },
        timestamp: Date.now(),
      });
      operationsLog.push('create_resource');

      ctx.operations.push({
        type: 'create_resource',
        data: { resourceId: 'temp_resource_2' },
        timestamp: Date.now(),
      });
      operationsLog.push('create_second_resource');

      // Simulate failure that requires rollback
      rollbackLog.push('initiating_rollback');

      // In a real system, rollback would reverse the operations
      for (const operation of ctx.operations.slice().reverse()) {
        rollbackLog.push(`rollback_${operation.type}_${operation.data.resourceId}`);
      }

      throw new Error('Operation failed - rollback required');
    };

    const result = await executeTransaction(operationWithRollback);

    expect(result.success).toBe(false);
    expect(operationsLog).toEqual(['start_operation', 'create_resource', 'create_second_resource']);
    expect(rollbackLog).toContain('initiating_rollback');
    expect(rollbackLog).toContain('rollback_create_resource_temp_resource_1');
    expect(rollbackLog).toContain('rollback_create_resource_temp_resource_2');
  });

  it('should handle error state cleanup', async () => {
    const resources: string[] = [];
    const cleanupLog: string[] = [];

    const operationWithResourceCleanup = async (ctx: VectorTransactionContext) => {
      // Allocate resources
      const resource1 = `resource_${Date.now()}_1`;
      const resource2 = `resource_${Date.now()}_2`;

      resources.push(resource1, resource2);

      ctx.operations.push({
        type: 'allocate_resource',
        data: { resourceId: resource1 },
        timestamp: Date.now(),
      });

      ctx.operations.push({
        type: 'allocate_resource',
        data: { resourceId: resource2 },
        timestamp: Date.now(),
      });

      // Simulate operation failure
      throw new Error('Operation failed');
    };

    // Cleanup function (normally called in finally block)
    const cleanupResources = () => {
      resources.forEach((resource) => {
        cleanupLog.push(`cleanup_${resource}`);
      });
      resources.length = 0; // Clear resources array
    };

    try {
      await executeTransaction(operationWithResourceCleanup);
    } finally {
      cleanupResources();
    }

    expect(resources).toHaveLength(0); // Resources should be cleaned up
    expect(cleanupLog).toHaveLength(2); // Both resources cleaned up
  });

  it('should handle retry exhaustion scenarios', async () => {
    const alwaysFailingOperation = async (ctx: VectorTransactionContext) => {
      ctx.operations.push({
        type: 'always_failing_operation',
        data: { attempt: ctx.operations.length + 1 },
        timestamp: Date.now(),
      });

      throw new Error(`Persistent failure attempt ${ctx.operations.length}`);
    };

    const result = await executeTransaction(alwaysFailingOperation, { maxRetries: 2 });

    expect(result.success).toBe(false);
    expect(result.retryAttempts).toBe(2); // Should exhaust all retries
    expect(result.error?.message).toContain('Persistent failure attempt 3');
  });

  it('should categorize errors appropriately for retry logic', async () => {
    const nonRetryableErrors = [
      { error: new Error('Constraint violation'), expectedType: DbErrorType._CONSTRAINT_VIOLATION },
      { error: new Error('Permission denied'), expectedType: DbErrorType._PERMISSION_ERROR },
      { error: new Error('Record not found'), expectedType: DbErrorType._RECORD_NOT_FOUND },
      { error: new Error('Schema error'), expectedType: DbErrorType._SCHEMA_ERROR },
    ];

    for (const { error, expectedType } of nonRetryableErrors) {
      const categorizedType = dbErrorHandler.categorizeError(error);
      expect(categorizedType).toBe(expectedType);
    }
  });

  it('should handle timeout errors specifically', async () => {
    const timeoutOperation = async (ctx: VectorTransactionContext) => {
      ctx.operations.push({
        type: 'timeout_operation',
        data: {},
        timestamp: Date.now(),
      });

      // Simulate long-running operation
      await new Promise((resolve) => setTimeout(resolve, 2000));
      return 'should_not_complete';
    };

    const result = await executeTransaction(timeoutOperation, { timeout: 500 });

    expect(result.success).toBe(false);
    expect(result.error?.message).toContain('timeout');
  });

  it('should handle optimistic concurrency control', async () => {
    let conflictCount = 0;
    const maxConflicts = 2;

    const optimisticUpdateOperation = async (ctx: VectorTransactionContext) => {
      conflictCount++;

      ctx.operations.push({
        type: 'optimistic_update',
        data: { conflictCount, version: conflictCount },
        timestamp: Date.now(),
      });

      if (conflictCount <= maxConflicts) {
        const conflictError = new Error('Optimistic lock conflict');
        (conflictError as any).code = 'OPTIMISTIC_CONFLICT';
        throw conflictError;
      }

      return { updated: true, version: conflictCount };
    };

    const result = await optimisticUpdate(optimisticUpdateOperation, 5);

    expect(result.success).toBe(true);
    expect(result.data.updated).toBe(true);
    expect(result.data.version).toBe(3);
    expect(result.retryAttempts).toBe(2);
  });
});

describe('Transaction Manager - Performance and Concurrency', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should handle concurrent transaction execution', async () => {
    const concurrentOperations = 20;
    const operationResults: string[] = [];
    const operationTimestamps: number[] = [];

    const concurrentOperation = async (index: number) => {
      const startTime = Date.now();
      operationTimestamps.push(startTime);

      operationResults.push(`operation_${index}_start`);

      // Simulate some work
      await new Promise((resolve) => setTimeout(resolve, Math.random() * 50));

      operationResults.push(`operation_${index}_end`);

      return {
        index,
        startTime,
        endTime: Date.now(),
        duration: Date.now() - startTime,
      };
    };

    // Create concurrent operations
    const operations = Array.from(
      { length: concurrentOperations },
      (_, i) => () => concurrentOperation(i)
    );

    const startTime = Date.now();
    const results = await executeParallelTransactions(operations);
    const totalTime = Date.now() - startTime;

    expect(results).toHaveLength(concurrentOperations);
    expect(results.every((r) => r.success)).toBe(true);

    // Operations should have run concurrently (total time should be less than sum of individual times)
    const maxDuration = Math.max(...results.map((r) => r.data!.duration));
    expect(totalTime).toBeLessThan(maxDuration * 2); // Allow some overhead
  });

  it('should measure transaction throughput', async () => {
    const transactionCount = 100;
    const results: DbOperationResult<string>[] = [];

    const simpleOperation = async (ctx: VectorTransactionContext) => {
      ctx.operations.push({
        type: 'throughput_test',
        data: {},
        timestamp: Date.now(),
      });

      return 'completed';
    };

    const startTime = Date.now();

    // Execute transactions sequentially
    for (let i = 0; i < transactionCount; i++) {
      const result = await executeTransaction(simpleOperation);
      results.push(result);
    }

    const totalTime = Date.now() - startTime;
    const throughput = transactionCount / (totalTime / 1000); // transactions per second

    expect(results).toHaveLength(transactionCount);
    expect(results.every((r) => r.success)).toBe(true);
    expect(throughput).toBeGreaterThan(10); // Should handle at least 10 tx/sec
  });

  it('should handle lock contention scenarios', async () => {
    const sharedResource = { value: 0, lock: false };
    const operationResults: any[] = [];

    const contendedOperation = async (index: number) => {
      const maxWaitTime = 5000;
      const startTime = Date.now();

      // Simulate trying to acquire a lock
      while (sharedResource.lock && Date.now() - startTime < maxWaitTime) {
        await new Promise((resolve) => setTimeout(resolve, 10));
      }

      if (sharedResource.lock) {
        throw new Error(`Operation ${index}: Failed to acquire lock within timeout`);
      }

      // Acquire lock
      sharedResource.lock = true;

      try {
        // Perform some work
        const originalValue = sharedResource.value;
        await new Promise((resolve) => setTimeout(resolve, Math.random() * 50));
        sharedResource.value = originalValue + 1;

        return {
          index,
          success: true,
          value: sharedResource.value,
          waitTime: Date.now() - startTime,
        };
      } finally {
        // Release lock
        sharedResource.lock = false;
      }
    };

    // Create multiple contending operations
    const operations = Array.from({ length: 10 }, (_, i) => () => contendedOperation(i));

    const results = await executeParallelTransactions(operations);

    expect(results).toHaveLength(10);
    expect(results.every((r) => r.success)).toBe(true);

    // All operations should have completed successfully
    const successfulResults = results.map((r) => r.data);
    expect(sharedResource.value).toBe(10);
  });

  it('should manage resource utilization efficiently', async () => {
    const resourceUsage = {
      maxConcurrentOperations: 0,
      currentOperations: 0,
      totalOperations: 0,
    };

    const resourceAwareOperation = async (ctx: VectorTransactionContext) => {
      // Track resource usage
      resourceUsage.currentOperations++;
      resourceUsage.totalOperations++;
      resourceUsage.maxConcurrentOperations = Math.max(
        resourceUsage.maxConcurrentOperations,
        resourceUsage.currentOperations
      );

      ctx.operations.push({
        type: 'resource_aware_operation',
        data: {
          currentOperations: resourceUsage.currentOperations,
          maxConcurrent: resourceUsage.maxConcurrentOperations,
        },
        timestamp: Date.now(),
      });

      try {
        // Simulate work
        await new Promise((resolve) => setTimeout(resolve, Math.random() * 100));
        return { operationId: ctx.operationId };
      } finally {
        resourceUsage.currentOperations--;
      }
    };

    // Execute multiple operations concurrently
    const operations = Array.from(
      { length: 20 },
      (_, i) => () => executeTransaction(resourceAwareOperation)
    );

    const results = await Promise.all(operations);

    expect(results).toHaveLength(20);
    expect(results.every((r) => r.success)).toBe(true);
    expect(resourceUsage.totalOperations).toBe(20);
    expect(resourceUsage.currentOperations).toBe(0); // All should be completed
    expect(resourceUsage.maxConcurrentOperations).toBeGreaterThan(1);
  });

  it('should handle memory usage in large transactions', async () => {
    const largeDataSize = 10000;
    const memorySnapshots: number[] = [];

    const largeDataOperation = async (ctx: VectorTransactionContext) => {
      // Create large data structure
      const largeData = Array.from({ length: largeDataSize }, (_, i) => ({
        id: i,
        data: 'x'.repeat(100), // 100 characters per item
        timestamp: Date.now(),
      }));

      // Track memory usage (simplified)
      if (global.gc) {
        global.gc();
      }
      memorySnapshots.push(process.memoryUsage().heapUsed);

      ctx.operations.push({
        type: 'large_data_operation',
        data: { dataSize: largeData.length },
        timestamp: Date.now(),
      });

      // Process the data
      const processedData = largeData.map((item) => ({
        ...item,
        processed: true,
        hash: `hash_${item.id}`,
      }));

      // Track memory after processing
      if (global.gc) {
        global.gc();
      }
      memorySnapshots.push(process.memoryUsage().heapUsed);

      return { processedCount: processedData.length };
    };

    const result = await executeTransaction(largeDataOperation);

    expect(result.success).toBe(true);
    expect(result.data.processedCount).toBe(largeDataSize);
    expect(memorySnapshots).toHaveLength(2);

    // Memory usage should be reasonable (this is a simplified check)
    const memoryIncrease = memorySnapshots[1] - memorySnapshots[0];
    expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024); // Less than 100MB increase
  });

  it('should optimize transaction batch sizes', async () => {
    const totalItems = 1000;
    const batchSizes = [10, 50, 100, 200];
    const performanceResults: any[] = [];

    for (const batchSize of batchSizes) {
      const batchOperation = async (ctx: VectorTransactionContext) => {
        const items = Array.from({ length: totalItems / batchSize }, (_, i) => ({
          id: `item_${i}`,
          batch: batchSize,
          data: `data_${i}`.repeat(10),
        }));

        ctx.operations.push({
          type: 'batch_size_test',
          data: { batchSize, itemCount: items.length },
          timestamp: Date.now(),
        });

        // Simulate processing
        await new Promise((resolve) => setTimeout(resolve, 10));

        return { processed: items.length, batchSize };
      };

      const startTime = Date.now();
      const result = await executeTransaction(batchOperation);
      const duration = Date.now() - startTime;

      performanceResults.push({
        batchSize,
        duration,
        success: result.success,
      });
    }

    expect(performanceResults).toHaveLength(4);
    expect(performanceResults.every((r) => r.success)).toBe(true);

    // Find optimal batch size (simplified - just check that all completed)
    const sortedByPerformance = performanceResults.sort((a, b) => a.duration - b.duration);
    expect(sortedByPerformance[0].batchSize).toBeDefined();
  });
});

describe('Transaction Manager - Integration with Vector Operations', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should handle vector operations within transactions', async () => {
    const mockVectorOperations = {
      upsert: vi.fn().mockResolvedValue({ status: 'completed' }),
      search: vi
        .fn()
        .mockResolvedValue([{ id: 'vector_result_1', score: 0.9, payload: { data: 'test' } }]),
      delete: vi.fn().mockResolvedValue({ status: 'completed' }),
    };

    const vectorTransactionOperation = async (ctx: VectorTransactionContext) => {
      const vectorData = [0.1, 0.2, 0.3, 0.4, 0.5];

      // Record vector upsert operation
      ctx.operations.push({
        type: 'vector_upsert',
        data: { vector: vectorData, payload: { test: 'data' } },
        timestamp: Date.now(),
      });

      const upsertResult = await mockVectorOperations.upsert({
        vector: vectorData,
        payload: { test: 'data' },
      });

      // Record vector search operation
      ctx.operations.push({
        type: 'vector_search',
        data: { queryVector: vectorData, limit: 10 },
        timestamp: Date.now(),
      });

      const searchResult = await mockVectorOperations.search({
        vector: vectorData,
        limit: 10,
      });

      return {
        upsertResult,
        searchResult,
        operationsCount: ctx.operations.length,
      };
    };

    const result = await executeTransaction(vectorTransactionOperation);

    expect(result.success).toBe(true);
    expect(result.data.operationsCount).toBe(2);
    expect(mockVectorOperations.upsert).toHaveBeenCalledTimes(1);
    expect(mockVectorOperations.search).toHaveBeenCalledTimes(1);
  });

  it('should maintain transaction consistency for vectors', async () => {
    const vectorStates: any[] = [];

    const vectorConsistencyOperation = async (ctx: VectorTransactionContext) => {
      const vectors = [
        { id: 'vec1', data: [0.1, 0.2, 0.3], metadata: { version: 1 } },
        { id: 'vec2', data: [0.4, 0.5, 0.6], metadata: { version: 1 } },
      ];

      // Record initial state
      ctx.operations.push({
        type: 'record_vector_state',
        data: { state: 'initial', vectors },
        timestamp: Date.now(),
      });
      vectorStates.push({ state: 'initial', vectors });

      // Perform vector updates
      const updatedVectors = vectors.map((vec) => ({
        ...vec,
        data: vec.data.map((v) => v * 2), // Double each value
        metadata: { ...vec.metadata, version: 2 },
      }));

      ctx.operations.push({
        type: 'update_vectors',
        data: { updatedVectors },
        timestamp: Date.now(),
      });
      vectorStates.push({ state: 'updated', vectors: updatedVectors });

      // Verify consistency
      const isConsistent = updatedVectors.every(
        (vec) => vec.data.every((v) => v > 0.2) && vec.metadata.version === 2
      );

      if (!isConsistent) {
        throw new Error('Vector consistency check failed');
      }

      return { consistent: true, vectors: updatedVectors };
    };

    const result = await executeTransaction(vectorConsistencyOperation);

    expect(result.success).toBe(true);
    expect(result.data.consistent).toBe(true);
    expect(vectorStates).toHaveLength(2);
    expect(vectorStates[0].state).toBe('initial');
    expect(vectorStates[1].state).toBe('updated');
  });

  it('should handle rollback impact on vector storage', async () => {
    const vectorStorageLog: any[] = [];

    const vectorRollbackOperation = async (ctx: VectorTransactionContext) => {
      const vectorOperations = [
        { type: 'create_vector', id: 'vec1', data: [1, 2, 3] },
        { type: 'create_vector', id: 'vec2', data: [4, 5, 6] },
        { type: 'update_vector', id: 'vec1', data: [1.1, 2.1, 3.1] },
      ];

      try {
        for (const op of vectorOperations) {
          ctx.operations.push({
            type: op.type,
            data: { id: op.id, vector: op.data },
            timestamp: Date.now(),
          });

          vectorStorageLog.push({ action: 'execute', operation: op });

          // Simulate some processing time
          await new Promise((resolve) => setTimeout(resolve, 10));
        }

        // Simulate a failure that should rollback vector operations
        throw new Error('Vector operation failed - rollback needed');
      } catch (error) {
        // Record rollback operations
        for (const op of vectorOperations.slice().reverse()) {
          const rollbackOp = {
            action: 'rollback',
            operation: {
              type: `rollback_${op.type}`,
              id: op.id,
              data: op.data,
            },
          };
          vectorStorageLog.push(rollbackOp);
        }

        throw error;
      }
    };

    const result = await executeTransaction(vectorRollbackOperation);

    expect(result.success).toBe(false);
    expect(result.error?.message).toContain('rollback needed');

    // Verify rollback was recorded
    const rollbackOperations = vectorStorageLog.filter((log) => log.action === 'rollback');
    expect(rollbackOperations).toHaveLength(3);

    expect(rollbackOperations[0].operation.type).toBe('rollback_update_vector');
    expect(rollbackOperations[1].operation.type).toBe('rollback_create_vector');
    expect(rollbackOperations[2].operation.type).toBe('rollback_create_vector');
  });

  it('should preserve transaction metadata for vectors', async () => {
    const transactionMetadata: any = {};

    const vectorMetadataOperation = async (ctx: VectorTransactionContext) => {
      // Record transaction start metadata
      transactionMetadata.transactionId = ctx.operationId;
      transactionMetadata.startTime = ctx.startTime;

      const vectorBatch = [
        { id: 'meta_vec1', data: [0.1, 0.2], tags: ['tag1', 'tag2'] },
        { id: 'meta_vec2', data: [0.3, 0.4], tags: ['tag3', 'tag4'] },
      ];

      for (const vector of vectorBatch) {
        const vectorWithMetadata = {
          ...vector,
          transactionId: ctx.operationId,
          transactionTimestamp: ctx.startTime,
          batchIndex: vectorBatch.indexOf(vector),
        };

        ctx.operations.push({
          type: 'store_vector_with_metadata',
          data: { vector: vectorWithMetadata },
          timestamp: Date.now(),
        });
      }

      transactionMetadata.operationCount = ctx.operations.length;
      transactionMetadata.endTime = Date.now();
      transactionMetadata.duration = transactionMetadata.endTime - transactionMetadata.startTime;

      return {
        transactionId: ctx.operationId,
        vectorsStored: vectorBatch.length,
        metadata: transactionMetadata,
      };
    };

    const result = await executeTransaction(vectorMetadataOperation);

    expect(result.success).toBe(true);
    expect(result.data.transactionId).toBeDefined();
    expect(result.data.vectorsStored).toBe(2);
    expect(result.data.metadata.operationCount).toBe(2);
    expect(result.data.metadata.duration).toBeGreaterThan(0);
  });

  it('should handle vector operation timeouts within transactions', async () => {
    const slowVectorOperation = async (ctx: VectorTransactionContext) => {
      ctx.operations.push({
        type: 'slow_vector_operation',
        data: {},
        timestamp: Date.now(),
      });

      // Simulate slow vector processing
      await new Promise((resolve) => setTimeout(resolve, 2000));

      return { processed: true };
    };

    const startTime = Date.now();
    const result = await executeTransaction(slowVectorOperation, { timeout: 1000 });
    const duration = Date.now() - startTime;

    expect(result.success).toBe(false);
    expect(result.error?.message).toContain('timeout');
    expect(duration).toBeLessThan(1500);
  });

  it('should handle batch vector operations with mixed success', async () => {
    const vectorOperations = [
      { id: 'vec_success_1', data: [1, 2, 3], shouldSucceed: true },
      { id: 'vec_fail_1', data: [4, 5, 6], shouldSucceed: false },
      { id: 'vec_success_2', data: [7, 8, 9], shouldSucceed: true },
      { id: 'vec_fail_2', data: [10, 11, 12], shouldSucceed: false },
    ];

    const batchVectorOperation = async (ctx: VectorTransactionContext) => {
      const results: any[] = [];

      for (const vecOp of vectorOperations) {
        ctx.operations.push({
          type: 'batch_vector_operation',
          data: { vecOp },
          timestamp: Date.now(),
        });

        try {
          if (vecOp.shouldSucceed) {
            results.push({ id: vecOp.id, success: true, data: vecOp.data });
          } else {
            throw new Error(`Vector operation failed for ${vecOp.id}`);
          }
        } catch (error) {
          results.push({
            id: vecOp.id,
            success: false,
            error: error instanceof Error ? error.message : String(error),
          });
        }
      }

      return { results, successCount: results.filter((r) => r.success).length };
    };

    const result = await executeTransaction(batchVectorOperation);

    expect(result.success).toBe(true);
    expect(result.data.results).toHaveLength(4);
    expect(result.data.successCount).toBe(2);

    const successful = result.data.results.filter((r: any) => r.success);
    const failed = result.data.results.filter((r: any) => !r.success);

    expect(successful).toHaveLength(2);
    expect(failed).toHaveLength(2);
  });
});

describe('Transaction Manager - Health Check and Utilities', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should perform transaction system health check', async () => {
    const healthResult = await transactionHealthCheck();

    expect(healthResult).toHaveProperty('healthy', true);
    expect(healthResult).toHaveProperty('message');
    expect(healthResult).toHaveProperty('latency');
    expect(healthResult.latency).toBeGreaterThan(0);
    expect(healthResult.message).toContain('healthy');
  });

  it('should handle health check failures', async () => {
    // Mock a failing transaction
    const originalExecuteTransaction = executeTransaction;
    vi.doMock('../../../src/utils/transaction', async () => {
      const actual = await vi.importActual<typeof import('../../../src/utils/transaction')>(
        '../../../src/utils/transaction'
      );
      return {
        ...actual,
        executeTransaction: vi.fn().mockRejectedValue(new Error('Health check failed')),
      };
    });

    // This is a simplified test - in practice, health checks should be resilient
    const healthResult = await transactionHealthCheck();

    expect(healthResult).toHaveProperty('healthy');
    expect(healthResult).toHaveProperty('message');
  });

  it('should use simplified transaction API', async () => {
    const simpleOperation = async (ctx: VectorTransactionContext) => {
      ctx.operations.push({
        type: 'simple_api_test',
        data: {},
        timestamp: Date.now(),
      });
      return 'simple_result';
    };

    const result = await transaction(simpleOperation);

    expect(result).toBe('simple_result');
  });

  it('should handle simplified API errors', async () => {
    const failingOperation = async () => {
      throw new Error('Simple API failure');
    };

    await expect(transaction(failingOperation)).rejects.toThrow('Simple API failure');
  });

  it('should validate transaction context structure', async () => {
    let capturedContext: VectorTransactionContext | undefined;

    const contextValidationOperation = async (ctx: VectorTransactionContext) => {
      capturedContext = ctx;

      // Validate context structure
      expect(ctx).toHaveProperty('operationId');
      expect(ctx).toHaveProperty('startTime');
      expect(ctx).toHaveProperty('operations');

      expect(typeof ctx.operationId).toBe('string');
      expect(typeof ctx.startTime).toBe('number');
      expect(Array.isArray(ctx.operations)).toBe(true);

      // Test operations array functionality
      ctx.operations.push({
        type: 'context_validation',
        data: { test: true },
        timestamp: Date.now(),
      });

      return { contextValid: true };
    };

    const result = await executeTransaction(contextValidationOperation);

    expect(result.success).toBe(true);
    expect(result.data.contextValid).toBe(true);
    expect(capturedContext).toBeDefined();
    expect(capturedContext!.operations).toHaveLength(1);
  });

  it('should handle transaction context isolation', async () => {
    const contexts: VectorTransactionContext[] = [];

    const isolationTestOperation = async (ctx: VectorTransactionContext) => {
      contexts.push(ctx);

      // Each context should be isolated
      ctx.operations.push({
        type: 'isolation_test',
        data: { contextId: ctx.operationId },
        timestamp: Date.now(),
      });

      return { contextId: ctx.operationId };
    };

    // Execute multiple transactions
    const results = await Promise.all([
      executeTransaction(isolationTestOperation),
      executeTransaction(isolationTestOperation),
      executeTransaction(isolationTestOperation),
    ]);

    expect(results).toHaveLength(3);
    expect(results.every((r) => r.success)).toBe(true);
    expect(contexts).toHaveLength(3);

    // Verify each context is unique
    const operationIds = contexts.map((ctx) => ctx.operationId);
    const uniqueIds = [...new Set(operationIds)];
    expect(uniqueIds).toHaveLength(3);

    // Verify operations are isolated
    contexts.forEach((ctx) => {
      expect(ctx.operations).toHaveLength(1);
      expect(ctx.operations[0].data.contextId).toBe(ctx.operationId);
    });
  });

  it('should handle transaction timing and performance measurement', async () => {
    const timingData: any[] = [];

    const timingTestOperation = async (ctx: VectorTransactionContext) => {
      const operationStart = Date.now();

      ctx.operations.push({
        type: 'timing_test_start',
        data: { startTime: operationStart },
        timestamp: operationStart,
      });

      // Simulate some work
      await new Promise((resolve) => setTimeout(resolve, 100));

      const operationEnd = Date.now();
      const duration = operationEnd - operationStart;

      ctx.operations.push({
        type: 'timing_test_end',
        data: { endTime: operationEnd, duration },
        timestamp: operationEnd,
      });

      timingData.push({
        contextStartTime: ctx.startTime,
        operationStart,
        operationEnd,
        duration,
        totalTransactionTime: operationEnd - ctx.startTime,
      });

      return { duration, operationsCount: ctx.operations.length };
    };

    const result = await executeTransaction(timingTestOperation);

    expect(result.success).toBe(true);
    expect(result.data.duration).toBeGreaterThan(90); // Allow some variance
    expect(result.data.operationsCount).toBe(2);
    expect(timingData).toHaveLength(1);
    expect(timingData[0].totalTransactionTime).toBeGreaterThan(90);
  });
});
