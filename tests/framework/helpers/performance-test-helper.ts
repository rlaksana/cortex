/**
 * Performance Test Helper
 *
 * Provides performance testing utilities for measuring operation
 * speed, memory usage, and scalability.
 */

// PostgreSQL import removed - now using Qdrant;
import { memoryStore } from '../../../src/services/memory-store.js';
import { memoryFind } from '../../../src/services/memory-find.js';
import { softDelete } from '../../../src/services/delete-operations.js';
import type { TestContext } from '../test-setup.js';

/**
 * Performance metrics collection
 */
export interface PerformanceMetrics {
  operation: string;
  duration: number;
  memoryUsageBefore: number;
  memoryUsageAfter: number;
  memoryDelta: number;
  cpuUsage?: number;
  timestamp: string;
  itemCount?: number;
  batchSize?: number;
  concurrency?: number;
}

/**
 * Performance test helper
 */
export class PerformanceTestHelper {
  private metrics: PerformanceMetrics[] = [];
  private thresholds: Map<string, number> = new Map();

  constructor() {
    // Set default performance thresholds (in milliseconds)
    this.thresholds.set('memory_store_single', 100);
    this.thresholds.set('memory_store_batch', 500);
    this.thresholds.set('memory_find_basic', 200);
    this.thresholds.set('memory_find_complex', 500);
    this.thresholds.set('soft_delete_single', 50);
    this.thresholds.set('soft_delete_batch', 200);
  }

  /**
   * Measure performance of an operation
   */
  async measureOperation<T>(
    operation: string,
    fn: () => Promise<T>,
    context?: {
      itemCount?: number;
      batchSize?: number;
      concurrency?: number;
    }
  ): Promise<{ result: T; metrics: PerformanceMetrics }> {
    // Force garbage collection if available
    if (global.gc) {
      global.gc();
    }

    const memoryBefore = this.getMemoryUsage();
    const startTime = Date.now();
    const cpuBefore = process.cpuUsage();

    try {
      const result = await fn();

      const endTime = Date.now();
      const memoryAfter = this.getMemoryUsage();
      const cpuAfter = process.cpuUsage(cpuBefore);

      const metrics: PerformanceMetrics = {
        operation,
        duration: endTime - startTime,
        memoryUsageBefore: memoryBefore,
        memoryUsageAfter: memoryAfter,
        memoryDelta: memoryAfter - memoryBefore,
        timestamp: new Date().toISOString(),
        ...context,
      };

      this.metrics.push(metrics);

      return { result, metrics };
    } catch (error) {
      const endTime = Date.now();
      const memoryAfter = this.getMemoryUsage();

      const metrics: PerformanceMetrics = {
        operation,
        duration: endTime - startTime,
        memoryUsageBefore: memoryBefore,
        memoryUsageAfter: memoryAfter,
        memoryDelta: memoryAfter - memoryBefore,
        timestamp: new Date().toISOString(),
        ...context,
      };

      this.metrics.push(metrics);
      throw error;
    }
  }

  /**
   * Get current memory usage in MB
   */
  private getMemoryUsage(): number {
    const usage = process.memoryUsage();
    return Math.round(usage.heapUsed / 1024 / 1024);
  }

  /**
   * Run performance tests for memory store
   */
  async testMemoryStorePerformance(context: TestContext): Promise<void> {
    console.log('\n🚀 Testing Memory Store Performance...');

    // Test single item storage
    await this.measureOperation('memory_store_single', async () => {
      const item = context.dataFactory.createSection();
      const result = await memoryStore([item]);
      if (result.errors.length > 0) {
        throw new Error(`Store operation failed: ${result.errors[0].message}`);
      }
      return result;
    }, { itemCount: 1 });

    // Test batch storage
    const batchSizes = [10, 50, 100];
    for (const batchSize of batchSizes) {
      await this.measureOperation('memory_store_batch', async () => {
        const items = context.dataFactory.createMixedBatch(batchSize);
        const result = await memoryStore(items);
        if (result.errors.length > 0) {
          throw new Error(`Batch store operation failed: ${result.errors[0].message}`);
        }
        return result;
      }, { itemCount: batchSize, batchSize });
    }

    // Test concurrent operations
    await this.testConcurrentStoreOperations(context);

    console.log('✅ Memory Store Performance Tests Completed');
  }

  /**
   * Test concurrent store operations
   */
  private async testConcurrentStoreOperations(context: TestContext): Promise<void> {
    const concurrencyLevels = [2, 5, 10];

    for (const concurrency of concurrencyLevels) {
      await this.measureOperation('memory_store_concurrent', async () => {
        const promises = Array.from({ length: concurrency }, async (_, i) => {
          const item = context.dataFactory.createSection({
            title: `Concurrent Section ${i}`,
          });
          return memoryStore([item]);
        });

        const results = await Promise.all(promises);

        // Check all operations succeeded
        for (const result of results) {
          if (result.errors.length > 0) {
            throw new Error(`Concurrent operation failed: ${result.errors[0].message}`);
          }
        }

        return results;
      }, { itemCount: concurrency, concurrency });
    }
  }

  /**
   * Run performance tests for memory find
   */
  async testMemoryFindPerformance(context: TestContext): Promise<void> {
    console.log('\n🔍 Testing Memory Find Performance...');

    // Prepare test data
    const testData = context.dataFactory.createMixedBatch(100);
    const storeResult = await memoryStore(testData);
    if (storeResult.errors.length > 0) {
      throw new Error('Failed to setup test data for find performance tests');
    }

    // Test basic search
    await this.measureOperation('memory_find_basic', async () => {
      return memoryFind({
        query: 'test',
        types: ['section'],
        top_k: 10,
      });
    });

    // Test complex search with multiple types
    await this.measureOperation('memory_find_complex', async () => {
      return memoryFind({
        query: 'authentication',
        types: ['section', 'decision', 'issue'],
        top_k: 20,
        mode: 'deep',
        traverse: {
          depth: 2,
        },
      });
    });

    // Test search performance with different result sizes
    const resultSizes = [10, 50, 100];
    for (const size of resultSizes) {
      await this.measureOperation('memory_find_large_results', async () => {
        return memoryFind({
          query: 'test',
          top_k: size,
        });
      }, { itemCount: size });
    }

    // Test query enhancement performance
    await this.measureOperation('memory_find_enhanced', async () => {
      return memoryFind({
        query: 'authntication', // Intentional typo
        enableAutoFix: true,
        enableSuggestions: true,
      });
    });

    console.log('✅ Memory Find Performance Tests Completed');
  }

  /**
   * Run performance tests for delete operations
   */
  async testDeletePerformance(context: TestContext): Promise<void> {
    console.log('\n🗑️  Testing Delete Performance...');

    // Prepare test data
    const testData = context.dataFactory.createMixedBatch(50);
    const storeResult = await memoryStore(testData);
    if (storeResult.errors.length > 0) {
      throw new Error('Failed to setup test data for delete performance tests');
    }

    // Test single delete
    if (storeResult.stored.length > 0) {
      const firstItem = storeResult.stored[0];
      await this.measureOperation('soft_delete_single', async () => {
        return softDelete(context.testDb, {
          entity_type: firstItem.kind,
          entity_id: firstItem.id,
        });
      });
    }

    // Test batch delete
    const deletePromises = storeResult.stored.slice(0, 10).map(item =>
      this.measureOperation('soft_delete_batch', async () => {
        return softDelete(context.testDb, {
          entity_type: item.kind,
          entity_id: item.id,
        });
      })
    );

    await Promise.all(deletePromises);

    // Test cascade delete
    if (storeResult.stored.length > 0) {
      const entityItem = storeResult.stored.find(item => item.kind === 'entity');
      if (entityItem) {
        await this.measureOperation('soft_delete_cascade', async () => {
          return softDelete(context.testDb, {
            entity_type: entityItem.kind,
            entity_id: entityItem.id,
            cascade_relations: true,
          });
        });
      }
    }

    console.log('✅ Delete Performance Tests Completed');
  }

  /**
   * Run scalability tests
   */
  async testScalability(context: TestContext): Promise<void> {
    console.log('\n📈 Testing Scalability...');

    const dataSizes = [100, 500, 1000];

    for (const size of dataSizes) {
      console.log(`  Testing with ${size} items...`);

      // Store performance test
      await this.measureOperation(`store_${size}_items`, async () => {
        const items = context.dataFactory.createMixedBatch(size);
        const result = await memoryStore(items);
        if (result.errors.length > 0) {
          throw new Error(`Store operation failed for ${size} items`);
        }
        return result;
      }, { itemCount: size });

      // Search performance test
      await this.measureOperation(`search_${size}_items`, async () => {
        return memoryFind({
          query: 'test',
          top_k: Math.min(50, size),
        });
      }, { itemCount: size });
    }

    console.log('✅ Scalability Tests Completed');
  }

  /**
   * Run memory usage tests
   */
  async testMemoryUsage(context: TestContext): Promise<void> {
    console.log('\n💾 Testing Memory Usage...');

    // Test memory usage for different operations
    const operations = [
      {
        name: 'store_small_batch',
        fn: () => memoryStore(context.dataFactory.createMixedBatch(10)),
      },
      {
        name: 'store_medium_batch',
        fn: () => memoryStore(context.dataFactory.createMixedBatch(50)),
      },
      {
        name: 'store_large_batch',
        fn: () => memoryStore(context.dataFactory.createMixedBatch(100)),
      },
    ];

    for (const operation of operations) {
      const { metrics } = await this.measureOperation(operation.name, operation.fn);
      console.log(`  ${operation.name}: ${metrics.memoryDelta}MB increase`);
    }

    // Test memory cleanup
    if (global.gc) {
      const memoryBefore = this.getMemoryUsage();
      global.gc();
      const memoryAfter = this.getMemoryUsage();
      console.log(`  Memory cleanup: ${memoryBefore - memoryAfter}MB freed`);
    }

    console.log('✅ Memory Usage Tests Completed');
  }

  /**
   * Run load testing
   */
  async testLoad(context: TestContext): Promise<void> {
    console.log('\n⚡ Running Load Tests...');

    const duration = 10000; // 10 seconds
    const startTime = Date.now();
    let operationsCompleted = 0;

    while (Date.now() - startTime < duration) {
      try {
        // Mix of different operations
        const operations = [
          () => memoryStore([context.dataFactory.createSection()]),
          () => memoryFind({ query: 'test', top_k: 10 }),
          () => memoryFind({ query: 'decision', types: ['decision'] }),
        ];

        const randomOperation = operations[Math.floor(Math.random() * operations.length)];
        await randomOperation();
        operationsCompleted++;
      } catch (error) {
        // Log error but continue testing
        console.warn(`Load test operation failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    }

    const actualDuration = Date.now() - startTime;
    const operationsPerSecond = (operationsCompleted / actualDuration) * 1000;

    console.log(`  Load test completed: ${operationsCompleted} operations in ${actualDuration}ms`);
    console.log(`  Throughput: ${Math.round(operationsPerSecond)} operations/second`);

    console.log('✅ Load Tests Completed');
  }

  /**
   * Verify performance against thresholds
   */
  verifyPerformanceThresholds(): {
    passed: string[];
    failed: Array<{ operation: string; threshold: number; actual: number }>;
  } {
    const passed: string[] = [];
    const failed: Array<{ operation: string; threshold: number; actual: number }> = [];

    for (const metrics of this.metrics) {
      const threshold = this.thresholds.get(metrics.operation);
      if (threshold && metrics.duration > threshold) {
        failed.push({
          operation: metrics.operation,
          threshold,
          actual: metrics.duration,
        });
      } else {
        passed.push(metrics.operation);
      }
    }

    return { passed, failed };
  }

  /**
   * Get performance summary
   */
  getPerformanceSummary(): {
    totalOperations: number;
    averageDuration: number;
    minDuration: number;
    maxDuration: number;
    totalMemoryUsed: number;
    averageMemoryUsed: number;
    operationsByType: Record<string, number>;
  } {
    if (this.metrics.length === 0) {
      return {
        totalOperations: 0,
        averageDuration: 0,
        minDuration: 0,
        maxDuration: 0,
        totalMemoryUsed: 0,
        averageMemoryUsed: 0,
        operationsByType: {},
      };
    }

    const durations = this.metrics.map(m => m.duration);
    const memoryDeltas = this.metrics.map(m => m.memoryDelta);

    const operationsByType: Record<string, number> = {};
    for (const metrics of this.metrics) {
      operationsByType[metrics.operation] = (operationsByType[metrics.operation] || 0) + 1;
    }

    return {
      totalOperations: this.metrics.length,
      averageDuration: durations.reduce((sum, d) => sum + d, 0) / durations.length,
      minDuration: Math.min(...durations),
      maxDuration: Math.max(...durations),
      totalMemoryUsed: memoryDeltas.reduce((sum, d) => sum + Math.max(0, d), 0),
      averageMemoryUsed: memoryDeltas.reduce((sum, d) => sum + Math.max(0, d), 0) / memoryDeltas.length,
      operationsByType,
    };
  }

  /**
   * Print performance report
   */
  printPerformanceReport(): void {
    console.log('\n📊 Performance Test Report');
    console.log('='.repeat(50));

    const summary = this.getPerformanceSummary();
    const verification = this.verifyPerformanceThresholds();

    console.log(`Total Operations: ${summary.totalOperations}`);
    console.log(`Average Duration: ${Math.round(summary.averageDuration)}ms`);
    console.log(`Min Duration: ${summary.minDuration}ms`);
    console.log(`Max Duration: ${summary.maxDuration}ms`);
    console.log(`Total Memory Used: ${summary.totalMemoryUsed}MB`);
    console.log(`Average Memory Used: ${Math.round(summary.averageMemoryUsed)}MB`);

    console.log('\nOperations by Type:');
    for (const [operation, count] of Object.entries(summary.operationsByType)) {
      console.log(`  ${operation}: ${count}`);
    }

    if (verification.failed.length > 0) {
      console.log('\n❌ Performance Thresholds Failed:');
      for (const failure of verification.failed) {
        console.log(`  ${failure.operation}: ${failure.actual}ms (threshold: ${failure.threshold}ms)`);
      }
    } else {
      console.log('\n✅ All performance thresholds passed');
    }

    console.log('\nDetailed Metrics:');
    for (const metrics of this.metrics) {
      const status = verification.failed.some(f => f.operation === metrics.operation) ? '❌' : '✅';
      console.log(`  ${status} ${metrics.operation}: ${metrics.duration}ms, ${metrics.memoryDelta}MB`);
    }
  }

  /**
   * Clear all collected metrics
   */
  clearMetrics(): void {
    this.metrics = [];
  }

  /**
   * Set custom performance threshold
   */
  setThreshold(operation: string, thresholdMs: number): void {
    this.thresholds.set(operation, thresholdMs);
  }

  /**
   * Get all collected metrics
   */
  getMetrics(): PerformanceMetrics[] {
    return [...this.metrics];
  }
}