/**
 * Cleanup Metrics Performance Tests
 *
 * Performance tests focused on metrics accuracy and tracking:
 * - cleanup_deleted_total metric accuracy
 * - Performance under high load
 * - Metrics consistency across operations
 * - Memory usage during metrics tracking
 */

import { describe, it, expect, beforeAll, afterAll, jest } from '@jest/globals';
import { performance } from 'node:perf_hooks';

describe('Cleanup Metrics Performance', () => {
  let cleanupWorker: any;

  beforeAll(async () => {
    const { createCleanupWorker } = await import('../../src/services/cleanup-worker.service.js');
    cleanupWorker = createCleanupWorker({
      dry_run: false,
      require_confirmation: false,
      enable_backup: false,
      batch_size: 100,
      max_batches: 10,
      performance: {
        max_items_per_second: 10000,
        enable_parallel_processing: false,
        max_parallel_workers: 1,
      },
    });

    // Mock dependencies for performance testing
    jest.mock('../../src/services/expiry-worker.js', () => ({
      runExpiryWorker: jest.fn().mockResolvedValue({
        total_processed: 1000,
        total_deleted: 950,
        deleted_counts: {
          entity: 400,
          relation: 300,
          todo: 150,
          decision: 80,
          issue: 20,
        },
        duration_ms: 500,
      }),
      getRecentPurgeReports: jest.fn().mockResolvedValue([]),
      getPurgeStatistics: jest.fn().mockResolvedValue({
        total_reports: 0,
        total_items_deleted: 0,
        average_performance: { items_per_second: 0, average_duration_ms: 0 },
        top_deleted_kinds: [],
      }),
    }));

    jest.mock('../../src/services/memory-find.js', () => ({
      memoryFind: jest.fn().mockResolvedValue({
        items: Array.from({ length: 500 }, (_, i) => ({
          id: `orphaned_${i}`,
          kind: 'relation',
          data: {},
        })),
      }),
    }));

    jest.mock('../../src/services/memory-store.js', () => ({
      memoryStore: jest.fn().mockResolvedValue({
        stored: [],
        errors: [],
        summary: { total: 0, stored: 0, skipped_dedupe: 0 },
      }),
    }));

    jest.mock('../../src/services/metrics/system-metrics.js', () => ({
      systemMetricsService: {
        updateMetrics: jest.fn(),
        getMetrics: jest.fn().mockReturnValue({
          store_count: 10000,
          find_count: 20000,
          purge_count: 500,
          dedupe_rate: 0.85,
          validator_fail_rate: 0.02,
          performance: {},
          errors: [],
          rate_limiting: {},
          memory: {},
        }),
        getMetricsSummary: jest.fn().mockReturnValue({
          operations: { stores: 1000, finds: 2000, purges: 50 },
          performance: {
            dedupe_rate: 0.85,
            validator_fail_rate: 0.02,
            avg_response_time: 150,
          },
          health: {
            error_rate: 0.01,
            block_rate: 0.05,
            uptime_hours: 24,
          },
        }),
      },
    }));
  });

  afterAll(() => {
    jest.clearAllMocks();
  });

  describe('cleanup_deleted_total Metric Accuracy', () => {
    it('should accurately track cleanup_deleted_total across multiple operations', async () => {
      const operationCounts = [950, 875, 1020, 785, 1100];
      let totalExpected = 0;

      for (let i = 0; i < operationCounts.length; i++) {
        // Mock different counts for each operation
        jest.doMock('../../src/services/expiry-worker.js', () => ({
          runExpiryWorker: jest.fn().mockResolvedValue({
            total_processed: operationCounts[i] + 50,
            total_deleted: operationCounts[i],
            deleted_counts: {
              entity: Math.floor(operationCounts[i] * 0.4),
              relation: Math.floor(operationCounts[i] * 0.3),
              todo: Math.floor(operationCounts[i] * 0.2),
              decision: Math.floor(operationCounts[i] * 0.1),
            },
            duration_ms: 400 + i * 50,
          }),
        }));

        const report = await cleanupWorker.runCleanup({
          dry_run: false,
          operations: ['expired'],
          require_confirmation: false,
        });

        totalExpected += operationCounts[i];
        expect(report.metrics.cleanup_deleted_total).toBe(totalExpected);
        expect(report.metrics.expired_items_deleted).toBe(totalExpected);
      }
    });

    it('should distinguish between dry_run and actual deletions', async () => {
      // Run dry-run first
      const dryRunReport = await cleanupWorker.runCleanup({
        dry_run: true,
        operations: ['expired'],
        require_confirmation: false,
      });

      expect(dryRunReport.metrics.cleanup_deleted_total).toBe(0);
      expect(dryRunReport.metrics.cleanup_dryrun_total).toBeGreaterThan(0);

      // Then run actual cleanup
      const cleanupReport = await cleanupWorker.runCleanup({
        dry_run: false,
        operations: ['expired'],
        require_confirmation: false,
      });

      expect(cleanupReport.metrics.cleanup_deleted_total).toBeGreaterThan(0);
      expect(cleanupReport.metrics.cleanup_dryrun_total).toBe(0);
    });

    it('should track cleanup_deleted_total per operation type', async () => {
      const report = await cleanupWorker.runCleanup({
        dry_run: false,
        operations: ['expired', 'orphaned', 'duplicate', 'metrics', 'logs'],
        require_confirmation: false,
      });

      expect(report.metrics.expired_items_deleted).toBeGreaterThan(0);
      expect(report.metrics.orphaned_items_deleted).toBeGreaterThan(0);
      expect(report.metrics.duplicate_items_deleted).toBeGreaterThan(0);
      expect(report.metrics.metrics_items_deleted).toBeGreaterThan(0);
      expect(report.metrics.logs_items_deleted).toBeGreaterThan(0);

      // Total should be sum of all operation types
      const expectedTotal =
        report.metrics.expired_items_deleted +
        report.metrics.orphaned_items_deleted +
        report.metrics.duplicate_items_deleted +
        report.metrics.metrics_items_deleted +
        report.metrics.logs_items_deleted;

      expect(report.metrics.cleanup_deleted_total).toBe(expectedTotal);
    });
  });

  describe('Performance Under Load', () => {
    it('should maintain accuracy during high-volume operations', async () => {
      const highVolumeCount = 50000;
      const startTime = performance.now();

      // Mock high-volume operation
      jest.doMock('../../src/services/expiry-worker.js', () => ({
        runExpiryWorker: jest.fn().mockResolvedValue({
          total_processed: highVolumeCount,
          total_deleted: highVolumeCount - 5000,
          deleted_counts: {
            entity: 20000,
            relation: 15000,
            todo: 8000,
            decision: 2000,
          },
          duration_ms: 2000,
        }),
      }));

      const report = await cleanupWorker.runCleanup({
        dry_run: false,
        operations: ['expired'],
        require_confirmation: false,
        batch_size: 1000,
        max_batches: 50,
      });

      const endTime = performance.now();
      const duration = endTime - startTime;

      expect(report.metrics.cleanup_deleted_total).toBe(highVolumeCount - 5000);
      expect(report.metrics.items_per_second).toBeGreaterThan(10000); // Should be efficient
      expect(duration).toBeLessThan(5000); // Should complete within 5 seconds

      // Verify type breakdown accuracy
      const typeTotal = Object.values(report.metrics.cleanup_by_type)
        .reduce((sum: number, count: number) => sum + count, 0);
      expect(typeTotal).toBe(highVolumeCount - 5000);
    });

    it('should handle concurrent operations efficiently', async () => {
      const concurrentOps = 10;
      const itemsPerOp = 1000;

      const promises = Array.from({ length: concurrentOps }, async (_, i) => {
        // Mock different operation counts
        jest.doMock('../../src/services/expiry-worker.js', () => ({
          runExpiryWorker: jest.fn().mockResolvedValue({
            total_processed: itemsPerOp + i * 10,
            total_deleted: itemsPerOp,
            deleted_counts: {
              entity: itemsPerOp * 0.5,
              relation: itemsPerOp * 0.3,
              todo: itemsPerOp * 0.2,
            },
            duration_ms: 100 + i * 10,
          }),
        }));

        return cleanupWorker.runCleanup({
          dry_run: false,
          operations: ['expired'],
          require_confirmation: false,
        });
      });

      const startTime = performance.now();
      const results = await Promise.all(promises);
      const endTime = performance.now();

      const totalDuration = endTime - startTime;

      // All operations should complete successfully
      expect(results).toHaveLength(concurrentOps);
      results.forEach((report, index) => {
        expect(report.metrics.cleanup_deleted_total).toBe(itemsPerOp);
        expect(report.metrics.cleanup_duration.expired).toBe(100 + index * 10);
      });

      // Performance should be reasonable even with concurrent operations
      expect(totalDuration).toBeLessThan(2000);
    });

    it('should maintain memory efficiency during large operations', async () => {
      const initialMemory = process.memoryUsage().heapUsed;

      // Simulate large operation
      const largeOperationCount = 100000;
      jest.doMock('../../src/services/expiry-worker.js', () => ({
        runExpiryWorker: jest.fn().mockResolvedValue({
          total_processed: largeOperationCount,
          total_deleted: largeOperationCount - 10000,
          deleted_counts: {
            entity: 40000,
            relation: 30000,
            todo: 15000,
            decision: 5000,
          },
          duration_ms: 3000,
        }),
      }));

      await cleanupWorker.runCleanup({
        dry_run: false,
        operations: ['expired'],
        require_confirmation: false,
        batch_size: 2000,
        max_batches: 50,
      });

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;

      // Memory increase should be reasonable (less than 50MB for this operation)
      expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024);
    });
  });

  describe('Metrics Consistency', () => {
    it('should maintain consistent metrics across operation history', async () => {
      const operationReports = [];

      // Run multiple operations
      for (let i = 0; i < 5; i++) {
        const itemCount = 100 + i * 50;
        jest.doMock('../../src/services/expiry-worker.js', () => ({
          runExpiryWorker: jest.fn().mockResolvedValue({
            total_processed: itemCount + 10,
            total_deleted: itemCount,
            deleted_counts: {
              entity: Math.floor(itemCount * 0.5),
              relation: Math.floor(itemCount * 0.3),
              todo: Math.floor(itemCount * 0.2),
            },
            duration_ms: 100 + i * 20,
          }),
        }));

        const report = await cleanupWorker.runCleanup({
          dry_run: false,
          operations: ['expired'],
          require_confirmation: false,
        });

        operationReports.push(report);
      }

      // Get history and verify consistency
      const history = cleanupWorker.getOperationHistory(10);
      expect(history).toHaveLength(5);

      // Verify metrics are consistent
      history.forEach((report: any, index: number) => {
        const originalReport = operationReports[index];
        expect(report.metrics.cleanup_deleted_total).toBe(originalReport.metrics.cleanup_deleted_total);
        expect(report.metrics.cleanup_dryrun_total).toBe(originalReport.metrics.cleanup_dryrun_total);
        expect(JSON.stringify(report.metrics.cleanup_by_type))
          .toBe(JSON.stringify(originalReport.metrics.cleanup_by_type));
      });
    });

    it('should calculate accurate performance metrics', async () => {
      const itemCount = 5000;
      const expectedDuration = 1000;

      jest.doMock('../../src/services/expiry-worker.js', () => ({
        runExpiryWorker: jest.fn().mockResolvedValue({
          total_processed: itemCount,
          total_deleted: itemCount - 200,
          deleted_counts: {
            entity: 2000,
            relation: 1500,
            todo: 1000,
            decision: 300,
          },
          duration_ms: expectedDuration,
        }),
      }));

      const report = await cleanupWorker.runCleanup({
        dry_run: false,
        operations: ['expired'],
        require_confirmation: false,
      });

      // Verify performance calculations
      const expectedItemsPerSecond = (itemCount - 200) / (expectedDuration / 1000);
      expect(report.metrics.items_per_second).toBeCloseTo(expectedItemsPerSecond, 1);
      expect(report.metrics.average_batch_duration_ms).toBe(expectedDuration);
      expect(report.performance.items_processed_per_second)
        .toBeCloseTo(expectedItemsPerSecond, 1);
    });

    it('should track error rates accurately', async () => {
      // Mock some operations to fail
      let callCount = 0;
      jest.doMock('../../src/services/expiry-worker.js', () => ({
        runExpiryWorker: jest.fn().mockImplementation(() => {
          callCount++;
          if (callCount <= 2) {
            return Promise.resolve({
              total_processed: 100,
              total_deleted: 95,
              deleted_counts: { entity: 50, relation: 30, todo: 15 },
              duration_ms: 100,
            });
          } else {
            return Promise.reject(new Error('Simulated operation failure'));
          }
        }),
      }));

      const reports = [];
      for (let i = 0; i < 5; i++) {
        try {
          const report = await cleanupWorker.runCleanup({
            dry_run: false,
            operations: ['expired'],
            require_confirmation: false,
          });
          reports.push(report);
        } catch (error) {
          // Expected failures
        }
      }

      // Check statistics
      const stats = await cleanupWorker.getCleanupStatistics(30);
      expect(stats.total_operations).toBeGreaterThan(0);
      expect(stats.success_rate).toBeLessThan(100); // Should account for failures
      expect(stats.errors_by_type).toBeDefined();
    });
  });

  describe('Metrics Tracking Edge Cases', () => {
    it('should handle zero-item operations', async () => {
      jest.doMock('../../src/services/expiry-worker.js', () => ({
        runExpiryWorker: jest.fn().mockResolvedValue({
          total_processed: 0,
          total_deleted: 0,
          deleted_counts: {},
          duration_ms: 50,
        }),
      }));

      const report = await cleanupWorker.runCleanup({
        dry_run: false,
        operations: ['expired'],
        require_confirmation: false,
      });

      expect(report.metrics.cleanup_deleted_total).toBe(0);
      expect(report.metrics.cleanup_dryrun_total).toBe(0);
      expect(report.metrics.items_per_second).toBe(0);
      expect(Object.keys(report.metrics.cleanup_by_type)).toHaveLength(0);
    });

    it('should handle mixed successful/failed operations', async () => {
      // Mock mixed results
      jest.doMock('../../src/services/expiry-worker.js', () => ({
        runExpiryWorker: jest.fn().mockResolvedValue({
          total_processed: 200,
          total_deleted: 150,
          deleted_counts: { entity: 80, relation: 50, todo: 20 },
          duration_ms: 300,
          errors: [
            { item_id: 'error_item_1', error: 'Failed to delete item 1' },
            { item_id: 'error_item_2', error: 'Failed to delete item 2' },
          ],
        }),
      }));

      const report = await cleanupWorker.runCleanup({
        dry_run: false,
        operations: ['expired'],
        require_confirmation: false,
      });

      expect(report.metrics.cleanup_deleted_total).toBe(150);
      expect(report.errors).toHaveLength(2);
      // Metrics should still be accurate despite some errors
      expect(report.metrics.items_per_second).toBeGreaterThan(0);
    });

    it('should handle rapid successive operations', async () => {
      const rapidOperations = 20;
      const reports = [];

      for (let i = 0; i < rapidOperations; i++) {
        jest.doMock('../../src/services/expiry-worker.js', () => ({
          runExpiryWorker: jest.fn().mockResolvedValue({
            total_processed: 50 + i,
            total_deleted: 45 + i,
            deleted_counts: {
              entity: 20 + Math.floor(i * 0.5),
              relation: 15 + Math.floor(i * 0.3),
              todo: 10 + Math.floor(i * 0.2),
            },
            duration_ms: 50,
          }),
        }));

        const report = await cleanupWorker.runCleanup({
          dry_run: false,
          operations: ['expired'],
          require_confirmation: false,
        });
        reports.push(report);
      }

      // Verify all operations were tracked correctly
      expect(reports).toHaveLength(rapidOperations);

      let cumulativeTotal = 0;
      reports.forEach((report, index) => {
        cumulativeTotal += report.metrics.cleanup_deleted_total;
        // Each report should have its own count (not cumulative)
        expect(report.metrics.cleanup_deleted_total).toBe(45 + index);
      });

      // History should contain all operations
      const history = cleanupWorker.getOperationHistory(25);
      expect(history).toHaveLength(rapidOperations);
    });
  });
});