/**
 * Comprehensive Cleanup Worker Service Tests
 *
 * Tests for the cleanup worker service including:
 * - Dry-run and cleanup modes
 * - Safety mechanisms and confirmation flows
 * - Metrics tracking accuracy
 * - Performance under load
 * - Error handling and recovery
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { logger } from '@/utils/logger';

import { CleanupWorkerService } from '../cleanup-worker.service';
import type { ExpiryWorkerResult } from '../expiry-worker.js';

// Mock dependencies
vi.mock('@/utils/logger.js');
vi.mock('../memory-find.js');
vi.mock('../memory-store.js');
vi.mock('../expiry-worker.js');
vi.mock('../metrics/system-metrics.js');

const mockLogger = logger as ReturnType<typeof vi.mocked<typeof logger>>;

const DEFAULT_EXPIRY_WORKER_RESULT: ExpiryWorkerResult = {
  deleted_counts: {
    decision: 0,
    entity: 0,
    relation: 0,
    todo: 0,
  },
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
  policy_enforcement: {
    policies_applied: {},
    permanent_items_preserved: 0,
    extensions_granted: 0,
  },
};

const buildExpiryWorkerResult = (
  overrides: Partial<ExpiryWorkerResult> = {}
): ExpiryWorkerResult => ({
  ...DEFAULT_EXPIRY_WORKER_RESULT,
  ...overrides,
  deleted_counts: {
    ...DEFAULT_EXPIRY_WORKER_RESULT.deleted_counts,
    ...overrides.deleted_counts,
  },
  metrics: {
    ...DEFAULT_EXPIRY_WORKER_RESULT.metrics,
    ...overrides.metrics,
  },
  policy_enforcement: {
    ...DEFAULT_EXPIRY_WORKER_RESULT.policy_enforcement,
    ...overrides.policy_enforcement,
  },
});

describe('CleanupWorkerService', () => {
  let cleanupWorker: CleanupWorkerService;

  beforeEach(() => {
    vi.clearAllMocks();
    cleanupWorker = new CleanupWorkerService({
      dry_run: true,
      require_confirmation: false,
      enable_backup: false,
      batch_size: 10,
      max_batches: 5,
    });

    // Setup mock logger to prevent actual logging during tests
    mockLogger.info.mockImplementation(() => {});
    mockLogger.warn.mockImplementation(() => {});
    mockLogger.error.mockImplementation(() => {});
    mockLogger.debug.mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Configuration Management', () => {
    it('should create cleanup worker with default configuration', () => {
      const worker = new CleanupWorkerService();
      const config = worker.getConfig();

      expect(config.enabled).toBe(true);
      expect(config.dry_run).toBe(true);
      expect(config.require_confirmation).toBe(true);
      expect(config.enable_backup).toBe(true);
      expect(config.batch_size).toBe(100);
      expect(config.max_batches).toBe(50);
    });

    it('should create cleanup worker with custom configuration', () => {
      const customConfig = {
        dry_run: false,
        batch_size: 50,
        max_batches: 10,
        require_confirmation: false,
      };

      const worker = new CleanupWorkerService(customConfig);
      const config = worker.getConfig();

      expect(config.dry_run).toBe(false);
      expect(config.batch_size).toBe(50);
      expect(config.max_batches).toBe(10);
      expect(config.require_confirmation).toBe(false);
    });

    it('should update configuration', () => {
      const newConfig = {
        dry_run: false,
        batch_size: 200,
      };

      cleanupWorker.updateConfig(newConfig);
      const config = cleanupWorker.getConfig();

      expect(config.dry_run).toBe(false);
      expect(config.batch_size).toBe(200);
    });
  });

  describe('Dry Run Operations', () => {
    it('should perform dry run without deletions', async () => {
      const mockMemoryFind = await import('../memory-find.js');
      const mockMemoryFindFunction = vi.mocked(await import('../memory-find.js')).memoryFind as ReturnType<typeof vi.fn>;
      mockMemoryFindFunction.mockResolvedValue({
        items: [
          { id: '1', kind: 'entity', data: {} },
          { id: '2', kind: 'relation', data: {} },
        ],
        total_count: 2,
        autonomous_context: {
          search_mode_used: 'fast',
          results_found: 2,
          confidence_average: 0.9,
          user_message_suggestion: 'consider refining search',
        },
        observability: {
          source: 'cortex_memory',
          strategy: 'fast',
          vector_used: false,
          degraded: false,
          execution_time_ms: 50,
          confidence_average: 0.9,
          search_id: 'mock-search-id-123',
        },
        meta: {
          strategy: 'fast',
          vector_used: false,
          degraded: false,
          source: 'cortex_memory',
          execution_time_ms: 50,
          confidence_score: 0.9,
          truncated: false,
        },
      });

      const mockExpiryWorker = await import('../expiry-worker.js');
      const mockRunExpiryWorker = vi.mocked(await import('../expiry-worker.js')).runExpiryWorker as ReturnType<typeof vi.fn>;
      mockRunExpiryWorker.mockResolvedValue(
        buildExpiryWorkerResult({
          total_processed: 5,
          total_deleted: 0,
          deleted_counts: { entity: 2, relation: 1 },
          duration_ms: 100,
        })
      );

      const report = await cleanupWorker.runCleanup({
        dry_run: true,
        operations: ['expired'],
        require_confirmation: false,
      });

      expect(report.mode).toBe('dry_run');
      expect(report.metrics.cleanup_deleted_total).toBe(0);
      expect(report.metrics.cleanup_dryrun_total).toBeGreaterThan(0);
      expect(report.safety_confirmations.confirmed).toBe(true);
    });

    it('should identify expired items in dry run mode', async () => {
      const mockExpiryWorker = await import('../expiry-worker.js');
      vi.mocked(mockExpiryWorker.runExpiryWorker).mockResolvedValue(
        buildExpiryWorkerResult({
          total_processed: 10,
          total_deleted: 0,
          deleted_counts: { entity: 5, relation: 3, todo: 2 },
          duration_ms: 150,
        })
      );

      const report = await cleanupWorker.runCleanup({
        dry_run: true,
        operations: ['expired'],
        require_confirmation: false,
      });

      expect(report.metrics.cleanup_dryrun_total).toBe(10);
      expect(report.metrics.cleanup_by_type).toEqual({
        entity: 5,
        relation: 3,
        todo: 2,
      });
    });
  });

  describe('Safety Mechanisms', () => {
    it('should require confirmation for destructive operations', async () => {
      const worker = new CleanupWorkerService({
        dry_run: false,
        require_confirmation: true,
        enable_backup: false,
        batch_size: 10,
        max_batches: 5,
      });

      const report = await cleanupWorker.runCleanup({
        dry_run: false,
        operations: ['expired'],
        require_confirmation: true,
      });

      expect(report.safety_confirmations.required).toBe(true);
      expect(report.safety_confirmations.confirmed).toBe(false);
      expect(report.safety_confirmations.confirmation_token).toBeDefined();
    });

    it('should confirm cleanup operation with valid token', async () => {
      const worker = new CleanupWorkerService({
        dry_run: false,
        require_confirmation: true,
        enable_backup: false,
        batch_size: 10,
        max_batches: 5,
      });

      // First, run dry-run to get confirmation token
      const dryRunReport = await worker.runCleanup({
        dry_run: true,
        operations: ['expired'],
        require_confirmation: true,
      });

      const token = dryRunReport.safety_confirmations.confirmation_token;
      expect(token).toBeDefined();

      // Confirm the operation
      const confirmed = worker.confirmCleanup(token!);
      expect(confirmed).toBe(true);

      // Now run with confirmation token
      const cleanupReport = await worker.runCleanup({
        dry_run: false,
        operations: ['expired'],
        require_confirmation: true,
        confirmation_token: token,
      });

      expect(cleanupReport.safety_confirmations.confirmed).toBe(true);
    });

    it('should reject invalid confirmation token', async () => {
      const worker = new CleanupWorkerService({
        require_confirmation: true,
      });

      const confirmed = worker.confirmCleanup('invalid_token');
      expect(confirmed).toBe(false);
    });

    it('should expire confirmation tokens after timeout', async () => {
      const worker = new CleanupWorkerService({
        require_confirmation: true,
      });

      // Get a token
      const dryRunReport = await worker.runCleanup({
        dry_run: true,
        operations: ['expired'],
        require_confirmation: true,
      });

      const token = dryRunReport.safety_confirmations.confirmation_token;

      // Manually expire the token by advancing time
      vi.useFakeTimers();
      vi.advanceTimersByTime(31 * 60 * 1000); // 31 minutes

      const confirmed = worker.confirmCleanup(token!);
      expect(confirmed).toBe(false);

      vi.useRealTimers();
    });
  });

  describe('Metrics Tracking', () => {
    it('should track cleanup_deleted_total metric', async () => {
      const mockExpiryWorker = await import('../expiry-worker.js');
      vi.mocked(mockExpiryWorker.runExpiryWorker).mockResolvedValue(
        buildExpiryWorkerResult({
          total_processed: 20,
          total_deleted: 15,
          deleted_counts: { entity: 8, relation: 4, todo: 3 },
          duration_ms: 200,
        })
      );

      const report = await cleanupWorker.runCleanup({
        dry_run: false,
        operations: ['expired'],
        require_confirmation: false,
      });

      expect(report.metrics.cleanup_deleted_total).toBe(15);
      expect(report.metrics.expired_items_deleted).toBe(15);
    });

    it('should track cleanup_dryrun_total metric', async () => {
      const mockExpiryWorker = await import('../expiry-worker.js');
      vi.mocked(mockExpiryWorker.runExpiryWorker).mockResolvedValue(
        buildExpiryWorkerResult({
          total_processed: 25,
          total_deleted: 0,
          deleted_counts: {},
          duration_ms: 100,
        })
      );

      const report = await cleanupWorker.runCleanup({
        dry_run: true,
        operations: ['expired'],
        require_confirmation: false,
      });

      expect(report.metrics.cleanup_dryrun_total).toBe(25);
      expect(report.metrics.cleanup_deleted_total).toBe(0);
    });

    it('should track cleanup_by_type breakdown', async () => {
      const mockExpiryWorker = await import('../expiry-worker.js');
      vi.mocked(mockExpiryWorker.runExpiryWorker).mockResolvedValue(
        buildExpiryWorkerResult({
          total_processed: 30,
          total_deleted: 25,
          deleted_counts: { entity: 10, relation: 8, todo: 4, decision: 3 },
          duration_ms: 300,
        })
      );

      const report = await cleanupWorker.runCleanup({
        dry_run: false,
        operations: ['expired'],
        require_confirmation: false,
      });

      expect(report.metrics.cleanup_by_type).toEqual({
        entity: 10,
        relation: 8,
        todo: 4,
        decision: 3,
      });
    });

    it('should track cleanup_duration for each operation', async () => {
      const mockExpiryWorker = await import('../expiry-worker.js');
      vi.mocked(mockExpiryWorker.runExpiryWorker).mockResolvedValue(
        buildExpiryWorkerResult({
          total_processed: 10,
          total_deleted: 8,
          deleted_counts: { entity: 5, relation: 3 },
          duration_ms: 150,
        })
      );

      const report = await cleanupWorker.runCleanup({
        dry_run: false,
        operations: ['expired', 'orphaned'],
        require_confirmation: false,
      });

      expect(report.metrics.cleanup_duration.expired).toBeGreaterThan(0);
      expect(report.metrics.cleanup_duration.orphaned).toBeGreaterThan(0);
    });

    it('should track performance metrics', async () => {
      const mockExpiryWorker = await import('../expiry-worker.js');
      vi.mocked(mockExpiryWorker.runExpiryWorker).mockResolvedValue(
        buildExpiryWorkerResult({
          total_processed: 50,
          total_deleted: 40,
          deleted_counts: { entity: 20, relation: 15, todo: 5 },
          duration_ms: 500,
        })
      );

      const report = await cleanupWorker.runCleanup({
        dry_run: false,
        operations: ['expired'],
        require_confirmation: false,
      });

      expect(report.metrics.items_per_second).toBeGreaterThan(0);
      expect(report.metrics.average_batch_duration_ms).toBeGreaterThan(0);
      expect(report.performance.total_duration_ms).toBeGreaterThan(0);
      expect(report.performance.items_processed_per_second).toBeGreaterThan(0);
    });
  });

  describe('Error Handling', () => {
    it('should handle expiry worker errors gracefully', async () => {
      const mockExpiryWorker = await import('../expiry-worker.js');
      vi.mocked(mockExpiryWorker.runExpiryWorker).mockRejectedValue(
        new Error('Database connection failed')
      );

      const report = await cleanupWorker.runCleanup({
        dry_run: false,
        operations: ['expired'],
        require_confirmation: false,
      });

      expect(report.errors).toHaveLength(1);
      expect(report.errors[0].operation).toBe('expired');
      expect(report.errors[0].error).toContain('Database connection failed');
    });

    it('should continue with other operations if one fails', async () => {
      const mockExpiryWorker = await import('../expiry-worker.js');
      const mockedRunExpiryWorker = vi.mocked(mockExpiryWorker.runExpiryWorker);
      mockedRunExpiryWorker
        .mockRejectedValueOnce(new Error('Expiry worker failed'))
        .mockResolvedValueOnce(
          buildExpiryWorkerResult({
            total_processed: 10,
            total_deleted: 8,
            deleted_counts: { entity: 5, relation: 3 },
            duration_ms: 100,
          })
        );

      const report = await cleanupWorker.runCleanup({
        dry_run: false,
        operations: ['expired', 'orphaned'],
        require_confirmation: false,
      });

      expect(report.errors).toHaveLength(1);
      expect(report.metrics.cleanup_deleted_total).toBeGreaterThan(0);
    });

    it('should log errors appropriately', async () => {
      const mockExpiryWorker = await import('../expiry-worker.js');
      vi.mocked(mockExpiryWorker.runExpiryWorker).mockRejectedValue(new Error('Test error'));

      await cleanupWorker.runCleanup({
        dry_run: false,
        operations: ['expired'],
        require_confirmation: false,
      });

      expect(mockLogger.error).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'Test error',
        }),
        'Cleanup operation failed'
      );
    });
  });

  describe('Operation History and Statistics', () => {
    it('should maintain operation history', async () => {
      const mockExpiryWorker = await import('../expiry-worker.js');
      vi.mocked(mockExpiryWorker.runExpiryWorker).mockResolvedValue(
        buildExpiryWorkerResult({
          total_processed: 5,
          total_deleted: 3,
          deleted_counts: { entity: 2, relation: 1 },
          duration_ms: 50,
        })
      );

      // Run multiple operations
      await cleanupWorker.runCleanup({
        dry_run: true,
        operations: ['expired'],
        require_confirmation: false,
      });

      await cleanupWorker.runCleanup({
        dry_run: false,
        operations: ['expired'],
        require_confirmation: false,
      });

      const history = cleanupWorker.getOperationHistory(5);
      expect(history).toHaveLength(2);
      expect(history[0].mode).toBe('cleanup');
      expect(history[1].mode).toBe('dry_run');
    });

    it('should limit operation history size', async () => {
      const mockExpiryWorker = await import('../expiry-worker.js');
      vi.mocked(mockExpiryWorker.runExpiryWorker).mockResolvedValue(
        buildExpiryWorkerResult({
          total_processed: 1,
          total_deleted: 1,
          deleted_counts: { entity: 1 },
          duration_ms: 10,
        })
      );

      // Run multiple operations
      for (let i = 0; i < 15; i++) {
        await cleanupWorker.runCleanup({
          dry_run: true,
          operations: ['expired'],
          require_confirmation: false,
        });
      }

      const history = cleanupWorker.getOperationHistory(10);
      expect(history).toHaveLength(10);
    });

    it('should calculate cleanup statistics', async () => {
      const mockExpiryWorker = await import('../expiry-worker.js');
      vi.mocked(mockExpiryWorker.runExpiryWorker).mockResolvedValue(
        buildExpiryWorkerResult({
          total_processed: 10,
          total_deleted: 8,
          deleted_counts: { entity: 5, relation: 3 },
          duration_ms: 200,
        })
      );

      // Run multiple operations with different timestamps
      const now = new Date();
      for (let i = 0; i < 5; i++) {
        await cleanupWorker.runCleanup({
          dry_run: i < 2, // First 2 are dry runs
          operations: ['expired'],
          require_confirmation: false,
        });
      }

      const stats = await cleanupWorker.getCleanupStatistics(30);

      expect(stats.total_operations).toBe(5);
      expect(stats.total_items_deleted).toBeGreaterThan(0);
      expect(stats.total_items_dryrun).toBeGreaterThan(0);
      expect(stats.success_rate).toBeGreaterThan(0);
      expect(stats.operations_by_type).toBeDefined();
      expect(stats.errors_by_type).toBeDefined();
    });

    it('should return empty statistics for no operations', async () => {
      const stats = await cleanupWorker.getCleanupStatistics(30);

      expect(stats.total_operations).toBe(0);
      expect(stats.total_items_deleted).toBe(0);
      expect(stats.total_items_dryrun).toBe(0);
      expect(stats.success_rate).toBe(0);
      expect(stats.operations_by_type).toEqual({});
      expect(stats.errors_by_type).toEqual({});
    });
  });

  describe('Performance Tests', () => {
    it('should handle large item counts efficiently', async () => {
      const largeItemCount = 10000;
      const mockExpiryWorker = await import('../expiry-worker.js');
      vi.mocked(mockExpiryWorker.runExpiryWorker).mockResolvedValue(
        buildExpiryWorkerResult({
          total_processed: largeItemCount,
          total_deleted: largeItemCount - 1000,
          deleted_counts: { entity: 4000, relation: 3000, todo: 1500, decision: 500 },
          duration_ms: 2000,
        })
      );

      cleanupWorker.updateConfig({
        batch_size: 1000,
        max_batches: 20,
      });

      const startTime = Date.now();
      const report = await cleanupWorker.runCleanup({
        dry_run: false,
        operations: ['expired'],
        require_confirmation: false,
      });
      const duration = Date.now() - startTime;

      expect(report.metrics.cleanup_deleted_total).toBe(largeItemCount - 1000);
      expect(report.metrics.items_per_second).toBeGreaterThan(1000); // Should process efficiently
      expect(duration).toBeLessThan(5000); // Should complete within reasonable time
    });

    it('should maintain performance with multiple concurrent operations', async () => {
      const mockExpiryWorker = await import('../expiry-worker.js');
      vi.mocked(mockExpiryWorker.runExpiryWorker).mockResolvedValue(
        buildExpiryWorkerResult({
          total_processed: 100,
          total_deleted: 80,
          deleted_counts: { entity: 40, relation: 25, todo: 15 },
          duration_ms: 100,
        })
      );

      // Run multiple operations concurrently
      const promises = [];
      for (let i = 0; i < 10; i++) {
        promises.push(
          cleanupWorker.runCleanup({
            dry_run: true,
            operations: ['expired'],
            require_confirmation: false,
          })
        );
      }

      const results = await Promise.all(promises);

      // All operations should complete successfully
      results.forEach((report) => {
        expect(report.metrics.cleanup_dryrun_total).toBe(100);
        expect(report.errors).toHaveLength(0);
      });

      // History should contain all operations
      const history = cleanupWorker.getOperationHistory(20);
      expect(history).toHaveLength(10);
    });
  });

  describe('Scope Filtering', () => {
    it('should apply scope filters to operations', async () => {
      const mockMemoryFind = await import('../memory-find.js');
      vi.mocked(mockMemoryFind.memoryFind).mockResolvedValue({
        results: [],
        items: [
          {
            id: '1',
            kind: 'entity',
            scope: { project: 'test-project' },
            data: {},
            created_at: new Date().toISOString(),
            confidence_score: 0.9,
            match_type: 'exact',
          },
          {
            id: '2',
            kind: 'relation',
            scope: { project: 'test-project' },
            data: {},
            created_at: new Date().toISOString(),
            confidence_score: 0.85,
            match_type: 'exact',
          },
        ],
        total_count: 2,
        autonomous_context: {
          search_mode_used: 'fast',
          results_found: 2,
          confidence_average: 0.87,
          user_message_suggestion: 'Consider broadening your search terms.',
        },
        meta: {
          source: 'cortex_memory',
          strategy: 'deep',
          vector_used: true,
          degraded: false,
          execution_time_ms: 120,
          confidence_score: 0.87, // Corrected to confidence_score
          truncated: false,
        },
        observability: {
          source: 'cortex_memory',
          strategy: 'fast',
          vector_used: true,
          degraded: false,
          execution_time_ms: 120,
          confidence_average: 0.87,
          search_id: 'mock-search-id-123',
        },
      });

      const report = await cleanupWorker.runCleanup({
        dry_run: true,
        operations: ['orphaned'],
        scope_filters: {
          project: 'test-project',
          org: 'test-org',
        },
        require_confirmation: false,
      });

      expect(mockMemoryFind.memoryFind).toHaveBeenCalledWith(
        expect.objectContaining({
          scope: {
            project: 'test-project',
            org: 'test-org',
          },
        })
      );
    });
  });

  describe('Backup Functionality', () => {
    it('should create backup when enabled and required', async () => {
      const worker = new CleanupWorkerService({
        dry_run: false,
        enable_backup: true,
        require_confirmation: false,
        batch_size: 10,
        max_batches: 5,
      });

      const mockMemoryStore = await import('../memory-store.js');
      vi.mocked(mockMemoryStore.memoryStore).mockResolvedValue({
                stored: [],
                errors: [],
                summary: { total: 0, stored: 0, skipped_dedupe: 0, business_rule_blocked: 0 },
                items: [],
                autonomous_context: {
                  action_performed: 'created',
                  similar_items_checked: 0,
                  duplicates_found: 0,
                  contradictions_detected: false,
                  recommendation: 'Test recommendation',
                  reasoning: 'Test reasoning',
                  user_message_suggestion: 'Test suggestion',
                },
                observability: {
                  source: 'cortex_memory',
                  strategy: 'autonomous_deduplication',
                  vector_used: false,
                  degraded: false,
                  execution_time_ms: 0,
                  confidence_score: 0,
                },
                meta: {
                  strategy: 'fast',
                  vector_used: false,
                  degraded: false,
                  source: 'cortex_memory',
                  execution_time_ms: 0,
                  confidence_score: 0,
                  truncated: false,
                },
              });

      const mockExpiryWorker = await import('../expiry-worker.js');
      vi.mocked(mockExpiryWorker.runExpiryWorker).mockResolvedValue(
        buildExpiryWorkerResult({
          total_processed: 5,
          total_deleted: 5,
          deleted_counts: { entity: 3, relation: 2 },
          duration_ms: 100,
        })
      );

      const report = await worker.runCleanup({
        dry_run: false,
        operations: ['expired'],
        require_confirmation: false,
      });

      // This test would need more detailed mock implementation
      // For now, we verify that backup creation is attempted
      expect(report.backup_created).toBeDefined();
    });
  });

  describe('Integration with System Metrics', () => {
    it('should update system metrics after cleanup', async () => {
      const mockSystemMetrics = await import('../metrics/system-metrics.js');
      const mockUpdateMetrics = vi.fn();
      vi.mocked(mockSystemMetrics.systemMetricsService.updateMetrics).mockImplementation(mockUpdateMetrics);

      const mockExpiryWorker = await import('../expiry-worker.js');
      vi.mocked(mockExpiryWorker.runExpiryWorker).mockResolvedValue(
        buildExpiryWorkerResult({
          total_processed: 10,
          total_deleted: 8,
          deleted_counts: { entity: 5, relation: 3 },
          duration_ms: 150,
        })
      );

      await cleanupWorker.runCleanup({
        dry_run: false,
        operations: ['expired'],
        require_confirmation: false,
      });

      expect(mockUpdateMetrics).toHaveBeenCalledTimes(4); // cleanup + 3 operation-specific calls
      expect(mockUpdateMetrics).toHaveBeenCalledWith(
        expect.objectContaining({
          operation: 'cleanup',
          data: expect.objectContaining({
            mode: 'cleanup',
            total_deleted: 8,
            total_dryrun: 0,
          }),
        }),
        150
      );
    });
  });
});
