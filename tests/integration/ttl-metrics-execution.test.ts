/**
 * TTL Metrics and Execution Tests
 *
 * Tests TTL (Time To Live) metrics and cleanup functionality without requiring full database setup:
 * - TTL metrics collection through SystemMetricsService
 * - TTL Management Service operations with real deletions
 * - CleanupWorkerService integration with TTL
 * - System metrics emission for TTL operations
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { TTLManagementService } from '../../src/services/ttl/ttl-management-service.js';
import { CleanupWorkerService } from '../../src/services/cleanup-worker.service.js';
import { systemMetricsService } from '../../src/services/metrics/system-metrics.js';
import { runExpiryWorker } from '../../src/services/expiry-worker.js';
import type { TTLBulkOperationOptions, TTLOperationResult } from '../../src/services/ttl/ttl-management-service.js';

// Mock database layer for testing
const mockDatabase = {
  search: vi.fn(),
  delete: vi.fn(),
  store: vi.fn(),
  findById: vi.fn(),
};

// Mock memory services
const mockMemoryStore = vi.fn();
const mockMemoryFind = vi.fn(() => ({ items: [] }));

describe('TTL Metrics and Execution', () => {
  let ttlService: TTLManagementService;
  let cleanupService: CleanupWorkerService;

  beforeEach(async () => {
    // Reset system metrics
    systemMetricsService.resetMetrics();

    // Initialize TTL Management Service with mock database
    ttlService = new TTLManagementService(mockDatabase as any);

    // Initialize Cleanup Worker Service
    cleanupService = new CleanupWorkerService({
      enabled: true,
      dry_run: false,
      batch_size: 10,
    });

    // Setup default mock behaviors
    mockDatabase.search.mockResolvedValue({
      results: [],
    });

    mockDatabase.delete.mockResolvedValue({
      deleted: 0,
    });

    mockDatabase.store.mockResolvedValue({
      stored: 0,
    });

    mockDatabase.findById.mockResolvedValue({
      results: [],
    });

    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('TTL Metrics Collection', () => {
    it('should initialize TTL metrics with zero values', () => {
      const metrics = systemMetricsService.getMetrics();

      expect(metrics.ttl).toEqual({
        ttl_deletes_total: 0,
        ttl_skips_total: 0,
        ttl_errors_total: 0,
        ttl_processing_rate_per_second: 0,
        ttl_batch_count: 0,
        ttl_average_batch_size: 0,
        ttl_policies_applied: {},
        ttl_extensions_granted: 0,
        ttl_permanent_items_preserved: 0,
        ttl_cleanup_duration_ms: 0,
        ttl_last_cleanup_timestamp: '',
        ttl_success_rate: 100,
      });
    });

    it('should update TTL metrics when expiry worker runs', async () => {
      // Mock expired items
      const expiredItems = [
        { id: 'item1', kind: 'observation', expiryTime: '2025-01-01T00:00:00Z', policy: 'short' },
        { id: 'item2', kind: 'entity', expiryTime: '2025-01-01T00:00:00Z', policy: 'default' },
      ];

      mockDatabase.search.mockResolvedValue({
        results: expiredItems.map(item => ({
          id: item.id,
          kind: item.kind,
          data: {
            expiry_at: item.expiryTime,
            ttl_policy: item.policy,
          },
        })),
      });

      mockDatabase.delete.mockResolvedValue({
        deleted: 2,
      });

      // Run expiry worker
      const result = await runExpiryWorker({ dry_run: false });

      // Verify TTL metrics were updated
      const metrics = systemMetricsService.getMetrics();

      expect(metrics.ttl.ttl_deletes_total).toBeGreaterThan(0);
      expect(metrics.ttl.ttl_last_cleanup_timestamp).toBeDefined();
      expect(metrics.ttl.ttl_success_rate).toBeGreaterThan(0);

      // Verify expiry worker result
      expect(result.total_deleted).toBe(2);
      expect(result.metrics.ttl_deletes_total).toBe(2);
    });

    it('should track TTL policy statistics', async () => {
      // Mock items with different TTL policies
      const itemsWithPolicies = [
        { id: 'item1', kind: 'observation', data: { expiry_at: '2025-01-01T00:00:00Z', ttl_policy: 'short' } },
        { id: 'item2', kind: 'entity', data: { expiry_at: '2025-01-01T00:00:00Z', ttl_policy: 'short' } },
        { id: 'item3', kind: 'decision', data: { expiry_at: '2025-01-01T00:00:00Z', ttl_policy: 'default' } },
        { id: 'item4', kind: 'todo', data: { expiry_at: '9999-12-31T23:59:59.999Z', ttl_policy: 'permanent' } },
      ];

      mockDatabase.search.mockResolvedValue({
        results: itemsWithPolicies,
      });

      mockDatabase.delete.mockResolvedValue({
        deleted: 3, // Only 3 items, permanent item preserved
      });

      // Run TTL cleanup
      const result = await ttlService.cleanupExpiredItems({ dryRun: false });

      // Check metrics
      const metrics = systemMetricsService.getMetrics();
      expect(metrics.ttl.ttl_permanent_items_preserved).toBeGreaterThan(0);
      expect(metrics.ttl.ttl_deletes_total).toBe(3);
    });

    it('should handle TTL errors and update error metrics', async () => {
      // Mock database error
      mockDatabase.search.mockRejectedValue(new Error('Database connection failed'));

      // Run expiry worker - should handle error gracefully
      await expect(runExpiryWorker({ dry_run: false })).rejects.toThrow();

      // Check error metrics
      const metrics = systemMetricsService.getMetrics();
      expect(metrics.ttl.ttl_errors_total).toBeGreaterThan(0);
    });
  });

  describe('Real Deletion Operations', () => {
    it('should perform real deletions in non-dry-run mode', async () => {
      const expiredItems = [
        { id: 'item1', kind: 'observation', expiryTime: '2025-01-01T00:00:00Z', policy: 'short' },
        { id: 'item2', kind: 'entity', expiryTime: '2025-01-01T00:00:00Z', policy: 'default' },
      ];

      mockDatabase.search.mockResolvedValue({
        results: expiredItems.map(item => ({
          id: item.id,
          kind: item.kind,
          data: {
            expiry_at: item.expiryTime,
            ttl_policy: item.policy,
          },
        })),
      });

      mockDatabase.delete.mockResolvedValue({
        deleted: 2,
      });

      // Run cleanup with real deletions
      const result = await ttlService.cleanupExpiredItems({
        dryRun: false,
        generateAudit: true,
      });

      expect(result.success).toBe(true);
      expect(result.updated).toBe(2);
      expect(result.details!.itemsProcessed).toHaveLength(2);

      // Verify delete was called
      expect(mockDatabase.delete).toHaveBeenCalledWith(['item1', 'item2']);
    });

    it('should preserve permanent items during cleanup', async () => {
      const itemsIncludingPermanent = [
        { id: 'item1', kind: 'observation', expiryTime: '2025-01-01T00:00:00Z', policy: 'short' },
        { id: 'item2', kind: 'entity', expiryTime: '9999-12-31T23:59:59.999Z', policy: 'permanent' },
        { id: 'item3', kind: 'decision', expiryTime: '2025-01-01T00:00:00Z', policy: 'default' },
      ];

      mockDatabase.search.mockResolvedValue({
        results: itemsIncludingPermanent.map(item => ({
          id: item.id,
          kind: item.kind,
          data: {
            expiry_at: item.expiryTime,
            ttl_policy: item.policy,
          },
        })),
      });

      mockDatabase.delete.mockResolvedValue({
        deleted: 2, // Only 2 items, permanent preserved
      });

      const result = await ttlService.cleanupExpiredItems({ dryRun: false });

      expect(result.updated).toBe(2); // Permanent item not deleted
      expect(mockDatabase.delete).toHaveBeenCalledWith(['item1', 'item3']); // Permanent item excluded
    });

    it('should identify items but not delete in dry-run mode', async () => {
      const expiredItems = [
        { id: 'item1', kind: 'observation', expiryTime: '2025-01-01T00:00:00Z', policy: 'short' },
        { id: 'item2', kind: 'entity', expiryTime: '2025-01-01T00:00:00Z', policy: 'default' },
      ];

      mockDatabase.search.mockResolvedValue({
        results: expiredItems.map(item => ({
          id: item.id,
          kind: item.kind,
          data: {
            expiry_at: item.expiryTime,
            ttl_policy: item.policy,
          },
        })),
      });

      const result = await ttlService.cleanupExpiredItems({ dryRun: true });

      expect(result.success).toBe(true);
      expect(result.updated).toBe(0); // No actual deletions in dry run
      expect(result.warnings).toContain('Dry run: Would delete 2 expired items (0 permanent items preserved)');

      // Verify delete was NOT called
      expect(mockDatabase.delete).not.toHaveBeenCalled();
    });
  });

  describe('Cleanup Worker Integration', () => {
    it('should integrate TTL cleanup with cleanup worker service', async () => {
      // Mock expiry worker result
      const mockExpiryResult = {
        deleted_counts: { observation: 1, entity: 1 },
        total_deleted: 2,
        total_processed: 2,
        total_skipped: 0,
        duration_ms: 100,
        metrics: {
          ttl_deletes_total: 2,
          ttl_skips_total: 0,
          ttl_errors_total: 0,
          processing_rate_per_second: 20,
          batch_count: 1,
          average_batch_size: 2,
        },
        dry_run: false,
        policy_enforcement: {
          policies_applied: { short: 1, default: 1 },
          permanent_items_preserved: 0,
          extensions_granted: 0,
        },
      };

      // Mock the expiry worker
      vi.mocked(runExpiryWorker).mockResolvedValue(mockExpiryResult);

      // Run cleanup
      const report = await cleanupService.runCleanup({
        dry_run: false,
        operations: ['expired'],
      });

      expect(report.success).toBe(true);
      expect(report.metrics.expired_items_deleted).toBe(2);

      // Verify system metrics were updated
      const metrics = systemMetricsService.getMetrics();
      expect(metrics.ttl.ttl_deletes_total).toBeGreaterThan(0);
    });

    it('should handle cleanup worker errors gracefully', async () => {
      // Mock expiry worker failure
      vi.mocked(runExpiryWorker).mockRejectedValue(new Error('Cleanup failed'));

      const report = await cleanupService.runCleanup({
        dry_run: false,
        operations: ['expired'],
      });

      // Should not throw, but report errors
      expect(report.errors.length).toBeGreaterThan(0);
    });

    it('should provide compatible cleanup metrics for tests', () => {
      const metrics = cleanupService.getMetrics();

      expect(metrics).toHaveProperty('itemsCleaned');
      expect(metrics).toHaveProperty('itemsIdentifiedForCleanup');
      expect(metrics).toHaveProperty('cleanupCount');
      expect(metrics).toHaveProperty('errorCount');
      expect(metrics).toHaveProperty('lastCleanupTime');
      expect(metrics).toHaveProperty('averageCleanupTime');
      expect(metrics).toHaveProperty('totalItemsProcessed');
    });
  });

  describe('TTL Policy Enforcement', () => {
    it('should enforce different TTL policies correctly', async () => {
      const now = new Date();
      const pastDate = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString(); // 24 hours ago

      const itemsWithDifferentPolicies = [
        {
          id: 'short-item',
          kind: 'observation',
          data: {
            expiry_at: pastDate,
            ttl_policy: 'short',
            auto_extend: false,
          }
        },
        {
          id: 'default-item',
          kind: 'entity',
          data: {
            expiry_at: pastDate,
            ttl_policy: 'default',
            auto_extend: false,
          }
        },
        {
          id: 'permanent-item',
          kind: 'decision',
          data: {
            expiry_at: '9999-12-31T23:59:59.999Z',
            ttl_policy: 'permanent',
            auto_extend: false,
          }
        },
      ];

      mockDatabase.search.mockResolvedValue({
        results: itemsWithDifferentPolicies,
      });

      mockDatabase.delete.mockResolvedValue({
        deleted: 2, // Only short and default items, permanent preserved
      });

      const result = await ttlService.cleanupExpiredItems({ dryRun: false });

      expect(result.updated).toBe(2);
      expect(result.details!.policiesApplied).toEqual({
        short: 1,
        default: 1,
        permanent: 1,
      });
    });

    it('should handle TTL policy extensions', async () => {
      const itemWithExtension = {
        id: 'extendable-item',
        kind: 'observation',
        data: {
          expiry_at: '2025-01-01T00:00:00Z',
          ttl_policy: 'short',
          auto_extend: true,
        },
      };

      mockDatabase.search.mockResolvedValue({
        results: [itemWithExtension],
      });

      mockDatabase.delete.mockResolvedValue({
        deleted: 1,
      });

      const result = await ttlService.cleanupExpiredItems({
        dryRun: false,
        generateAudit: true,
      });

      // In a real implementation, this would check for extension eligibility
      // For now, we verify the item is processed
      expect(result.processed).toBe(1);
      expect(result.details!.policiesApplied).toHaveProperty('short');
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle large numbers of expired items efficiently', async () => {
      const largeExpiredSet = Array.from({ length: 1000 }, (_, i) => ({
        id: `expired-item-${i}`,
        kind: 'observation',
        data: {
          expiry_at: '2025-01-01T00:00:00Z',
          ttl_policy: 'short',
        },
      }));

      mockDatabase.search.mockResolvedValue({
        results: largeExpiredSet,
      });

      mockDatabase.delete.mockResolvedValue({
        deleted: 1000,
      });

      const startTime = Date.now();
      const result = await ttlService.cleanupExpiredItems({
        dryRun: false,
        batchSize: 100,
      });
      const duration = Date.now() - startTime;

      expect(result.success).toBe(true);
      expect(result.updated).toBe(1000);
      expect(duration).toBeLessThan(1000); // Should complete in under 1 second

      // Check metrics
      const metrics = systemMetricsService.getMetrics();
      expect(metrics.ttl.ttl_deletes_total).toBe(1000);
      expect(metrics.ttl.ttl_processing_rate_per_second).toBeGreaterThan(0);
    });

    it('should maintain metrics accuracy during concurrent operations', async () => {
      const expiredItems = [
        { id: 'item1', kind: 'observation', data: { expiry_at: '2025-01-01T00:00:00Z', ttl_policy: 'short' } },
        { id: 'item2', kind: 'entity', data: { expiry_at: '2025-01-01T00:00:00Z', ttl_policy: 'default' } },
      ];

      mockDatabase.search.mockResolvedValue({
        results: expiredItems,
      });

      mockDatabase.delete.mockResolvedValue({
        deleted: 2,
      });

      // Run multiple concurrent cleanup operations
      const promises = Array.from({ length: 5 }, () =>
        ttlService.cleanupExpiredItems({ dryRun: false })
      );

      const results = await Promise.all(promises);

      // All operations should succeed
      results.forEach(result => {
        expect(result.success).toBe(true);
        expect(result.updated).toBe(2);
      });

      // Metrics should be consistent
      const metrics = systemMetricsService.getMetrics();
      expect(metrics.ttl.ttl_deletes_total).toBe(10); // 5 operations × 2 deletions each
    });
  });
});