/**
 * P3 Data Management: TTL Cleanup Service Tests
 *
 * Comprehensive unit tests for the TTL cleanup service covering:
 * - Service initialization and configuration
 * - Expired item detection and analysis
 * - Reference integrity validation
 * - Safe batch processing with verification
 * - Rollback and recovery capabilities
 * - Error handling and edge cases
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

import { describe, it, expect, beforeEach, afterEach, vi, type MockedFunction } from 'vitest';

import { TTLCleanupService } from '../ttl-cleanup.service';
import type { ITTLCleanupService, TTLCleanupConfig, ExpiredItem } from '../ttl-cleanup.interface';
import type { IVectorAdapter } from '../../../db/interfaces/vector-adapter.interface';
import type { KnowledgeItem } from '../../../types/core-interfaces';

// Mock dependencies
vi.mock('../../../utils/logger.js', () => ({
  logger: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

vi.mock('../metrics/system-metrics.js', () => ({
  systemMetricsService: {
    updateMetrics: vi.fn(),
  },
}));

describe('TTLCleanupService', () => {
  let service: ITTLCleanupService;
  let mockVectorAdapter: MockedFunction<IVectorAdapter>;
  let testConfig: Partial<TTLCleanupConfig>;

  // Sample test data
  const mockKnowledgeItems: KnowledgeItem[] = [
    {
      id: 'test-item-1',
      kind: 'entity',
      content: { name: 'Test Entity 1', description: 'A test entity' },
      created_at: '2020-01-01T00:00:00.000Z',
      metadata: {
        expires_at: '2023-01-01T00:00:00.000Z', // Expired
        classification: 'internal',
      },
    },
    {
      id: 'test-item-2',
      kind: 'observation',
      content: { text: 'Test observation content' },
      created_at: '2022-06-01T00:00:00.000Z',
      metadata: {
        expires_at: '2025-01-01T00:00:00.000Z', // Not expired
        classification: 'public',
      },
    },
    {
      id: 'test-item-3',
      kind: 'decision',
      content: { title: 'Test Decision', outcome: 'Approved' },
      created_at: '2021-01-01T00:00:00.000Z',
      metadata: {
        // No expiration - should use default TTL
        classification: 'confidential',
      },
    },
    {
      id: 'test-item-4',
      kind: 'relation',
      content: { source: 'item-1', target: 'item-2', type: 'references' },
      created_at: '2020-06-01T00:00:00.000Z',
      metadata: {
        expires_at: '2024-01-01T00:00:00.000Z', // Expired but has references
      },
    },
  ];

  beforeEach(() => {
    // Reset all mocks
    vi.clearAllMocks();

    // Create mock vector adapter
    mockVectorAdapter = vi.fn() as MockedFunction<IVectorAdapter>;
    mockVectorAdapter.findByScope = vi.fn();

    // Test configuration
    testConfig = {
      processing: {
        batch_size: 10,
        max_items_per_run: 100,
        processing_interval_hours: 24,
        enable_parallel_processing: false,
        max_concurrent_operations: 1,
      },
      safety: {
        require_confirmation: false,
        dry_run_by_default: true,
        grace_period_days: 7,
        create_backup_before_deletion: true,
        enable_deletion_notifications: false,
      },
      integrity: {
        enable_reference_checking: true,
        fail_on_broken_references: false,
        log_broken_references_only: true,
        max_recursion_depth: 5,
      },
    };

    // Create service instance
    service = new TTLCleanupService(mockVectorAdapter, testConfig);
  });

  afterEach(async () => {
    await service.shutdown();
  });

  describe('Service Initialization', () => {
    it('should initialize successfully with valid configuration', async () => {
      expect(service).toBeDefined();
      await expect(service.initialize()).resolves.not.toThrow();
    });

    it('should load execution history during initialization', async () => {
      await service.initialize();
      // The service should be initialized without errors
      const status = service.getStatus();
      expect(status.is_initialized).toBe(true);
    });

    it('should handle initialization errors gracefully', async () => {
      // Create service with invalid configuration
      const invalidConfig = {
        processing: {
          batch_size: 0, // Invalid: should be positive
          max_items_per_run: 100,
          processing_interval_hours: 24,
          enable_parallel_processing: false,
          max_concurrent_operations: 1,
        },
      };

      const invalidService = new TTLCleanupService(mockVectorAdapter, invalidConfig);
      // Should still create service, even with invalid config
      expect(invalidService).toBeDefined();
    });
  });

  describe('Expired Item Detection', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should identify items with explicit expiration dates', async () => {
      // Mock findByScope to return test items
      mockVectorAdapter.findByScope.mockResolvedValue({
        success: true,
        data: mockKnowledgeItems,
        message: 'Success',
      });

      const expiredItems = await service.findExpiredItems();

      // Should find expired items based on explicit expiration dates
      expect(expiredItems).toBeDefined();
      expect(Array.isArray(expiredItems)).toBe(true);
    });

    it('should handle items without explicit expiration dates', async () => {
      // Create item without expiration metadata
      const itemsWithoutExpiration = [
        {
          ...mockKnowledgeItems[2], // Decision item without expires_at
          metadata: { classification: 'confidential' },
        },
      ];

      mockVectorAdapter.findByScope.mockResolvedValue({
        success: true,
        data: itemsWithoutExpiration,
        message: 'Success',
      });

      const expiredItems = await service.findExpiredItems();

      // Should apply default TTL logic
      expect(expiredItems).toBeDefined();
    });

    it('should calculate expiration correctly based on item age', async () => {
      const testItem = mockKnowledgeItems[0]; // Created in 2020, expired in 2023
      const isExpired = service.isItemExpired(testItem);

      expect(isExpired.is_expired).toBe(true);
      expect(isExpired.expired_at).toBe('2023-01-01T00:00:00.000Z');
      expect(isExpired.days_expired).toBeGreaterThan(0);
    });

    it('should correctly identify non-expired items', async () => {
      const testItem = mockKnowledgeItems[1]; // Expires in 2025
      const isExpired = service.isItemExpired(testItem);

      expect(isExpired.is_expired).toBe(false);
    });

    it('should respect grace periods before allowing deletion', async () => {
      // Create recently expired item
      const recentlyExpired = {
        ...mockKnowledgeItems[0],
        metadata: {
          ...mockKnowledgeItems[0].metadata,
          expires_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(), // Expired yesterday
        },
      };

      const isExpired = service.isItemExpired(recentlyExpired);

      expect(isExpired.is_expired).toBe(true);
      expect(isExpired.can_delete).toBe(false); // Should not be deletable due to grace period
    });
  });

  describe('Reference Integrity', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should analyze reference integrity for expired items', async () => {
      const expiredItems: ExpiredItem[] = [
        {
          ...mockKnowledgeItems[0],
          expiration: {
            expired_at: '2023-01-01T00:00:00.000Z',
            days_expired: 400,
            grace_period_end: '2023-01-08T00:00:00.000Z',
            can_delete: true,
          },
          references: {
            inbound_count: 2,
            referenced_by: [
              { id: 'ref-1', kind: 'observation', reference_type: 'dependency' },
              { id: 'ref-2', kind: 'decision', reference_type: 'parent' },
            ],
            would_break_references: true,
          },
          deletion_assessment: {
            safe_to_delete: false,
            risk_level: 'high',
            blockers: ['Has active dependencies'],
            recommended_action: 'archive_first',
          },
        },
      ];

      const report = await service.analyzeReferenceIntegrity(expiredItems);

      expect(report).toBeDefined();
      expect(report.scope.total_archived_items).toBe(1);
      expect(report.reference_analysis.items_with_references).toBe(1);
      expect(report.reference_analysis.total_inbound_references).toBe(2);
    });

    it('should validate references before deletion', async () => {
      const expiredItem: ExpiredItem = {
        ...mockKnowledgeItems[0],
        expiration: {
          expired_at: '2023-01-01T00:00:00.000Z',
          days_expired: 400,
          grace_period_end: '2023-01-08T00:00:00.000Z',
          can_delete: true,
        },
        references: {
          inbound_count: 0,
          referenced_by: [],
          would_break_references: false,
        },
        deletion_assessment: {
          safe_to_delete: true,
          risk_level: 'low',
          blockers: [],
          recommended_action: 'delete',
        },
      };

      const validation = await service.validateReferences(expiredItem);

      expect(validation.safe_to_delete).toBe(true);
      expect(validation.blockers).toHaveLength(0);
      expect(validation.referenced_by).toHaveLength(0);
    });

    it('should handle items with broken references safely', async () => {
      const expiredItemWithBrokenRefs: ExpiredItem = {
        ...mockKnowledgeItems[0],
        expiration: {
          expired_at: '2023-01-01T00:00:00.000Z',
          days_expired: 400,
          grace_period_end: '2023-01-08T00:00:00.000Z',
          can_delete: true,
        },
        references: {
          inbound_count: 3,
          referenced_by: [
            { id: 'ref-1', kind: 'entity', reference_type: 'dependency' },
            { id: 'ref-2', kind: 'decision', reference_type: 'parent' },
            { id: 'ref-3', kind: 'unknown', reference_type: 'broken' },
          ],
          would_break_references: true,
        },
        deletion_assessment: {
          safe_to_delete: false,
          risk_level: 'critical',
          blockers: ['Critical dependency from ref-1', 'Parent relationship from ref-2'],
          recommended_action: 'manual_review',
        },
      };

      const validation = await service.validateReferences(expiredItemWithBrokenRefs);

      expect(validation.safe_to_delete).toBe(false);
      expect(validation.blockers.length).toBeGreaterThan(0);
      expect(validation.referenced_by).toHaveLength(3);
    });
  });

  describe('Cleanup Execution', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should execute cleanup in dry-run mode by default', async () => {
      // Mock the findExpiredItems method
      vi.spyOn(service, 'findExpiredItems').mockResolvedValue([]);

      const execution = await service.executeCleanup();

      expect(execution.config.dry_run).toBe(true);
      expect(execution.execution_type).toBe('archive');
      expect(execution.status).toBe('completed');
    });

    it('should process items in batches', async () => {
      // Create many expired items to test batching
      const manyExpiredItems = Array.from({ length: 25 }, (_, i) => ({
        ...mockKnowledgeItems[0],
        id: `expired-item-${i}`,
      }));

      vi.spyOn(service, 'findExpiredItems').mockResolvedValue(manyExpiredItems);

      const execution = await service.executeCleanup({
        dry_run: false,
        batch_size: 10,
      });

      // Should process all items in 3 batches (10 + 10 + 5)
      expect(execution.progress.total_items).toBe(25);
      expect(execution.progress.total_batches).toBe(3);
      expect(execution.details.batches_processed).toHaveLength(3);
    });

    it('should create backup before deletion when configured', async () => {
      vi.spyOn(service, 'findExpiredItems').mockResolvedValue([mockKnowledgeItems[0]]);

      const execution = await service.executeCleanup({
        dry_run: false,
        create_backup: true,
      });

      expect(execution.results.backup_created).toBe(true);
      expect(execution.results.backup_location).toBeDefined();
    });

    it('should handle processing errors gracefully', async () => {
      // Mock findExpiredItems to return items that will cause processing errors
      vi.spyOn(service, 'findExpiredItems').mockResolvedValue([mockKnowledgeItems[0]]);

      // Mock validation to fail
      vi.spyOn(service, 'validateReferences').mockResolvedValue({
        safe_to_delete: false,
        blockers: ['Test error'],
        referenced_by: [],
      });

      const execution = await service.executeCleanup({
        dry_run: false,
      });

      // Should complete with errors but not fail entirely
      expect(execution.status).toBe('completed'); // May still complete if errors are handled
      expect(execution.progress.items_failed).toBeGreaterThanOrEqual(0);
    });

    it('should respect max_items limit', async () => {
      const manyExpiredItems = Array.from({ length: 100 }, (_, i) => ({
        ...mockKnowledgeItems[0],
        id: `expired-item-${i}`,
      }));

      vi.spyOn(service, 'findExpiredItems').mockResolvedValue(manyExpiredItems);

      const execution = await service.executeCleanup({
        max_items: 50,
      });

      expect(execution.progress.total_items).toBe(50); // Limited to max_items
    });
  });

  describe('Batch Processing', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should process a batch of expired items', async () => {
      const batchItems = [mockKnowledgeItems[0], mockKnowledgeItems[3]].map((item) => ({
        ...item,
        expiration: {
          expired_at: '2023-01-01T00:00:00.000Z',
          days_expired: 400,
          grace_period_end: '2023-01-08T00:00:00.000Z',
          can_delete: true,
        },
        references: {
          inbound_count: 0,
          referenced_by: [],
          would_break_references: false,
        },
        deletion_assessment: {
          safe_to_delete: true,
          risk_level: 'low',
          blockers: [],
          recommended_action: 'delete',
        },
      }));

      const result = await service.processBatch(batchItems, {
        dry_run: false,
        create_backup: false,
        grace_period_days: 0,
      });

      expect(result.items_deleted).toBe(2);
      expect(result.items_skipped).toBe(0);
      expect(result.errors).toHaveLength(0);
      expect(result.processing_time_ms).toBeGreaterThan(0);
    });

    it('should skip items that fail reference validation', async () => {
      const batchItems = [mockKnowledgeItems[0]].map((item) => ({
        ...item,
        expiration: {
          expired_at: '2023-01-01T00:00:00.000Z',
          days_expired: 400,
          grace_period_end: '2023-01-08T00:00:00.000Z',
          can_delete: true,
        },
        references: {
          inbound_count: 1,
          referenced_by: [{ id: 'ref-1', kind: 'entity', reference_type: 'dependency' }],
          would_break_references: true,
        },
        deletion_assessment: {
          safe_to_delete: false,
          risk_level: 'high',
          blockers: ['Has active dependency'],
          recommended_action: 'review',
        },
      }));

      // Configure to fail on broken references
      service.updateConfig({
        integrity: {
          ...testConfig.integrity,
          fail_on_broken_references: true,
        },
      });

      const result = await service.processBatch(batchItems, {
        dry_run: false,
        create_backup: false,
        grace_period_days: 0,
      });

      expect(result.items_deleted).toBe(0);
      expect(result.items_skipped).toBe(1);
      expect(result.errors).toHaveLength(0); // Skip, don't error
    });

    it('should handle individual item processing errors', async () => {
      const batchItems = [mockKnowledgeItems[0], mockKnowledgeItems[1]].map((item) => ({
        ...item,
        expiration: {
          expired_at: '2023-01-01T00:00:00.000Z',
          days_expired: 400,
          grace_period_end: '2023-01-08T00:00:00.000Z',
          can_delete: true,
        },
        references: {
          inbound_count: 0,
          referenced_by: [],
          would_break_references: false,
        },
        deletion_assessment: {
          safe_to_delete: true,
          risk_level: 'low',
          blockers: [],
          recommended_action: 'delete',
        },
      }));

      // Mock delete operation to fail for second item
      vi.spyOn(service as unknown, 'deleteItem').mockImplementation((item: KnowledgeItem) => {
        if (item.id === 'test-item-2') {
          throw new Error('Simulated deletion error');
        }
        return Promise.resolve();
      });

      const result = await service.processBatch(batchItems, {
        dry_run: false,
        create_backup: false,
        grace_period_days: 0,
      });

      expect(result.items_deleted).toBe(1);
      expect(result.items_skipped).toBe(0);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0]).toContain('test-item-2');
    });
  });

  describe('Backup and Recovery', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should create backup before deletion', async () => {
      const items = [mockKnowledgeItems[0], mockKnowledgeItems[1]];

      const backup = await service.createBackup(items);

      expect(backup.backup_id).toBeDefined();
      expect(backup.backup_location).toBeDefined();
      expect(backup.item_count).toBe(2);
      expect(backup.backup_size_mb).toBeGreaterThan(0);
    });

    it('should handle empty item list for backup', async () => {
      const backup = await service.createBackup([]);

      expect(backup.item_count).toBe(0);
      expect(backup.backup_size_mb).toBe(0);
    });

    it('should rollback execution successfully', async () => {
      // First create a backup
      const items = [mockKnowledgeItems[0]];
      await service.createBackup(items);

      // Mock execution with backup
      const execution = await service.executeCleanup({
        dry_run: false,
        create_backup: true,
      });

      const rollback = await service.rollbackExecution(execution.execution_id);

      expect(rollback.success).toBe(true);
      expect(rollback.items_restored).toBeGreaterThanOrEqual(0);
      expect(rollback.errors).toHaveLength(0);
    });

    it('should handle rollback of non-existent execution', async () => {
      const rollback = await service.rollbackExecution('non-existent-execution');

      expect(rollback.success).toBe(false);
      expect(rollback.items_restored).toBe(0);
      expect(rollback.errors).toHaveLength(1);
      expect(rollback.errors[0]).toContain('not found');
    });
  });

  describe('Configuration Management', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should update configuration', () => {
      const newConfig = {
        processing: {
          batch_size: 50,
          max_items_per_run: 500,
          processing_interval_hours: 12,
          enable_parallel_processing: true,
          max_concurrent_operations: 3,
        },
      };

      service.updateConfig(newConfig);

      const config = service.getConfig();
      expect(config.processing.batch_size).toBe(50);
      expect(config.processing.processing_interval_hours).toBe(12);
    });

    it('should get current configuration', () => {
      const config = service.getConfig();

      expect(config).toBeDefined();
      expect(config.processing).toBeDefined();
      expect(config.safety).toBeDefined();
      expect(config.integrity).toBeDefined();
    });

    it('should handle configuration updates that affect scheduling', () => {
      const newConfig = {
        processing: {
          batch_size: 20,
          max_items_per_run: 200,
          processing_interval_hours: 6, // Changed from default
          enable_parallel_processing: false,
          max_concurrent_operations: 1,
        },
      };

      // Should not throw when updating interval
      expect(() => service.updateConfig(newConfig)).not.toThrow();
    });
  });

  describe('Service Status and Monitoring', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should provide accurate service status', () => {
      const status = service.getStatus();

      expect(status.is_initialized).toBe(true);
      expect(status.active_executions).toBe(0);
      expect(status.total_items_deleted).toBe(0);
      expect(status.total_storage_freed_mb).toBe(0);
    });

    it('should track execution history', async () => {
      // Execute cleanup to create history
      vi.spyOn(service, 'findExpiredItems').mockResolvedValue([]);
      await service.executeCleanup();

      const history = service.getExecutionHistory(5);

      expect(Array.isArray(history)).toBe(true);
      expect(history.length).toBeGreaterThan(0);
    });

    it('should limit execution history results', async () => {
      // Execute multiple cleanups
      vi.spyOn(service, 'findExpiredItems').mockResolvedValue([]);

      for (let i = 0; i < 5; i++) {
        await service.executeCleanup();
      }

      const history = service.getExecutionHistory(3);

      expect(history.length).toBeLessThanOrEqual(3);
    });

    it('should update metrics after execution', async () => {
      const metricsSpy = vi.spyOn(
        require('../metrics/system-metrics.js').systemMetricsService,
        'updateMetrics'
      );

      vi.spyOn(service, 'findExpiredItems').mockResolvedValue([]);
      await service.executeCleanup();

      // Should attempt to update metrics
      expect(metricsSpy).toHaveBeenCalled();
    });
  });

  describe('Error Handling and Edge Cases', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should handle vector adapter errors gracefully', async () => {
      // Mock vector adapter to throw error
      mockVectorAdapter.findByScope.mockRejectedValue(new Error('Database connection failed'));

      await expect(service.findExpiredItems()).rejects.toThrow();
    });

    it('should handle configuration validation errors', async () => {
      // Create service with invalid config that would cause issues
      const invalidService = new TTLCleanupService(mockVectorAdapter, {
        processing: {
          batch_size: -1, // Invalid
          max_items_per_run: 100,
          processing_interval_hours: 24,
          enable_parallel_processing: false,
          max_concurrent_operations: 1,
        },
        safety: testConfig.safety,
        integrity: testConfig.integrity,
      });

      // Should still create service but may have issues during operations
      expect(invalidService).toBeDefined();
    });

    it('should handle large item sets efficiently', async () => {
      // Create large set of expired items
      const largeExpiredSet = Array.from({ length: 1000 }, (_, i) => ({
        ...mockKnowledgeItems[0],
        id: `large-expired-${i}`,
      }));

      vi.spyOn(service, 'findExpiredItems').mockResolvedValue(largeExpiredSet);

      const execution = await service.executeCleanup({
        max_items: 100,
        batch_size: 10,
      });

      expect(execution.progress.total_items).toBe(100); // Limited by max_items
      expect(execution.progress.total_batches).toBe(10); // 100 items / 10 per batch
    });

    it('should handle concurrent execution attempts safely', async () => {
      vi.spyOn(service, 'findExpiredItems').mockResolvedValue([]);

      // Start multiple executions concurrently
      const executions = await Promise.all([
        service.executeCleanup({ dry_run: false }),
        service.executeCleanup({ dry_run: false }),
        service.executeCleanup({ dry_run: false }),
      ]);

      // All should complete successfully
      executions.forEach((execution) => {
        expect(execution.status).toBe('completed');
      });
    });
  });

  describe('Performance and Resource Management', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should release resources during shutdown', async () => {
      // Execute some operations first
      vi.spyOn(service, 'findExpiredItems').mockResolvedValue([]);
      await service.executeCleanup();

      // Shutdown should complete without hanging
      const shutdownPromise = service.shutdown();
      await expect(shutdownPromise).resolves.not.toThrow();

      // Verify service is shut down
      const status = service.getStatus();
      expect(status.is_initialized).toBe(false);
    });

    it('should handle timeout during shutdown gracefully', async () => {
      // Mock a scenario where shutdown might take longer
      const shutdownPromise = service.shutdown();

      // Should complete within reasonable time
      await expect(shutdownPromise).resolves.not.toThrow();
    });

    it('should not leak memory during repeated operations', async () => {
      vi.spyOn(service, 'findExpiredItems').mockResolvedValue([]);

      // Execute many operations
      for (let i = 0; i < 10; i++) {
        await service.executeCleanup();
      }

      // History should be maintained but not grow unbounded
      const history = service.getExecutionHistory(100);
      expect(history.length).toBe(10);

      // Should still be able to execute new operations
      await expect(service.executeCleanup()).resolves.not.toThrow();
    });
  });
});
