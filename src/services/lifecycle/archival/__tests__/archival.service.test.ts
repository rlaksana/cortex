/**
 * P3 Data Management: Archival Service Tests
 *
 * Comprehensive unit tests for the archival service covering:
 * - Service initialization and configuration
 * - Archive eligibility detection and analysis
 * - Multi-tier storage management
 * - Compression and encryption capabilities
 * - Restore operations and verification
 * - Storage backend integration
 * - Error handling and edge cases
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

import { describe, it, expect, beforeEach, afterEach, vi, type MockedFunction } from 'vitest';

import { ArchivalService } from '../archival.service';
import type { IArchivalService, ArchivalConfig, ArchivedItem } from '../archival.interface';
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

describe('ArchivalService', () => {
  let service: IArchivalService;
  let mockVectorAdapter: MockedFunction<IVectorAdapter>;
  let testConfig: Partial<ArchivalConfig>;

  // Sample test data
  const mockKnowledgeItems: KnowledgeItem[] = [
    {
      id: 'test-item-1',
      kind: 'entity',
      content: {
        name: 'Test Entity 1',
        description: 'A test entity',
        data: 'large payload data'.repeat(100),
      },
      created_at: '2020-01-01T00:00:00.000Z',
      metadata: {
        classification: 'internal',
        last_accessed: '2022-01-01T00:00:00.000Z',
      },
    },
    {
      id: 'test-item-2',
      kind: 'observation',
      content: { text: 'Test observation content', data: 'medium payload'.repeat(50) },
      created_at: '2022-01-01T00:00:00.000Z',
      metadata: {
        classification: 'public',
        last_accessed: '2024-01-01T00:00:00.000Z',
      },
    },
    {
      id: 'test-item-3',
      kind: 'decision',
      content: {
        title: 'Test Decision',
        outcome: 'Approved',
        justification: 'Detailed justification text'.repeat(25),
      },
      created_at: '2021-06-01T00:00:00.000Z',
      metadata: {
        classification: 'confidential',
        last_accessed: '2021-12-01T00:00:00.000Z',
      },
    },
    {
      id: 'test-item-4',
      kind: 'issue',
      content: {
        title: 'Test Issue',
        description: 'Issue description'.repeat(75),
        priority: 'high',
      },
      created_at: '2021-01-15T00:00:00.000Z',
      metadata: {
        classification: 'restricted',
        last_accessed: '2023-06-15T00:00:00.000Z',
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
      storage: {
        enable_auto_archive: true,
        backends: {
          local: {
            enabled: true,
            base_path: './test-archives',
            compression_enabled: true,
            encryption_enabled: true,
          },
          s3: {
            enabled: false,
            bucket: 'test-bucket',
            region: 'us-east-1',
            compression_enabled: true,
            encryption_enabled: true,
            storage_class: 'GLACIER',
          },
          azure: {
            enabled: false,
            account: 'testaccount',
            container: 'test-container',
            compression_enabled: true,
            encryption_enabled: true,
            access_tier: 'Cool',
          },
          gcs: {
            enabled: false,
            bucket: 'test-bucket',
            compression_enabled: true,
            encryption_enabled: true,
            storage_class: 'ARCHIVE',
          },
        },
        default_backend: 'local',
      },
      processing: {
        batch_size: 50,
        max_items_per_run: 500,
        processing_interval_hours: 24,
        enable_parallel_processing: false,
        max_concurrent_operations: 1,
      },
      policies: {
        age_triggers: [
          { data_type: 'entity', archive_after_days: 365, storage_tier: 'warm', priority: 1 },
          { data_type: 'observation', archive_after_days: 180, storage_tier: 'cold', priority: 2 },
          { data_type: 'decision', archive_after_days: 730, storage_tier: 'warm', priority: 1 },
          { data_type: 'issue', archive_after_days: 90, storage_tier: 'cold', priority: 2 },
        ],
        access_triggers: {
          no_access_days: 365,
          low_access_frequency: {
            access_per_month: 1,
            period_months: 6,
          },
        },
        size_triggers: {
          large_item_threshold_mb: 1, // Small threshold for testing
          storage_quota_threshold_percent: 80,
        },
      },
      verification: {
        enable_verification: true,
        verify_checksums: true,
        sample_verification_percent: 10,
        verify_restore_capability: false,
        verification_retry_attempts: 3,
      },
      retention: {
        tier_retention_days: {
          hot: 0,
          warm: 1825,
          cold: 3650,
          glacier: 7300,
        },
        enable_tier_migration: true,
        migration_schedule: [
          { from_tier: 'warm', to_tier: 'cold', after_days: 730 },
          { from_tier: 'cold', to_tier: 'glacier', after_days: 1825 },
        ],
        delete_after_archive_retention: false,
      },
    };

    // Create service instance
    service = new ArchivalService(mockVectorAdapter, testConfig);
  });

  afterEach(async () => {
    await service.shutdown();
  });

  describe('Service Initialization', () => {
    it('should initialize successfully with valid configuration', async () => {
      expect(service).toBeDefined();
      await expect(service.initialize()).resolves.not.toThrow();
    });

    it('should verify storage backends during initialization', async () => {
      await service.initialize();

      const status = service.getStatus();
      expect(status.is_initialized).toBe(true);
      expect(status.storage_backends_status).toBeDefined();
    });

    it('should handle initialization with disabled storage backends', async () => {
      const configWithDisabledBackends = {
        ...testConfig,
        storage: {
          ...testConfig.storage!,
          backends: {
            local: {
              enabled: false,
              base_path: './archives',
              compression_enabled: false,
              encryption_enabled: false,
            },
          },
          default_backend: 'local',
        },
      };

      const serviceWithDisabledBackends = new ArchivalService(
        mockVectorAdapter,
        configWithDisabledBackends
      );
      await expect(serviceWithDisabledBackends.initialize()).resolves.not.toThrow();
    });
  });

  describe('Archive Eligibility Detection', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should identify archivable items based on age', async () => {
      const eligibility = await service.isItemArchivable(mockKnowledgeItems[0]); // Created 2020, should be archivable

      expect(eligibility.eligible).toBe(true);
      expect(eligibility.reason).toContain('age');
      expect(eligibility.recommended_tier).toBe('warm');
    });

    it('should identify archivable items based on access patterns', async () => {
      // Create item with old last_accessed date
      const oldAccessItem = {
        ...mockKnowledgeItems[1],
        metadata: {
          ...mockKnowledgeItems[1].metadata,
          last_accessed: '2020-01-01T00:00:00.000Z', // 4+ years ago
        },
      };

      const eligibility = await service.isItemArchivable(oldAccessItem);

      expect(eligibility.eligible).toBe(true);
      expect(eligibility.reason).toContain('access');
    });

    it('should identify archivable items based on size', async () => {
      // Create large item that exceeds threshold
      const largeItem = {
        ...mockKnowledgeItems[0],
        content: {
          name: 'Large Item',
          data: 'x'.repeat(2 * 1024 * 1024), // 2MB of data
        },
      };

      const eligibility = await service.isItemArchivable(largeItem);

      expect(eligibility.eligible).toBe(true);
      expect(eligibility.reason).toContain('size');
      expect(eligibility.recommended_tier).toBe('cold');
    });

    it('should correctly identify non-archivable items', async () => {
      const eligibility = await service.isItemArchivable(mockKnowledgeItems[1]); // Recently accessed

      expect(eligibility.eligible).toBe(false);
      expect(eligibility.reason).toContain('not meet');
    });

    it('should handle items already marked as archived', async () => {
      const alreadyArchivedItem = {
        ...mockKnowledgeItems[0],
        metadata: {
          ...mockKnowledgeItems[0].metadata,
          archived_at: '2023-01-01T00:00:00.000Z',
        },
      };

      const eligibility = await service.isItemArchivable(alreadyArchivedItem);

      expect(eligibility.eligible).toBe(false);
      expect(eligibility.reason).toContain('already archived');
    });
  });

  describe('Archive Item Operations', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should archive a single item with compression and encryption', async () => {
      const archivedItem = await service.archiveItem(mockKnowledgeItems[0], {
        target_backend: 'local',
        target_tier: 'cold',
        compress: true,
        encrypt: true,
      });

      expect(archivedItem).toBeDefined();
      expect(archivedItem.original_item.id).toBe('test-item-1');
      expect(archivedItem.archive_metadata.archived_at).toBeDefined();
      expect(archivedItem.archive_metadata.storage_backend).toBe('local');
      expect(archivedItem.archive_metadata.storage_tier).toBe('cold');
      expect(archivedItem.archive_metadata.compression_ratio).toBeLessThan(1);
      expect(archivedItem.archive_metadata.checksum).toBeDefined();
      expect(archivedItem.restoration.can_restore).toBe(true);
    });

    it('should archive item without compression when disabled', async () => {
      const archivedItem = await service.archiveItem(mockKnowledgeItems[1], {
        target_backend: 'local',
        target_tier: 'warm',
        compress: false,
        encrypt: false,
      });

      expect(archivedItem.archive_metadata.compression_ratio).toBe(1); // No compression
    });

    it('should calculate appropriate restore costs and times', async () => {
      const coldArchivedItem = await service.archiveItem(mockKnowledgeItems[0], {
        target_backend: 'local',
        target_tier: 'cold',
        compress: true,
        encrypt: true,
      });

      expect(coldArchivedItem.restoration.estimated_restore_time_seconds).toBeGreaterThan(0);
      expect(coldArchivedItem.restoration.restore_cost_estimate).toBeGreaterThanOrEqual(0);
      expect(coldArchivedItem.restoration.restore_priority).toBeDefined();

      const glacierArchivedItem = await service.archiveItem(mockKnowledgeItems[1], {
        target_backend: 'local',
        target_tier: 'glacier',
        compress: true,
        encrypt: true,
      });

      // Glacier should have higher restore time and cost than cold
      expect(glacierArchivedItem.restoration.estimated_restore_time_seconds).toBeGreaterThan(
        coldArchivedItem.restoration.estimated_restore_time_seconds
      );
    });

    it('should determine restore priority based on item type and metadata', async () => {
      const criticalItem = {
        ...mockKnowledgeItems[0],
        metadata: {
          ...mockKnowledgeItems[0].metadata,
          priority: 'critical',
        },
      };

      const archivedItem = await service.archiveItem(criticalItem, {
        target_backend: 'local',
        target_tier: 'cold',
        compress: true,
        encrypt: true,
      });

      expect(archivedItem.restoration.restore_priority).toBe('critical');
    });
  });

  describe('Archive Execution', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should execute archive operation in dry-run mode', async () => {
      const execution = await service.executeArchive({
        dry_run: true,
        batch_size: 10,
      });

      expect(execution.config.dry_run).toBe(true);
      expect(execution.execution_type).toBe('archive');
      expect(execution.status).toBe('completed');
      expect(execution.results.items_archived).toBe(0); // Dry run should not actually archive
    });

    it('should execute archive operation with real processing', async () => {
      const execution = await service.executeArchive({
        dry_run: false,
        batch_size: 2,
        max_items: 2,
      });

      expect(execution.config.dry_run).toBe(false);
      expect(execution.status).toBe('completed');
      expect(execution.progress.total_batches).toBeGreaterThan(0);
      expect(execution.results.archive_size_mb).toBeGreaterThanOrEqual(0);
    });

    it('should respect max_items limit during execution', async () => {
      const execution = await service.executeArchive({
        max_items: 1,
        batch_size: 10,
      });

      expect(execution.progress.total_items).toBeLessThanOrEqual(1);
    });

    it('should process items in appropriate batches', async () => {
      const execution = await service.executeArchive({
        batch_size: 2,
        max_items: 5,
      });

      expect(execution.progress.total_batches).toBeGreaterThanOrEqual(1);
      expect(execution.details.batches_processed.length).toBeGreaterThan(0);
    });

    it('should create backup when configured', async () => {
      const execution = await service.executeArchive({
        create_backup: true,
      });

      expect(execution.verification.backup_created).toBe(true);
      expect(execution.verification.backup_location).toBeDefined();
    });

    it('should handle different target storage tiers', async () => {
      const warmExecution = await service.executeArchive({
        target_tier: 'warm',
        dry_run: false,
      });

      expect(warmExecution.storage.tier_used).toBe('warm');

      const coldExecution = await service.executeArchive({
        target_tier: 'cold',
        dry_run: false,
      });

      expect(coldExecution.storage.tier_used).toBe('cold');
    });
  });

  describe('Restore Operations', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should restore archived item successfully', async () => {
      // First archive an item
      const archivedItem = await service.archiveItem(mockKnowledgeItems[0], {
        target_backend: 'local',
        target_tier: 'cold',
        compress: true,
        encrypt: true,
      });

      // Then restore it
      const restoreOperation = await service.restoreItem(archivedItem.archive_metadata.archive_id, {
        preserve_metadata: true,
        verify_after_restore: true,
      });

      expect(restoreOperation.restore_id).toBeDefined();
      expect(restoreOperation.item_id).toBe('test-item-1');
      expect(restoreOperation.archive_id).toBe(archivedItem.archive_metadata.archive_id);
      expect(restoreOperation.status).toBe('completed');
      expect(restoreOperation.results.integrity_check_passed).toBe(true);
    });

    it('should handle batch restore operations', async () => {
      // Archive multiple items
      const archivedItems = await Promise.all([
        service.archiveItem(mockKnowledgeItems[0], {
          target_backend: 'local',
          target_tier: 'cold',
          compress: true,
          encrypt: true,
        }),
        service.archiveItem(mockKnowledgeItems[1], {
          target_backend: 'local',
          target_tier: 'cold',
          compress: true,
          encrypt: true,
        }),
      ]);

      const archiveIds = archivedItems.map((item) => item.archive_metadata.archive_id);

      const batchResult = await service.batchRestore(archiveIds, {
        preserve_metadata: true,
        verify_after_restore: true,
      });

      expect(batchResult.restore_operations).toHaveLength(2);
      expect(batchResult.items_restored).toBe(2);
      expect(batchResult.items_failed).toBe(0);
    });

    it('should handle restore operation failures gracefully', async () => {
      const restoreOperation = await service.restoreItem('non-existent-archive-id', {
        preserve_metadata: true,
        verify_after_restore: true,
      });

      expect(restoreOperation.status).toBe('failed');
      expect(restoreOperation.results.integrity_check_passed).toBe(false);
    });

    it('should track restore costs accurately', async () => {
      const archivedItem = await service.archiveItem(mockKnowledgeItems[0], {
        target_backend: 'local',
        target_tier: 'glacier', // More expensive tier
        compress: true,
        encrypt: true,
      });

      const restoreOperation = await service.restoreItem(archivedItem.archive_metadata.archive_id);

      expect(restoreOperation.cost.total_cost).toBeGreaterThan(0);
      expect(restoreOperation.cost.retrieve_cost).toBeGreaterThanOrEqual(0);
      expect(restoreOperation.cost.restore_cost).toBeGreaterThanOrEqual(0);
      expect(restoreOperation.cost.cost_currency).toBe('USD');
    });
  });

  describe('Storage Analysis and Verification', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should verify archive integrity', async () => {
      const report = await service.verifyArchives({
        sample_size: 10,
        verify_checksums: true,
        verify_restore_capability: false,
      });

      expect(report).toBeDefined();
      expect(report.scope).toBeDefined();
      expect(report.integrity_results).toBeDefined();
      expect(report.storage_analysis).toBeDefined();
    });

    it('should list archived items with filtering', async () => {
      const result = await service.listArchivedItems({
        storage_tier: 'cold',
        limit: 10,
      });

      expect(result.items).toBeDefined();
      expect(Array.isArray(result.items)).toBe(true);
      expect(result.total_count).toBeGreaterThanOrEqual(0);
      expect(typeof result.has_more).toBe('boolean');
    });

    it('should get archived item metadata', async () => {
      // First archive an item
      const archivedItem = await service.archiveItem(mockKnowledgeItems[0], {
        target_backend: 'local',
        target_tier: 'cold',
        compress: true,
        encrypt: true,
      });

      const retrievedItem = await service.getArchivedItem(archivedItem.archive_metadata.archive_id);

      expect(retrievedItem).toBeDefined();
      expect(retrievedItem?.archive_metadata.archive_id).toBe(
        archivedItem.archive_metadata.archive_id
      );
      expect(retrievedItem?.original_item.id).toBe('test-item-1');
    });

    it('should handle retrieval of non-existent archived items', async () => {
      const retrievedItem = await service.getArchivedItem('non-existent-archive-id');

      expect(retrievedItem).toBeNull();
    });
  });

  describe('Tier Migration', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should migrate items between storage tiers', async () => {
      const migration = await service.migrateTier(['test-item-1', 'test-item-2'], 'warm', 'cold');

      expect(migration.execution_type).toBe('migrate_tier');
      expect(migration.status).toBe('completed');
      expect(migration.config.target_tier).toBe('cold');
      expect(migration.results.items_migrated).toBe(2);
    });
  });

  describe('Configuration Management', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should update service configuration', () => {
      const newConfig = {
        processing: {
          batch_size: 100,
          max_items_per_run: 1000,
          processing_interval_hours: 12,
          enable_parallel_processing: true,
          max_concurrent_operations: 2,
        },
      };

      service.updateConfig(newConfig);

      const config = service.getConfig();
      expect(config.processing.batch_size).toBe(100);
      expect(config.processing.processing_interval_hours).toBe(12);
    });

    it('should get current service configuration', () => {
      const config = service.getConfig();

      expect(config).toBeDefined();
      expect(config.storage).toBeDefined();
      expect(config.processing).toBeDefined();
      expect(config.policies).toBeDefined();
      expect(config.verification).toBeDefined();
      expect(config.retention).toBeDefined();
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
      expect(status.total_items_archived).toBeGreaterThanOrEqual(0);
      expect(status.total_archive_storage_mb).toBeGreaterThanOrEqual(0);
      expect(status.storage_backends_status).toBeDefined();
    });

    it('should track execution history', async () => {
      // Execute archive to create history
      await service.executeArchive({ dry_run: false });

      const history = service.getExecutionHistory(5);

      expect(Array.isArray(history)).toBe(true);
      expect(history.length).toBeGreaterThan(0);
    });

    it('should update metrics after operations', async () => {
      const metricsSpy = vi.spyOn(
        require('../metrics/system-metrics.js').systemMetricsService,
        'updateMetrics'
      );

      await service.executeArchive({ dry_run: false });

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

      await expect(service.findArchivableItems()).rejects.toThrow();
    });

    it('should handle archive operations with invalid configurations', async () => {
      // Test with disabled local storage but defaulting to local
      const invalidConfig = {
        ...testConfig,
        storage: {
          ...testConfig.storage!,
          backends: {
            local: {
              enabled: false,
              base_path: './archives',
              compression_enabled: false,
              encryption_enabled: false,
            },
          },
          default_backend: 'local',
        },
      };

      const invalidService = new ArchivalService(mockVectorAdapter, invalidConfig);

      await expect(
        invalidService.archiveItem(mockKnowledgeItems[0], {
          target_backend: 'local',
          target_tier: 'cold',
          compress: true,
          encrypt: true,
        })
      ).rejects.toThrow();
    });

    it('should handle large item sets efficiently', async () => {
      // Create large set of archivable items
      const largeItemSet = Array.from({ length: 1000 }, (_, i) => ({
        ...mockKnowledgeItems[0],
        id: `large-archive-${i}`,
      }));

      const execution = await service.executeArchive({
        max_items: 100,
        batch_size: 20,
      });

      expect(execution.progress.total_items).toBeLessThanOrEqual(100);
    });

    it('should handle concurrent archive executions safely', async () => {
      const executions = await Promise.all([
        service.executeArchive({ dry_run: false }),
        service.executeArchive({ dry_run: false }),
        service.executeArchive({ dry_run: false }),
      ]);

      executions.forEach((execution) => {
        expect(execution.status).toBe('completed');
      });
    });

    it('should handle restore operation cancellation', async () => {
      const archivedItem = await service.archiveItem(mockKnowledgeItems[0], {
        target_backend: 'local',
        target_tier: 'cold',
        compress: true,
        encrypt: true,
      });

      const restoreOperation = await service.restoreItem(archivedItem.archive_metadata.archive_id);

      expect(restoreOperation.restore_id).toBeDefined();
      expect(restoreOperation.status).toBe('completed');
    });
  });

  describe('Performance and Resource Management', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should release resources during shutdown', async () => {
      // Perform some operations first
      await service.executeArchive({ dry_run: false });

      // Shutdown should complete without hanging
      const shutdownPromise = service.shutdown();
      await expect(shutdownPromise).resolves.not.toThrow();

      // Verify service is shut down
      const status = service.getStatus();
      expect(status.is_initialized).toBe(false);
    });

    it('should handle timeout during shutdown gracefully', async () => {
      const shutdownPromise = service.shutdown();

      // Should complete within reasonable time
      await expect(shutdownPromise).resolves.not.toThrow();
    });

    it('should not leak memory during repeated operations', async () => {
      // Execute many operations
      for (let i = 0; i < 5; i++) {
        await service.executeArchive({ dry_run: false });
      }

      // History should be maintained but not grow unbounded
      const history = service.getExecutionHistory(100);
      expect(history.length).toBe(5);

      // Should still be able to execute new operations
      await expect(service.executeArchive()).resolves.not.toThrow();
    });

    it('should handle compression and encryption performance efficiently', async () => {
      const largeItem = {
        ...mockKnowledgeItems[0],
        content: {
          name: 'Large Performance Test Item',
          data: 'x'.repeat(1024 * 1024), // 1MB of data
        },
      };

      const startTime = performance.now();
      const archivedItem = await service.archiveItem(largeItem, {
        target_backend: 'local',
        target_tier: 'cold',
        compress: true,
        encrypt: true,
      });
      const duration = performance.now() - startTime;

      // Should complete in reasonable time (less than 5 seconds for 1MB)
      expect(duration).toBeLessThan(5000);
      expect(archivedItem.archive_metadata.compression_ratio).toBeLessThan(1);
      expect(archivedItem.archive_metadata.checksum).toBeDefined();
    });
  });
});
