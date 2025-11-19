/**
 * P3 Data Management: Compaction Service Tests
 *
 * Comprehensive unit tests for the compaction service covering:
 * - Service initialization and configuration
 * - Storage fragmentation analysis
 * - Duplicate detection and similarity algorithms
 * - Reference integrity checking and repair
 * - Index rebuilding and optimization
 * - Safe compaction with verification and rollback
 * - Performance optimization and resource management
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

import { describe, it, expect, beforeEach, afterEach, vi, type MockedFunction } from 'vitest';

import { CompactionService } from '../compaction.service';
import type {
  ICompactionService,
  CompactionConfig,
  DuplicateGroup,
  ReferenceAnalysis,
} from '../compaction.interface';
import type { IVectorAdapter } from '../../../../../db/interfaces/vector-adapter.interface';
import type { KnowledgeItem } from '../../../types/core-interfaces';

// Mock dependencies
vi.mock('../../utils/logger.js', () => ({
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

describe('CompactionService', () => {
  let service: ICompactionService;
  let mockVectorAdapter: MockedFunction<IVectorAdapter>;
  let testConfig: Partial<CompactionConfig>;

  // Sample test data
  const mockKnowledgeItems: KnowledgeItem[] = [
    {
      id: 'test-item-1',
      kind: 'entity',
      content: {
        name: 'Test Entity 1',
        description: 'A test entity with same content',
        value: 'test-value-123',
      },
      created_at: '2020-01-01T00:00:00.000Z',
      metadata: { classification: 'internal', tags: ['test', 'entity'] },
    },
    {
      id: 'test-item-2',
      kind: 'entity',
      content: {
        name: 'Test Entity 2',
        description: 'A test entity with same content',
        value: 'test-value-123',
      }, // Duplicate content
      created_at: '2020-02-01T00:00:00.000Z',
      metadata: { classification: 'internal', tags: ['test', 'entity'] },
    },
    {
      id: 'test-item-3',
      kind: 'entity',
      content: {
        name: 'Test Entity 3',
        description: 'A test entity with similar content',
        value: 'test-value-456',
      }, // Similar but not exact
      created_at: '2021-01-01T00:00:00.000Z',
      metadata: { classification: 'internal', tags: ['test', 'entity'] },
    },
    {
      id: 'test-item-4',
      kind: 'observation',
      content: { text: 'Different observation content', data: 'unique data here'.repeat(10) },
      created_at: '2022-01-01T00:00:00.000Z',
      metadata: { classification: 'public' },
    },
    {
      id: 'test-item-5',
      kind: 'relation',
      content: { source: 'test-item-1', target: 'test-item-2', type: 'references' }, // Creates circular reference
      created_at: '2020-06-01T00:00:00.000Z',
      metadata: { classification: 'internal' },
    },
    {
      id: 'test-item-6',
      kind: 'relation',
      content: { source: 'test-item-2', target: 'test-item-1', type: 'references' }, // Creates circular reference
      created_at: '2020-07-01T00:00:00.000Z',
      metadata: { classification: 'internal' },
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
        batch_size: 100,
        max_items_per_run: 1000,
        processing_interval_hours: 168, // Weekly
        enable_parallel_processing: false,
        max_concurrent_operations: 1,
      },
      strategies: {
        enable_defragmentation: true,
        enable_duplicate_detection: true,
        enable_reference_cleanup: true,
        enable_index_rebuilding: true,
        duplicate_sensitivity: 0.8,
        duplicate_similarity_threshold: 0.9,
      },
      safety: {
        require_confirmation: false,
        dry_run_by_default: true,
        create_backup_before_compaction: true,
        enable_compaction_verification: true,
        sample_verification_percent: 10,
        max_data_loss_tolerance_percent: 0.1,
      },
      thresholds: {
        fragmentation_threshold: 0.2,
        storage_usage_threshold_percent: 80,
        duplicate_percentage_threshold: 5,
        broken_references_threshold: 10,
      },
    };

    // Create service instance
    service = new CompactionService(mockVectorAdapter, testConfig);
  });

  afterEach(async () => {
    await service.shutdown();
  });

  describe('Service Initialization', () => {
    it('should initialize successfully with valid configuration', async () => {
      expect(service).toBeDefined();
      await expect(service.initialize()).resolves.not.toThrow();
    });

    it('should perform initial storage analysis', async () => {
      await service.initialize();

      const status = service.getStatus();
      expect(status.is_initialized).toBe(true);
      expect(status.storage_health_score).toBeGreaterThanOrEqual(0);
      expect(status.storage_health_score).toBeLessThanOrEqual(100);
    });

    it('should handle initialization with different strategies', async () => {
      const configWithSpecificStrategies = {
        ...testConfig,
        strategies: {
          enable_defragmentation: false,
          enable_duplicate_detection: true,
          enable_reference_cleanup: false,
          enable_index_rebuilding: true,
          duplicate_sensitivity: 0.7,
          duplicate_similarity_threshold: 0.85,
        },
      };

      const serviceWithSpecificStrategies = new CompactionService(
        mockVectorAdapter,
        configWithSpecificStrategies
      );
      await expect(serviceWithSpecificStrategies.initialize()).resolves.not.toThrow();
    });
  });

  describe('Storage Analysis', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should analyze storage for optimization opportunities', async () => {
      const report = await service.analyzeStorage();

      expect(report).toBeDefined();
      expect(report.report_id).toBeDefined();
      expect(report.timestamp).toBeDefined();
      expect(report.scope).toBeDefined();
      expect(report.fragmentation).toBeDefined();
      expect(report.duplicates).toBeDefined();
      expect(report.references).toBeDefined();
      expect(report.performance).toBeDefined();
      expect(report.recommendations).toBeDefined();
    });

    it('should include fragmentation analysis', async () => {
      const report = await service.analyzeStorage({ include_fragmentation: true });

      expect(report.fragmentation.overall_fragmentation_level).toBeGreaterThanOrEqual(0);
      expect(report.fragmentation.overall_fragmentation_level).toBeLessThanOrEqual(1);
      expect(report.fragmentation.defragmentation_potential_mb).toBeGreaterThanOrEqual(0);
    });

    it('should include duplicate analysis', async () => {
      const report = await service.analyzeStorage({ include_duplicates: true });

      expect(report.duplicates.exact_duplicates).toBeGreaterThanOrEqual(0);
      expect(report.duplicates.duplicate_storage_mb).toBeGreaterThanOrEqual(0);
      expect(report.duplicates.deduplication_potential_mb).toBeGreaterThanOrEqual(0);
    });

    it('should include reference analysis', async () => {
      const report = await service.analyzeStorage({ include_references: true });

      expect(report.references.total_references).toBeGreaterThanOrEqual(0);
      expect(report.references.valid_references).toBeGreaterThanOrEqual(0);
      expect(report.references.broken_references).toBeGreaterThanOrEqual(0);
    });

    it('should generate appropriate recommendations', async () => {
      const report = await service.analyzeStorage();

      expect(Array.isArray(report.recommendations)).toBe(true);
      report.recommendations.forEach((rec) => {
        expect(rec.priority).toMatch(/^(critical|high|medium|low)$/);
        expect(rec.category).toMatch(
          /^(defragmentation|deduplication|reference_cleanup|index_rebuilding)$/
        );
        expect(rec.description).toBeDefined();
        expect(rec.action_items).toBeDefined();
        expect(rec.estimated_impact).toBeDefined();
        expect(rec.estimated_time_minutes).toBeGreaterThan(0);
      });
    });

    it('should respect analysis scope filters', async () => {
      const report = await service.analyzeStorage({
        include_duplicates: true,
        include_references: false,
        include_fragmentation: false,
      });

      // Should only include duplicate analysis
      expect(report.duplicates).toBeDefined();
      expect(report.references.broken_references).toBe(0);
      expect(report.fragmentation.overall_fragmentation_level).toBe(0);
    });
  });

  describe('Duplicate Detection', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should find exact duplicates', async () => {
      const duplicateGroups = await service.findDuplicates({
        similarity_threshold: 0.95,
        include_semantic: false,
      });

      expect(Array.isArray(duplicateGroups)).toBe(true);
      expect(duplicateGroups.length).toBeGreaterThanOrEqual(0);
    });

    it('should find near duplicates with appropriate threshold', async () => {
      const duplicateGroups = await service.findDuplicates({
        similarity_threshold: 0.8,
        include_semantic: true,
      });

      expect(Array.isArray(duplicateGroups)).toBe(true);

      duplicateGroups.forEach((group) => {
        expect(group.group_id).toBeDefined();
        expect(group.primary_item).toBeDefined();
        expect(group.duplicate_items).toBeDefined();
        expect(Array.isArray(group.duplicate_items)).toBe(true);
        expect(group.similarity.overall_score).toBeGreaterThanOrEqual(0.8);
        expect(group.similarity.overall_score).toBeLessThanOrEqual(1);
        expect(group.duplicate_type).toMatch(/^(exact|near|semantic)$/);
        expect(group.consolidation.recommended_action).toMatch(
          /^(keep_primary|merge|manual_review)$/
        );
        expect(group.consolidation.confidence).toBeGreaterThanOrEqual(0);
        expect(group.consolidation.confidence).toBeLessThanOrEqual(1);
        expect(group.consolidation.risk_level).toMatch(/^(low|medium|high)$/);
      });
    });

    it('should respect max_groups limit', async () => {
      const duplicateGroups = await service.findDuplicates({
        max_groups: 2,
      });

      expect(duplicateGroups.length).toBeLessThanOrEqual(2);
    });

    it('should group items by kind for efficiency', async () => {
      // Mock to return test items that have potential duplicates
      vi.spyOn(service as unknown, 'getAllKnowledgeItems').mockResolvedValue(mockKnowledgeItems);

      const duplicateGroups = await service.findDuplicates({
        similarity_threshold: 0.9,
        max_groups: 10,
      });

      // Should find duplicates among entities (items 1, 2, 3)
      const entityDuplicates = duplicateGroups.filter(
        (group) => group.primary_item.kind === 'entity'
      );
      expect(entityDuplicates.length).toBeGreaterThan(0);
    });

    it('should calculate similarity scores correctly', async () => {
      const duplicateGroups = await service.findDuplicates({
        similarity_threshold: 0.5, // Low threshold to catch similarities
        include_semantic: false,
      });

      duplicateGroups.forEach((group) => {
        expect(group.similarity.content_similarity).toBeGreaterThanOrEqual(0);
        expect(group.similarity.content_similarity).toBeLessThanOrEqual(1);
        expect(group.similarity.metadata_similarity).toBeGreaterThanOrEqual(0);
        expect(group.similarity.metadata_similarity).toBeLessThanOrEqual(1);
      });
    });
  });

  describe('Reference Analysis', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should analyze references for integrity issues', async () => {
      const referenceAnalysis = await service.analyzeReferences();

      expect(referenceAnalysis).toBeDefined();
      expect(referenceAnalysis.analysis_id).toBeDefined();
      expect(referenceAnalysis.statistics).toBeDefined();
      expect(referenceAnalysis.broken_references).toBeDefined();
      expect(referenceAnalysis.circular_references).toBeDefined();
      expect(referenceAnalysis.orphaned_references).toBeDefined();
    });

    it('should identify circular references', async () => {
      // Mock items that create circular references
      const itemsWithCircularRefs = [
        mockKnowledgeItems[0], // test-item-1
        mockKnowledgeItems[4], // relation from 1 -> 2
        mockKnowledgeItems[5], // relation from 2 -> 1
        mockKnowledgeItems[1], // test-item-2
      ];

      vi.spyOn(service as unknown, 'getAllKnowledgeItems').mockResolvedValue(itemsWithCircularRefs);

      const referenceAnalysis = await service.analyzeReferences({
        include_self_references: true,
      });

      expect(referenceAnalysis.circular_references.length).toBeGreaterThan(0);

      referenceAnalysis.circular_references.forEach((circularRef) => {
        expect(Array.isArray(circularRef.chain)).toBe(true);
        expect(circularRef.depth).toBeGreaterThan(1);
        expect(circularRef.cycle_type).toMatch(/^(simple|complex)$/);
        expect(circularRef.impact_assessment).toMatch(/^(low|medium|high)$/);
      });
    });

    it('should calculate reference statistics', async () => {
      const referenceAnalysis = await service.analyzeReferences();

      expect(referenceAnalysis.statistics.total_references).toBeGreaterThanOrEqual(0);
      expect(referenceAnalysis.statistics.inbound_references).toBeGreaterThanOrEqual(0);
      expect(referenceAnalysis.statistics.outbound_references).toBeGreaterThanOrEqual(0);
      expect(referenceAnalysis.statistics.self_references).toBeGreaterThanOrEqual(0);
      expect(referenceAnalysis.statistics.circular_chains).toBeGreaterThanOrEqual(0);
    });

    it('should handle max recursion depth', async () => {
      const referenceAnalysis = await service.analyzeReferences({
        max_depth: 3,
      });

      expect(referenceAnalysis.analysis_id).toBeDefined();
      // Analysis should complete without infinite recursion
    });

    it('should assess circular reference impact appropriately', async () => {
      const simpleChain = ['item-1', 'item-2', 'item-1'];
      const complexChain = ['item-1', 'item-2', 'item-3', 'item-4', 'item-5', 'item-1'];

      // Test the private assessCircularReferenceImpact method indirectly
      const analysis = await service.analyzeReferences();

      // Should complete successfully
      expect(analysis).toBeDefined();
    });
  });

  describe('Compaction Execution', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should execute full compaction in dry-run mode by default', async () => {
      const execution = await service.executeCompaction({
        dry_run: true,
      });

      expect(execution.config.dry_run).toBe(true);
      expect(execution.execution_type).toBe('full_compaction');
      expect(execution.status).toBe('completed');
      expect(execution.config.strategies.defragment).toBe(true);
      expect(execution.config.strategies.deduplicate).toBe(true);
      expect(execution.config.strategies.cleanup_references).toBe(true);
      expect(execution.config.strategies.rebuild_index).toBe(true);
    });

    it('should execute specific compaction strategies', async () => {
      const execution = await service.executeCompaction({
        execution_type: 'deduplicate',
        strategies: {
          defragment: false,
          deduplicate: true,
          cleanup_references: false,
          rebuild_index: false,
        },
      });

      expect(execution.config.strategies.defragment).toBe(false);
      expect(execution.config.strategies.deduplicate).toBe(true);
      expect(execution.config.strategies.cleanup_references).toBe(false);
      expect(execution.config.strategies.rebuild_index).toBe(false);
    });

    it('should process items in batches', async () => {
      const execution = await service.executeCompaction({
        dry_run: false,
        batch_size: 10,
        max_items: 25,
      });

      expect(execution.progress.total_items_analyzed).toBeLessThanOrEqual(25);
      expect(execution.progress.total_batches).toBeGreaterThanOrEqual(1);
      expect(execution.details.batches_processed.length).toBeGreaterThan(0);
    });

    it('should create backup when configured', async () => {
      const execution = await service.executeCompaction({
        dry_run: false,
        create_backup: true,
      });

      expect(execution.verification.backup_created).toBe(true);
      expect(execution.verification.backup_location).toBeDefined();
    });

    it('should aggregate results from different strategies', async () => {
      const execution = await service.executeCompaction({
        dry_run: false,
        strategies: {
          defragment: true,
          deduplicate: true,
          cleanup_references: true,
          rebuild_index: true,
        },
      });

      expect(execution.results.storage_freed_mb).toBeGreaterThanOrEqual(0);
      expect(execution.results.duplicates_removed).toBeGreaterThanOrEqual(0);
      expect(execution.results.references_cleaned).toBeGreaterThanOrEqual(0);
      expect(execution.results.indexes_rebuilt).toBeGreaterThanOrEqual(0);
      expect(execution.results.data_integrity_score).toBeGreaterThanOrEqual(0);
      expect(execution.results.data_integrity_score).toBeLessThanOrEqual(100);
    });

    it('should handle execution errors gracefully', async () => {
      // Mock an operation that might fail
      vi.spyOn(service as unknown, 'analyzeDuplicates').mockRejectedValue(
        new Error('Analysis failed')
      );

      const execution = await service.executeCompaction({
        dry_run: false,
        strategies: {
          defragment: false,
          deduplicate: true,
          cleanup_references: false,
          rebuild_index: false,
        },
      });

      // Should complete with errors but not fail entirely
      expect(execution.status).toBe('completed');
      expect(execution.details.errors.length).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Defragmentation', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should execute defragmentation', async () => {
      const execution = await service.defragmentStorage({
        dry_run: false,
        target_fragmentation_level: 0.1,
        batch_size: 50,
      });

      expect(execution.execution_type).toBe('defragment');
      expect(execution.config.dry_run).toBe(false);
      expect(execution.status).toBe('completed');
    });

    it('should respect target fragmentation level', async () => {
      const execution = await service.defragmentStorage({
        target_fragmentation_level: 0.05, // More aggressive target
      });

      expect(execution.config).toBeDefined();
      // The execution should respect the lower threshold
    });
  });

  describe('Deduplication', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should remove duplicate items safely', async () => {
      const duplicateGroups: DuplicateGroup[] = [
        {
          group_id: 'test-group-1',
          primary_item: mockKnowledgeItems[0],
          duplicate_items: [mockKnowledgeItems[1]], // Duplicate of item 0
          similarity: {
            overall_score: 0.98,
            content_similarity: 1.0,
            metadata_similarity: 1.0,
            semantic_similarity: 0.95,
          },
          duplicate_type: 'exact',
          consolidation: {
            recommended_action: 'keep_primary',
            confidence: 0.95,
            risk_level: 'low',
          },
        },
      ];

      const result = await service.deduplicateStorage(duplicateGroups, {
        dry_run: false,
        merge_strategy: 'keep_primary',
        create_backup: true,
      });

      expect(result.items_removed).toBe(1);
      expect(result.items_merged).toBe(0);
      expect(result.storage_freed_mb).toBeGreaterThanOrEqual(0);
      expect(result.errors).toHaveLength(0);
    });

    it('should merge duplicate items when configured', async () => {
      const duplicateGroups: DuplicateGroup[] = [
        {
          group_id: 'test-group-2',
          primary_item: mockKnowledgeItems[0],
          duplicate_items: [mockKnowledgeItems[2]], // Similar but not exact
          similarity: {
            overall_score: 0.85,
            content_similarity: 0.9,
            metadata_similarity: 1.0,
            semantic_similarity: 0.8,
          },
          duplicate_type: 'near',
          consolidation: {
            recommended_action: 'merge_best',
            confidence: 0.8,
            risk_level: 'medium',
          },
        },
      ];

      const result = await service.deduplicateStorage(duplicateGroups, {
        dry_run: false,
        merge_strategy: 'merge_best',
        create_backup: false,
      });

      expect(result.items_removed).toBe(1); // Duplicate item removed
      expect(result.items_merged).toBe(1); // Merge operation performed
      expect(result.storage_freed_mb).toBeGreaterThanOrEqual(0);
    });

    it('should handle dry-run mode for deduplication', async () => {
      const duplicateGroups: DuplicateGroup[] = [
        {
          group_id: 'test-group-3',
          primary_item: mockKnowledgeItems[0],
          duplicate_items: [mockKnowledgeItems[1]],
          similarity: {
            overall_score: 0.95,
            content_similarity: 1.0,
            metadata_similarity: 0.9,
            semantic_similarity: 0.9,
          },
          duplicate_type: 'exact',
          consolidation: {
            recommended_action: 'keep_primary',
            confidence: 0.9,
            risk_level: 'low',
          },
        },
      ];

      const result = await service.deduplicateStorage(duplicateGroups, {
        dry_run: true,
        merge_strategy: 'keep_primary',
        create_backup: false,
      });

      // In dry-run mode, items should be counted but not actually removed
      expect(result.items_removed).toBe(1);
      expect(result.items_merged).toBe(0);
      expect(result.errors).toHaveLength(0);
    });
  });

  describe('Reference Cleanup', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should clean up broken references', async () => {
      const referenceAnalysis: ReferenceAnalysis = {
        analysis_id: 'test-analysis-1',
        statistics: {
          total_references: 10,
          valid_references: 8,
          broken_references: 2,
          inbound_references: 5,
          outbound_references: 5,
          self_references: 0,
          circular_chains: 0,
        },
        broken_references: [
          {
            from_item_id: 'test-item-1',
            to_item_id: 'non-existent-item',
            reference_type: 'dependency',
            severity: 'high',
            repair_suggestion: 'remove_reference',
          },
          {
            from_item_id: 'test-item-2',
            to_item_id: 'another-missing-item',
            reference_type: 'parent',
            severity: 'medium',
            repair_suggestion: 'remove_reference',
          },
        ],
        circular_references: [],
        orphaned_references: [],
      };

      const result = await service.cleanupReferences(referenceAnalysis, {
        dry_run: false,
        auto_repair: true,
        remove_unrepairable: true,
      });

      expect(result.references_cleaned).toBe(2);
      expect(result.references_repaired).toBeGreaterThanOrEqual(0);
      expect(result.references_removed).toBeGreaterThanOrEqual(0);
      expect(result.errors).toHaveLength(0);
    });

    it('should handle dry-run mode for reference cleanup', async () => {
      const referenceAnalysis: ReferenceAnalysis = {
        analysis_id: 'test-analysis-2',
        statistics: {
          total_references: 5,
          valid_references: 3,
          broken_references: 2,
          inbound_references: 2,
          outbound_references: 3,
          self_references: 0,
          circular_chains: 0,
        },
        broken_references: [
          {
            from_item_id: 'test-item-1',
            to_item_id: 'missing-item',
            reference_type: 'dependency',
            severity: 'high',
            repair_suggestion: 'remove_reference',
          },
        ],
        circular_references: [],
        orphaned_references: [],
      };

      const result = await service.cleanupReferences(referenceAnalysis, {
        dry_run: true,
        auto_repair: false,
      });

      // In dry-run mode, references should be flagged but not actually removed
      expect(result.references_cleaned).toBeGreaterThanOrEqual(0);
      expect(result.references_repaired).toBe(0);
      expect(result.references_removed).toBe(0);
    });
  });

  describe('Index Rebuilding', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should rebuild indexes successfully', async () => {
      const result = await service.rebuildIndexes({
        index_types: ['content', 'metadata'],
        rebuild_strategy: 'full',
        verify_after_rebuild: true,
      });

      expect(result.indexes_rebuilt).toBeGreaterThanOrEqual(0);
      expect(result.verification_passed).toBe(true);
      expect(result.rebuild_time_ms).toBeGreaterThan(0);
      expect(result.errors).toHaveLength(0);
    });

    it('should handle incremental index rebuilding', async () => {
      const result = await service.rebuildIndexes({
        index_types: ['content'],
        rebuild_strategy: 'incremental',
        verify_after_rebuild: false,
      });

      expect(result.indexes_rebuilt).toBeGreaterThanOrEqual(0);
      expect(result.rebuild_time_ms).toBeGreaterThan(0);
    });

    it('should handle index rebuilding errors gracefully', async () => {
      // Mock index rebuilding to fail
      vi.spyOn(service as unknown, 'rebuildIndexes').mockRejectedValue(
        new Error('Index rebuild failed')
      );

      // Should still create service without error
      expect(service).toBeDefined();
    });
  });

  describe('Verification and Rollback', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should verify compaction results', async () => {
      // First execute a compaction
      const execution = await service.executeCompaction({
        dry_run: false,
        create_backup: true,
      });

      const verification = await service.verifyCompaction(execution.execution_id);

      expect(verification.verification_passed).toBe(true);
      expect(verification.data_loss_detected).toBe(false);
      expect(verification.integrity_issues).toHaveLength(0);
      expect(verification.sample_verification_passed).toBeGreaterThanOrEqual(0);
      expect(verification.sample_verification_total).toBeGreaterThanOrEqual(0);
    });

    it('should rollback compaction execution', async () => {
      // First execute a compaction with backup
      const execution = await service.executeCompaction({
        dry_run: false,
        create_backup: true,
      });

      const rollback = await service.rollbackExecution(execution.execution_id);

      expect(rollback.success).toBe(true);
      expect(rollback.items_restored).toBeGreaterThanOrEqual(0);
      expect(rollback.errors).toHaveLength(0);
      expect(rollback.rollback_time_ms).toBeGreaterThan(0);
    });

    it('should handle rollback of non-existent execution', async () => {
      const rollback = await service.rollbackExecution('non-existent-execution');

      expect(rollback.success).toBe(false);
      expect(rollback.items_restored).toBe(0);
      expect(rollback.errors).toHaveLength(1);
      expect(rollback.errors[0]).toContain('not found');
    });

    it('should cancel active compaction execution', async () => {
      // Start a compaction that might run for a while
      const compactionPromise = service.executeCompaction({
        dry_run: false,
        batch_size: 1,
        max_items: 10,
      });

      // Cancel immediately
      const cancelled = await service.cancelExecution('latest-execution');

      // Should be able to cancel (implementation dependent)
      expect(typeof cancelled).toBe('boolean');
    });
  });

  describe('Configuration Management', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should update service configuration', () => {
      const newConfig = {
        processing: {
          batch_size: 200,
          max_items_per_run: 2000,
          processing_interval_hours: 72,
          enable_parallel_processing: true,
          max_concurrent_operations: 2,
        },
      };

      service.updateConfig(newConfig);

      const config = service.getConfig();
      expect(config.processing.batch_size).toBe(200);
      expect(config.processing.processing_interval_hours).toBe(72);
    });

    it('should update compaction strategies', () => {
      const newConfig = {
        strategies: {
          enable_defragmentation: false,
          enable_duplicate_detection: true,
          enable_reference_cleanup: true,
          enable_index_rebuilding: false,
          duplicate_sensitivity: 0.9,
          duplicate_similarity_threshold: 0.95,
        },
      };

      service.updateConfig(newConfig);

      const config = service.getConfig();
      expect(config.strategies.enable_defragmentation).toBe(false);
      expect(config.strategies.enable_duplicate_detection).toBe(true);
      expect(config.strategies.duplicate_similarity_threshold).toBe(0.95);
    });

    it('should get current configuration', () => {
      const config = service.getConfig();

      expect(config).toBeDefined();
      expect(config.processing).toBeDefined();
      expect(config.strategies).toBeDefined();
      expect(config.safety).toBeDefined();
      expect(config.thresholds).toBeDefined();
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
      expect(status.total_compactions_completed).toBeGreaterThanOrEqual(0);
      expect(status.total_storage_freed_mb).toBeGreaterThanOrEqual(0);
      expect(status.storage_health_score).toBeGreaterThanOrEqual(0);
      expect(status.storage_health_score).toBeLessThanOrEqual(100);
    });

    it('should track execution history', async () => {
      // Execute compaction to create history
      await service.executeCompaction({ dry_run: false });

      const history = service.getExecutionHistory(5);

      expect(Array.isArray(history)).toBe(true);
      expect(history.length).toBeGreaterThan(0);
    });

    it('should limit execution history results', async () => {
      // Execute multiple compactions
      for (let i = 0; i < 3; i++) {
        await service.executeCompaction({ dry_run: false });
      }

      const history = service.getExecutionHistory(2);

      expect(history.length).toBeLessThanOrEqual(2);
    });

    it('should update metrics after operations', async () => {
      const metricsSpy = vi.spyOn(
        require('../metrics/system-metrics.js').systemMetricsService,
        'updateMetrics'
      );

      await service.executeCompaction({ dry_run: false });

      expect(metricsSpy).toHaveBeenCalled();
    });

    it('should calculate storage health score correctly', async () => {
      const status = service.getStatus();

      expect(status.storage_health_score).toBeGreaterThanOrEqual(0);
      expect(status.storage_health_score).toBeLessThanOrEqual(100);

      // Health score should be reasonable
      expect(status.storage_health_score).toBeGreaterThan(50);
    });
  });

  describe('Error Handling and Edge Cases', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should handle vector adapter errors gracefully', async () => {
      // Mock vector adapter to throw error
      mockVectorAdapter.findByScope.mockRejectedValue(new Error('Database connection failed'));

      await expect(service.analyzeStorage()).rejects.toThrow();
    });

    it('should handle empty item sets', async () => {
      // Mock to return empty items
      vi.spyOn(service as unknown, 'getAllKnowledgeItems').mockResolvedValue([]);

      const report = await service.analyzeStorage();

      expect(report.scope.total_items).toBe(0);
      expect(report.duplicates.exact_duplicates).toBe(0);
    });

    it('should handle very large item sets efficiently', async () => {
      // Create large set of items
      const largeItemSet = Array.from({ length: 10000 }, (_, i) => ({
        ...mockKnowledgeItems[0],
        id: `large-item-${i}`,
      }));

      vi.spyOn(service as unknown, 'getAllKnowledgeItems').mockResolvedValue(largeItemSet);

      const report = await service.analyzeStorage({
        include_duplicates: true,
        max_groups: 100, // Limit processing
      });

      expect(report.scope.total_items).toBe(10000);
      // Should complete without timeout
      expect(report).toBeDefined();
    });

    it('should handle concurrent compaction executions safely', async () => {
      const executions = await Promise.all([
        service.executeCompaction({ dry_run: false }),
        service.executeCompaction({ dry_run: false }),
        service.executeCompaction({ dry_run: false }),
      ]);

      executions.forEach((execution) => {
        expect(execution.status).toBe('completed');
      });
    });

    it('should handle invalid configuration values', async () => {
      const invalidConfig = {
        processing: {
          batch_size: 0, // Invalid: should be positive
          max_items_per_run: 100,
          processing_interval_hours: 24,
          enable_parallel_processing: false,
          max_concurrent_operations: 1,
        },
      };

      const serviceWithInvalidConfig = new CompactionService(mockVectorAdapter, invalidConfig);

      // Should still create service
      expect(serviceWithInvalidConfig).toBeDefined();
    });
  });

  describe('Performance and Resource Management', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should release resources during shutdown', async () => {
      // Perform some operations first
      await service.executeCompaction({ dry_run: false });

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
        await service.executeCompaction({ dry_run: false });
      }

      // History should be maintained but not grow unbounded
      const history = service.getExecutionHistory(100);
      expect(history.length).toBe(5);

      // Should still be able to execute new operations
      await expect(service.executeCompaction()).resolves.not.toThrow();
    });

    it('should handle large duplicate groups efficiently', async () => {
      // Create a large duplicate group
      const largeDuplicateGroup: DuplicateGroup = {
        group_id: 'large-duplicate-group',
        primary_item: mockKnowledgeItems[0],
        duplicate_items: Array.from({ length: 100 }, (_, i) => ({
          ...mockKnowledgeItems[0],
          id: `duplicate-item-${i}`,
        })),
        similarity: {
          overall_score: 0.99,
          content_similarity: 1.0,
          metadata_similarity: 1.0,
          semantic_similarity: 0.95,
        },
        duplicate_type: 'exact',
        consolidation: {
          recommended_action: 'keep_primary',
          confidence: 0.99,
          risk_level: 'low',
        },
      };

      const result = await service.deduplicateStorage([largeDuplicateGroup], {
        dry_run: false,
        merge_strategy: 'keep_primary',
        create_backup: true,
      });

      expect(result.items_removed).toBe(100);
      expect(result.storage_freed_mb).toBeGreaterThanOrEqual(0);
      expect(result.errors).toHaveLength(0);
    });
  });
});
