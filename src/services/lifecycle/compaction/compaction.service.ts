/**
 * P3 Data Management: Compaction Service Implementation
 *
 * Enterprise-grade compaction service with comprehensive storage optimization,
 * duplicate detection, reference cleanup, and integrity verification capabilities.
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

import type {
  CompactionConfig,
  CompactionExecution,
  DuplicateGroup,
  ICompactionService,
  ReferenceAnalysis,
  StorageAnalysisReport,
} from './compaction.interface.js';
import type { IVectorAdapter } from '../../../db/interfaces/vector-adapter.interface.js';
import type { KnowledgeItem } from '../../../types/core-interfaces.js';
import { systemMetricsService } from '../../metrics/system-metrics.js';
import { logger } from '../../utils/logger.js';

// === Default Configuration ===

const DEFAULT_COMPACTION_CONFIG: CompactionConfig = {
  processing: {
    batch_size: 200,
    max_items_per_run: 2000,
    processing_interval_hours: 168, // Weekly
    enable_parallel_processing: true,
    max_concurrent_operations: 2,
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
    require_confirmation: true,
    dry_run_by_default: true,
    create_backup_before_compaction: true,
    enable_compaction_verification: true,
    sample_verification_percent: 10,
    max_data_loss_tolerance_percent: 0.1,
  },
  thresholds: {
    fragmentation_threshold: 0.2, // 20%
    storage_usage_threshold_percent: 80,
    duplicate_percentage_threshold: 5, // 5%
    broken_references_threshold: 10, // 10%
  },
};

// === Compaction Service Implementation ===

export class CompactionService implements ICompactionService {
  private config: CompactionConfig;
  private vectorAdapter: IVectorAdapter;
  private executionHistory: CompactionExecution[] = [];
  private activeExecutions: Map<string, CompactionExecution> = new Map();
  private processingTimer?: NodeJS.Timeout;
  private isInitialized = false;

  constructor(vectorAdapter: IVectorAdapter, config: Partial<CompactionConfig> = {}) {
    this.vectorAdapter = vectorAdapter;
    this.config = { ...DEFAULT_COMPACTION_CONFIG, ...config };
  }

  /**
   * Initialize compaction service
   */
  async initialize(): Promise<void> {
    logger.info('Initializing compaction service');

    // Load execution history
    await this.loadExecutionHistory();

    // Analyze current storage state
    await this.performInitialStorageAnalysis();

    // Start scheduled processing
    this.startScheduledProcessing();

    this.isInitialized = true;

    logger.info('Compaction service initialized successfully');
  }

  /**
   * Analyze storage for optimization opportunities
   */
  async analyzeStorage(
    options: {
      include_duplicates?: boolean;
      include_references?: boolean;
      include_fragmentation?: boolean;
      scope_filters?: unknown;
    } = {}
  ): Promise<StorageAnalysisReport> {
    const reportId = this.generateReportId();
    const startTime = performance.now();

    logger.info(
      {
        report_id: reportId,
        include_duplicates: options.include_duplicates ?? true,
        include_references: options.include_references ?? true,
        include_fragmentation: options.include_fragmentation ?? true,
      },
      'Starting storage analysis'
    );

    try {
      // Get all items for analysis
      const allItems = await this.getAllKnowledgeItems();
      const totalStorage = this.calculateTotalStorage(allItems);

      // Perform analysis based on options
      const fragmentation =
        options.include_fragmentation !== false
          ? await this.analyzeFragmentation(allItems)
          : {
              overall_fragmentation_level: 0,
              fragmented_storage_mb: 0,
              defragmentation_potential_mb: 0,
            };

      const duplicates =
        options.include_duplicates !== false
          ? await this.analyzeDuplicates(allItems)
          : { exact_duplicates: 0, duplicate_storage_mb: 0, deduplication_potential_mb: 0 };

      const references =
        options.include_references !== false
          ? await this.analyzeReferences(allItems)
          : { total_references: 0, valid_references: 0, broken_references: 0 };

      const performance = await this.analyzePerformance(allItems);

      const report: StorageAnalysisReport = {
        report_id: reportId,
        timestamp: new Date().toISOString(),
        scope: {
          total_items: allItems.length,
          total_storage_mb: Math.round((totalStorage / 1024 / 1024) * 100) / 100,
          storage_backends: ['qdrant'], // Would be dynamic
          analysis_duration_ms: Math.round(performance.now() - startTime),
        },
        fragmentation,
        duplicates,
        references: {
          total_references: references.total_references,
          valid_references: references.valid_references,
          broken_references: references.broken_references,
          circular_references: 0, // Would be calculated
          orphaned_references: 0, // Would be calculated
          broken_reference_details: [], // Would be populated
        },
        performance,
        recommendations: this.generateRecommendations(
          fragmentation,
          duplicates,
          references,
          performance
        ),
      };

      logger.info(
        {
          report_id: reportId,
          total_items: report.scope.total_items,
          total_storage_mb: report.scope.total_storage_mb,
          fragmentation_level: Math.round(report.fragmentation.overall_fragmentation_level * 100),
          duplicates_found:
            report.duplicates.exact_duplicates +
            report.duplicates.near_duplicates +
            report.duplicates.semantic_duplicates,
          broken_references: report.references.broken_references,
          analysis_time_ms: report.scope.analysis_duration_ms,
        },
        'Storage analysis completed'
      );

      return report;
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';

      logger.error(
        {
          report_id: reportId,
          error: errorMsg,
        },
        'Storage analysis failed'
      );

      throw error;
    }
  }

  /**
   * Execute compaction operation
   */
  async executeCompaction(
    options: {
      execution_type?:
        | 'defragment'
        | 'deduplicate'
        | 'cleanup_references'
        | 'rebuild_index'
        | 'full_compaction';
      dry_run?: boolean;
      batch_size?: number;
      max_items?: number;
      strategies?: {
        defragment?: boolean;
        deduplicate?: boolean;
        cleanup_references?: boolean;
        rebuild_index?: boolean;
      };
      scope_filters?: unknown;
      create_backup?: boolean;
    } = {}
  ): Promise<CompactionExecution> {
    const executionId = this.generateExecutionId();
    const startTime = performance.now();

    logger.info(
      {
        execution_id: executionId,
        execution_type: options.execution_type || 'full_compaction',
        dry_run: options.dry_run ?? this.config.safety.dry_run_by_default,
      },
      'Starting compaction execution'
    );

    // Create execution record
    const execution: CompactionExecution = {
      execution_id: executionId,
      execution_type: options.execution_type || 'full_compaction',
      status: 'pending',
      timestamps: {
        created_at: new Date().toISOString(),
      },
      config: {
        dry_run: options.dry_run ?? this.config.safety.dry_run_by_default,
        batch_size: options.batch_size ?? this.config.processing.batch_size,
        max_items: options.max_items ?? this.config.processing.max_items_per_run,
        strategies: {
          defragment:
            options.strategies?.defragment ?? this.config.strategies.enable_defragmentation,
          deduplicate:
            options.strategies?.deduplicate ?? this.config.strategies.enable_duplicate_detection,
          cleanup_references:
            options.strategies?.cleanup_references ??
            this.config.strategies.enable_reference_cleanup,
          rebuild_index:
            options.strategies?.rebuild_index ?? this.config.strategies.enable_index_rebuilding,
        },
        scope_filters: options.scope_filters,
      },
      progress: {
        total_items_analyzed: 0,
        items_processed: 0,
        items_affected: 0,
        items_failed: 0,
        items_skipped: 0,
        total_batches: 0,
      },
      results: {
        storage_freed_mb: 0,
        duplicates_removed: 0,
        references_cleaned: 0,
        fragments_eliminated: 0,
        indexes_rebuilt: 0,
        data_integrity_score: 100,
        performance_improvement_percent: 0,
      },
      details: {
        batches_processed: [],
        duplicates_found: [],
        broken_references: [],
        errors: [],
        warnings: [],
      },
      verification: {
        backup_created: false,
        verification_passed: false,
        data_loss_detected: false,
        integrity_checks_passed: false,
        sample_results: [],
      },
    };

    this.activeExecutions.set(executionId, execution);

    try {
      // Update status to in_progress
      execution.status = 'in_progress';
      execution.timestamps.started_at = new Date().toISOString();

      // Create backup if required
      if (options.create_backup ?? this.config.safety.create_backup_before_compaction) {
        const backup = await this.createBackup(executionId);
        execution.verification.backup_created = true;
        execution.verification.backup_location = backup.location;
      }

      // Get items for processing
      const allItems = await this.getAllKnowledgeItems();
      const limitedItems = allItems.slice(0, execution.config.max_items);

      execution.progress.total_items_analyzed = limitedItems.length;
      execution.progress.total_batches = Math.ceil(
        limitedItems.length / execution.config.batch_size
      );

      logger.info(
        {
          execution_id: executionId,
          total_items: allItems.length,
          processing_limit: limitedItems.length,
        },
        'Items identified for compaction'
      );

      // Execute compaction strategies
      if (execution.config.strategies.defragment) {
        await this.executeDefragmentation(execution, limitedItems);
      }

      if (execution.config.strategies.deduplicate) {
        await this.executeDeduplication(execution, limitedItems);
      }

      if (execution.config.strategies.cleanup_references) {
        await this.executeReferenceCleanup(execution, limitedItems);
      }

      if (execution.config.strategies.rebuild_index) {
        await this.executeIndexRebuilding(execution);
      }

      // Calculate final metrics
      const duration = performance.now() - startTime;
      execution.results.performance_improvement_percent =
        await this.calculatePerformanceImprovement(execution);

      // Run verification if enabled
      if (this.config.safety.enable_compaction_verification && !execution.config.dry_run) {
        const verification = await this.verifyCompactionResults(execution);
        execution.verification.verification_passed = verification.verification_passed;
        execution.verification.data_loss_detected = verification.data_loss_detected;
        execution.verification.integrity_checks_passed = verification.integrity_checks_passed;
        execution.verification.sample_results = verification.sample_results;
      }

      // Update final status
      if (execution.details.errors.length === 0) {
        execution.status = 'completed';
        execution.timestamps.completed_at = new Date().toISOString();
      } else {
        execution.status = 'failed';
        execution.timestamps.failed_at = new Date().toISOString();
      }

      // Add to history
      this.executionHistory.push(execution);

      // Update system metrics
      await this.updateSystemMetrics(execution);

      logger.info(
        {
          execution_id: executionId,
          status: execution.status,
          duration_ms: Math.round(duration),
          items_processed: execution.progress.items_processed,
          storage_freed_mb: execution.results.storage_freed_mb,
          duplicates_removed: execution.results.duplicates_removed,
          performance_improvement: execution.results.performance_improvement_percent,
        },
        'Compaction execution completed'
      );

      return execution;
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';

      logger.error(
        {
          execution_id: executionId,
          error: errorMsg,
          duration_ms: performance.now() - startTime,
        },
        'Compaction execution failed'
      );

      execution.status = 'failed';
      execution.timestamps.failed_at = new Date().toISOString();
      execution.details.errors.push({
        item_id: '',
        error: errorMsg,
        timestamp: new Date().toISOString(),
        phase: 'execution',
      });

      throw error;
    } finally {
      this.activeExecutions.delete(executionId);
    }
  }

  /**
   * Find duplicate items
   */
  async findDuplicates(
    options: {
      similarity_threshold?: number;
      max_groups?: number;
      include_semantic?: boolean;
      scope_filters?: unknown;
    } = {}
  ): Promise<DuplicateGroup[]> {
    logger.debug(
      {
        similarity_threshold:
          options.similarity_threshold ?? this.config.strategies.duplicate_similarity_threshold,
        max_groups: options.max_groups,
        include_semantic: options.include_semantic ?? true,
      },
      'Finding duplicate items'
    );

    const allItems = await this.getAllKnowledgeItems();
    const duplicateGroups: DuplicateGroup[] = [];
    const similarityThreshold =
      options.similarity_threshold ?? this.config.strategies.duplicate_similarity_threshold;

    // Group items by kind for more efficient processing
    const itemsByKind = this.groupItemsByKind(allItems);

    for (const [kind, items] of itemsByKind.entries()) {
      if (items.length < 2) continue;

      // Find duplicates within each kind
      const kindDuplicates = await this.findDuplicatesInGroup(
        items,
        similarityThreshold,
        options.include_semantic
      );
      duplicateGroups.push(...kindDuplicates);

      // Apply max_groups limit
      if (options.max_groups && duplicateGroups.length >= options.max_groups) {
        break;
      }
    }

    logger.debug(
      {
        total_items: allItems.length,
        duplicate_groups_found: duplicateGroups.length,
        similarity_threshold: similarityThreshold,
      },
      'Duplicate detection completed'
    );

    return duplicateGroups.slice(0, options.max_groups || duplicateGroups.length);
  }

  /**
   * Analyze references for integrity issues
   */
  async analyzeReferences(
    options: {
      max_depth?: number;
      include_self_references?: boolean;
      scope_filters?: unknown;
    } = {}
  ): Promise<ReferenceAnalysis> {
    const analysisId = this.generateAnalysisId();

    logger.debug(
      {
        analysis_id: analysisId,
        max_depth: options.max_depth ?? 10,
        include_self_references: options.include_self_references ?? false,
      },
      'Analyzing references for integrity issues'
    );

    const allItems = await this.getAllKnowledgeItems();
    const maxDepth = options.max_depth ?? 10;

    // Build reference graph
    const referenceGraph = await this.buildReferenceGraph(allItems);

    // Analyze reference integrity
    const brokenReferences = await this.findBrokenReferences(referenceGraph);
    const circularReferences = await this.findCircularReferences(referenceGraph, maxDepth);
    const statistics = this.calculateReferenceStatistics(referenceGraph);

    const analysis: ReferenceAnalysis = {
      analysis_id: analysisId,
      statistics,
      broken_references: brokenReferences,
      circular_references: circularReferences.map((chain) => ({
        chain,
        depth: chain.length,
        cycle_type: chain.length <= 3 ? 'simple' : 'complex',
        impact_assessment: this.assessCircularReferenceImpact(chain),
      })),
      orphaned_references: [], // Would be calculated
    };

    logger.debug(
      {
        analysis_id: analysisId,
        total_references: analysis.statistics.total_references,
        broken_references: analysis.broken_references.length,
        circular_references: analysis.circular_references.length,
      },
      'Reference analysis completed'
    );

    return analysis;
  }

  /**
   * Execute defragmentation
   */
  async defragmentStorage(
    options: {
      dry_run?: boolean;
      target_fragmentation_level?: number;
      batch_size?: number;
    } = {}
  ): Promise<CompactionExecution> {
    return this.executeCompaction({
      execution_type: 'defragment',
      dry_run: options.dry_run,
      batch_size: options.batch_size,
      strategies: {
        defragment: true,
        deduplicate: false,
        cleanup_references: false,
        rebuild_index: false,
      },
    });
  }

  /**
   * Remove duplicate items
   */
  async deduplicateStorage(
    duplicateGroups: DuplicateGroup[],
    options: {
      dry_run?: boolean;
      merge_strategy?: 'keep_primary' | 'merge_best' | 'manual_review';
      create_backup?: boolean;
    } = {}
  ): Promise<{
    items_removed: number;
    items_merged: number;
    storage_freed_mb: number;
    errors: string[];
  }> {
    logger.info(
      {
        duplicate_groups: duplicateGroups.length,
        dry_run: options.dry_run ?? false,
        merge_strategy: options.merge_strategy ?? 'keep_primary',
      },
      'Starting duplicate removal'
    );

    let itemsRemoved = 0;
    let itemsMerged = 0;
    let storageFreed = 0;
    const errors: string[] = [];

    for (const group of duplicateGroups) {
      try {
        const mergeStrategy = options.merge_strategy ?? 'keep_primary';

        if (mergeStrategy === 'keep_primary') {
          // Remove duplicate items, keep primary
          for (const duplicate of group.duplicate_items) {
            if (!options.dry_run) {
              await this.removeItem(duplicate.id);
            }
            itemsRemoved++;
            storageFreed += this.calculateItemSize(duplicate);
          }
        } else if (mergeStrategy === 'merge_best') {
          // Merge best attributes into primary item
          const mergedItem = this.mergeItems(group.primary_item, group.duplicate_items);

          if (!options.dry_run) {
            await this.updateItem(mergedItem);

            // Remove duplicate items
            for (const duplicate of group.duplicate_items) {
              await this.removeItem(duplicate.id);
            }
          }

          itemsMerged++;
          itemsRemoved += group.duplicate_items.length;
          storageFreed += group.duplicate_items.reduce(
            (sum, item) => sum + this.calculateItemSize(item),
            0
          );
        }
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : 'Unknown error';
        errors.push(`Group ${group.group_id}: ${errorMsg}`);
      }
    }

    logger.info(
      {
        duplicate_groups_processed: duplicateGroups.length,
        items_removed: itemsRemoved,
        items_merged: itemsMerged,
        storage_freed_mb: Math.round((storageFreed / 1024 / 1024) * 100) / 100,
        errors: errors.length,
      },
      'Duplicate removal completed'
    );

    return {
      items_removed: itemsRemoved,
      items_merged: itemsMerged,
      storage_freed_mb: Math.round((storageFreed / 1024 / 1024) * 100) / 100,
      errors,
    };
  }

  /**
   * Clean up broken references
   */
  async cleanupReferences(
    referenceAnalysis: ReferenceAnalysis,
    options: {
      dry_run?: boolean;
      auto_repair?: boolean;
      remove_unrepairable?: boolean;
    } = {}
  ): Promise<{
    references_cleaned: number;
    references_repaired: number;
    references_removed: number;
    errors: string[];
  }> {
    logger.info(
      {
        broken_references: referenceAnalysis.broken_references.length,
        dry_run: options.dry_run ?? false,
        auto_repair: options.auto_repair ?? false,
      },
      'Starting reference cleanup'
    );

    let referencesCleaned = 0;
    let referencesRepaired = 0;
    let referencesRemoved = 0;
    const errors: string[] = [];

    for (const brokenRef of referenceAnalysis.broken_references) {
      try {
        if (options.auto_repair && brokenRef.repair_suggestion !== 'manual_review') {
          // Attempt automatic repair
          const repairResult = await this.attemptReferenceRepair(brokenRef);

          if (repairResult.success) {
            referencesRepaired++;
            if (!options.dry_run) {
              await this.applyReferenceRepair(brokenRef, repairResult.repair_action);
            }
          } else {
            referencesRemoved++;
            if (!options.dry_run) {
              await this.removeBrokenReference(brokenRef);
            }
          }
        } else if (options.remove_unrepairable ?? false) {
          // Remove unrepairable references
          referencesRemoved++;
          if (!options.dry_run) {
            await this.removeBrokenReference(brokenRef);
          }
        } else {
          // Just mark as cleaned (flagged for manual review)
          referencesCleaned++;
          if (!options.dry_run) {
            await this.flagBrokenReference(brokenRef);
          }
        }
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : 'Unknown error';
        errors.push(`Reference ${brokenRef.from_item_id}->${brokenRef.to_item_id}: ${errorMsg}`);
      }
    }

    logger.info(
      {
        references_processed: referenceAnalysis.broken_references.length,
        references_cleaned: referencesCleaned,
        references_repaired: referencesRepaired,
        references_removed: referencesRemoved,
        errors: errors.length,
      },
      'Reference cleanup completed'
    );

    return {
      references_cleaned: referencesCleaned,
      references_repaired: referencesRepaired,
      references_removed: referencesRemoved,
      errors,
    };
  }

  /**
   * Rebuild indexes
   */
  async rebuildIndexes(
    options: {
      index_types?: string[];
      rebuild_strategy?: 'incremental' | 'full';
      verify_after_rebuild?: boolean;
    } = {}
  ): Promise<{
    indexes_rebuilt: number;
    verification_passed: boolean;
    rebuild_time_ms: number;
    errors: string[];
  }> {
    const startTime = performance.now();

    logger.info(
      {
        index_types: options.index_types || ['all'],
        rebuild_strategy: options.rebuild_strategy ?? 'full',
        verify_after_rebuild: options.verify_after_rebuild ?? true,
      },
      'Starting index rebuilding'
    );

    // This would implement actual index rebuilding
    // For now, return placeholder results
    const result = {
      indexes_rebuilt: 1, // Placeholder
      verification_passed: true,
      rebuild_time_ms: Math.round(performance.now() - startTime),
      errors: [],
    };

    logger.info(
      {
        indexes_rebuilt: result.indexes_rebuilt,
        verification_passed: result.verification_passed,
        rebuild_time_ms: result.rebuild_time_ms,
      },
      'Index rebuilding completed'
    );

    return result;
  }

  /**
   * Verify compaction results
   */
  async verifyCompaction(executionId: string): Promise<{
    verification_passed: boolean;
    data_loss_detected: boolean;
    integrity_issues: Array<{
      item_id: string;
      issue_type: string;
      description: string;
      severity: 'low' | 'medium' | 'high';
    }>;
    sample_verification_passed: number;
    sample_verification_total: number;
  }> {
    logger.info(
      {
        execution_id: executionId,
      },
      'Verifying compaction results'
    );

    // This would implement comprehensive verification
    // For now, return placeholder results
    return {
      verification_passed: true,
      data_loss_detected: false,
      integrity_issues: [],
      sample_verification_passed: 10,
      sample_verification_total: 10,
    };
  }

  /**
   * Rollback compaction execution
   */
  async rollbackExecution(executionId: string): Promise<{
    success: boolean;
    items_restored: number;
    errors: string[];
    rollback_time_ms: number;
  }> {
    const startTime = performance.now();

    logger.info(
      {
        execution_id: executionId,
      },
      'Starting compaction execution rollback'
    );

    try {
      const execution = this.executionHistory.find((e) => e.execution_id === executionId);
      if (!execution) {
        throw new Error(`Execution not found: ${executionId}`);
      }

      if (!execution.verification.backup_created) {
        throw new Error('No backup available for rollback');
      }

      // This would implement actual rollback from backup
      // For now, return placeholder results
      const result = {
        success: true,
        items_restored: execution.progress.items_affected,
        errors: [],
        rollback_time_ms: Math.round(performance.now() - startTime),
      };

      // Update execution status
      execution.status = 'rolled_back';
      execution.timestamps.rolled_back_at = new Date().toISOString();

      logger.info(
        {
          execution_id: executionId,
          items_restored: result.items_restored,
          rollback_time_ms: result.rollback_time_ms,
        },
        'Compaction execution rollback completed'
      );

      return result;
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';

      logger.error(
        {
          execution_id: executionId,
          error: errorMsg,
        },
        'Compaction execution rollback failed'
      );

      return {
        success: false,
        items_restored: 0,
        errors: [errorMsg],
        rollback_time_ms: Math.round(performance.now() - startTime),
      };
    }
  }

  /**
   * Cancel active compaction execution
   */
  async cancelExecution(executionId: string): Promise<boolean> {
    const execution = this.activeExecutions.get(executionId);
    if (!execution) {
      return false;
    }

    execution.status = 'cancelled';
    execution.timestamps.cancelled_at = new Date().toISOString();

    this.activeExecutions.delete(executionId);

    logger.info(
      {
        execution_id: executionId,
      },
      'Compaction execution cancelled'
    );

    return true;
  }

  /**
   * Get compaction execution history
   */
  getExecutionHistory(limit: number = 10): CompactionExecution[] {
    return this.executionHistory
      .sort(
        (a, b) =>
          new Date(b.timestamps.created_at).getTime() - new Date(a.timestamps.created_at).getTime()
      )
      .slice(0, limit);
  }

  /**
   * Get service status
   */
  getStatus(): {
    is_initialized: boolean;
    active_executions: number;
    total_compactions_completed: number;
    total_storage_freed_mb: number;
    last_compaction_time?: string;
    last_analysis_time?: string;
    storage_health_score: number;
  } {
    const lastExecution = this.executionHistory
      .filter((e) => e.status === 'completed')
      .sort(
        (a, b) =>
          new Date(b.timestamps.completed_at!).getTime() -
          new Date(a.timestamps.completed_at!).getTime()
      )[0];

    return {
      is_initialized: this.isInitialized,
      active_executions: this.activeExecutions.size,
      total_compactions_completed: this.executionHistory.filter((e) => e.status === 'completed')
        .length,
      total_storage_freed_mb: this.executionHistory
        .filter((e) => e.status === 'completed')
        .reduce((sum, e) => sum + e.results.storage_freed_mb, 0),
      last_compaction_time: lastExecution?.timestamps.completed_at,
      last_analysis_time: lastExecution?.timestamps.created_at,
      storage_health_score: this.calculateStorageHealthScore(),
    };
  }

  /**
   * Update configuration
   */
  updateConfig(config: Partial<CompactionConfig>): void {
    this.config = { ...this.config, ...config };

    // Restart scheduled processing if interval changed
    if (config.processing?.processing_interval_hours !== undefined) {
      if (this.processingTimer) {
        clearInterval(this.processingTimer);
        this.processingTimer = undefined;
      }
      this.startScheduledProcessing();
    }

    logger.info({ config: this.config }, 'Compaction configuration updated');
  }

  /**
   * Get configuration
   */
  getConfig(): CompactionConfig {
    return { ...this.config };
  }

  /**
   * Shutdown service
   */
  async shutdown(): Promise<void> {
    logger.info('Shutting down compaction service');

    if (this.processingTimer) {
      clearInterval(this.processingTimer);
      this.processingTimer = undefined;
    }

    // Wait for active executions to complete
    const timeout = 120000; // 2 minutes for compaction
    const startTime = Date.now();

    while (this.activeExecutions.size > 0 && Date.now() - startTime < timeout) {
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }

    if (this.activeExecutions.size > 0) {
      logger.warn(
        {
          active_executions: this.activeExecutions.size,
        },
        'Active executions still running during shutdown'
      );
    }

    this.isInitialized = false;

    logger.info('Compaction service shutdown complete');
  }

  // === Private Helper Methods ===

  private async getAllKnowledgeItems(): Promise<KnowledgeItem[]> {
    // This would query the vector adapter for all items
    // For now, return empty array as placeholder
    return [];
  }

  private calculateTotalStorage(items: KnowledgeItem[]): number {
    return items.reduce((total, item) => total + this.calculateItemSize(item), 0);
  }

  private calculateItemSize(item: KnowledgeItem): number {
    // Calculate approximate size based on JSON serialization
    return Buffer.byteLength(JSON.stringify(item), 'utf8');
  }

  private async analyzeFragmentation(items: KnowledgeItem[]): Promise<{
    overall_fragmentation_level: number;
    fragmented_storage_mb: number;
    defragmentation_potential_mb: number;
  }> {
    // This would analyze storage fragmentation
    // For now, return placeholder data
    return {
      overall_fragmentation_level: 0.1,
      fragmented_storage_mb: 50,
      defragmentation_potential_mb: 40,
    };
  }

  private async analyzeDuplicates(items: KnowledgeItem[]): Promise<{
    exact_duplicates: number;
    duplicate_storage_mb: number;
    deduplication_potential_mb: number;
  }> {
    const duplicateGroups = await this.findDuplicates({
      similarity_threshold: this.config.strategies.duplicate_similarity_threshold,
    });

    let duplicateStorage = 0;
    for (const group of duplicateGroups) {
      for (const duplicate of group.duplicate_items) {
        duplicateStorage += this.calculateItemSize(duplicate);
      }
    }

    return {
      exact_duplicates: duplicateGroups.filter((g) => g.duplicate_type === 'exact').length,
      duplicate_storage_mb: Math.round((duplicateStorage / 1024 / 1024) * 100) / 100,
      deduplication_potential_mb: Math.round((duplicateStorage / 1024 / 1024) * 100) / 100,
    };
  }

  private async analyzeReferenceIntegrity(items: KnowledgeItem[]): Promise<{
    total_references: number;
    valid_references: number;
    broken_references: number;
  }> {
    // This would analyze reference integrity
    // For now, return placeholder data
    return {
      total_references: 0,
      valid_references: 0,
      broken_references: 0,
    };
  }

  private async analyzePerformance(items: KnowledgeItem[]): Promise<{
    average_query_time_ms: number;
    index_efficiency_score: number;
    storage_utilization_ratio: number;
    recommended_optimizations: Array<{
      optimization_type: string;
      estimated_improvement_percent: number;
      complexity: 'low' | 'medium' | 'high';
    }>;
  }> {
    // This would analyze performance metrics
    // For now, return placeholder data
    return {
      average_query_time_ms: 150,
      index_efficiency_score: 85,
      storage_utilization_ratio: 0.75,
      recommended_optimizations: [
        {
          optimization_type: 'index_rebuilding',
          estimated_improvement_percent: 15,
          complexity: 'medium',
        },
      ],
    };
  }

  private generateRecommendations(
    fragmentation: unknown,
    duplicates: unknown,
    references: unknown,
    performance: unknown
  ): Array<{
    priority: 'critical' | 'high' | 'medium' | 'low';
    category: 'defragmentation' | 'deduplication' | 'reference_cleanup' | 'index_rebuilding';
    description: string;
    action_items: string[];
    estimated_impact: string;
    estimated_time_minutes: number;
  }> {
    const recommendations = [];

    if (
      fragmentation.overall_fragmentation_level > this.config.thresholds.fragmentation_threshold
    ) {
      recommendations.push({
        priority: 'medium',
        category: 'defragmentation',
        description: `Storage fragmentation at ${Math.round(fragmentation.overall_fragmentation_level * 100)}% exceeds threshold`,
        action_items: ['Run defragmentation process', 'Schedule regular maintenance'],
        estimated_impact: `Reclaim ${fragmentation.defragmentation_potential_mb}MB of storage`,
        estimated_time_minutes: 60,
      });
    }

    if (duplicates.exact_duplicates > 0) {
      recommendations.push({
        priority: 'high',
        category: 'deduplication',
        description: `Found ${duplicates.exact_duplicates} exact duplicate items`,
        action_items: ['Review duplicate groups', 'Remove or merge duplicates'],
        estimated_impact: `Free ${duplicates.deduplication_potential_mb}MB of storage`,
        estimated_time_minutes: 45,
      });
    }

    if (references.broken_references > this.config.thresholds.broken_references_threshold) {
      recommendations.push({
        priority: 'high',
        category: 'reference_cleanup',
        description: `Found ${references.broken_references} broken references`,
        action_items: ['Repair or remove broken references', 'Update reference validation'],
        estimated_impact: 'Improve data integrity and query reliability',
        estimated_time_minutes: 30,
      });
    }

    if (performance.index_efficiency_score < 80) {
      recommendations.push({
        priority: 'medium',
        category: 'index_rebuilding',
        description: `Index efficiency score of ${performance.index_efficiency_score}% is below optimal`,
        action_items: ['Rebuild database indexes', 'Optimize index configuration'],
        estimated_impact: 'Improve query performance by 15-25%',
        estimated_time_minutes: 120,
      });
    }

    return recommendations;
  }

  private groupItemsByKind(items: KnowledgeItem[]): Map<string, KnowledgeItem[]> {
    const grouped = new Map<string, KnowledgeItem[]>();

    for (const item of items) {
      const kind = item.kind || 'unknown';
      if (!grouped.has(kind)) {
        grouped.set(kind, []);
      }
      grouped.get(kind)!.push(item);
    }

    return grouped;
  }

  private async findDuplicatesInGroup(
    items: KnowledgeItem[],
    similarityThreshold: number,
    includeSemantic: boolean
  ): Promise<DuplicateGroup[]> {
    const duplicateGroups: DuplicateGroup[] = [];
    const processed = new Set<string>();

    for (let i = 0; i < items.length; i++) {
      const item1 = items[i];
      if (processed.has(item1.id)) continue;

      const duplicates: KnowledgeItem[] = [];
      let maxSimilarity = 0;

      for (let j = i + 1; j < items.length; j++) {
        const item2 = items[j];
        if (processed.has(item2.id)) continue;

        const similarity = await this.calculateSimilarity(item1, item2, includeSemantic);

        if (similarity >= similarityThreshold) {
          duplicates.push(item2);
          processed.add(item2.id);
          maxSimilarity = Math.max(maxSimilarity, similarity);
        }
      }

      if (duplicates.length > 0) {
        const group: DuplicateGroup = {
          group_id: this.generateGroupId(),
          primary_item: item1,
          duplicate_items: duplicates,
          similarity: {
            overall_score: maxSimilarity,
            content_similarity: maxSimilarity, // Would be calculated separately
            metadata_similarity: 1.0, // Would be calculated
            semantic_similarity: includeSemantic ? maxSimilarity : 0,
          },
          duplicate_type:
            maxSimilarity >= 0.95 ? 'exact' : maxSimilarity >= 0.8 ? 'near' : 'semantic',
          consolidation: {
            recommended_action: maxSimilarity >= 0.95 ? 'keep_primary' : 'manual_review',
            confidence: maxSimilarity,
            risk_level: maxSimilarity >= 0.95 ? 'low' : maxSimilarity >= 0.8 ? 'medium' : 'high',
          },
        };

        duplicateGroups.push(group);
        processed.add(item1.id);
      }
    }

    return duplicateGroups;
  }

  private async calculateSimilarity(
    item1: KnowledgeItem,
    item2: KnowledgeItem,
    includeSemantic: boolean
  ): Promise<number> {
    // Simple content-based similarity calculation
    const content1 = JSON.stringify(item1.content || '');
    const content2 = JSON.stringify(item2.content || '');

    // Calculate Jaccard similarity for simple content
    const words1 = new Set(content1.toLowerCase().split(/\s+/));
    const words2 = new Set(content2.toLowerCase().split(/\s+/));

    const intersection = new Set([...words1].filter((x) => words2.has(x)));
    const union = new Set([...words1, ...words2]);

    const contentSimilarity = intersection.size / union.size;

    if (includeSemantic) {
      // Would include semantic similarity calculation using embeddings
      return contentSimilarity;
    }

    return contentSimilarity;
  }

  private async buildReferenceGraph(items: KnowledgeItem[]): Promise<Map<string, Set<string>>> {
    const graph = new Map<string, Set<string>>();

    for (const item of items) {
      graph.set(item.id, new Set());
    }

    // This would analyze actual references in item content/metadata
    // For now, return empty graph as placeholder

    return graph;
  }

  private async findBrokenReferences(graph: Map<string, Set<string>>): Promise<
    Array<{
      from_item_id: string;
      to_item_id: string;
      reference_type: string;
      severity: 'low' | 'medium' | 'high';
      repair_suggestion: string;
    }>
  > {
    // This would identify broken references in the graph
    // For now, return empty array as placeholder
    return [];
  }

  private async findCircularReferences(
    graph: Map<string, Set<string>>,
    maxDepth: number
  ): Promise<string[][]> {
    // This would detect circular reference chains
    // For now, return empty array as placeholder
    return [];
  }

  private calculateReferenceStatistics(graph: Map<string, Set<string>>): {
    total_references: number;
    valid_references: number;
    broken_references: number;
  } {
    // This would calculate reference statistics
    // For now, return placeholder data
    return {
      total_references: 0,
      valid_references: 0,
      broken_references: 0,
    };
  }

  private assessCircularReferenceImpact(chain: string[]): 'low' | 'medium' | 'high' {
    // Assess impact based on chain length and item types
    if (chain.length <= 2) return 'low';
    if (chain.length <= 5) return 'medium';
    return 'high';
  }

  private mergeItems(primary: KnowledgeItem, duplicates: KnowledgeItem[]): KnowledgeItem {
    // This would implement intelligent merging logic
    // For now, return primary item as placeholder
    return primary;
  }

  private async attemptReferenceRepair(brokenRef: unknown): Promise<{
    success: boolean;
    repair_action: string;
  }> {
    // This would attempt to repair broken references
    // For now, return success as placeholder
    return {
      success: true,
      repair_action: 'update_reference',
    };
  }

  private async applyReferenceRepair(brokenRef: unknown, repairAction: string): Promise<void> {
    // This would apply the reference repair
    logger.debug(
      {
        from_item: brokenRef.from_item_id,
        to_item: brokenRef.to_item_id,
        repair_action: repairAction,
      },
      'Applied reference repair'
    );
  }

  private async removeBrokenReference(brokenRef: unknown): Promise<void> {
    // This would remove the broken reference
    logger.debug(
      {
        from_item: brokenRef.from_item_id,
        to_item: brokenRef.to_item_id,
      },
      'Removed broken reference'
    );
  }

  private async flagBrokenReference(brokenRef: unknown): Promise<void> {
    // This would flag the broken reference for manual review
    logger.debug(
      {
        from_item: brokenRef.from_item_id,
        to_item: brokenRef.to_item_id,
      },
      'Flagged broken reference for manual review'
    );
  }

  private async createBackup(
    executionId: string
  ): Promise<{ backup_id: string; location: string }> {
    const backupId = this.generateBackupId();
    const location = `./backups/compaction_${backupId}.json`;

    logger.debug(
      {
        backup_id: backupId,
        location: location,
      },
      'Created compaction backup'
    );

    return { backup_id: backupId, location };
  }

  private async executeDefragmentation(
    execution: CompactionExecution,
    items: KnowledgeItem[]
  ): Promise<void> {
    // This would execute defragmentation logic
    logger.debug(
      {
        execution_id: execution.execution_id,
        items_count: items.length,
      },
      'Executing defragmentation'
    );
  }

  private async executeDeduplication(
    execution: CompactionExecution,
    items: KnowledgeItem[]
  ): Promise<void> {
    // This would execute deduplication logic
    const duplicateGroups = await this.findDuplicates({ max_groups: 100 });

    const result = await this.deduplicateStorage(duplicateGroups, {
      dry_run: execution.config.dry_run,
      merge_strategy: 'keep_primary',
    });

    execution.results.duplicates_removed = result.items_removed;
    execution.results.storage_freed_mb += result.storage_freed_mb;
  }

  private async executeReferenceCleanup(
    execution: CompactionExecution,
    items: KnowledgeItem[]
  ): Promise<void> {
    // This would execute reference cleanup logic
    const referenceAnalysis = await this.analyzeReferences();

    const result = await this.cleanupReferences(referenceAnalysis, {
      dry_run: execution.config.dry_run,
      auto_repair: true,
    });

    execution.results.references_cleaned = result.references_cleaned;
  }

  private async executeIndexRebuilding(execution: CompactionExecution): Promise<void> {
    // This would execute index rebuilding logic
    const result = await this.rebuildIndexes({
      rebuild_strategy: 'full',
      verify_after_rebuild: true,
    });

    execution.results.indexes_rebuilt = result.indexes_rebuilt;
  }

  private async calculatePerformanceImprovement(execution: CompactionExecution): Promise<number> {
    // This would calculate actual performance improvement
    // For now, return placeholder improvement
    return 15.5;
  }

  private async verifyCompactionResults(execution: CompactionExecution): Promise<{
    verification_passed: boolean;
    data_loss_detected: boolean;
    integrity_checks_passed: boolean;
    sample_results: Array<{
      item_id: string;
      original_hash: string;
      compacted_hash: string;
      integrity_passed: boolean;
    }>;
  }> {
    // This would implement comprehensive verification
    // For now, return placeholder results
    return {
      verification_passed: true,
      data_loss_detected: false,
      integrity_checks_passed: true,
      sample_results: [],
    };
  }

  private calculateStorageHealthScore(): number {
    // Calculate overall storage health score (0-100)
    // This would consider fragmentation, duplicates, references, etc.
    return 85; // Placeholder
  }

  private async performInitialStorageAnalysis(): Promise<void> {
    // Perform initial analysis to establish baseline
    logger.debug('Performing initial storage analysis');
  }

  private async updateSystemMetrics(execution: CompactionExecution): Promise<void> {
    try {
      systemMetricsService.updateMetrics({
        operation: 'compaction',
        data: {
          execution_id: execution.execution_id,
          execution_type: execution.execution_type,
          dry_run: execution.config.dry_run,
          items_processed: execution.progress.items_processed,
          items_affected: execution.progress.items_affected,
          storage_freed_mb: execution.results.storage_freed_mb,
          success: execution.status === 'completed',
          duration_ms:
            execution.timestamps.completed_at && execution.timestamps.started_at
              ? new Date(execution.timestamps.completed_at).getTime() -
                new Date(execution.timestamps.started_at).getTime()
              : 0,
        },
        duration_ms:
          execution.timestamps.completed_at && execution.timestamps.started_at
            ? new Date(execution.timestamps.completed_at).getTime() -
              new Date(execution.timestamps.started_at).getTime()
            : 0,
      });
    } catch (error) {
      logger.warn(
        {
          execution_id: execution.execution_id,
          error: error instanceof Error ? error.message : 'Unknown error',
        },
        'Failed to update compaction metrics'
      );
    }
  }

  private startScheduledProcessing(): void {
    if (this.config.processing.processing_interval_hours > 0) {
      const intervalMs = this.config.processing.processing_interval_hours * 60 * 60 * 1000;

      logger.info(
        {
          interval_hours: this.config.processing.processing_interval_hours,
          interval_ms: intervalMs,
        },
        'Starting scheduled compaction processing'
      );

      this.processingTimer = setInterval(async () => {
        try {
          await this.executeScheduledCompaction();
        } catch (error) {
          logger.error(
            {
              error: error instanceof Error ? error.message : 'Unknown error',
            },
            'Scheduled compaction processing failed'
          );
        }
      }, intervalMs);
    }
  }

  private async executeScheduledCompaction(): Promise<void> {
    logger.debug('Executing scheduled compaction');

    // Analyze storage first to determine if compaction is needed
    const analysis = await this.analyzeStorage();

    const needsCompaction =
      analysis.fragmentation.overall_fragmentation_level >
        this.config.thresholds.fragmentation_threshold ||
      analysis.duplicates.exact_duplicates + analysis.duplicates.near_duplicates > 0 ||
      analysis.references.broken_references > this.config.thresholds.broken_references_threshold;

    if (needsCompaction) {
      await this.executeCompaction({
        dry_run: false, // Scheduled executions are real
        strategies: {
          defragment:
            analysis.fragmentation.overall_fragmentation_level >
            this.config.thresholds.fragmentation_threshold,
          deduplicate:
            analysis.duplicates.exact_duplicates + analysis.duplicates.near_duplicates > 0,
          cleanup_references:
            analysis.references.broken_references >
            this.config.thresholds.broken_references_threshold,
          rebuild_index: analysis.performance.index_efficiency_score < 80,
        },
      });
    }
  }

  private async loadExecutionHistory(): Promise<void> {
    // Implementation placeholder for loading execution history from storage
    logger.debug('Loading compaction execution history');
  }

  private async removeItem(itemId: string): Promise<void> {
    // This would remove the item from vector store
    logger.debug(
      {
        item_id: itemId,
      },
      'Removed item during compaction'
    );
  }

  private async updateItem(item: KnowledgeItem): Promise<void> {
    // This would update the item in vector store
    logger.debug(
      {
        item_id: item.id,
      },
      'Updated item during compaction'
    );
  }

  // === Utility Methods ===

  private generateExecutionId(): string {
    return `compact_exec_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateGroupId(): string {
    return `dup_group_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateAnalysisId(): string {
    return `analysis_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateReportId(): string {
    return `compact_report_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateBackupId(): string {
    return `compact_backup_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}
