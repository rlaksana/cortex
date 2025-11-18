/**
 * P3 Data Management: Compaction Service Interface
 *
 * Focused service responsible for storage optimization through defragmentation,
 * duplicate detection, reference cleanup, and index rebuilding. Provides safe
 * compaction operations with comprehensive verification and rollback capabilities.
 *
 * Features:
 * - Storage defragmentation and gap elimination
 * - Duplicate detection and consolidation
 * - Broken reference cleanup and repair
 * - Index rebuilding and optimization
 * - Storage space analysis and reclamation
 * - Safe batch processing with verification
 * - Rollback capabilities for failed operations
 * - Performance-optimized algorithms
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

import type { KnowledgeItem } from '../../../types/core-interfaces.js';

// === Type Definitions ===

export interface CompactionConfig {
  /** Processing configuration */
  processing: {
    /** Batch size for compaction operations */
    batch_size: number;
    /** Max items per compaction run */
    max_items_per_run: number;
    /** Processing interval (hours) */
    processing_interval_hours: number;
    /** Enable parallel processing */
    enable_parallel_processing: boolean;
    /** Max concurrent operations */
    max_concurrent_operations: number;
  };
  /** Compaction strategies */
  strategies: {
    /** Enable defragmentation */
    enable_defragmentation: boolean;
    /** Enable duplicate detection */
    enable_duplicate_detection: boolean;
    /** Enable reference cleanup */
    enable_reference_cleanup: boolean;
    /** Enable index rebuilding */
    enable_index_rebuilding: boolean;
    /** Duplicate detection sensitivity (0.0-1.0) */
    duplicate_sensitivity: number;
    /** Minimum similarity threshold for duplicates */
    duplicate_similarity_threshold: number;
  };
  /** Safety and verification */
  safety: {
    /** Require confirmation for destructive operations */
    require_confirmation: boolean;
    /** Enable dry-run mode by default */
    dry_run_by_default: boolean;
    /** Create backup before compaction */
    create_backup_before_compaction: boolean;
    /** Enable compaction verification */
    enable_compaction_verification: boolean;
    /** Sample verification percentage (0-100) */
    sample_verification_percent: number;
    /** Max data loss tolerance percentage */
    max_data_loss_tolerance_percent: number;
  };
  /** Performance thresholds */
  thresholds: {
    /** Fragmentation level to trigger compaction (0.0-1.0) */
    fragmentation_threshold: number;
    /** Storage usage percentage to trigger cleanup */
    storage_usage_threshold_percent: number;
    /** Duplicate percentage threshold for action */
    duplicate_percentage_threshold: number;
    /** Broken references threshold for cleanup */
    broken_references_threshold: number;
  };
}

export interface CompactionExecution {
  /** Execution identifier */
  execution_id: string;
  /** Execution type */
  execution_type:
    | 'defragment'
    | 'deduplicate'
    | 'cleanup_references'
    | 'rebuild_index'
    | 'full_compaction';
  /** Execution status */
  status: 'pending' | 'in_progress' | 'completed' | 'failed' | 'cancelled' | 'rolled_back';
  /** Timestamps */
  timestamps: {
    created_at: string;
    started_at?: string;
    completed_at?: string;
    failed_at?: string;
    cancelled_at?: string;
    rolled_back_at?: string;
  };
  /** Execution configuration */
  config: {
    dry_run: boolean;
    batch_size: number;
    max_items?: number;
    strategies: {
      defragment: boolean;
      deduplicate: boolean;
      cleanup_references: boolean;
      rebuild_index: boolean;
    };
    scope_filters?: unknown;
  };
  /** Progress tracking */
  progress: {
    total_items_analyzed: number;
    items_processed: number;
    items_affected: number;
    items_failed: number;
    items_skipped: number;
    current_batch?: number;
    total_batches: number;
  };
  /** Results summary */
  results: {
    storage_freed_mb: number;
    duplicates_removed: number;
    references_cleaned: number;
    fragments_eliminated: number;
    indexes_rebuilt: number;
    data_integrity_score: number; // 0-100
    performance_improvement_percent: number;
  };
  /** Execution details */
  details: {
    batches_processed: Array<{
      batch_id: string;
      items_count: number;
      items_affected: number;
      processing_time_ms: number;
      storage_freed_mb: number;
      errors: string[];
    }>;
    duplicates_found: Array<{
      primary_item_id: string;
      duplicate_item_ids: string[];
      similarity_score: number;
      duplicate_type: 'exact' | 'near' | 'semantic';
    }>;
    broken_references: Array<{
      from_item_id: string;
      to_item_id: string;
      reference_type: string;
      action_taken: 'removed' | 'repaired' | 'flagged';
    }>;
    errors: Array<{
      item_id: string;
      error: string;
      timestamp: string;
      phase: string;
    }>;
    warnings: string[];
  };
  /** Verification results */
  verification: {
    backup_created: boolean;
    backup_location?: string;
    verification_passed: boolean;
    data_loss_detected: boolean;
    integrity_checks_passed: boolean;
    sample_results: Array<{
      item_id: string;
      original_hash: string;
      compacted_hash: string;
      integrity_passed: boolean;
    }>;
  };
}

export interface StorageAnalysisReport {
  /** Report identifier */
  report_id: string;
  /** Timestamp */
  timestamp: string;
  /** Analysis scope */
  scope: {
    total_items: number;
    total_storage_mb: number;
    storage_backends: string[];
    analysis_duration_ms: number;
  };
  /** Fragmentation analysis */
  fragmentation: {
    overall_fragmentation_level: number; // 0-1
    fragmented_storage_mb: number;
    fragmentation_sources: Array<{
      source: string;
      fragmentation_level: number;
      storage_impact_mb: number;
      recommended_action: string;
    }>;
    defragmentation_potential_mb: number;
  };
  /** Duplicate analysis */
  duplicates: {
    exact_duplicates: number;
    near_duplicates: number;
    semantic_duplicates: number;
    duplicate_storage_mb: number;
    duplicate_groups: Array<{
      primary_item_id: string;
      duplicate_item_ids: string[];
      total_storage_mb: number;
      similarity_score: number;
    }>;
    deduplication_potential_mb: number;
  };
  /** Reference analysis */
  references: {
    total_references: number;
    valid_references: number;
    broken_references: number;
    circular_references: number;
    orphaned_references: number;
    broken_reference_details: Array<{
      from_item_id: string;
      to_item_id: string;
      reference_type: string;
      severity: 'low' | 'medium' | 'high';
    }>;
  };
  /** Performance analysis */
  performance: {
    average_query_time_ms: number;
    index_efficiency_score: number; // 0-100
    storage_utilization_ratio: number;
    recommended_optimizations: Array<{
      optimization_type: string;
      estimated_improvement_percent: number;
      complexity: 'low' | 'medium' | 'high';
    }>;
  };
  /** Recommendations */
  recommendations: Array<{
    priority: 'critical' | 'high' | 'medium' | 'low';
    category: 'defragmentation' | 'deduplication' | 'reference_cleanup' | 'index_rebuilding';
    description: string;
    action_items: string[];
    estimated_impact: string;
    estimated_time_minutes: number;
  }>;
}

export interface DuplicateGroup {
  /** Group identifier */
  group_id: string;
  /** Primary item to keep */
  primary_item: KnowledgeItem;
  /** Duplicate items */
  duplicate_items: KnowledgeItem[];
  /** Similarity analysis */
  similarity: {
    overall_score: number; // 0-1
    content_similarity: number;
    metadata_similarity: number;
    semantic_similarity: number;
  };
  /** Duplicate type */
  duplicate_type: 'exact' | 'near' | 'semantic';
  /** Consolidation recommendation */
  consolidation: {
    recommended_action: 'keep_primary' | 'merge' | 'manual_review';
    confidence: number; // 0-1
    risk_level: 'low' | 'medium' | 'high';
    merged_item_suggestion?: KnowledgeItem;
  };
}

export interface ReferenceAnalysis {
  /** Analysis identifier */
  analysis_id: string;
  /** Reference statistics */
  statistics: {
    total_references: number;
    inbound_references: number;
    outbound_references: number;
    self_references: number;
    circular_chains: number;
  };
  /** Broken references */
  broken_references: Array<{
    from_item_id: string;
    to_item_id: string;
    reference_type: string;
    reference_path: string[];
    severity: 'low' | 'medium' | 'high';
    repair_suggestion: string;
  }>;
  /** Circular references */
  circular_references: Array<{
    chain: string[];
    depth: number;
    cycle_type: 'simple' | 'complex';
    impact_assessment: 'low' | 'medium' | 'high';
  }>;
  /** Orphaned references */
  orphaned_references: Array<{
    item_id: string;
    orphaned_reference_count: number;
    cleanup_strategy: 'remove' | 'archive' | 'flag';
  }>;
}

// === Compaction Service Interface ===

export interface ICompactionService {
  /**
   * Initialize compaction service
   */
  initialize(): Promise<void>;

  /**
   * Analyze storage for optimization opportunities
   */
  analyzeStorage(options?: {
    include_duplicates?: boolean;
    include_references?: boolean;
    include_fragmentation?: boolean;
    scope_filters?: unknown;
  }): Promise<StorageAnalysisReport>;

  /**
   * Execute compaction operation
   */
  executeCompaction(options: {
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
  }): Promise<CompactionExecution>;

  /**
   * Find duplicate items
   */
  findDuplicates(options?: {
    similarity_threshold?: number;
    max_groups?: number;
    include_semantic?: boolean;
    scope_filters?: unknown;
  }): Promise<DuplicateGroup[]>;

  /**
   * Analyze references for integrity issues
   */
  analyzeReferences(options?: {
    max_depth?: number;
    include_self_references?: boolean;
    scope_filters?: unknown;
  }): Promise<ReferenceAnalysis>;

  /**
   * Execute defragmentation
   */
  defragmentStorage(options?: {
    dry_run?: boolean;
    target_fragmentation_level?: number;
    batch_size?: number;
  }): Promise<CompactionExecution>;

  /**
   * Remove duplicate items
   */
  deduplicateStorage(
    duplicateGroups: DuplicateGroup[],
    options?: {
      dry_run?: boolean;
      merge_strategy?: 'keep_primary' | 'merge_best' | 'manual_review';
      create_backup?: boolean;
    }
  ): Promise<{
    items_removed: number;
    items_merged: number;
    storage_freed_mb: number;
    errors: string[];
  }>;

  /**
   * Clean up broken references
   */
  cleanupReferences(
    referenceAnalysis: ReferenceAnalysis,
    options?: {
      dry_run?: boolean;
      auto_repair?: boolean;
      remove_unrepairable?: boolean;
    }
  ): Promise<{
    references_cleaned: number;
    references_repaired: number;
    references_removed: number;
    errors: string[];
  }>;

  /**
   * Rebuild indexes
   */
  rebuildIndexes(options?: {
    index_types?: string[];
    rebuild_strategy?: 'incremental' | 'full';
    verify_after_rebuild?: boolean;
  }): Promise<{
    indexes_rebuilt: number;
    verification_passed: boolean;
    rebuild_time_ms: number;
    errors: string[];
  }>;

  /**
   * Verify compaction results
   */
  verifyCompaction(executionId: string): Promise<{
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
  }>;

  /**
   * Rollback compaction execution
   */
  rollbackExecution(executionId: string): Promise<{
    success: boolean;
    items_restored: number;
    errors: string[];
    rollback_time_ms: number;
  }>;

  /**
   * Cancel active compaction execution
   */
  cancelExecution(executionId: string): Promise<boolean>;

  /**
   * Get compaction execution history
   */
  getExecutionHistory(limit?: number): CompactionExecution[];

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
    storage_health_score: number; // 0-100
  };

  /**
   * Update configuration
   */
  updateConfig(config: Partial<CompactionConfig>): void;

  /**
   * Get configuration
   */
  getConfig(): CompactionConfig;

  /**
   * Shutdown service
   */
  shutdown(): Promise<void>;
}
