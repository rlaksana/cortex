/**
 * P3 Data Management: TTL Cleanup Service Interface
 *
 * Focused service responsible for time-based expiration and safe removal
 * of expired knowledge items from the vector store. Provides atomic
 * operations with comprehensive audit trails and rollback capabilities.
 *
 * Features:
 * - Time-to-live (TTL) based expiration checking
 * - Safe batch removal with rollback capabilities
 * - Reference integrity validation before deletion
 * - Configurable grace periods and warning notifications
 * - Performance-optimized batch processing
 * - Comprehensive audit logging and metrics
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

import type { KnowledgeItem } from '../../../types/core-interfaces.js';

// === Type Definitions ===

export interface TTLCleanupConfig {
  /** Processing configuration */
  processing: {
    /** Batch size for cleanup operations */
    batch_size: number;
    /** Max items per cleanup run */
    max_items_per_run: number;
    /** Processing interval (hours) */
    processing_interval_hours: number;
    /** Enable parallel processing */
    enable_parallel_processing: boolean;
    /** Max concurrent operations */
    max_concurrent_operations: number;
  };
  /** Safety and verification */
  safety: {
    /** Require confirmation for destructive operations */
    require_confirmation: boolean;
    /** Enable dry-run mode by default */
    dry_run_by_default: boolean;
    /** Grace period before deletion (days) */
    grace_period_days: number;
    /** Create backup before deletion */
    create_backup_before_deletion: boolean;
    /** Enable deletion notifications */
    enable_deletion_notifications: boolean;
  };
  /** Reference integrity */
  integrity: {
    /** Enable reference checking before deletion */
    enable_reference_checking: boolean;
    /** Fail on broken references */
    fail_on_broken_references: boolean;
    /** Log broken references only (don't fail) */
    log_broken_references_only: boolean;
    /** Max recursion depth for reference checking */
    max_recursion_depth: number;
  };
}

export interface TTLCleanupExecution {
  /** Execution identifier */
  execution_id: string;
  /** Execution status */
  status: 'pending' | 'in_progress' | 'completed' | 'failed' | 'rolled_back';
  /** Timestamps */
  timestamps: {
    created_at: string;
    started_at?: string;
    completed_at?: string;
    failed_at?: string;
    rolled_back_at?: string;
  };
  /** Execution configuration */
  config: {
    dry_run: boolean;
    batch_size: number;
    max_items?: number;
    grace_period_days: number;
    scope_filters?: unknown;
  };
  /** Progress tracking */
  progress: {
    total_expired_items: number;
    items_processed: number;
    items_deleted: number;
    items_failed: number;
    items_skipped: number;
    references_checked: number;
    broken_references_found: number;
    current_batch?: number;
    total_batches: number;
  };
  /** Results summary */
  results: {
    items_deleted: number;
    storage_freed_mb: number;
    references_validated: number;
    broken_references: Array<{
      item_id: string;
      referenced_by: string[];
      reference_type: string;
    }>;
    backup_created: boolean;
    backup_location?: string;
  };
  /** Execution details */
  details: {
    batches_processed: Array<{
      batch_id: string;
      items_count: number;
      items_deleted: number;
      processing_time_ms: number;
      errors: string[];
    }>;
    errors: Array<{
      item_id: string;
      error: string;
      timestamp: string;
      phase: string;
    }>;
    warnings: string[];
  };
}

export interface ExpiredItem extends KnowledgeItem {
  /** Expiration information */
  expiration: {
    /** Expiration timestamp */
    expired_at: string;
    /** Days since expiration */
    days_expired: number;
    /** Grace period end */
    grace_period_end: string;
    /** Has passed grace period */
    can_delete: boolean;
  };
  /** Reference analysis */
  references: {
    /** Number of inbound references */
    inbound_count: number;
    /** Items that reference this item */
    referenced_by: Array<{
      id: string;
      kind: string;
      reference_type: string;
    }>;
    /** Has broken references that would be created */
    would_break_references: boolean;
  };
  /** Deletion assessment */
  deletion_assessment: {
    /** Safe to delete */
    safe_to_delete: boolean;
    /** Risk level */
    risk_level: 'low' | 'medium' | 'high' | 'critical';
    /** Deletion blockers */
    blockers: string[];
    /** Recommended action */
    recommended_action: 'delete' | 'review' | 'extend_grace' | 'archive_first';
  };
}

export interface ReferenceIntegrityReport {
  /** Report identifier */
  report_id: string;
  /** Timestamp */
  timestamp: string;
  /** Analysis scope */
  scope: {
    total_items_analyzed: number;
    expired_items_found: number;
    references_analyzed: number;
  };
  /** Reference analysis */
  reference_analysis: {
    /** Items with inbound references */
    items_with_references: number;
    /** Total inbound references */
    total_inbound_references: number;
    /** Broken references found */
    broken_references: Array<{
      from_item: string;
      to_item: string;
      reference_type: string;
      impact_assessment: 'low' | 'medium' | 'high';
    }>;
    /** Circular reference chains */
    circular_references: Array<{
      chain: string[];
      depth: number;
    }>;
  };
  /** Deletion safety assessment */
  safety_assessment: {
    /** Safe to delete immediately */
    safe_to_delete: number;
    /** Require review */
    require_review: number;
    /** Require archival before deletion */
    require_archival: number;
    /** Cannot delete (critical blockers) */
    cannot_delete: number;
  };
}

// === TTL Cleanup Service Interface ===

export interface ITTLCleanupService {
  /**
   * Initialize TTL cleanup service
   */
  initialize(): Promise<void>;

  /**
   * Find expired items
   */
  findExpiredItems(options?: {
    include_references?: boolean;
    max_recursion_depth?: number;
    scope_filters?: unknown;
  }): Promise<ExpiredItem[]>;

  /**
   * Check if an item is expired
   */
  isItemExpired(item: KnowledgeItem): {
    is_expired: boolean;
    expired_at?: string;
    days_expired?: number;
    can_delete?: boolean;
  };

  /**
   * Analyze reference integrity for expired items
   */
  analyzeReferenceIntegrity(items: ExpiredItem[]): Promise<ReferenceIntegrityReport>;

  /**
   * Execute TTL cleanup
   */
  executeCleanup(options: {
    dry_run?: boolean;
    batch_size?: number;
    max_items?: number;
    grace_period_days?: number;
    scope_filters?: unknown;
    require_confirmation?: boolean;
    create_backup?: boolean;
  }): Promise<TTLCleanupExecution>;

  /**
   * Process a batch of expired items
   */
  processBatch(
    items: ExpiredItem[],
    options: {
      dry_run: boolean;
      create_backup: boolean;
      grace_period_days: number;
    }
  ): Promise<{
    items_deleted: number;
    items_skipped: number;
    errors: string[];
    processing_time_ms: number;
  }>;

  /**
   * Validate reference integrity before deletion
   */
  validateReferences(item: ExpiredItem): Promise<{
    safe_to_delete: boolean;
    blockers: string[];
    referenced_by: Array<{
      id: string;
      kind: string;
      reference_type: string;
    }>;
  }>;

  /**
   * Create backup before deletion
   */
  createBackup(items: KnowledgeItem[]): Promise<{
    backup_id: string;
    backup_location: string;
    item_count: number;
    backup_size_mb: number;
  }>;

  /**
   * Rollback cleanup execution
   */
  rollbackExecution(executionId: string): Promise<{
    success: boolean;
    items_restored: number;
    errors: string[];
  }>;

  /**
   * Get cleanup execution history
   */
  getExecutionHistory(limit?: number): TTLCleanupExecution[];

  /**
   * Get service status
   */
  getStatus(): {
    is_initialized: boolean;
    last_cleanup_time?: string;
    total_items_deleted: number;
    total_storage_freed_mb: number;
    active_executions: number;
  };

  /**
   * Update configuration
   */
  updateConfig(config: Partial<TTLCleanupConfig>): void;

  /**
   * Get configuration
   */
  getConfig(): TTLCleanupConfig;

  /**
   * Shutdown service
   */
  shutdown(): Promise<void>;
}
