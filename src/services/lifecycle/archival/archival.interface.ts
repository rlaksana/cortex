/**
 * P3 Data Management: Archival Service Interface
 *
 * Focused service responsible for moving data to cold storage with compression,
 * encryption, and verification. Provides tiered storage management with
 * configurable retention policies and comprehensive audit trails.
 *
 * Features:
 * - Automated archiving based on age and access patterns
 * - Multi-tier storage support (hot, warm, cold, glacier)
 * - Compression and encryption for long-term storage
 * - Reference-preserving archival with metadata retention
 * - Configurable retention periods per data tier
 * - Comprehensive verification and integrity checks
 * - Restore capabilities with full data fidelity
 * - Cost-optimized storage tier management
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

import type { KnowledgeItem } from '../../../types/core-interfaces.js';

// === Type Definitions ===

export interface ArchivalConfig {
  /** Storage configuration */
  storage: {
    /** Enable automatic archiving */
    enable_auto_archive: boolean;
    /** Archive storage backends */
    backends: {
      /** Local filesystem storage */
      local: {
        enabled: boolean;
        base_path: string;
        compression_enabled: boolean;
        encryption_enabled: boolean;
      };
      /** Amazon S3 storage */
      s3: {
        enabled: boolean;
        bucket: string;
        region: string;
        compression_enabled: boolean;
        encryption_enabled: boolean;
        storage_class: 'STANDARD' | 'GLACIER' | 'DEEP_ARCHIVE';
      };
      /** Azure Blob storage */
      azure: {
        enabled: boolean;
        account: string;
        container: string;
        compression_enabled: boolean;
        encryption_enabled: boolean;
        access_tier: 'Hot' | 'Cool' | 'Archive';
      };
      /** Google Cloud Storage */
      gcs: {
        enabled: boolean;
        bucket: string;
        compression_enabled: boolean;
        encryption_enabled: boolean;
        storage_class: 'STANDARD' | 'NEARLINE' | 'COLDLINE' | 'ARCHIVE';
      };
    };
    /** Default backend */
    default_backend: 'local' | 's3' | 'azure' | 'gcs';
  };
  /** Processing configuration */
  processing: {
    /** Batch size for archival operations */
    batch_size: number;
    /** Max items per archival run */
    max_items_per_run: number;
    /** Processing interval (hours) */
    processing_interval_hours: number;
    /** Enable parallel processing */
    enable_parallel_processing: boolean;
    /** Max concurrent operations */
    max_concurrent_operations: number;
  };
  /** Archival policies */
  policies: {
    /** Age-based archival triggers */
    age_triggers: Array<{
      data_type: string;
      archive_after_days: number;
      storage_tier: 'hot' | 'warm' | 'cold' | 'glacier';
      priority: number;
    }>;
    /** Access pattern based triggers */
    access_triggers: {
      /** Archive if not accessed for X days */
      no_access_days: number;
      /** Archive if access frequency below threshold */
      low_access_frequency: {
        access_per_month: number;
        period_months: number;
      };
    };
    /** Size-based triggers */
    size_triggers: {
      /** Archive items larger than X MB */
      large_item_threshold_mb: number;
      /** Archive items that exceed storage quota */
      storage_quota_threshold_percent: number;
    };
  };
  /** Verification and integrity */
  verification: {
    /** Enable post-archive verification */
    enable_verification: boolean;
    /** Verify integrity checksums */
    verify_checksums: boolean;
    /** Sample verification percentage (0-100) */
    sample_verification_percent: number;
    /** Verify restore capability */
    verify_restore_capability: boolean;
    /** Verification retry attempts */
    verification_retry_attempts: number;
  };
  /** Retention and lifecycle */
  retention: {
    /** Archive retention periods by tier */
    tier_retention_days: {
      hot: number;
      warm: number;
      cold: number;
      glacier: number;
    };
    /** Automatic tier migration */
    enable_tier_migration: boolean;
    /** Tier migration schedule */
    migration_schedule: Array<{
      from_tier: string;
      to_tier: string;
      after_days: number;
    }>;
    /** Archive deletion policy */
    delete_after_archive_retention: boolean;
  };
}

export interface ArchivalExecution {
  /** Execution identifier */
  execution_id: string;
  /** Execution type */
  execution_type: 'archive' | 'restore' | 'verify' | 'migrate_tier';
  /** Execution status */
  status: 'pending' | 'in_progress' | 'completed' | 'failed' | 'cancelled';
  /** Timestamps */
  timestamps: {
    created_at: string;
    started_at?: string;
    completed_at?: string;
    failed_at?: string;
    cancelled_at?: string;
  };
  /** Execution configuration */
  config: {
    dry_run: boolean;
    batch_size: number;
    max_items?: number;
    target_backend: string;
    target_tier?: string;
    compression_enabled: boolean;
    encryption_enabled: boolean;
    scope_filters?: unknown;
  };
  /** Progress tracking */
  progress: {
    total_items: number;
    items_processed: number;
    items_affected: number;
    items_failed: number;
    items_skipped: number;
    current_batch?: number;
    total_batches: number;
    bytes_processed: number;
    bytes_compressed: number;
  };
  /** Results summary */
  results: {
    items_archived: number;
    items_restored: number;
    items_verified: number;
    items_migrated: number;
    storage_saved_mb: number;
    archive_size_mb: number;
    compression_ratio: number;
    verification_passed: boolean;
  };
  /** Execution details */
  details: {
    batches_processed: Array<{
      batch_id: string;
      items_count: number;
      items_affected: number;
      processing_time_ms: number;
      compression_ratio: number;
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
  /** Storage information */
  storage: {
    backend_used: string;
    tier_used?: string;
    storage_locations: Array<{
      item_id: string;
      location: string;
      tier: string;
      size_bytes: number;
      compressed_size_bytes: number;
    }>;
  };
}

export interface ArchivedItem {
  /** Original item information */
  original_item: KnowledgeItem;
  /** Archival metadata */
  archive_metadata: {
    /** Archive identifier */
    archive_id: string;
    /** Archive timestamp */
    archived_at: string;
    /** Storage backend used */
    storage_backend: string;
    /** Storage tier */
    storage_tier: string;
    /** Storage location */
    storage_location: string;
    /** Original size */
    original_size_bytes: number;
    /** Compressed size */
    compressed_size_bytes: number;
    /** Compression ratio */
    compression_ratio: number;
    /** Checksum for integrity verification */
    checksum: string;
    /** Encryption key identifier */
    encryption_key_id?: string;
    /** Retention until date */
    retention_until?: string;
  };
  /** Access statistics */
  access_stats: {
    last_accessed_at: string;
    access_count: number;
    archive_access_count: number;
    days_since_last_access: number;
  };
  /** Restoration metadata */
  restoration: {
    /** Can be restored */
    can_restore: boolean;
    /** Estimated restore time (seconds) */
    estimated_restore_time_seconds: number;
    /** Restore cost estimate */
    restore_cost_estimate: number;
    /** Restore priority */
    restore_priority: 'low' | 'medium' | 'high' | 'critical';
  };
}

export interface RestoreOperation {
  /** Restore identifier */
  restore_id: string;
  /** Item being restored */
  item_id: string;
  /** Archive ID */
  archive_id: string;
  /** Restore status */
  status: 'pending' | 'in_progress' | 'completed' | 'failed';
  /** Timestamps */
  timestamps: {
    requested_at: string;
    started_at?: string;
    completed_at?: string;
    failed_at?: string;
  };
  /** Restore configuration */
  config: {
    /** Target location in active storage */
    target_location?: string;
    /** Preserve original metadata */
    preserve_metadata: boolean;
    /** Restore to specific version */
    restore_to_version?: string;
    /** Verify after restore */
    verify_after_restore: boolean;
  };
  /** Restore progress */
  progress: {
    bytes_retrieved: number;
    bytes_restored: number;
    estimated_completion?: string;
  };
  /** Restore results */
  results: {
    restored_item?: KnowledgeItem;
    restore_size_mb: number;
    verification_passed: boolean;
    integrity_check_passed: boolean;
  };
  /** Cost information */
  cost: {
    retrieve_cost: number;
    restore_cost: number;
    total_cost: number;
    cost_currency: string;
  };
}

export interface ArchivalIntegrityReport {
  /** Report identifier */
  report_id: string;
  /** Timestamp */
  timestamp: string;
  /** Report scope */
  scope: {
    total_archived_items: number;
    items_verified: number;
    verification_sample_size: number;
    storage_backends: string[];
  };
  /** Integrity verification results */
  integrity_results: {
    /** Items with valid checksums */
    checksums_valid: number;
    /** Items with invalid checksums */
    checksums_invalid: Array<{
      item_id: string;
      archive_id: string;
      expected_checksum: string;
      actual_checksum: string;
      corruption_detected: boolean;
    }>;
    /** Items missing from storage */
    missing_items: Array<{
      item_id: string;
      archive_id: string;
      expected_location: string;
      last_verified_at?: string;
    }>;
    /** Over-all integrity score */
    integrity_score: number; // 0-100
  };
  /** Storage analysis */
  storage_analysis: {
    /** Total archive storage used */
    total_storage_mb: number;
    /** Average compression ratio */
    average_compression_ratio: number;
    /** Storage by tier */
    storage_by_tier: Record<string, number>;
    /** Storage by backend */
    storage_by_backend: Record<string, number>;
  };
  /** Recommendations */
  recommendations: Array<{
    priority: 'critical' | 'high' | 'medium' | 'low';
    category: 'integrity' | 'optimization' | 'migration' | 'retention';
    description: string;
    action_items: string[];
    estimated_impact: string;
  }>;
}

// === Archival Service Interface ===

export interface IArchivalService {
  /**
   * Initialize archival service
   */
  initialize(): Promise<void>;

  /**
   * Find items eligible for archiving
   */
  findArchivableItems(options?: {
    age_threshold_days?: number;
    access_threshold_days?: number;
    size_threshold_mb?: number;
    target_tier?: string;
    scope_filters?: unknown;
  }): Promise<KnowledgeItem[]>;

  /**
   * Check if an item is eligible for archival
   */
  isItemArchivable(item: KnowledgeItem): Promise<{
    eligible: boolean;
    reason: string;
    recommended_tier: 'hot' | 'warm' | 'cold' | 'glacier';
    priority: number;
  }>;

  /**
   * Execute archival operation
   */
  executeArchive(options: {
    dry_run?: boolean;
    batch_size?: number;
    max_items?: number;
    target_backend?: string;
    target_tier?: string;
    compression_enabled?: boolean;
    encryption_enabled?: boolean;
    scope_filters?: unknown;
  }): Promise<ArchivalExecution>;

  /**
   * Archive a single item
   */
  archiveItem(
    item: KnowledgeItem,
    options: {
      target_backend: string;
      target_tier: string;
      compress: boolean;
      encrypt: boolean;
    }
  ): Promise<ArchivedItem>;

  /**
   * Restore archived item
   */
  restoreItem(
    archiveId: string,
    options?: {
      target_location?: string;
      preserve_metadata?: boolean;
      verify_after_restore?: boolean;
    }
  ): Promise<RestoreOperation>;

  /**
   * Batch restore items
   */
  batchRestore(
    archiveIds: string[],
    options?: {
      batch_size?: number;
      preserve_metadata?: boolean;
      verify_after_restore?: boolean;
    }
  ): Promise<{
    restore_operations: RestoreOperation[];
    items_restored: number;
    items_failed: number;
  }>;

  /**
   * Verify archive integrity
   */
  verifyArchives(options?: {
    sample_size?: number;
    verify_checksums?: boolean;
    verify_restore_capability?: boolean;
    storage_backends?: string[];
  }): Promise<ArchivalIntegrityReport>;

  /**
   * Migrate items between storage tiers
   */
  migrateTier(items: string[], fromTier: string, toTier: string): Promise<ArchivalExecution>;

  /**
   * Get archived item metadata
   */
  getArchivedItem(archiveId: string): Promise<ArchivedItem | null>;

  /**
   * List archived items
   */
  listArchivedItems(options?: {
    storage_backend?: string;
    storage_tier?: string;
    archived_after?: string;
    archived_before?: string;
    limit?: number;
    offset?: number;
  }): Promise<{
    items: ArchivedItem[];
    total_count: number;
    has_more: boolean;
  }>;

  /**
   * Get restore operation status
   */
  getRestoreOperation(restoreId: string): Promise<RestoreOperation | null>;

  /**
   * Cancel archive execution
   */
  cancelExecution(executionId: string): Promise<boolean>;

  /**
   * Get archival execution history
   */
  getExecutionHistory(limit?: number): ArchivalExecution[];

  /**
   * Get service status
   */
  getStatus(): {
    is_initialized: boolean;
    active_executions: number;
    total_items_archived: number;
    total_archive_storage_mb: number;
    last_archive_time?: string;
    storage_backends_status: Record<string, 'healthy' | 'degraded' | 'unhealthy'>;
  };

  /**
   * Update configuration
   */
  updateConfig(config: Partial<ArchivalConfig>): void;

  /**
   * Get configuration
   */
  getConfig(): ArchivalConfig;

  /**
   * Shutdown service
   */
  shutdown(): Promise<void>;
}
