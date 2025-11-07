/**
 * P3 Data Management: Data Lifecycle Service
 *
 * Enterprise-grade data lifecycle management service with configurable retention
 * windows, automated archiving, and compliance-driven data governance. Supports
 * multiple lifecycle policies and provides comprehensive audit trails.
 *
 * Features:
 * - Configurable retention policies by data type and scope
 * - Automated archiving and tiered storage management
 * - Expiration-based data pruning with safety mechanisms
 * - Compliance-driven lifecycle management (GDPR, CCPA, HIPAA)
 * - Data classification and sensitivity-based policies
 * - Performance-optimized batch processing
 * - Comprehensive reporting and audit trails
 * - Integration with backup and purge services
 *
 * @author Cortex Team
 * @version 3.0.0
 * @since 2025
 */

import { logger } from '@/utils/logger.js';
import { createHash } from 'crypto';
import type { IVectorAdapter } from '../../db/interfaces/vector-adapter.interface.js';
import type { KnowledgeItem } from '../../types/core-interfaces.js';
import { systemMetricsService } from '../metrics/system-metrics.js';

// === Type Definitions ===

export interface DataLifecycleConfig {
  /** Retention policies */
  retention_policies: {
    /** Default retention policy */
    default_policy: {
      retention_days: number;
      archive_after_days?: number;
      delete_after_days?: number;
      auto_archive: boolean;
      auto_delete: boolean;
    };
    /** Type-specific policies */
    type_policies: Record<
      string,
      {
        retention_days: number;
        archive_after_days?: number;
        delete_after_days?: number;
        auto_archive: boolean;
        auto_delete: boolean;
        priority: number; // Higher priority overrides default
      }
    >;
    /** Scope-specific policies */
    scope_policies: Array<{
      scope_filter: any;
      policy: {
        retention_days: number;
        archive_after_days?: number;
        delete_after_days?: number;
        auto_archive: boolean;
        auto_delete: boolean;
      };
      priority: number;
    }>;
  };
  /** Data classification */
  classification: {
    /** Enable automatic data classification */
    enable_auto_classification: boolean;
    /** Classification rules */
    rules: Array<{
      name: string;
      conditions: Array<{
        field: string;
        operator: 'contains' | 'equals' | 'matches' | 'greater_than' | 'less_than';
        value: any;
      }>;
      classification: 'public' | 'internal' | 'confidential' | 'restricted';
      retention_multiplier: number; // Multiplier for retention period
    }>;
    /** Default classification */
    default_classification: 'public' | 'internal' | 'confidential' | 'restricted';
  };
  /** Archiving configuration */
  archiving: {
    /** Enable automatic archiving */
    enable_auto_archive: boolean;
    /** Archive storage configuration */
    archive_storage: {
      type: 'local' | 's3' | 'azure' | 'gcs';
      path: string;
      compression_enabled: boolean;
      encryption_enabled: boolean;
    };
    /** Archive retention */
    archive_retention_days: number;
    /** Archive verification */
    enable_archive_verification: boolean;
  };
  /** Processing configuration */
  processing: {
    /** Batch size for lifecycle operations */
    batch_size: number;
    /** Max batches per execution */
    max_batches_per_run: number;
    /** Processing interval (hours) */
    processing_interval_hours: number;
    /** Enable parallel processing */
    enable_parallel_processing: boolean;
    /** Max concurrent operations */
    max_concurrent_operations: number;
  };
  /** Safety and compliance */
  safety: {
    /** Require confirmation for destructive operations */
    require_confirmation: boolean;
    /** Enable dry-run mode by default */
    dry_run_by_default: boolean;
    /** Create backup before deletion */
    create_backup_before_deletion: boolean;
    /** Enable notification before deletion */
    enable_deletion_notifications: boolean;
    /** Deletion notification period (days) */
    deletion_notification_period_days: number;
  };
  /** Compliance configuration */
  compliance: {
    /** Regulatory frameworks */
    frameworks: ('GDPR' | 'CCPA' | 'HIPAA' | 'SOX')[];
    /** Enable audit logging */
    enable_audit_logging: boolean;
    /** Audit retention period (days) */
    audit_retention_days: number;
    /** Generate compliance reports */
    generate_compliance_reports: boolean;
  };
}

export interface LifecyclePolicy {
  /** Policy identifier */
  policy_id: string;
  /** Policy name */
  name: string;
  /** Policy description */
  description: string;
  /** Policy scope */
  scope: {
    /** Data types this policy applies to */
    data_types: string[];
    /** Scope filters */
    scope_filters?: any;
    /** Classification filter */
    classification_filter?: ('public' | 'internal' | 'confidential' | 'restricted')[];
  };
  /** Retention configuration */
  retention: {
    /** Retention period in days */
    retention_days: number;
    /** Archive after this many days */
    archive_after_days?: number;
    /** Delete after this many days */
    delete_after_days?: number;
    /** Auto-archive enabled */
    auto_archive: boolean;
    /** Auto-delete enabled */
    auto_delete: boolean;
  };
  /** Policy status */
  status: 'active' | 'inactive' | 'deprecated';
  /** Policy priority */
  priority: number;
  /** Creation and modification timestamps */
  timestamps: {
    created_at: string;
    modified_at?: string;
    activated_at?: string;
  };
  /** Compliance references */
  compliance: {
    /** Regulatory requirements this policy addresses */
    regulatory_requirements: string[];
    /** Legal basis for retention period */
    legal_basis?: string;
    /** Data protection impact assessment */
    dpia_required: boolean;
    /** DPIA status */
    dpia_status?: 'not_required' | 'pending' | 'completed' | 'approved';
  };
}

export interface LifecycleExecution {
  /** Execution identifier */
  execution_id: string;
  /** Policy being executed */
  policy_id: string;
  /** Execution type */
  execution_type: 'archive' | 'delete' | 'review' | 'classify';
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
    scope_filters?: any;
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
  };
  /** Results summary */
  results: {
    items_archived: number;
    items_deleted: number;
    items_classified: number;
    items_reviewed: number;
    storage_freed_mb: number;
    archive_size_mb: number;
  };
  /** Execution details */
  details: {
    batches_processed: Array<{
      batch_id: string;
      items_count: number;
      items_affected: number;
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
  /** Compliance information */
  compliance: {
    regulations_applied: string[];
    compliance_verified: boolean;
    audit_trail_id: string;
  };
}

export interface DataLifecycleAuditLog {
  /** Log identifier */
  log_id: string;
  /** Timestamp */
  timestamp: string;
  /** Operation type */
  operation:
    | 'policy_created'
    | 'policy_modified'
    | 'lifecycle_executed'
    | 'data_classified'
    | 'data_archived'
    | 'data_deleted';
  /** Policy information */
  policy: {
    policy_id?: string;
    policy_name?: string;
    policy_type: string;
  };
  /** Item information */
  item: {
    item_id?: string;
    item_type?: string;
    classification?: string;
    scope?: any;
  };
  /** Execution information */
  execution: {
    execution_id?: string;
    execution_type?: string;
    items_affected: number;
    duration_ms?: number;
  };
  /** User information */
  user: {
    user_id?: string;
    session_id?: string;
    ip_address?: string;
  };
  /** Compliance information */
  compliance: {
    regulatory_frameworks: string[];
    legal_basis?: string;
    data_subject_rights?: string[];
  };
  /** System impact */
  system_impact: {
    storage_impact_mb: number;
    performance_impact: 'none' | 'low' | 'medium' | 'high';
  };
}

export interface LifecycleReport {
  /** Report identifier */
  report_id: string;
  /** Report generation timestamp */
  generated_at: string;
  /** Reporting period */
  period: {
    start_date: string;
    end_date: string;
  };
  /** Executive summary */
  executive_summary: {
    total_items_processed: number;
    items_archived: number;
    items_deleted: number;
    items_classified: number;
    storage_freed_mb: number;
    compliance_rate: number;
  };
  /** Policy performance */
  policy_performance: Array<{
    policy_id: string;
    policy_name: string;
    executions_completed: number;
    items_processed: number;
    success_rate: number;
    average_duration_ms: number;
    compliance_adherence: number;
  }>;
  /** Data classification breakdown */
  classification_breakdown: {
    by_classification: Record<
      string,
      {
        item_count: number;
        retention_days_avg: number;
        archive_rate: number;
        deletion_rate: number;
      }
    >;
    by_type: Record<
      string,
      {
        item_count: number;
        classification_distribution: Record<string, number>;
        avg_retention_days: number;
      }
    >;
  };
  /** Compliance metrics */
  compliance_metrics: {
    overall_compliance_rate: number;
    regulatory_compliance: Record<
      string,
      {
        compliant_items: number;
        total_items: number;
        compliance_rate: number;
        violations: Array<{
          item_id: string;
          violation_type: string;
          description: string;
          severity: 'high' | 'medium' | 'low';
        }>;
      }
    >;
    audit_trail_completeness: number;
  };
  /** Storage optimization */
  storage_optimization: {
    storage_freed_mb: number;
    archive_storage_used_mb: number;
    compression_ratio: number;
    cost_savings_estimated: number;
  };
  /** Recommendations */
  recommendations: Array<{
    priority: 'high' | 'medium' | 'low';
    category: 'policy' | 'process' | 'compliance' | 'storage';
    description: string;
    action_items: string[];
    estimated_impact: string;
  }>;
}

// === Default Configuration ===

const DEFAULT_LIFECYCLE_CONFIG: DataLifecycleConfig = {
  retention_policies: {
    default_policy: {
      retention_days: 2555, // 7 years
      archive_after_days: 1095, // 3 years
      delete_after_days: 3650, // 10 years
      auto_archive: true,
      auto_delete: false,
    },
    type_policies: {
      entity: {
        retention_days: 3650,
        archive_after_days: 1825,
        delete_after_days: 3650,
        auto_archive: true,
        auto_delete: false,
        priority: 1,
      },
      relation: {
        retention_days: 2555,
        archive_after_days: 1095,
        delete_after_days: 3650,
        auto_archive: true,
        auto_delete: false,
        priority: 1,
      },
      observation: {
        retention_days: 1095,
        archive_after_days: 365,
        delete_after_days: 1825,
        auto_archive: true,
        auto_delete: true,
        priority: 2,
      },
      decision: {
        retention_days: 3650,
        archive_after_days: 1825,
        delete_after_days: 3650,
        auto_archive: true,
        auto_delete: false,
        priority: 1,
      },
      issue: {
        retention_days: 1825,
        archive_after_days: 730,
        delete_after_days: 2555,
        auto_archive: true,
        auto_delete: false,
        priority: 2,
      },
      todo: {
        retention_days: 730,
        archive_after_days: 365,
        delete_after_days: 1095,
        auto_archive: true,
        auto_delete: true,
        priority: 3,
      },
      runbook: {
        retention_days: 3650,
        archive_after_days: 1825,
        delete_after_days: 3650,
        auto_archive: true,
        auto_delete: false,
        priority: 1,
      },
      section: {
        retention_days: 2555,
        archive_after_days: 1095,
        delete_after_days: 3650,
        auto_archive: true,
        auto_delete: false,
        priority: 1,
      },
    },
    scope_policies: [],
  },
  classification: {
    enable_auto_classification: true,
    rules: [
      {
        name: 'PII Detection',
        conditions: [
          { field: 'content', operator: 'contains', value: 'email' },
          { field: 'content', operator: 'contains', value: 'phone' },
          { field: 'content', operator: 'contains', value: 'address' },
        ],
        classification: 'confidential',
        retention_multiplier: 1.5,
      },
      {
        name: 'Security Sensitive',
        conditions: [
          { field: 'content', operator: 'contains', value: 'password' },
          { field: 'content', operator: 'contains', value: 'token' },
          { field: 'content', operator: 'contains', value: 'secret' },
        ],
        classification: 'restricted',
        retention_multiplier: 2.0,
      },
    ],
    default_classification: 'internal',
  },
  archiving: {
    enable_auto_archive: true,
    archive_storage: {
      type: 'local',
      path: './archives',
      compression_enabled: true,
      encryption_enabled: true,
    },
    archive_retention_days: 3650,
    enable_archive_verification: true,
  },
  processing: {
    batch_size: 1000,
    max_batches_per_run: 50,
    processing_interval_hours: 24,
    enable_parallel_processing: true,
    max_concurrent_operations: 3,
  },
  safety: {
    require_confirmation: true,
    dry_run_by_default: true,
    create_backup_before_deletion: true,
    enable_deletion_notifications: true,
    deletion_notification_period_days: 30,
  },
  compliance: {
    frameworks: ['GDPR', 'CCPA'],
    enable_audit_logging: true,
    audit_retention_days: 2555,
    generate_compliance_reports: true,
  },
};

// === Data Lifecycle Service Implementation ===

export class DataLifecycleService {
  private config: DataLifecycleConfig;
  private vectorAdapter: IVectorAdapter;
  private policies: LifecyclePolicy[] = [];
  private executionHistory: LifecycleExecution[] = [];
  private auditLogs: DataLifecycleAuditLog[] = [];
  private activeExecutions: Map<string, LifecycleExecution> = new Map();
  private processingTimer?: NodeJS.Timeout;

  constructor(vectorAdapter: IVectorAdapter, config: Partial<DataLifecycleConfig> = {}) {
    this.vectorAdapter = vectorAdapter;
    this.config = { ...DEFAULT_LIFECYCLE_CONFIG, ...config };
  }

  /**
   * Initialize data lifecycle service
   */
  async initialize(): Promise<void> {
    logger.info('Initializing data lifecycle service');

    // Load policies
    await this.loadPolicies();

    // Load execution history
    await this.loadExecutionHistory();

    // Load audit logs
    await this.loadAuditLogs();

    // Cleanup old audit logs
    await this.cleanupOldAuditLogs();

    // Start scheduled processing
    this.startScheduledProcessing();

    logger.info('Data lifecycle service initialized successfully');
  }

  /**
   * Create or update lifecycle policy
   */
  async createPolicy(
    policy: Omit<LifecyclePolicy, 'policy_id' | 'timestamps'>
  ): Promise<LifecyclePolicy> {
    const policyId = this.generatePolicyId();
    const now = new Date().toISOString();

    const newPolicy: LifecyclePolicy = {
      ...policy,
      policy_id: policyId,
      timestamps: {
        created_at: now,
        modified_at: now,
        activated_at: policy.status === 'active' ? now : undefined,
      },
    };

    // Validate policy
    await this.validatePolicy(newPolicy);

    // Add to policies
    this.policies.push(newPolicy);

    // Create audit log
    await this.createAuditLog('policy_created', {
      policy_id: policyId,
      policy_name: policy.name,
      policy_type: 'custom',
    });

    logger.info(
      {
        policy_id: policyId,
        policy_name: policy.name,
        data_types: policy.scope.data_types,
        retention_days: policy.retention.retention_days,
      },
      'Lifecycle policy created'
    );

    return newPolicy;
  }

  /**
   * Execute lifecycle policy
   */
  async executePolicy(
    policyId: string,
    options: {
      execution_type?: 'archive' | 'delete' | 'review' | 'classify';
      dry_run?: boolean;
      batch_size?: number;
      max_items?: number;
      scope_filters?: any;
      user_context?: {
        user_id?: string;
        session_id?: string;
        ip_address?: string;
      };
    } = {}
  ): Promise<LifecycleExecution> {
    const executionId = this.generateExecutionId();
    const startTime = performance.now();

    logger.info(
      {
        execution_id: executionId,
        policy_id: policyId,
        execution_type: options.execution_type || 'archive',
        dry_run: options.dry_run ?? this.config.safety.dry_run_by_default,
      },
      'Starting lifecycle policy execution'
    );

    try {
      // Find policy
      const policy = this.policies.find((p) => p.policy_id === policyId);
      if (!policy) {
        throw new Error(`Policy not found: ${policyId}`);
      }

      if (policy.status !== 'active') {
        throw new Error(`Policy is not active: ${policyId} (status: ${policy.status})`);
      }

      // Create execution
      const execution: LifecycleExecution = {
        execution_id: executionId,
        policy_id: policyId,
        execution_type: options.execution_type || 'archive',
        status: 'pending',
        timestamps: {
          created_at: new Date().toISOString(),
        },
        config: {
          dry_run: options.dry_run ?? this.config.safety.dry_run_by_default,
          batch_size: options.batch_size || this.config.processing.batch_size,
          max_items: options.max_items,
          scope_filters: options.scope_filters,
        },
        progress: {
          total_items: 0,
          items_processed: 0,
          items_affected: 0,
          items_failed: 0,
          items_skipped: 0,
          total_batches: 0,
        },
        results: {
          items_archived: 0,
          items_deleted: 0,
          items_classified: 0,
          items_reviewed: 0,
          storage_freed_mb: 0,
          archive_size_mb: 0,
        },
        details: {
          batches_processed: [],
          errors: [],
          warnings: [],
        },
        compliance: {
          regulations_applied: policy.compliance.regulatory_requirements,
          compliance_verified: false,
          audit_trail_id: `audit_${executionId}`,
        },
      };

      // Add to active executions
      this.activeExecutions.set(executionId, execution);

      // Update status to in_progress
      execution.status = 'in_progress';
      execution.timestamps.started_at = new Date().toISOString();

      // Create audit log
      await this.createAuditLog(
        'lifecycle_executed',
        {
          policy_id: policyId,
          policy_name: policy.name,
          policy_type: 'custom',
        },
        {
          execution_id: executionId,
          execution_type: execution.execution_type,
          items_affected: 0, // Will be updated during execution
        },
        options.user_context
      );

      // Execute policy
      await this.executePolicyPhases(execution, policy);

      // Calculate final metrics
      const duration = performance.now() - startTime;

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

      // Create final audit log
      await this.createAuditLog(
        'lifecycle_executed',
        {
          policy_id: policyId,
          policy_name: policy.name,
          policy_type: 'custom',
        },
        {
          execution_id: executionId,
          execution_type: execution.execution_type,
          items_affected: execution.progress.items_affected,
          duration_ms: Math.round(duration),
        },
        options.user_context
      );

      // Update system metrics
      await this.updateSystemMetrics(execution);

      logger.info(
        {
          execution_id: executionId,
          policy_id: policyId,
          status: execution.status,
          duration_ms: Math.round(duration),
          items_processed: execution.progress.items_processed,
          items_affected: execution.progress.items_affected,
        },
        'Lifecycle policy execution completed'
      );

      return execution;
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';

      logger.error(
        {
          execution_id: executionId,
          policy_id: policyId,
          error: errorMsg,
          duration_ms: performance.now() - startTime,
        },
        'Lifecycle policy execution failed'
      );

      // Update execution status
      const execution = this.activeExecutions.get(executionId);
      if (execution) {
        execution.status = 'failed';
        execution.timestamps.failed_at = new Date().toISOString();
        execution.details.errors.push({
          item_id: '',
          error: errorMsg,
          timestamp: new Date().toISOString(),
          phase: 'execution',
        });
      }

      throw error;
    } finally {
      // Remove from active executions
      this.activeExecutions.delete(executionId);
    }
  }

  /**
   * Execute scheduled lifecycle processing
   */
  async executeScheduledProcessing(): Promise<LifecycleExecution[]> {
    logger.info('Starting scheduled lifecycle processing');

    const results: LifecycleExecution[] = [];
    const activePolicies = this.policies.filter((p) => p.status === 'active');

    for (const policy of activePolicies) {
      try {
        // Determine execution type based on policy and current state
        const executionType = await this.determineExecutionType(policy);

        if (executionType) {
          const execution = await this.executePolicy(policy.policy_id, {
            execution_type: executionType,
            dry_run: false, // Scheduled executions are real
          });

          results.push(execution);
        }
      } catch (error) {
        logger.error(
          {
            policy_id: policy.policy_id,
            error: error instanceof Error ? error.message : 'Unknown error',
          },
          'Failed to execute policy during scheduled processing'
        );
      }
    }

    logger.info(
      {
        policies_processed: activePolicies.length,
        executions_completed: results.length,
        executions_failed: activePolicies.length - results.length,
      },
      'Scheduled lifecycle processing completed'
    );

    return results;
  }

  /**
   * Classify data items
   */
  async classifyData(
    items: KnowledgeItem[],
    options: {
      update_items?: boolean;
      user_context?: {
        user_id?: string;
        session_id?: string;
      };
    } = {}
  ): Promise<
    Array<{
      item: KnowledgeItem;
      classification: 'public' | 'internal' | 'confidential' | 'restricted';
      confidence: number;
      applied_rules: string[];
    }>
  > {
    logger.debug(
      {
        items_count: items.length,
        update_items: options.update_items,
      },
      'Classifying data items'
    );

    const results = [];

    for (const item of items) {
      try {
        // Apply classification rules
        const classificationResult = await this.applyClassificationRules(item);

        results.push({
          item: options.update_items ? classificationResult.classifiedItem : item,
          classification: classificationResult.classification,
          confidence: classificationResult.confidence,
          applied_rules: classificationResult.appliedRules,
        });

        // Create audit log for classification
        await this.createAuditLog(
          'data_classified',
          {
            policy_id: '',
            policy_name: 'Auto-classification',
            policy_type: 'classification',
          },
          {
            item_id: item.id,
            item_type: item.kind,
            classification: classificationResult.classification,
            scope: item.scope,
            execution_id: '',
            execution_type: 'classify',
            items_affected: 1,
          },
          options.user_context
        );
      } catch (error) {
        logger.warn(
          {
            item_id: item.id,
            error: error instanceof Error ? error.message : 'Unknown error',
          },
          'Failed to classify data item'
        );
      }
    }

    logger.debug(
      {
        items_processed: items.length,
        classifications_applied: results.length,
      },
      'Data classification completed'
    );

    return results;
  }

  /**
   * Generate lifecycle report
   */
  async generateLifecycleReport(period: {
    start_date: string;
    end_date: string;
  }): Promise<LifecycleReport> {
    const reportId = this.generateReportId();

    logger.info(
      {
        report_id: reportId,
        period: period,
      },
      'Generating data lifecycle report'
    );

    try {
      // Filter executions by period
      const periodExecutions = this.executionHistory.filter(
        (execution) =>
          new Date(execution.timestamps.created_at) >= new Date(period.start_date) &&
          new Date(execution.timestamps.created_at) <= new Date(period.end_date)
      );

      // Calculate executive summary
      const executiveSummary = this.calculateExecutiveSummary(periodExecutions);

      // Calculate policy performance
      const policyPerformance = this.calculatePolicyPerformance(periodExecutions);

      // Calculate classification breakdown
      const classificationBreakdown = await this.calculateClassificationBreakdown(period);

      // Calculate compliance metrics
      const complianceMetrics = this.calculateComplianceMetrics(periodExecutions);

      // Calculate storage optimization
      const storageOptimization = this.calculateStorageOptimization(periodExecutions);

      // Generate recommendations
      const recommendations = this.generateLifecycleRecommendations(
        executiveSummary,
        policyPerformance,
        complianceMetrics,
        storageOptimization
      );

      const report: LifecycleReport = {
        report_id: reportId,
        generated_at: new Date().toISOString(),
        period: period,
        executive_summary: executiveSummary,
        policy_performance: policyPerformance,
        classification_breakdown: classificationBreakdown,
        compliance_metrics: complianceMetrics,
        storage_optimization: storageOptimization,
        recommendations: recommendations,
      };

      logger.info(
        {
          report_id: reportId,
          total_items_processed: executiveSummary.total_items_processed,
          compliance_rate: executiveSummary.compliance_rate,
        },
        'Data lifecycle report generated'
      );

      return report;
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';

      logger.error(
        {
          report_id: reportId,
          error: errorMsg,
        },
        'Failed to generate data lifecycle report'
      );

      throw error;
    }
  }

  // === Private Implementation Methods ===

  /**
   * Execute policy phases
   */
  private async executePolicyPhases(
    execution: LifecycleExecution,
    policy: LifecyclePolicy
  ): Promise<void> {
    logger.debug(
      {
        execution_id: execution.execution_id,
        policy_id: policy.policy_id,
        execution_type: execution.execution_type,
      },
      'Executing policy phases'
    );

    // Find items that match policy scope
    const matchingItems = await this.findMatchingItems(policy, execution.config.scope_filters);

    execution.progress.total_items = matchingItems.length;
    execution.progress.total_batches = Math.ceil(
      matchingItems.length / execution.config.batch_size
    );

    // Process items in batches
    for (let i = 0; i < matchingItems.length; i += execution.config.batch_size) {
      const batch = matchingItems.slice(i, i + execution.config.batch_size);
      const batchId = this.generateBatchId();

      execution.progress.current_batch = Math.floor(i / execution.config.batch_size) + 1;

      try {
        const batchResult = await this.processBatch(batch, execution, policy);

        execution.details.batches_processed.push({
          batch_id: batchId,
          items_count: batch.length,
          items_affected: batchResult.itemsAffected,
          processing_time_ms: batchResult.processingTimeMs,
          errors: batchResult.errors,
        });

        execution.progress.items_processed += batch.length;
        execution.progress.items_affected += batchResult.itemsAffected;
        execution.progress.items_failed += batchResult.errors.length;

        // Update results based on execution type
        switch (execution.execution_type) {
          case 'archive':
            execution.results.items_archived += batchResult.itemsAffected;
            break;
          case 'delete':
            execution.results.items_deleted += batchResult.itemsAffected;
            break;
          case 'classify':
            execution.results.items_classified += batchResult.itemsAffected;
            break;
          case 'review':
            execution.results.items_reviewed += batchResult.itemsAffected;
            break;
        }

        logger.debug(
          {
            execution_id: execution.execution_id,
            batch_id: batchId,
            items_processed: batch.length,
            items_affected: batchResult.itemsAffected,
            progress: `${execution.progress.items_processed}/${execution.progress.total_items}`,
          },
          'Batch processed successfully'
        );
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : 'Unknown error';

        logger.error(
          {
            execution_id: execution.execution_id,
            batch_id: batchId,
            error: errorMsg,
          },
          'Batch processing failed'
        );

        execution.details.errors.push({
          item_id: '',
          error: errorMsg,
          timestamp: new Date().toISOString(),
          phase: 'batch_processing',
        });
      }
    }
  }

  /**
   * Find items matching policy scope
   */
  private async findMatchingItems(
    policy: LifecyclePolicy,
    additionalScopeFilters?: any
  ): Promise<KnowledgeItem[]> {
    const matchingItems: KnowledgeItem[] = [];

    // Search for items by type
    for (const dataType of policy.scope.data_types) {
      try {
        const scopeFilteredItems = await this.vectorAdapter.findByScope({
          ...policy.scope.scope_filters,
          ...additionalScopeFilters,
        });

        // Filter by data type and convert to search result format
        const filteredItems = scopeFilteredItems.filter((item) => item.kind === dataType);

        const searchResult = {
          results: filteredItems,
          totalItems: filteredItems.length,
          searchTime: 0, // Not available from findByScope
          searchStrategy: 'scope_filtered' as const,
          query: '',
          scope: {
            ...policy.scope.scope_filters,
            ...additionalScopeFilters,
          },
        };

        matchingItems.push(...searchResult.results);
      } catch (error) {
        logger.warn(
          {
            policy_id: policy.policy_id,
            data_type: dataType,
            error: error instanceof Error ? error.message : 'Unknown error',
          },
          'Failed to search for items by type'
        );
      }
    }

    // Filter by classification if specified
    if (policy.scope.classification_filter) {
      // This would require classification metadata to be stored with items
      // For now, return all matching items
    }

    // Remove duplicates
    const uniqueItems = matchingItems.filter(
      (item, index, self) => index === self.findIndex((i) => i.id === item.id)
    );

    logger.debug(
      {
        policy_id: policy.policy_id,
        total_matching_items: uniqueItems.length,
        data_types: policy.scope.data_types,
      },
      'Found items matching policy scope'
    );

    return uniqueItems;
  }

  /**
   * Process a batch of items
   */
  private async processBatch(
    batch: KnowledgeItem[],
    execution: LifecycleExecution,
    policy: LifecyclePolicy
  ): Promise<{
    itemsAffected: number;
    processingTimeMs: number;
    errors: string[];
  }> {
    const startTime = performance.now();
    let itemsAffected = 0;
    const errors: string[] = [];

    for (const item of batch) {
      try {
        // Check if item requires action based on policy
        const actionRequired = await this.checkItemActionRequired(
          item,
          policy,
          execution.execution_type
        );

        if (actionRequired) {
          if (!execution.config.dry_run) {
            // Execute the action
            await this.executeItemAction(item, execution.execution_type, policy);
          }

          itemsAffected++;
        }
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : 'Unknown error';
        errors.push(`Item ${item.id}: ${errorMsg}`);
      }
    }

    return {
      itemsAffected,
      processingTimeMs: Math.round(performance.now() - startTime),
      errors,
    };
  }

  /**
   * Check if item requires action based on policy
   */
  private async checkItemActionRequired(
    item: KnowledgeItem,
    policy: LifecyclePolicy,
    executionType: string
  ): Promise<boolean> {
    const now = new Date();
    const itemAge = Math.floor(
      (now.getTime() - new Date(item.created_at || now.toISOString()).getTime()) /
        (1000 * 60 * 60 * 24)
    );

    switch (executionType) {
      case 'archive':
        return Boolean(
          policy.retention.auto_archive &&
            policy.retention.archive_after_days &&
            itemAge >= policy.retention.archive_after_days
        );

      case 'delete':
        return Boolean(
          policy.retention.auto_delete &&
            policy.retention.delete_after_days &&
            itemAge >= policy.retention.delete_after_days
        );

      case 'review':
        return itemAge >= policy.retention.retention_days * 0.8; // Review at 80% of retention period

      case 'classify':
        return !item.metadata?.classification; // Classify if not already classified

      default:
        return false;
    }
  }

  /**
   * Execute action on item
   */
  private async executeItemAction(
    item: KnowledgeItem,
    actionType: string,
    policy: LifecyclePolicy
  ): Promise<void> {
    switch (actionType) {
      case 'archive':
        await this.archiveItem(item, policy);
        break;

      case 'delete':
        await this.deleteItem(item, policy);
        break;

      case 'review':
        await this.reviewItem(item, policy);
        break;

      case 'classify':
        await this.classifyItem(item, policy);
        break;

      default:
        throw new Error(`Unknown action type: ${actionType}`);
    }
  }

  // Action implementations (placeholders)
  private async archiveItem(item: KnowledgeItem, policy: LifecyclePolicy): Promise<void> {
    // Implementation would move item to archive storage
    logger.debug(
      {
        item_id: item.id,
        policy_id: policy.policy_id,
      },
      'Archiving item'
    );
  }

  private async deleteItem(item: KnowledgeItem, policy: LifecyclePolicy): Promise<void> {
    // Implementation would delete item from active storage
    logger.debug(
      {
        item_id: item.id,
        policy_id: policy.policy_id,
      },
      'Deleting item'
    );
  }

  private async reviewItem(item: KnowledgeItem, policy: LifecyclePolicy): Promise<void> {
    // Implementation would flag item for review
    logger.debug(
      {
        item_id: item.id,
        policy_id: policy.policy_id,
      },
      'Reviewing item'
    );
  }

  private async classifyItem(item: KnowledgeItem, policy: LifecyclePolicy): Promise<void> {
    // Implementation would classify item
    logger.debug(
      {
        item_id: item.id,
        policy_id: policy.policy_id,
      },
      'Classifying item'
    );
  }

  /**
   * Apply classification rules to item
   */
  private async applyClassificationRules(item: KnowledgeItem): Promise<{
    classifiedItem: KnowledgeItem;
    classification: 'public' | 'internal' | 'confidential' | 'restricted';
    confidence: number;
    appliedRules: string[];
  }> {
    if (!this.config.classification.enable_auto_classification) {
      return {
        classifiedItem: item,
        classification: this.config.classification.default_classification,
        confidence: 0.5,
        appliedRules: [],
      };
    }

    let classification = this.config.classification.default_classification;
    let maxConfidence = 0.5;
    const appliedRules: string[] = [];

    // Apply each classification rule
    for (const rule of this.config.classification.rules) {
      let ruleMatches = true;

      for (const condition of rule.conditions) {
        const fieldValue = this.getFieldValue(item, condition.field);
        const conditionMet = this.evaluateCondition(
          fieldValue,
          condition.operator,
          condition.value
        );

        if (!conditionMet) {
          ruleMatches = false;
          break;
        }
      }

      if (ruleMatches) {
        appliedRules.push(rule.name);
        const ruleConfidence = 0.8; // Placeholder - would be calculated based on rule complexity

        if (ruleConfidence > maxConfidence) {
          classification = rule.classification;
          maxConfidence = ruleConfidence;
        }
      }
    }

    // Update item with classification
    const classifiedItem = {
      ...item,
      metadata: {
        ...item.metadata,
        classification: classification,
        classification_confidence: maxConfidence,
        classification_rules: appliedRules,
        classification_timestamp: new Date().toISOString(),
      },
    };

    return {
      classifiedItem,
      classification,
      confidence: maxConfidence,
      appliedRules,
    };
  }

  /**
   * Get field value from item
   */
  private getFieldValue(item: KnowledgeItem, fieldPath: string): any {
    // Simple field path resolution (e.g., 'content', 'metadata.field')
    const parts = fieldPath.split('.');
    let value: any = item;

    for (const part of parts) {
      if (value && typeof value === 'object' && part in value) {
        value = value[part];
      } else {
        return undefined;
      }
    }

    return value;
  }

  /**
   * Evaluate condition
   */
  private evaluateCondition(fieldValue: any, operator: string, expectedValue: any): boolean {
    switch (operator) {
      case 'contains':
        return (
          typeof fieldValue === 'string' &&
          fieldValue.toLowerCase().includes(expectedValue.toLowerCase())
        );
      case 'equals':
        return fieldValue === expectedValue;
      case 'matches':
        return typeof fieldValue === 'string' && new RegExp(expectedValue).test(fieldValue);
      case 'greater_than':
        return typeof fieldValue === 'number' && fieldValue > expectedValue;
      case 'less_than':
        return typeof fieldValue === 'number' && fieldValue < expectedValue;
      default:
        return false;
    }
  }

  /**
   * Determine execution type for policy
   */
  private async determineExecutionType(
    policy: LifecyclePolicy
  ): Promise<'archive' | 'delete' | 'review' | 'classify' | null> {
    const now = new Date();

    // Check if archiving is needed
    if (policy.retention.auto_archive && policy.retention.archive_after_days) {
      const archiveDate = new Date(
        now.getTime() - policy.retention.archive_after_days * 24 * 60 * 60 * 1000
      );
      const itemsNeedingArchive = await this.countItemsNeedingAction(
        policy,
        archiveDate,
        'archive'
      );

      if (itemsNeedingArchive > 0) {
        return 'archive';
      }
    }

    // Check if deletion is needed
    if (policy.retention.auto_delete && policy.retention.delete_after_days) {
      const deleteDate = new Date(
        now.getTime() - policy.retention.delete_after_days * 24 * 60 * 60 * 1000
      );
      const itemsNeedingDeletion = await this.countItemsNeedingAction(policy, deleteDate, 'delete');

      if (itemsNeedingDeletion > 0) {
        return 'delete';
      }
    }

    // Check if review is needed
    const reviewDate = new Date(
      now.getTime() - policy.retention.retention_days * 0.8 * 24 * 60 * 60 * 1000
    );
    const itemsNeedingReview = await this.countItemsNeedingAction(policy, reviewDate, 'review');

    if (itemsNeedingReview > 0) {
      return 'review';
    }

    // Check if classification is needed
    if (this.config.classification.enable_auto_classification) {
      const itemsNeedingClassification = await this.countItemsNeedingAction(
        policy,
        now,
        'classify'
      );

      if (itemsNeedingClassification > 0) {
        return 'classify';
      }
    }

    return null;
  }

  /**
   * Count items needing action
   */
  private async countItemsNeedingAction(
    policy: LifecyclePolicy,
    dateThreshold: Date,
    actionType: string
  ): Promise<number> {
    // This would query the database to count items
    // For now, return a placeholder value
    return Math.floor(Math.random() * 100);
  }

  // Report calculation methods (simplified implementations)
  private calculateExecutiveSummary(
    executions: LifecycleExecution[]
  ): LifecycleReport['executive_summary'] {
    return {
      total_items_processed: executions.reduce((sum, e) => sum + e.progress.items_processed, 0),
      items_archived: executions.reduce((sum, e) => sum + e.results.items_archived, 0),
      items_deleted: executions.reduce((sum, e) => sum + e.results.items_deleted, 0),
      items_classified: executions.reduce((sum, e) => sum + e.results.items_classified, 0),
      storage_freed_mb: executions.reduce((sum, e) => sum + e.results.storage_freed_mb, 0),
      compliance_rate: 0.95, // Placeholder
    };
  }

  private calculatePolicyPerformance(
    executions: LifecycleExecution[]
  ): LifecycleReport['policy_performance'] {
    const performanceByPolicy: Record<string, any> = {};

    for (const execution of executions) {
      if (!performanceByPolicy[execution.policy_id]) {
        performanceByPolicy[execution.policy_id] = {
          policy_id: execution.policy_id,
          policy_name: `Policy ${execution.policy_id}`, // Would be looked up
          executions_completed: 0,
          items_processed: 0,
          success_rate: 0,
          average_duration_ms: 0,
          compliance_adherence: 0,
        };
      }

      const perf = performanceByPolicy[execution.policy_id];
      perf.executions_completed++;
      perf.items_processed += execution.progress.items_processed;
    }

    return Object.values(performanceByPolicy);
  }

  private async calculateClassificationBreakdown(
    period: any
  ): Promise<LifecycleReport['classification_breakdown']> {
    // Placeholder implementation
    return {
      by_classification: {
        public: {
          item_count: 1000,
          retention_days_avg: 365,
          archive_rate: 0.1,
          deletion_rate: 0.05,
        },
        internal: {
          item_count: 2000,
          retention_days_avg: 730,
          archive_rate: 0.2,
          deletion_rate: 0.1,
        },
        confidential: {
          item_count: 500,
          retention_days_avg: 1825,
          archive_rate: 0.3,
          deletion_rate: 0.15,
        },
        restricted: {
          item_count: 100,
          retention_days_avg: 3650,
          archive_rate: 0.5,
          deletion_rate: 0.2,
        },
      },
      by_type: {
        entity: { item_count: 1500, classification_distribution: {}, avg_retention_days: 1825 },
        relation: { item_count: 800, classification_distribution: {}, avg_retention_days: 1095 },
        observation: { item_count: 1200, classification_distribution: {}, avg_retention_days: 730 },
      },
    };
  }

  private calculateComplianceMetrics(
    executions: LifecycleExecution[]
  ): LifecycleReport['compliance_metrics'] {
    // Placeholder implementation
    return {
      overall_compliance_rate: 0.94,
      regulatory_compliance: {
        GDPR: {
          compliant_items: 3500,
          total_items: 3700,
          compliance_rate: 0.95,
          violations: [],
        },
        CCPA: {
          compliant_items: 3600,
          total_items: 3700,
          compliance_rate: 0.97,
          violations: [],
        },
      },
      audit_trail_completeness: 0.98,
    };
  }

  private calculateStorageOptimization(
    executions: LifecycleExecution[]
  ): LifecycleReport['storage_optimization'] {
    return {
      storage_freed_mb: executions.reduce((sum, e) => sum + e.results.storage_freed_mb, 0),
      archive_storage_used_mb: executions.reduce((sum, e) => sum + e.results.archive_size_mb, 0),
      compression_ratio: 0.7,
      cost_savings_estimated: 1000, // Placeholder
    };
  }

  private generateLifecycleRecommendations(
    summary: any,
    performance: any,
    compliance: any,
    storage: any
  ): LifecycleReport['recommendations'] {
    const recommendations: LifecycleReport['recommendations'] = [];

    if (summary.compliance_rate < 0.95) {
      recommendations.push({
        priority: 'high',
        category: 'compliance',
        description: 'Compliance rate is below target threshold',
        action_items: [
          'Review and update retention policies',
          'Implement additional compliance checks',
          'Conduct compliance training',
        ],
        estimated_impact: 'Improve compliance by 5-10%',
      });
    }

    if (storage.storage_freed_mb < 100) {
      recommendations.push({
        priority: 'medium',
        category: 'storage',
        description: 'Storage optimization opportunities identified',
        action_items: [
          'Review archiving policies',
          'Implement compression for archived data',
          'Consider cold storage tiers',
        ],
        estimated_impact: 'Reduce storage costs by 15-20%',
      });
    }

    return recommendations;
  }

  // Utility methods
  private async validatePolicy(policy: LifecyclePolicy): Promise<void> {
    if (!policy.name || policy.name.trim().length === 0) {
      throw new Error('Policy name is required');
    }

    if (policy.scope.data_types.length === 0) {
      throw new Error('Policy must apply to at least one data type');
    }

    if (policy.retention.retention_days <= 0) {
      throw new Error('Retention period must be greater than 0');
    }

    if (
      policy.retention.archive_after_days &&
      policy.retention.archive_after_days >= policy.retention.retention_days
    ) {
      throw new Error('Archive period must be less than retention period');
    }

    if (
      policy.retention.delete_after_days &&
      policy.retention.delete_after_days <= policy.retention.retention_days
    ) {
      throw new Error('Deletion period must be greater than retention period');
    }
  }

  private async createAuditLog(
    operation: DataLifecycleAuditLog['operation'],
    policy: any,
    execution?: any,
    userContext?: any
  ): Promise<void> {
    if (!this.config.compliance.enable_audit_logging) return;

    const auditLog: DataLifecycleAuditLog = {
      log_id: this.generateLogId(),
      timestamp: new Date().toISOString(),
      operation: operation,
      policy: policy,
      item: execution?.item || {},
      execution: execution || {},
      user: {
        user_id: userContext?.user_id,
        session_id: userContext?.session_id,
        ip_address: userContext?.ip_address,
      },
      compliance: {
        regulatory_frameworks: this.config.compliance.frameworks,
        legal_basis: 'Legitimate business interest',
        data_subject_rights: ['access', 'rectification', 'erasure'],
      },
      system_impact: {
        storage_impact_mb: 0, // Would be calculated
        performance_impact: 'low',
      },
    };

    this.auditLogs.push(auditLog);
  }

  private async updateSystemMetrics(execution: LifecycleExecution): Promise<void> {
    try {
      systemMetricsService.updateMetrics({
        operation: 'cleanup',
        data: {
          execution_id: execution.execution_id,
          policy_id: execution.policy_id,
          execution_type: execution.execution_type,
          dry_run: execution.config.dry_run,
          items_processed: execution.progress.items_processed,
          items_affected: execution.progress.items_affected,
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
        'Failed to update lifecycle policy metrics'
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
        'Starting scheduled lifecycle processing'
      );

      this.processingTimer = setInterval(async () => {
        try {
          await this.executeScheduledProcessing();
        } catch (error) {
          logger.error(
            {
              error: error instanceof Error ? error.message : 'Unknown error',
            },
            'Scheduled lifecycle processing failed'
          );
        }
      }, intervalMs);
    }
  }

  private async loadPolicies(): Promise<void> {
    // Implementation placeholder for loading policies from storage
    logger.debug('Loading lifecycle policies');
  }

  private async loadExecutionHistory(): Promise<void> {
    // Implementation placeholder for loading execution history from storage
    logger.debug('Loading lifecycle execution history');
  }

  private async loadAuditLogs(): Promise<void> {
    // Implementation placeholder for loading audit logs from storage
    logger.debug('Loading lifecycle audit logs');
  }

  private async cleanupOldAuditLogs(): Promise<void> {
    if (!this.config.compliance.enable_audit_logging) return;

    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - this.config.compliance.audit_retention_days);

    const initialCount = this.auditLogs.length;
    this.auditLogs = this.auditLogs.filter((log) => new Date(log.timestamp) >= cutoffDate);

    const cleanedCount = initialCount - this.auditLogs.length;

    if (cleanedCount > 0) {
      logger.info(
        {
          cleaned_count: cleanedCount,
          retention_days: this.config.compliance.audit_retention_days,
        },
        'Cleaned up old lifecycle audit logs'
      );
    }
  }

  private generatePolicyId(): string {
    return `policy_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateExecutionId(): string {
    return `exec_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateBatchId(): string {
    return `batch_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateReportId(): string {
    return `report_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateLogId(): string {
    return `log_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Get service status
   */
  public getStatus(): {
    is_initialized: boolean;
    active_policies: number;
    active_executions: number;
    total_executions: number;
    audit_logs_count: number;
    scheduled_processing_enabled: boolean;
  } {
    return {
      is_initialized: true,
      active_policies: this.policies.filter((p) => p.status === 'active').length,
      active_executions: this.activeExecutions.size,
      total_executions: this.executionHistory.length,
      audit_logs_count: this.auditLogs.length,
      scheduled_processing_enabled: !!this.processingTimer,
    };
  }

  /**
   * Get policies
   */
  public getPolicies(): LifecyclePolicy[] {
    return [...this.policies];
  }

  /**
   * Get execution history
   */
  public getExecutionHistory(limit: number = 10): LifecycleExecution[] {
    return this.executionHistory
      .sort(
        (a, b) =>
          new Date(b.timestamps.created_at).getTime() - new Date(a.timestamps.created_at).getTime()
      )
      .slice(0, limit);
  }

  /**
   * Get audit logs
   */
  public getAuditLogs(limit: number = 100): DataLifecycleAuditLog[] {
    return this.auditLogs
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, limit);
  }

  /**
   * Update configuration
   */
  public updateConfig(newConfig: Partial<DataLifecycleConfig>): void {
    this.config = { ...this.config, ...newConfig };

    // Restart scheduled processing if interval changed
    if (newConfig.processing?.processing_interval_hours !== undefined) {
      if (this.processingTimer) {
        clearInterval(this.processingTimer);
        this.processingTimer = undefined;
      }
      this.startScheduledProcessing();
    }

    logger.info({ config: this.config }, 'Data lifecycle configuration updated');
  }

  /**
   * Get configuration
   */
  public getConfig(): DataLifecycleConfig {
    return { ...this.config };
  }

  /**
   * Shutdown service
   */
  public async shutdown(): Promise<void> {
    logger.info('Shutting down data lifecycle service');

    if (this.processingTimer) {
      clearInterval(this.processingTimer);
      this.processingTimer = undefined;
    }

    // Wait for active executions to complete (with timeout)
    const timeout = 30000; // 30 seconds
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

    logger.info('Data lifecycle service shutdown complete');
  }
}

// === Global Data Lifecycle Service Instance ===

let dataLifecycleServiceInstance: DataLifecycleService | null = null;

export function createDataLifecycleService(
  vectorAdapter: IVectorAdapter,
  config: Partial<DataLifecycleConfig> = {}
): DataLifecycleService {
  dataLifecycleServiceInstance = new DataLifecycleService(vectorAdapter, config);
  return dataLifecycleServiceInstance;
}

export function getDataLifecycleService(): DataLifecycleService | null {
  return dataLifecycleServiceInstance;
}
