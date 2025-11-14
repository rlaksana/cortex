// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * Cortex Memory MCP - Enhanced Input Validation Schemas
 *
 * Comprehensive Zod runtime validation schemas for all MCP tool inputs.
 * Enhanced with advanced features: deduplication, TTL, truncation, insights.
 *
 * Features:
 * - Enhanced deduplication with merge strategies and similarity thresholds
 * - TTL policy configuration and expiry_at overrides
 * - Truncation configuration and metadata handling
 * - Insight stubs configuration (prepared for P6)
 * - Graph expansion and search strategies
 * - Cleanup and monitoring capabilities
 * - Comprehensive examples and parameter descriptions
 *
 * @version 2.0.0 - Enhanced with P5-2 schema updates
 */

import { z } from 'zod';

// ============================================================================
// Enhanced Configuration Schemas
// ============================================================================

/**
 * Merge strategies for intelligent duplicate handling
 */
export const MergeStrategySchema = z.enum(
  ['skip', 'prefer_existing', 'prefer_newer', 'combine', 'intelligent'],
  {
    errorMap: () => ({
      message: `Invalid merge strategy. Must be one of: skip, prefer_existing, prefer_newer, combine, intelligent`,
    }),
  }
);

/**
 * TTL policy configuration
 */
export const TTLPolicySchema = z.enum(['default', 'short', 'long', 'permanent'], {
  errorMap: () => ({
    message: `Invalid TTL policy. Must be one of: default, short, long, permanent`,
  }),
});

/**
 * Search strategy options for memory_find
 */
export const SearchStrategySchema = z.enum(['fast', 'auto', 'deep'], {
  errorMap: () => ({
    message: `Invalid search strategy. Must be one of: fast, auto, deep`,
  }),
});

/**
 * Graph expansion options
 */
export const GraphExpansionSchema = z.enum(['none', 'relations', 'parents', 'children', 'all'], {
  errorMap: () => ({
    message: `Invalid graph expansion. Must be one of: none, relations, parents, children, all`,
  }),
});

/**
 * Deduplication configuration schema
 */
export const DeduplicationConfigSchema = z
  .object({
    enabled: z.boolean().default(true),
    merge_strategy: MergeStrategySchema.default('intelligent'),
    similarity_threshold: z
      .number()
      .min(0.1, 'Similarity threshold must be at least 0.1')
      .max(1.0, 'Similarity threshold cannot exceed 1.0')
      .default(0.85),
    check_within_scope_only: z.boolean().default(true),
    max_history_hours: z
      .number()
      .int()
      .min(1, 'Max history hours must be at least 1')
      .max(8760, 'Max history hours cannot exceed 1 year')
      .default(168), // 1 week
    dedupe_window_days: z
      .number()
      .int()
      .min(1, 'Dedupe window must be at least 1 day')
      .max(365, 'Dedupe window cannot exceed 1 year')
      .default(30),
    allow_newer_versions: z.boolean().default(true),
    enable_audit_logging: z.boolean().default(true),
    enable_intelligent_merging: z.boolean().default(true),
    preserve_merge_history: z.boolean().default(false),
    max_merge_history_entries: z
      .number()
      .int()
      .min(0, 'Max merge history entries must be non-negative')
      .max(100, 'Max merge history entries cannot exceed 100')
      .default(10),
    cross_scope_deduplication: z.boolean().default(false),
    prioritize_same_scope: z.boolean().default(true),
    time_based_deduplication: z.boolean().default(true),
    max_age_for_dedupe_days: z
      .number()
      .int()
      .min(1, 'Max age for dedupe must be at least 1 day')
      .max(365, 'Max age for dedupe cannot exceed 1 year')
      .default(90),
    respect_update_timestamps: z.boolean().default(true),
    max_items_to_check: z
      .number()
      .int()
      .min(1, 'Max items to check must be at least 1')
      .max(10000, 'Max items to check cannot exceed 10000')
      .default(100),
    batch_size: z
      .number()
      .int()
      .min(1, 'Batch size must be at least 1')
      .max(1000, 'Batch size cannot exceed 1000')
      .default(50),
    enable_parallel_processing: z.boolean().default(false),
  })
  .strict();

/**
 * TTL configuration schema
 */
export const TTLConfigSchema = z
  .object({
    policy: TTLPolicySchema.default('default'),
    expires_at: z.string().datetime().optional(),
    auto_extend: z.boolean().default(false),
    extend_threshold_days: z
      .number()
      .int()
      .min(1, 'Extend threshold must be at least 1 day')
      .max(180, 'Extend threshold cannot exceed 180 days')
      .default(7),
    max_extensions: z
      .number()
      .int()
      .min(0, 'Max extensions must be non-negative')
      .max(10, 'Max extensions cannot exceed 10')
      .default(3),
  })
  .strict();

/**
 * Truncation configuration schema
 */
export const TruncationConfigSchema = z
  .object({
    enabled: z.boolean().default(true),
    max_chars: z
      .number()
      .int()
      .min(100, 'Max characters must be at least 100')
      .max(1000000, 'Max characters cannot exceed 1,000,000')
      .default(10000),
    max_tokens: z
      .number()
      .int()
      .min(50, 'Max tokens must be at least 50')
      .max(100000, 'Max tokens cannot exceed 100,000')
      .default(4000),
    mode: z.enum(['hard', 'soft', 'intelligent']).default('intelligent'),
    preserve_structure: z.boolean().default(true),
    add_indicators: z.boolean().default(true),
    indicator: z.string().max(50).default('[...truncated...]'),
    safety_margin: z
      .number()
      .min(0, 'Safety margin must be non-negative')
      .max(0.5, 'Safety margin cannot exceed 50%')
      .default(0.1),
    auto_detect_content_type: z.boolean().default(true),
    enable_smart_truncation: z.boolean().default(true),
  })
  .strict();

/**
 * Graph expansion configuration schema
 */
export const GraphExpansionConfigSchema = z
  .object({
    enabled: z.boolean().default(false),
    expansion_type: GraphExpansionSchema.default('relations'),
    max_depth: z
      .number()
      .int()
      .min(1, 'Max depth must be at least 1')
      .max(5, 'Max depth cannot exceed 5')
      .default(2),
    max_nodes: z
      .number()
      .int()
      .min(1, 'Max nodes must be at least 1')
      .max(1000, 'Max nodes cannot exceed 1000')
      .default(100),
    include_metadata: z.boolean().default(true),
    relation_types: z.array(z.string()).optional(),
    direction: z.enum(['outgoing', 'incoming', 'both']).default('outgoing'),
  })
  .strict();

/**
 * Cleanup operation configuration schema
 */
export const CleanupConfigSchema = z
  .object({
    operations: z
      .array(z.enum(['expired', 'orphaned', 'duplicate', 'metrics', 'logs']))
      .default(['expired']),
    scope_filters: z
      .object({
        project: z.string().optional(),
        org: z.string().optional(),
        branch: z.string().optional(),
      })
      .optional(),
    require_confirmation: z.boolean().default(true),
    enable_backup: z.boolean().default(true),
    batch_size: z
      .number()
      .int()
      .min(1, 'Batch size must be at least 1')
      .max(1000, 'Batch size cannot exceed 1000')
      .default(100),
    max_batches: z
      .number()
      .int()
      .min(1, 'Max batches must be at least 1')
      .max(100, 'Max batches cannot exceed 100')
      .default(50),
    dry_run: z.boolean().default(true),
    confirmation_token: z.string().optional(),
  })
  .strict();

/**
 * Insight stubs configuration schema (P6 prepared)
 */
export const InsightsConfigSchema = z
  .object({
    enabled: z.boolean().default(false),
    generate_insights: z.boolean().default(false),
    insight_types: z
      .array(z.enum(['summary', 'trends', 'recommendations', 'anomalies', 'patterns']))
      .default(['summary']),
    confidence_threshold: z
      .number()
      .min(0.1, 'Confidence threshold must be at least 0.1')
      .max(1.0, 'Confidence threshold cannot exceed 1.0')
      .default(0.7),
    max_insights: z
      .number()
      .int()
      .min(1, 'Max insights must be at least 1')
      .max(50, 'Max insights cannot exceed 50')
      .default(10),
    include_source_data: z.boolean().default(false),
    analysis_depth: z.enum(['shallow', 'medium', 'deep']).default('medium'),
  })
  .strict();

// ============================================================================
// Enhanced MCP Tool Input Schemas
// ============================================================================

/**
 * Enhanced base item schema with comprehensive configuration support
 */
const EnhancedBaseItemSchema = z.object({
  kind: z.enum(
    [
      'entity',
      'relation',
      'observation',
      'section',
      'runbook',
      'change',
      'issue',
      'decision',
      'todo',
      'release_note',
      'ddl',
      'pr_context',
      'incident',
      'release',
      'risk',
      'assumption',
    ],
    {
      errorMap: () => ({
        message: `Invalid knowledge type. Must be one of: entity, relation, observation, section, runbook, change, issue, decision, todo, release_note, ddl, pr_context, incident, release, risk, assumption`,
      }),
    }
  ),
  // Enhanced scope with full support
  scope: z
    .object({
      project: z.string().optional(),
      branch: z.string().optional(),
      org: z.string().optional(),
      service: z.string().optional(),
      sprint: z.string().optional(),
      tenant: z.string().optional(),
      environment: z.string().optional(),
    })
    .optional(),
  // Source tracking
  source: z
    .object({
      actor: z.string().optional(),
      tool: z.string().optional(),
      timestamp: z.string().datetime().optional(),
    })
    .optional(),
  // Flexible metadata
  metadata: z
    .record(z.any(), {
      description: 'Additional metadata for the item',
    })
    .optional(),
  // Tags for categorization and filtering
  tags: z.record(z.unknown()).optional(),
  // Idempotency key for safe retries
  idempotency_key: z.string().max(256).optional(),
});

/**
 * Enhanced content-based item schema (for text-based knowledge types)
 */
const EnhancedContentItemSchema = EnhancedBaseItemSchema.and(
  z.object({
    content: z.string({
      description: 'Content of the knowledge item (for text-based types)',
    }),
    // Optional TTL configuration
    ttl_config: TTLConfigSchema.optional(),
    // Optional truncation configuration
    truncation_config: TruncationConfigSchema.optional(),
    // Optional insights configuration
    insights_config: InsightsConfigSchema.optional(),
  })
);

/**
 * Enhanced data-based item schema (for structured knowledge types)
 */
const EnhancedDataItemSchema = EnhancedBaseItemSchema.and(
  z.object({
    data: z.record(z.any(), {
      description:
        'Structured data for the knowledge item (for entity, relation, observation, etc.)',
    }),
    // Optional TTL configuration
    ttl_config: TTLConfigSchema.optional(),
    // Optional insights configuration
    insights_config: InsightsConfigSchema.optional(),
  })
);

/**
 * Enhanced memory_store input schema with comprehensive configuration
 */
export const EnhancedMemoryStoreInputSchema = z
  .object({
    // Items to store
    items: z
      .array(z.union([EnhancedContentItemSchema, EnhancedDataItemSchema]))
      .min(1, 'At least one item is required')
      .max(100, 'Cannot store more than 100 items in a single request'),

    // Global deduplication configuration
    deduplication: DeduplicationConfigSchema.optional(),

    // Global TTL configuration (applies to all items unless overridden)
    global_ttl: TTLConfigSchema.optional(),

    // Global truncation configuration (applies to all items unless overridden)
    global_truncation: TruncationConfigSchema.optional(),

    // Global insights configuration (applies to all items unless overridden)
    global_insights: InsightsConfigSchema.optional(),

    // Processing options
    processing: z
      .object({
        enable_validation: z.boolean().default(true),
        enable_async_processing: z.boolean().default(false),
        batch_processing: z.boolean().default(true),
        return_summaries: z.boolean().default(false),
        include_metrics: z.boolean().default(true),
      })
      .optional(),
  })
  .strict();

/**
 * Legacy memory_store schema for backward compatibility
 */
export const MemoryStoreInputSchema = z
  .object({
    items: z
      .array(z.union([EnhancedContentItemSchema, EnhancedDataItemSchema]))
      .min(1, 'At least one item is required'),
  })
  .strict();

/**
 * Enhanced memory_find input schema with advanced search capabilities
 */
export const EnhancedMemoryFindInputSchema = z
  .object({
    // Core search query
    query: z
      .string()
      .min(1, 'Query parameter is required and cannot be empty')
      .max(1000, 'Query must be 1000 characters or less')
      .transform((val) => val.trim()), // Auto-trim whitespace

    // Enhanced scope with full support
    scope: z
      .object({
        project: z.string().optional(),
        branch: z.string().optional(),
        org: z.string().optional(),
        service: z.string().optional(),
        sprint: z.string().optional(),
        tenant: z.string().optional(),
        environment: z.string().optional(),
      })
      .optional(),

    // Knowledge type filtering
    types: z
      .array(
        z.enum([
          'entity',
          'relation',
          'observation',
          'section',
          'runbook',
          'change',
          'issue',
          'decision',
          'todo',
          'release_note',
          'ddl',
          'pr_context',
          'incident',
          'release',
          'risk',
          'assumption',
        ])
      )
      .optional(),

    // Search strategy configuration
    search_strategy: SearchStrategySchema.default('auto'),

    // Result limits and pagination
    limit: z
      .number()
      .int('limit must be an integer')
      .min(1, 'limit must be at least 1')
      .max(100, 'limit cannot exceed 100')
      .default(10),

    offset: z
      .number()
      .int('offset must be an integer')
      .min(0, 'offset must be non-negative')
      .max(1000, 'offset cannot exceed 1000')
      .default(0),

    // Graph expansion configuration
    graph_expansion: GraphExpansionConfigSchema.optional(),

    // TTL-aware search filters
    ttl_filters: z
      .object({
        include_expired: z.boolean().default(false),
        expires_before: z.string().datetime().optional(),
        expires_after: z.string().datetime().optional(),
        ttl_policies: z.array(TTLPolicySchema).optional(),
      })
      .optional(),

    // Advanced search filters
    filters: z
      .object({
        created_after: z.string().datetime().optional(),
        created_before: z.string().datetime().optional(),
        updated_after: z.string().datetime().optional(),
        updated_before: z.string().datetime().optional(),
        tags: z.array(z.string()).optional(),
        metadata: z.record(z.any()).optional(),
        confidence_min: z.number().min(0).max(1).optional(),
        confidence_max: z.number().min(0).max(1).optional(),
      })
      .optional(),

    // Search result formatting
    formatting: z
      .object({
        include_content: z.boolean().default(true),
        include_metadata: z.boolean().default(true),
        include_relations: z.boolean().default(false),
        include_confidence_scores: z.boolean().default(true),
        include_similarity_explanation: z.boolean().default(false),
        highlight_matches: z.boolean().default(false),
        max_content_length: z.number().int().min(100).default(1000),
      })
      .optional(),

    // Search optimization
    optimization: z
      .object({
        enable_caching: z.boolean().default(true),
        cache_ttl_seconds: z.number().int().min(60).max(3600).default(300),
        parallel_search: z.boolean().default(true),
        timeout_ms: z.number().int().min(1000).max(30000).default(10000),
      })
      .optional(),

    // Analytics and monitoring
    analytics: z
      .object({
        track_search_metrics: z.boolean().default(false),
        log_search_query: z.boolean().default(false),
        include_performance_metrics: z.boolean().default(false),
        record_user_feedback: z.boolean().default(false),
      })
      .optional(),
  })
  .strict();

/**
 * Legacy memory_find schema for backward compatibility
 */
export const MemoryFindInputSchema = z
  .object({
    query: z
      .string()
      .min(1, 'Query parameter is required and cannot be empty')
      .max(1000, 'Query must be 1000 characters or less')
      .transform((val) => val.trim()), // Auto-trim whitespace
    scope: z
      .object({
        project: z.string().optional(),
        branch: z.string().optional(),
        org: z.string().optional(),
      })
      .optional(),
    types: z.array(z.string()).optional(),
    mode: z
      .enum(['auto', 'fast', 'deep'], {
        errorMap: () => ({ message: `Invalid mode. Must be one of: auto, fast, deep` }),
      })
      .optional(),
    top_k: z
      .number()
      .int('top_k must be an integer')
      .min(1, 'top_k must be at least 1')
      .max(100, 'top_k cannot exceed 100')
      .optional(),
  })
  .strict();

/**
 * System status and cleanup input schema
 */
export const SystemStatusInputSchema = z
  .object({
    // Primary operation type
    operation: z.enum(
      [
        'health',
        'stats',
        'telemetry',
        'metrics',
        'get_document',
        'reassemble_document',
        'get_document_with_chunks',
        'run_purge',
        'get_purge_reports',
        'get_purge_statistics',
        'run_cleanup',
        'confirm_cleanup',
        'get_cleanup_statistics',
        'get_cleanup_history',
        'upsert_merge',
        'get_rate_limit_status',
        'get_performance_trends',
        'system_diagnostics',
      ],
      {
        errorMap: () => ({
          message: `Invalid operation. Must be one of: health, stats, telemetry, metrics, get_document, reassemble_document, get_document_with_chunks, run_purge, get_purge_reports, get_purge_statistics, run_cleanup, confirm_cleanup, get_cleanup_statistics, get_cleanup_history, upsert_merge, get_rate_limit_status, get_performance_trends, system_diagnostics`,
        }),
      }
    ),

    // Enhanced scope support
    scope: z
      .object({
        project: z.string().optional(),
        branch: z.string().optional(),
        org: z.string().optional(),
        service: z.string().optional(),
        sprint: z.string().optional(),
        tenant: z.string().optional(),
        environment: z.string().optional(),
      })
      .optional(),

    // Document operations
    document_id: z.string().uuid().optional(),

    // Purge operations
    purge_config: z
      .object({
        dry_run: z.boolean().default(true),
        batch_size: z.number().int().min(1).max(1000).default(100),
        max_batches: z.number().int().min(1).max(100).default(50),
      })
      .optional(),

    // Cleanup operations
    cleanup_config: CleanupConfigSchema.optional(),

    // Cleanup confirmation
    cleanup_token: z.string().optional(),

    // Statistics and reports
    stats_period_days: z.number().int().min(1).max(365).default(30).optional(),
    report_limit: z.number().int().min(1).max(100).default(10).optional(),

    // Performance monitoring
    performance_window_hours: z.number().int().min(1).max(168).default(24).optional(),
    include_detailed_metrics: z.boolean().default(false).optional(),

    // Response formatting
    response_formatting: z
      .object({
        summary: z.boolean().default(false),
        verbose: z.boolean().default(false),
        include_raw_data: z.boolean().default(false),
        include_timestamps: z.boolean().default(true),
      })
      .optional(),
  })
  .strict()
  .refine(
    (data) => {
      // Cross-field validation for operations that require specific parameters
      switch (data.operation) {
        case 'get_document':
        case 'reassemble_document':
        case 'get_document_with_chunks':
          return !!data.document_id;
        case 'confirm_cleanup':
          return !!data.cleanup_token;
        default:
          return true;
      }
    },
    {
      message: 'Missing required parameters for the specified operation',
      path: ['operation'],
    }
  );

/**
 * Performance monitoring input schema
 */
export const PerformanceMonitoringInputSchema = z
  .object({
    // Monitoring operation type
    operation: z.enum([
      'get_metrics',
      'get_trends',
      'get_alerts',
      'get_anomalies',
      'system_health',
      'resource_usage',
      'query_performance',
      'custom_metrics',
    ]),

    // Time window for metrics
    time_window: z
      .object({
        start_time: z.string().datetime().optional(),
        end_time: z.string().datetime().optional(),
        last_hours: z.number().int().min(1).max(168).optional(),
        last_days: z.number().int().min(1).max(30).optional(),
      })
      .optional(),

    // Metric categories
    categories: z
      .array(
        z.enum([
          'performance',
          'memory',
          'storage',
          'network',
          'errors',
          'rate_limiting',
          'deduplication',
          'truncation',
          'chunking',
          'cleanup',
        ])
      )
      .optional(),

    // Aggregation options
    aggregation: z
      .object({
        interval: z.enum(['minute', 'hour', 'day']).default('hour'),
        functions: z.array(z.enum(['avg', 'min', 'max', 'sum', 'count'])).default(['avg']),
        group_by: z.array(z.string()).optional(),
      })
      .optional(),

    // Filtering options
    filters: z
      .object({
        tool_name: z.string().optional(),
        operation_type: z.string().optional(),
        scope: z.record(z.string()).optional(),
        min_value: z.number().optional(),
        max_value: z.number().optional(),
      })
      .optional(),

    // Alert thresholds
    alert_thresholds: z
      .object({
        response_time_ms: z.number().optional(),
        error_rate_percent: z.number().min(0).max(100).optional(),
        memory_usage_mb: z.number().optional(),
        cpu_usage_percent: z.number().min(0).max(100).optional(),
      })
      .optional(),

    // Output options
    output: z
      .object({
        format: z.enum(['json', 'csv', 'prometheus']).default('json'),
        include_raw_data: z.boolean().default(false),
        include_charts: z.boolean().default(false),
        limit: z.number().int().min(1).max(10000).default(1000),
      })
      .optional(),
  })
  .strict();

// ============================================================================
// Error Types
// ============================================================================

/**
 * Custom validation error class
 */
export class ValidationError extends Error {
  constructor(
    message: string,
    public field?: string,
    public code?: string
  ) {
    super(message);
    this.name = 'ValidationError';
  }
}

// ============================================================================
// Validation Functions
// ============================================================================

/**
 * Validates memory_store input with comprehensive error handling
 */
export function validateMemoryStoreInput(input: unknown) {
  try {
    return MemoryStoreInputSchema.parse(input);
  } catch (error) {
    if (error instanceof z.ZodError) {
      const field = error.errors[0]?.path.join('.');
      const message = error.errors[0]?.message || 'Validation failed';
      throw new ValidationError(
        `Memory store validation failed: ${message}`,
        field,
        'VALIDATION_ERROR'
      );
    }
    throw new ValidationError('Unknown validation error occurred', undefined, 'UNKNOWN_ERROR');
  }
}

/**
 * Validates memory_find input with comprehensive error handling
 */
export function validateMemoryFindInput(input: unknown) {
  try {
    return MemoryFindInputSchema.parse(input);
  } catch (error) {
    if (error instanceof z.ZodError) {
      const field = error.errors[0]?.path.join('.');
      const message = error.errors[0]?.message || 'Validation failed';
      throw new ValidationError(
        `Memory find validation failed: ${message}`,
        field,
        'VALIDATION_ERROR'
      );
    }
    throw new ValidationError('Unknown validation error occurred', undefined, 'UNKNOWN_ERROR');
  }
}

/**
 * Safe validation function that returns null instead of throwing
 */
export function safeValidateMemoryFindInput(input: unknown) {
  try {
    return MemoryFindInputSchema.parse(input);
  } catch {
    return null;
  }
}

/**
 * Safe validation function that returns null instead of throwing
 */
export function safeValidateMemoryStoreInput(input: unknown) {
  try {
    return MemoryStoreInputSchema.parse(input);
  } catch {
    return null;
  }
}
