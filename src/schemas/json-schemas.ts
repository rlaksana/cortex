/**
 * Cortex Memory MCP - JSON Schema Definitions
 *
 * JSON Schema definitions for all enhanced MCP tool inputs.
 * Provides runtime validation and documentation for the enhanced features.
 *
 * @version 2.0.0 - Enhanced with P5-2 schema updates
 */

export const MEMORY_STORE_JSON_SCHEMA = {
  $schema: 'http://json-schema.org/draft-07/schema#',
  title: 'Cortex Memory Store Tool',
  description: 'Store knowledge items with enhanced deduplication, TTL, truncation, and insights',
  type: 'object',
  required: ['items'],
  properties: {
    items: {
      type: 'array',
      minItems: 1,
      maxItems: 100,
      description: 'Knowledge items to store',
      items: {
        type: 'object',
        required: ['kind'],
        properties: {
          kind: {
            type: 'string',
            enum: [
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
            description: 'Knowledge type',
          },
          content: {
            type: 'string',
            description: 'Content of the knowledge item (for text-based types)',
          },
          data: {
            type: 'object',
            description: 'Structured data for the knowledge item',
            additionalProperties: true,
          },
          scope: {
            type: 'object',
            properties: {
              project: { type: 'string' },
              branch: { type: 'string' },
              org: { type: 'string' },
              service: { type: 'string' },
              sprint: { type: 'string' },
              tenant: { type: 'string' },
              environment: { type: 'string' },
            },
            additionalProperties: false,
          },
          source: {
            type: 'object',
            properties: {
              actor: { type: 'string' },
              tool: { type: 'string' },
              timestamp: { type: 'string', format: 'date-time' },
            },
            additionalProperties: false,
          },
          metadata: {
            type: 'object',
            description: 'Additional metadata for the item',
            additionalProperties: true,
          },
          tags: {
            type: 'object',
            description: 'Tags for categorization and filtering',
            additionalProperties: true,
          },
          idempotency_key: {
            type: 'string',
            maxLength: 256,
            description: 'Idempotency key for safe retries',
          },
          ttl_config: {
            type: 'object',
            properties: {
              policy: {
                type: 'string',
                enum: ['default', 'short', 'long', 'permanent'],
                default: 'default',
              },
              expires_at: {
                type: 'string',
                format: 'date-time',
              },
              auto_extend: { type: 'boolean', default: false },
              extend_threshold_days: {
                type: 'integer',
                minimum: 1,
                maximum: 180,
                default: 7,
              },
              max_extensions: {
                type: 'integer',
                minimum: 0,
                maximum: 10,
                default: 3,
              },
            },
            additionalProperties: false,
          },
          truncation_config: {
            type: 'object',
            properties: {
              enabled: { type: 'boolean', default: true },
              max_chars: {
                type: 'integer',
                minimum: 100,
                maximum: 1000000,
                default: 10000,
              },
              max_tokens: {
                type: 'integer',
                minimum: 50,
                maximum: 100000,
                default: 4000,
              },
              mode: {
                type: 'string',
                enum: ['hard', 'soft', 'intelligent'],
                default: 'intelligent',
              },
              preserve_structure: { type: 'boolean', default: true },
              add_indicators: { type: 'boolean', default: true },
              indicator: {
                type: 'string',
                maxLength: 50,
                default: '[...truncated...]',
              },
              safety_margin: {
                type: 'number',
                minimum: 0,
                maximum: 0.5,
                default: 0.1,
              },
              auto_detect_content_type: { type: 'boolean', default: true },
              enable_smart_truncation: { type: 'boolean', default: true },
            },
            additionalProperties: false,
          },
          insights_config: {
            type: 'object',
            properties: {
              enabled: { type: 'boolean', default: false },
              generate_insights: { type: 'boolean', default: false },
              insight_types: {
                type: 'array',
                items: {
                  type: 'string',
                  enum: ['summary', 'trends', 'recommendations', 'anomalies', 'patterns'],
                },
                default: ['summary'],
              },
              confidence_threshold: {
                type: 'number',
                minimum: 0.1,
                maximum: 1.0,
                default: 0.7,
              },
              max_insights: {
                type: 'integer',
                minimum: 1,
                maximum: 50,
                default: 10,
              },
              include_source_data: { type: 'boolean', default: false },
              analysis_depth: {
                type: 'string',
                enum: ['shallow', 'medium', 'deep'],
                default: 'medium',
              },
            },
            additionalProperties: false,
          },
        },
        additionalProperties: false,
        oneOf: [
          { required: ['kind', 'content'] },
          { required: ['kind', 'data'] },
        ],
      },
    },
    deduplication: {
      type: 'object',
      properties: {
        enabled: { type: 'boolean', default: true },
        merge_strategy: {
          type: 'string',
          enum: ['skip', 'prefer_existing', 'prefer_newer', 'combine', 'intelligent'],
          default: 'intelligent',
        },
        similarity_threshold: {
          type: 'number',
          minimum: 0.1,
          maximum: 1.0,
          default: 0.85,
        },
        check_within_scope_only: { type: 'boolean', default: true },
        max_history_hours: {
          type: 'integer',
          minimum: 1,
          maximum: 8760,
          default: 168,
        },
        dedupe_window_days: {
          type: 'integer',
          minimum: 1,
          maximum: 365,
          default: 30,
        },
        allow_newer_versions: { type: 'boolean', default: true },
        enable_audit_logging: { type: 'boolean', default: true },
        enable_intelligent_merging: { type: 'boolean', default: true },
        preserve_merge_history: { type: 'boolean', default: false },
        max_merge_history_entries: {
          type: 'integer',
          minimum: 0,
          maximum: 100,
          default: 10,
        },
        cross_scope_deduplication: { type: 'boolean', default: false },
        prioritize_same_scope: { type: 'boolean', default: true },
        time_based_deduplication: { type: 'boolean', default: true },
        max_age_for_dedupe_days: {
          type: 'integer',
          minimum: 1,
          maximum: 365,
          default: 90,
        },
        respect_update_timestamps: { type: 'boolean', default: true },
        max_items_to_check: {
          type: 'integer',
          minimum: 1,
          maximum: 10000,
          default: 100,
        },
        batch_size: {
          type: 'integer',
          minimum: 1,
          maximum: 1000,
          default: 50,
        },
        enable_parallel_processing: { type: 'boolean', default: false },
      },
      additionalProperties: false,
    },
    global_ttl: {
      type: 'object',
      properties: {
        policy: {
          type: 'string',
          enum: ['default', 'short', 'long', 'permanent'],
          default: 'default',
        },
        expires_at: {
          type: 'string',
          format: 'date-time',
        },
        auto_extend: { type: 'boolean', default: false },
        extend_threshold_days: {
          type: 'integer',
          minimum: 1,
          maximum: 180,
          default: 7,
        },
        max_extensions: {
          type: 'integer',
          minimum: 0,
          maximum: 10,
          default: 3,
        },
      },
      additionalProperties: false,
    },
    global_truncation: {
      type: 'object',
      properties: {
        enabled: { type: 'boolean', default: true },
        max_chars: {
          type: 'integer',
          minimum: 100,
          maximum: 1000000,
          default: 10000,
        },
        max_tokens: {
          type: 'integer',
          minimum: 50,
          maximum: 100000,
          default: 4000,
        },
        mode: {
          type: 'string',
          enum: ['hard', 'soft', 'intelligent'],
          default: 'intelligent',
        },
        preserve_structure: { type: 'boolean', default: true },
        add_indicators: { type: 'boolean', default: true },
        indicator: {
          type: 'string',
          maxLength: 50,
          default: '[...truncated...]',
        },
        safety_margin: {
          type: 'number',
          minimum: 0,
          maximum: 0.5,
          default: 0.1,
        },
        auto_detect_content_type: { type: 'boolean', default: true },
        enable_smart_truncation: { type: 'boolean', default: true },
      },
      additionalProperties: false,
    },
    global_insights: {
      type: 'object',
      properties: {
        enabled: { type: 'boolean', default: false },
        generate_insights: { type: 'boolean', default: false },
        insight_types: {
          type: 'array',
          items: {
            type: 'string',
            enum: ['summary', 'trends', 'recommendations', 'anomalies', 'patterns'],
          },
          default: ['summary'],
        },
        confidence_threshold: {
          type: 'number',
          minimum: 0.1,
          maximum: 1.0,
          default: 0.7,
        },
        max_insights: {
          type: 'integer',
          minimum: 1,
          maximum: 50,
          default: 10,
        },
        include_source_data: { type: 'boolean', default: false },
        analysis_depth: {
          type: 'string',
          enum: ['shallow', 'medium', 'deep'],
          default: 'medium',
        },
      },
      additionalProperties: false,
    },
    processing: {
      type: 'object',
      properties: {
        enable_validation: { type: 'boolean', default: true },
        enable_async_processing: { type: 'boolean', default: false },
        batch_processing: { type: 'boolean', default: true },
        return_summaries: { type: 'boolean', default: false },
        include_metrics: { type: 'boolean', default: true },
      },
      additionalProperties: false,
    },
  },
  additionalProperties: false,
};

export const MEMORY_FIND_JSON_SCHEMA = {
  $schema: 'http://json-schema.org/draft-07/schema#',
  title: 'Cortex Memory Find Tool',
  description: 'Search Cortex memory with advanced strategies and graph expansion',
  type: 'object',
  required: ['query'],
  properties: {
    query: {
      type: 'string',
      minLength: 1,
      maxLength: 1000,
      description: 'Search query - natural language works best',
    },
    scope: {
      type: 'object',
      properties: {
        project: { type: 'string' },
        branch: { type: 'string' },
        org: { type: 'string' },
        service: { type: 'string' },
        sprint: { type: 'string' },
        tenant: { type: 'string' },
        environment: { type: 'string' },
      },
      additionalProperties: false,
    },
    types: {
      type: 'array',
      items: {
        type: 'string',
        enum: [
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
      },
      description: 'Knowledge types to search',
    },
    search_strategy: {
      type: 'string',
      enum: ['fast', 'auto', 'deep'],
      default: 'auto',
      description: 'Search strategy to use',
    },
    limit: {
      type: 'integer',
      minimum: 1,
      maximum: 100,
      default: 10,
      description: 'Maximum number of results to return',
    },
    offset: {
      type: 'integer',
      minimum: 0,
      maximum: 1000,
      default: 0,
      description: 'Number of results to skip (for pagination)',
    },
    graph_expansion: {
      type: 'object',
      properties: {
        enabled: { type: 'boolean', default: false },
        expansion_type: {
          type: 'string',
          enum: ['none', 'relations', 'parents', 'children', 'all'],
          default: 'relations',
        },
        max_depth: {
          type: 'integer',
          minimum: 1,
          maximum: 5,
          default: 2,
        },
        max_nodes: {
          type: 'integer',
          minimum: 1,
          maximum: 1000,
          default: 100,
        },
        include_metadata: { type: 'boolean', default: true },
        relation_types: {
          type: 'array',
          items: { type: 'string' },
        },
        direction: {
          type: 'string',
          enum: ['outgoing', 'incoming', 'both'],
          default: 'outgoing',
        },
      },
      additionalProperties: false,
    },
    ttl_filters: {
      type: 'object',
      properties: {
        include_expired: { type: 'boolean', default: false },
        expires_before: {
          type: 'string',
          format: 'date-time',
        },
        expires_after: {
          type: 'string',
          format: 'date-time',
        },
        ttl_policies: {
          type: 'array',
          items: {
            type: 'string',
            enum: ['default', 'short', 'long', 'permanent'],
          },
        },
      },
      additionalProperties: false,
    },
    filters: {
      type: 'object',
      properties: {
        created_after: {
          type: 'string',
          format: 'date-time',
        },
        created_before: {
          type: 'string',
          format: 'date-time',
        },
        updated_after: {
          type: 'string',
          format: 'date-time',
        },
        updated_before: {
          type: 'string',
          format: 'date-time',
        },
        tags: {
          type: 'array',
          items: { type: 'string' },
        },
        metadata: {
          type: 'object',
          additionalProperties: true,
        },
        confidence_min: {
          type: 'number',
          minimum: 0,
          maximum: 1,
        },
        confidence_max: {
          type: 'number',
          minimum: 0,
          maximum: 1,
        },
      },
      additionalProperties: false,
    },
    formatting: {
      type: 'object',
      properties: {
        include_content: { type: 'boolean', default: true },
        include_metadata: { type: 'boolean', default: true },
        include_relations: { type: 'boolean', default: false },
        include_confidence_scores: { type: 'boolean', default: true },
        include_similarity_explanation: { type: 'boolean', default: false },
        highlight_matches: { type: 'boolean', default: false },
        max_content_length: {
          type: 'integer',
          minimum: 100,
          default: 1000,
        },
      },
      additionalProperties: false,
    },
    optimization: {
      type: 'object',
      properties: {
        enable_caching: { type: 'boolean', default: true },
        cache_ttl_seconds: {
          type: 'integer',
          minimum: 60,
          maximum: 3600,
          default: 300,
        },
        parallel_search: { type: 'boolean', default: true },
        timeout_ms: {
          type: 'integer',
          minimum: 1000,
          maximum: 30000,
          default: 10000,
        },
      },
      additionalProperties: false,
    },
    analytics: {
      type: 'object',
      properties: {
        track_search_metrics: { type: 'boolean', default: false },
        log_search_query: { type: 'boolean', default: false },
        include_performance_metrics: { type: 'boolean', default: false },
        record_user_feedback: { type: 'boolean', default: false },
      },
      additionalProperties: false,
    },
  },
  additionalProperties: false,
};

export const SYSTEM_STATUS_JSON_SCHEMA = {
  $schema: 'http://json-schema.org/draft-07/schema#',
  title: 'Cortex System Status Tool',
  description: 'System monitoring, cleanup, and maintenance operations',
  type: 'object',
  required: ['operation'],
  properties: {
    operation: {
      type: 'string',
      enum: [
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
      description: 'System operation to perform',
    },
    scope: {
      type: 'object',
      properties: {
        project: { type: 'string' },
        branch: { type: 'string' },
        org: { type: 'string' },
        service: { type: 'string' },
        sprint: { type: 'string' },
        tenant: { type: 'string' },
        environment: { type: 'string' },
      },
      additionalProperties: false,
    },
    document_id: {
      type: 'string',
      format: 'uuid',
      description: 'Document ID for document operations',
    },
    purge_config: {
      type: 'object',
      properties: {
        dry_run: { type: 'boolean', default: true },
        batch_size: {
          type: 'integer',
          minimum: 1,
          maximum: 1000,
          default: 100,
        },
        max_batches: {
          type: 'integer',
          minimum: 1,
          maximum: 100,
          default: 50,
        },
      },
      additionalProperties: false,
    },
    cleanup_config: {
      type: 'object',
      properties: {
        operations: {
          type: 'array',
          items: {
            type: 'string',
            enum: ['expired', 'orphaned', 'duplicate', 'metrics', 'logs'],
          },
          default: ['expired'],
        },
        scope_filters: {
          type: 'object',
          properties: {
            project: { type: 'string' },
            org: { type: 'string' },
            branch: { type: 'string' },
          },
          additionalProperties: false,
        },
        require_confirmation: { type: 'boolean', default: true },
        enable_backup: { type: 'boolean', default: true },
        batch_size: {
          type: 'integer',
          minimum: 1,
          maximum: 1000,
          default: 100,
        },
        max_batches: {
          type: 'integer',
          minimum: 1,
          maximum: 100,
          default: 50,
        },
        dry_run: { type: 'boolean', default: true },
        confirmation_token: { type: 'string' },
      },
      additionalProperties: false,
    },
    cleanup_token: {
      type: 'string',
      description: 'Cleanup confirmation token',
    },
    stats_period_days: {
      type: 'integer',
      minimum: 1,
      maximum: 365,
      default: 30,
      description: 'Period in days for statistics',
    },
    report_limit: {
      type: 'integer',
      minimum: 1,
      maximum: 100,
      default: 10,
      description: 'Maximum number of reports to return',
    },
    performance_window_hours: {
      type: 'integer',
      minimum: 1,
      maximum: 168,
      default: 24,
      description: 'Time window for performance metrics',
    },
    include_detailed_metrics: {
      type: 'boolean',
      default: false,
      description: 'Include detailed metrics in response',
    },
    response_formatting: {
      type: 'object',
      properties: {
        summary: { type: 'boolean', default: false },
        verbose: { type: 'boolean', default: false },
        include_raw_data: { type: 'boolean', default: false },
        include_timestamps: { type: 'boolean', default: true },
      },
      additionalProperties: false,
    },
  },
  additionalProperties: false,
};

export const PERFORMANCE_MONITORING_JSON_SCHEMA = {
  $schema: 'http://json-schema.org/draft-07/schema#',
  title: 'Cortex Performance Monitoring Tool',
  description: 'Advanced performance monitoring and metrics collection',
  type: 'object',
  required: ['operation'],
  properties: {
    operation: {
      type: 'string',
      enum: [
        'get_metrics',
        'get_trends',
        'get_alerts',
        'get_anomalies',
        'system_health',
        'resource_usage',
        'query_performance',
        'custom_metrics',
      ],
      description: 'Monitoring operation type',
    },
    time_window: {
      type: 'object',
      properties: {
        start_time: {
          type: 'string',
          format: 'date-time',
        },
        end_time: {
          type: 'string',
          format: 'date-time',
        },
        last_hours: {
          type: 'integer',
          minimum: 1,
          maximum: 168,
        },
        last_days: {
          type: 'integer',
          minimum: 1,
          maximum: 30,
        },
      },
      additionalProperties: false,
    },
    categories: {
      type: 'array',
      items: {
        type: 'string',
        enum: [
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
        ],
      },
      description: 'Metric categories to include',
    },
    aggregation: {
      type: 'object',
      properties: {
        interval: {
          type: 'string',
          enum: ['minute', 'hour', 'day'],
          default: 'hour',
        },
        functions: {
          type: 'array',
          items: {
            type: 'string',
            enum: ['avg', 'min', 'max', 'sum', 'count'],
          },
          default: ['avg'],
        },
        group_by: {
          type: 'array',
          items: { type: 'string' },
        },
      },
      additionalProperties: false,
    },
    filters: {
      type: 'object',
      properties: {
        tool_name: { type: 'string' },
        operation_type: { type: 'string' },
        scope: {
          type: 'object',
          additionalProperties: { type: 'string' },
        },
        min_value: { type: 'number' },
        max_value: { type: 'number' },
      },
      additionalProperties: false,
    },
    alert_thresholds: {
      type: 'object',
      properties: {
        response_time_ms: { type: 'number' },
        error_rate_percent: {
          type: 'number',
          minimum: 0,
          maximum: 100,
        },
        memory_usage_mb: { type: 'number' },
        cpu_usage_percent: {
          type: 'number',
          minimum: 0,
          maximum: 100,
        },
      },
      additionalProperties: false,
    },
    output: {
      type: 'object',
      properties: {
        format: {
          type: 'string',
          enum: ['json', 'csv', 'prometheus'],
          default: 'json',
        },
        include_raw_data: { type: 'boolean', default: false },
        include_charts: { type: 'boolean', default: false },
        limit: {
          type: 'integer',
          minimum: 1,
          maximum: 10000,
          default: 1000,
        },
      },
      additionalProperties: false,
    },
  },
  additionalProperties: false,
};

// Export all schemas as a collection for easy access
export const ALL_JSON_SCHEMAS = {
  memory_store: MEMORY_STORE_JSON_SCHEMA,
  memory_find: MEMORY_FIND_JSON_SCHEMA,
  system_status: SYSTEM_STATUS_JSON_SCHEMA,
  performance_monitoring: PERFORMANCE_MONITORING_JSON_SCHEMA,
};
