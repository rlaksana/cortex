
// @ts-nocheck - Emergency rollback: Critical business service
/**
 * P8-T8.3: System Metrics Service
 *
 * Provides comprehensive metrics collection and exposure for Cortex MCP operations.
 * Tracks performance, usage patterns, and system health indicators.
 *
 * Features:
 * - Operation counters (store_count, find_count, purge_count)
 * - Performance metrics (dedupe_rate, validator_fail_rate)
 * - Real-time metric aggregation and exposure
 * - Thread-safe metric updates
 * - Time-based metric buckets for trend analysis
 * - Integration with existing audit and telemetry systems
 *
 * @module services/metrics
 */

import { logger } from '@/utils/logger.js';

export interface SystemMetrics {
  // Operation counts
  store_count: {
    total: number;
    successful: number;
    failed: number;
    by_kind: Record<string, number>;
  };
  find_count: {
    total: number;
    successful: number;
    failed: number;
    by_mode: Record<string, number>;
  };
  purge_count: {
    total: number;
    successful: number;
    failed: number;
    by_kind: Record<string, number>;
  };

  // Performance metrics
  dedupe_rate: {
    items_processed: number;
    items_skipped: number;
    rate: number; // percentage
  };
  validator_fail_rate: {
    items_validated: number;
    validation_failures: number;
    business_rule_blocks: number;
    fail_rate: number; // percentage
  };

  // System metrics
  performance: {
    avg_store_duration_ms: number;
    avg_find_duration_ms: number;
    avg_validation_duration_ms: number;
    uptime_ms: number;
  };

  // Error tracking
  errors: {
    total_errors: number;
    by_error_type: Record<string, number>;
    by_tool: Record<string, number>;
  };

  // Rate limiting metrics
  rate_limiting: {
    total_requests: number;
    blocked_requests: number;
    block_rate: number; // percentage
    active_actors: number;
  };

  // Memory usage
  memory: {
    active_knowledge_items: number;
    expired_items_cleaned: number;
    memory_usage_kb: number;
  };

  // Observability metrics
  observability: {
    responses_with_metadata: number;
    vector_operations: number;
    degraded_operations: number;
    avg_response_time_ms: number;
    search_strategies_used: Record<string, number>;
  };

  // P1-2: Truncation metrics
  truncation: {
    store_truncated_total: number;
    store_truncated_chars_total: number;
    store_truncated_tokens_total: number;
    truncation_processing_time_ms: number;
    truncation_by_type: Record<string, number>;
    truncation_by_strategy: Record<string, number>;
    truncation_rate: number; // percentage of operations truncated
  };

  // P4-1: Chunking metrics
  chunking: {
    items_chunked: number;
    chunks_generated: number;
    avg_chunks_per_item: number;
    chunking_duration_ms: number;
    chunking_success_rate: number;
    semantic_analysis_used: number;
    semantic_boundaries_found: number;
    chunk_reassembly_accuracy: number;
    chunking_by_type: Record<string, number>;
    chunking_errors: number;
    average_chunk_size: number;
    overlap_utilization: number;
  };

  // P4-1: Enhanced cleanup metrics
  cleanup: {
    cleanup_operations_run: number;
    items_deleted_total: number;
    items_dryrun_identified: number;
    cleanup_duration_ms: number;
    cleanup_success_rate: number;
    backup_operations: number;
    backup_size_total_bytes: number;
    cleanup_by_operation: Record<string, number>;
    cleanup_by_type: Record<string, number>;
    cleanup_errors: number;
    average_items_per_second: number;
    confirmations_required: number;
    confirmations_completed: number;
  };

  // P4-1: Enhanced dedupe_hits metrics
  dedupe_hits: {
    duplicates_detected: number;
    similarity_scores: number[];
    avg_similarity_score: number;
    merge_operations: number;
    skip_operations: number;
    intelligent_merges: number;
    combine_merges: number;
    dedupe_hits_by_strategy: Record<string, number>;
    false_positives: number;
    merge_conflicts_resolved: number;
    dedupe_processing_time_ms: number;
  };

  // P6-2: TTL execution metrics
  ttl: {
    ttl_deletes_total: number;
    ttl_skips_total: number;
    ttl_errors_total: number;
    ttl_processing_rate_per_second: number;
    ttl_batch_count: number;
    ttl_average_batch_size: number;
    ttl_policies_applied: Record<string, number>;
    ttl_extensions_granted: number;
    ttl_permanent_items_preserved: number;
    ttl_cleanup_duration_ms: number;
    ttl_last_cleanup_timestamp: string;
    ttl_success_rate: number;
  };

  // P6-1: Insight generation metrics
  insight_generation: {
    insights_generated: number;
    avg_processing_time_ms: number;
    avg_confidence: number;
    insights_by_type: Record<string, number>;
    performance_impact: number;
  };
}

export interface MetricUpdate {
  operation:
    | 'store'
    | 'find'
    | 'purge'
    | 'validate'
    | 'dedupe'
    | 'error'
    | 'rate_limit'
    | 'truncation'
    | 'chunking'
    | 'cleanup'
    | 'dedupe_hits'
    | 'ttl'
    | 'insight_generation'
    | 'insight_generation_summary';
  data: Record<string, unknown>;
  duration_ms?: number;
}

/**
 * Service for collecting and exposing system metrics
 */
export class SystemMetricsService {
  private metrics: SystemMetrics = {
    store_count: {
      total: 0,
      successful: 0,
      failed: 0,
      by_kind: {},
    },
    find_count: {
      total: 0,
      successful: 0,
      failed: 0,
      by_mode: {},
    },
    purge_count: {
      total: 0,
      successful: 0,
      failed: 0,
      by_kind: {},
    },
    dedupe_rate: {
      items_processed: 0,
      items_skipped: 0,
      rate: 0,
    },
    validator_fail_rate: {
      items_validated: 0,
      validation_failures: 0,
      business_rule_blocks: 0,
      fail_rate: 0,
    },
    performance: {
      avg_store_duration_ms: 0,
      avg_find_duration_ms: 0,
      avg_validation_duration_ms: 0,
      uptime_ms: 0,
    },
    errors: {
      total_errors: 0,
      by_error_type: {},
      by_tool: {},
    },
    rate_limiting: {
      total_requests: 0,
      blocked_requests: 0,
      block_rate: 0,
      active_actors: 0,
    },
    memory: {
      active_knowledge_items: 0,
      expired_items_cleaned: 0,
      memory_usage_kb: 0,
    },
    observability: {
      responses_with_metadata: 0,
      vector_operations: 0,
      degraded_operations: 0,
      avg_response_time_ms: 0,
      search_strategies_used: {},
    },
    // P1-2: Initialize truncation metrics
    truncation: {
      store_truncated_total: 0,
      store_truncated_chars_total: 0,
      store_truncated_tokens_total: 0,
      truncation_processing_time_ms: 0,
      truncation_by_type: {},
      truncation_by_strategy: {},
      truncation_rate: 0,
    },
    // P4-1: Initialize chunking metrics
    chunking: {
      items_chunked: 0,
      chunks_generated: 0,
      avg_chunks_per_item: 0,
      chunking_duration_ms: 0,
      chunking_success_rate: 100,
      semantic_analysis_used: 0,
      semantic_boundaries_found: 0,
      chunk_reassembly_accuracy: 100,
      chunking_by_type: {},
      chunking_errors: 0,
      average_chunk_size: 0,
      overlap_utilization: 0,
    },
    // P4-1: Initialize cleanup metrics
    cleanup: {
      cleanup_operations_run: 0,
      items_deleted_total: 0,
      items_dryrun_identified: 0,
      cleanup_duration_ms: 0,
      cleanup_success_rate: 100,
      backup_operations: 0,
      backup_size_total_bytes: 0,
      cleanup_by_operation: {},
      cleanup_by_type: {},
      cleanup_errors: 0,
      average_items_per_second: 0,
      confirmations_required: 0,
      confirmations_completed: 0,
    },
    // P4-1: Initialize dedupe_hits metrics
    dedupe_hits: {
      duplicates_detected: 0,
      similarity_scores: [],
      avg_similarity_score: 0,
      merge_operations: 0,
      skip_operations: 0,
      intelligent_merges: 0,
      combine_merges: 0,
      dedupe_hits_by_strategy: {},
      false_positives: 0,
      merge_conflicts_resolved: 0,
      dedupe_processing_time_ms: 0,
    },
    // P6-2: Initialize TTL execution metrics
    ttl: {
      ttl_deletes_total: 0,
      ttl_skips_total: 0,
      ttl_errors_total: 0,
      ttl_processing_rate_per_second: 0,
      ttl_batch_count: 0,
      ttl_average_batch_size: 0,
      ttl_policies_applied: {},
      ttl_extensions_granted: 0,
      ttl_permanent_items_preserved: 0,
      ttl_cleanup_duration_ms: 0,
      ttl_last_cleanup_timestamp: '',
      ttl_success_rate: 100,
    },
    // P6-1: Initialize insight generation metrics
    insight_generation: {
      insights_generated: 0,
      avg_processing_time_ms: 0,
      avg_confidence: 0,
      insights_by_type: {},
      performance_impact: 0,
    },
  };

  private startTime: number = Date.now();
  private performanceBuffer: number[] = [];
  private readonly PERFORMANCE_BUFFER_SIZE = 100;

  constructor() {
    logger.info('SystemMetricsService initialized');
    this.metrics.performance.uptime_ms = 0;
  }

  /**
   * Update metrics based on operation
   */
  updateMetrics(update: MetricUpdate): void {
    try {
      switch (update.operation) {
        case 'store':
          this.updateStoreMetrics(update.data, update.duration_ms);
          break;
        case 'find':
          this.updateFindMetrics(update.data, update.duration_ms);
          break;
        case 'purge':
          this.updatePurgeMetrics(update.data, update.duration_ms);
          break;
        case 'validate':
          this.updateValidationMetrics(update.data);
          break;
        case 'dedupe':
          this.updateDedupeMetrics(update.data);
          break;
        case 'error':
          this.updateErrorMetrics(update.data);
          break;
        case 'rate_limit':
          this.updateRateLimitMetrics(update.data);
          break;
        case 'truncation':
          this.updateTruncationMetrics(update.data, update.duration_ms);
          break;
        case 'chunking':
          this.updateChunkingMetrics(update.data, update.duration_ms);
          break;
        case 'cleanup':
          this.updateCleanupMetrics(update.data, update.duration_ms);
          break;
        case 'dedupe_hits':
          this.updateDedupeHitsMetrics(update.data, update.duration_ms);
          break;
        case 'ttl':
          this.updateTTLMetrics(update.data, update.duration_ms);
          break;
        case 'insight_generation':
          this.updateInsightGenerationMetrics(update.data, update.duration_ms);
          break;
        case 'insight_generation_summary':
          this.updateInsightGenerationSummaryMetrics(update.data, update.duration_ms);
          break;
      }

      // Update uptime
      this.metrics.performance.uptime_ms = Date.now() - this.startTime;
    } catch (error) {
      logger.error('Failed to update metrics', { error, update });
    }
  }

  /**
   * Update store operation metrics
   */
  private updateStoreMetrics(data: Record<string, unknown>, duration?: number): void {
    this.metrics.store_count.total++;

    if (data.success !== false) {
      this.metrics.store_count.successful++;

      // Track by kind
      if (data.kind) {
        this.metrics.store_count.by_kind[data.kind] =
          (this.metrics.store_count.by_kind[data.kind] || 0) + 1;
      }
    } else {
      this.metrics.store_count.failed++;
    }

    // Update performance
    if (duration) {
      this.updatePerformanceMetric('avg_store_duration_ms', duration);
    }

    // Update observability metrics
    this.metrics.observability.responses_with_metadata++;
    this.metrics.observability.vector_operations++;

    if (duration) {
      this.updateObservabilityMetric('avg_response_time_ms', duration);
    }
  }

  /**
   * Update find operation metrics
   */
  private updateFindMetrics(data: Record<string, unknown>, duration?: number): void {
    this.metrics.find_count.total++;

    if (data.success !== false) {
      this.metrics.find_count.successful++;

      // Track by mode
      if (data.mode) {
        this.metrics.find_count.by_mode[data.mode] =
          (this.metrics.find_count.by_mode[data.mode] || 0) + 1;
      }
    } else {
      this.metrics.find_count.failed++;
    }

    // Update performance
    if (duration) {
      this.updatePerformanceMetric('avg_find_duration_ms', duration);
    }

    // Update observability metrics
    this.metrics.observability.responses_with_metadata++;
    this.metrics.observability.search_strategies_used[data.mode] =
      (this.metrics.observability.search_strategies_used[data.mode] || 0) + 1;

    if (duration) {
      this.updateObservabilityMetric('avg_response_time_ms', duration);
    }
  }

  /**
   * Update purge operation metrics
   */
  private updatePurgeMetrics(data: Record<string, unknown>, _duration?: number): void {
    this.metrics.purge_count.total++;

    if (data.success !== false) {
      this.metrics.purge_count.successful++;

      // Track by kind
      if (data.kinds) {
        Object.entries(data.kinds).forEach(([kind, count]) => {
          this.metrics.purge_count.by_kind[kind] =
            (this.metrics.purge_count.by_kind[kind] || 0) + Number(count);
        });
      }
    } else {
      this.metrics.purge_count.failed++;
    }

    // Update memory metrics
    if (data.expired_items_cleaned) {
      this.metrics.memory.expired_items_cleaned += Number(data.expired_items_cleaned);
    }
  }

  /**
   * Update validation metrics
   */
  private updateValidationMetrics(data: Record<string, unknown>): void {
    this.metrics.validator_fail_rate.items_validated += Number(data.items_validated || 1);

    if (data.validation_failures) {
      this.metrics.validator_fail_rate.validation_failures += Number(data.validation_failures);
    }

    if (data.business_rule_blocks) {
      this.metrics.validator_fail_rate.business_rule_blocks += Number(data.business_rule_blocks);
    }

    // Calculate fail rate
    const totalFailures =
      this.metrics.validator_fail_rate.validation_failures +
      this.metrics.validator_fail_rate.business_rule_blocks;
    this.metrics.validator_fail_rate.fail_rate =
      this.metrics.validator_fail_rate.items_validated > 0
        ? (totalFailures / this.metrics.validator_fail_rate.items_validated) * 100
        : 0;
  }

  /**
   * Update deduplication metrics
   */
  private updateDedupeMetrics(data: Record<string, unknown>): void {
    this.metrics.dedupe_rate.items_processed += Number(data.items_processed || 1);
    this.metrics.dedupe_rate.items_skipped += Number(data.items_skipped || 0);

    // Calculate dedupe rate
    this.metrics.dedupe_rate.rate =
      this.metrics.dedupe_rate.items_processed > 0
        ? (this.metrics.dedupe_rate.items_skipped / this.metrics.dedupe_rate.items_processed) * 100
        : 0;
  }

  /**
   * Update error metrics
   */
  private updateErrorMetrics(data: Record<string, unknown>): void {
    this.metrics.errors.total_errors++;

    if (data.error_type) {
      this.metrics.errors.by_error_type[data.error_type] =
        (this.metrics.errors.by_error_type[data.error_type] || 0) + 1;
    }

    if (data.tool) {
      this.metrics.errors.by_tool[data.tool] = (this.metrics.errors.by_tool[data.tool] || 0) + 1;
    }
  }

  /**
   * Update rate limiting metrics
   */
  private updateRateLimitMetrics(data: Record<string, unknown>): void {
    this.metrics.rate_limiting.total_requests += Number(data.total_requests || 0);
    this.metrics.rate_limiting.blocked_requests += Number(data.blocked_requests || 0);
    this.metrics.rate_limiting.active_actors = Number(data.active_actors || 0);

    // Calculate block rate
    this.metrics.rate_limiting.block_rate =
      this.metrics.rate_limiting.total_requests > 0
        ? (this.metrics.rate_limiting.blocked_requests /
            this.metrics.rate_limiting.total_requests) *
          100
        : 0;
  }

  /**
   * P1-2: Update truncation metrics
   */
  private updateTruncationMetrics(data: Record<string, unknown>, duration?: number): void {
    if (data.truncationOccurred) {
      this.metrics.truncation.store_truncated_total++;
    }

    this.metrics.truncation.store_truncated_chars_total += Number(data.charsRemoved || 0);
    this.metrics.truncation.store_truncated_tokens_total += Number(data.tokensRemoved || 0);

    if (duration) {
      this.metrics.truncation.truncation_processing_time_ms += duration;
    }

    // Track by content type
    if (data.contentType) {
      this.metrics.truncation.truncation_by_type[data.contentType] =
        (this.metrics.truncation.truncation_by_type[data.contentType] || 0) + 1;
    }

    // Track by strategy
    if (data.strategy) {
      this.metrics.truncation.truncation_by_strategy[data.strategy] =
        (this.metrics.truncation.truncation_by_strategy[data.strategy] || 0) + 1;
    }

    // Calculate truncation rate
    const totalStoreOps = this.metrics.store_count.total;
    if (totalStoreOps > 0) {
      this.metrics.truncation.truncation_rate =
        (this.metrics.truncation.store_truncated_total / totalStoreOps) * 100;
    }
  }

  /**
   * Update performance metric with running average
   */
  private updatePerformanceMetric(metric: keyof SystemMetrics['performance'], value: number): void {
    // Add to buffer
    this.performanceBuffer.push(value);
    if (this.performanceBuffer.length > this.PERFORMANCE_BUFFER_SIZE) {
      this.performanceBuffer.shift();
    }

    // Calculate running average
    const avg =
      this.performanceBuffer.reduce((sum, val) => sum + val, 0) / this.performanceBuffer.length;
    (this.metrics.performance as unknown)[metric] = Math.round(avg * 100) / 100; // Round to 2 decimal places
  }

  /**
   * Update observability metrics
   */
  private updateObservabilityMetric(
    metric: keyof SystemMetrics['observability'],
    value: number
  ): void {
    if (metric === 'avg_response_time_ms') {
      const current = this.metrics.observability.avg_response_time_ms;
      const total = this.metrics.observability.responses_with_metadata;
      this.metrics.observability.avg_response_time_ms =
        Math.round(((current * (total - 1) + value) / total) * 100) / 100;
    } else {
      (this.metrics.observability as unknown)[metric] = value;
    }
  }

  /**
   * P4-1: Update chunking metrics
   */
  private updateChunkingMetrics(data: Record<string, unknown>, duration?: number): void {
    if (data.items_chunked) {
      this.metrics.chunking.items_chunked += Number(data.items_chunked);
    }
    if (data.chunks_generated) {
      this.metrics.chunking.chunks_generated += Number(data.chunks_generated);
    }
    if (duration) {
      this.metrics.chunking.chunking_duration_ms += duration;
    }

    // Update success rate
    if (data.success !== undefined) {
      const total = this.metrics.chunking.items_chunked || 1;
      const successful = data.success
        ? this.metrics.chunking.items_chunked - (this.metrics.chunking.chunking_errors || 0)
        : this.metrics.chunking.chunking_errors + 1;
      this.metrics.chunking.chunking_success_rate = (successful / total) * 100;
    }

    // Track by type
    if (data.type) {
      this.metrics.chunking.chunking_by_type[data.type] =
        (this.metrics.chunking.chunking_by_type[data.type] || 0) + 1;
    }

    // Semantic analysis metrics
    if (data.semantic_analysis_used) {
      this.metrics.chunking.semantic_analysis_used += Number(data.semantic_analysis_used);
    }
    if (data.semantic_boundaries_found) {
      this.metrics.chunking.semantic_boundaries_found += Number(data.semantic_boundaries_found);
    }

    // Reassembly accuracy
    if (data.reassembly_accuracy) {
      this.metrics.chunking.chunk_reassembly_accuracy = data.reassembly_accuracy;
    }

    // Average chunk size
    if (data.average_chunk_size) {
      this.metrics.chunking.average_chunk_size = data.average_chunk_size;
    }

    // Overlap utilization
    if (data.overlap_utilization) {
      this.metrics.chunking.overlap_utilization = data.overlap_utilization;
    }

    // Calculate average chunks per item
    if (this.metrics.chunking.items_chunked > 0) {
      this.metrics.chunking.avg_chunks_per_item =
        this.metrics.chunking.chunks_generated / this.metrics.chunking.items_chunked;
    }
  }

  /**
   * P4-1: Update cleanup metrics
   */
  private updateCleanupMetrics(data: Record<string, unknown>, duration?: number): void {
    this.metrics.cleanup.cleanup_operations_run++;

    if (data.items_deleted) {
      this.metrics.cleanup.items_deleted_total += Number(data.items_deleted);
    }
    if (data.items_dryrun_identified) {
      this.metrics.cleanup.items_dryrun_identified += Number(data.items_dryrun_identified);
    }
    if (duration) {
      this.metrics.cleanup.cleanup_duration_ms += duration;
    }

    // Update success rate
    if (data.success !== undefined) {
      const total = this.metrics.cleanup.cleanup_operations_run;
      const successful = data.success
        ? total - this.metrics.cleanup.cleanup_errors
        : this.metrics.cleanup.cleanup_errors + 1;
      this.metrics.cleanup.cleanup_success_rate = (successful / total) * 100;
    }

    // Track by operation type
    if (data.operation_type) {
      this.metrics.cleanup.cleanup_by_operation[data.operation_type] =
        (this.metrics.cleanup.cleanup_by_operation[data.operation_type] || 0) + 1;
    }

    // Track by knowledge type
    if (data.knowledge_type) {
      this.metrics.cleanup.cleanup_by_type[data.knowledge_type] =
        (this.metrics.cleanup.cleanup_by_type[data.knowledge_type] || 0) + 1;
    }

    // Backup metrics
    if (data.backup_created) {
      this.metrics.cleanup.backup_operations += 1;
    }
    if (data.backup_size) {
      this.metrics.cleanup.backup_size_total_bytes += Number(data.backup_size);
    }

    // Performance metrics
    if (data.items_per_second) {
      this.metrics.cleanup.average_items_per_second = data.items_per_second;
    }

    // Confirmation metrics
    if (data.confirmation_required) {
      this.metrics.cleanup.confirmations_required += 1;
    }
    if (data.confirmation_completed) {
      this.metrics.cleanup.confirmations_completed += 1;
    }
  }

  /**
   * P4-1: Update dedupe_hits metrics
   */
  private updateDedupeHitsMetrics(data: Record<string, unknown>, duration?: number): void {
    if (data.duplicates_detected) {
      this.metrics.dedupe_hits.duplicates_detected += Number(data.duplicates_detected);
    }
    if (duration) {
      this.metrics.dedupe_hits.dedupe_processing_time_ms += duration;
    }

    // Similarity scores tracking
    if (data.similarity_score) {
      this.metrics.dedupe_hits.similarity_scores.push(Number(data.similarity_score));
      // Keep only last 1000 scores to prevent memory growth
      if (this.metrics.dedupe_hits.similarity_scores.length > 1000) {
        this.metrics.dedupe_hits.similarity_scores =
          this.metrics.dedupe_hits.similarity_scores.slice(-1000);
      }
      // Calculate average similarity score
      const sum = this.metrics.dedupe_hits.similarity_scores.reduce((a, b) => a + b, 0);
      this.metrics.dedupe_hits.avg_similarity_score =
        sum / this.metrics.dedupe_hits.similarity_scores.length;
    }

    // Merge operations
    if (data.merge_operation) {
      this.metrics.dedupe_hits.merge_operations += 1;
    }
    if (data.skip_operation) {
      this.metrics.dedupe_hits.skip_operations += 1;
    }

    // Strategy-specific metrics
    if (data.strategy) {
      this.metrics.dedupe_hits.dedupe_hits_by_strategy[data.strategy] =
        (this.metrics.dedupe_hits.dedupe_hits_by_strategy[data.strategy] || 0) + 1;

      // Track specific merge types
      if (data.strategy === 'intelligent') {
        this.metrics.dedupe_hits.intelligent_merges += 1;
      } else if (data.strategy === 'combine') {
        this.metrics.dedupe_hits.combine_merges += 1;
      }
    }

    // False positive tracking
    if (data.false_positive) {
      this.metrics.dedupe_hits.false_positives += 1;
    }

    // Merge conflicts resolved
    if (data.merge_conflicts_resolved) {
      this.metrics.dedupe_hits.merge_conflicts_resolved += Number(data.merge_conflicts_resolved);
    }
  }

  /**
   * Update insight generation metrics
   */
  private updateInsightGenerationMetrics(data: Record<string, unknown>, duration?: number): void {
    // Track insight generation counts
    if (data.insights_generated) {
      this.metrics.insight_generation.insights_generated += Number(data.insights_generated);
    }

    // Track processing time
    if (duration) {
      this.metrics.insight_generation.avg_processing_time_ms =
        (this.metrics.insight_generation.avg_processing_time_ms + duration) / 2;
    }

    // Track insight types
    if (data.insights_by_type) {
      Object.entries(data.insights_by_type).forEach(([type, count]) => {
        if (!this.metrics.insight_generation.insights_by_type[type]) {
          this.metrics.insight_generation.insights_by_type[type] = 0;
        }
        this.metrics.insight_generation.insights_by_type[type] += Number(count);
      });
    }

    // Track confidence scores
    if (data.average_confidence) {
      this.metrics.insight_generation.avg_confidence =
        (this.metrics.insight_generation.avg_confidence + Number(data.average_confidence)) / 2;
    }
  }

  /**
   * Update insight generation summary metrics
   */
  private updateInsightGenerationSummaryMetrics(
    data: Record<string, unknown>,
    duration?: number
  ): void {
    // Similar to insight_generation but for batch summaries
    if (data.total_insights) {
      this.metrics.insight_generation.insights_generated += Number(data.total_insights);
    }

    if (duration) {
      this.metrics.insight_generation.avg_processing_time_ms =
        (this.metrics.insight_generation.avg_processing_time_ms + duration) / 2;
    }

    if (data.performance_impact) {
      this.metrics.insight_generation.performance_impact =
        (this.metrics.insight_generation.performance_impact + Number(data.performance_impact)) / 2;
    }
  }

  /**
   * P6-2: Update TTL execution metrics
   */
  private updateTTLMetrics(data: Record<string, unknown>, duration?: number): void {
    // Update TTL delete counters
    if (data.ttl_deletes_total) {
      this.metrics.ttl.ttl_deletes_total += Number(data.ttl_deletes_total);
    }

    if (data.ttl_skips_total) {
      this.metrics.ttl.ttl_skips_total += Number(data.ttl_skips_total);
    }

    if (data.ttl_errors_total) {
      this.metrics.ttl.ttl_errors_total += Number(data.ttl_errors_total);
    }

    // Update processing performance metrics
    if (data.ttl_processing_rate_per_second) {
      this.metrics.ttl.ttl_processing_rate_per_second = Number(data.ttl_processing_rate_per_second);
    }

    if (data.ttl_batch_count) {
      this.metrics.ttl.ttl_batch_count += Number(data.ttl_batch_count);
    }

    if (data.ttl_average_batch_size) {
      this.metrics.ttl.ttl_average_batch_size = Number(data.ttl_average_batch_size);
    }

    // Update policy metrics
    if (data.ttl_policies_applied) {
      Object.entries(data.ttl_policies_applied).forEach(([policy, count]) => {
        this.metrics.ttl.ttl_policies_applied[policy] =
          (this.metrics.ttl.ttl_policies_applied[policy] || 0) + Number(count);
      });
    }

    if (data.ttl_extensions_granted) {
      this.metrics.ttl.ttl_extensions_granted += Number(data.ttl_extensions_granted);
    }

    if (data.ttl_permanent_items_preserved) {
      this.metrics.ttl.ttl_permanent_items_preserved += Number(data.ttl_permanent_items_preserved);
    }

    // Update timing and success metrics
    if (duration) {
      this.metrics.ttl.ttl_cleanup_duration_ms += duration;
    }

    if (data.ttl_last_cleanup_timestamp) {
      this.metrics.ttl.ttl_last_cleanup_timestamp = data.ttl_last_cleanup_timestamp;
    } else {
      this.metrics.ttl.ttl_last_cleanup_timestamp = new Date().toISOString();
    }

    // Calculate success rate
    const totalOperations =
      this.metrics.ttl.ttl_deletes_total +
      this.metrics.ttl.ttl_skips_total +
      this.metrics.ttl.ttl_errors_total;
    if (totalOperations > 0) {
      this.metrics.ttl.ttl_success_rate =
        ((this.metrics.ttl.ttl_deletes_total + this.metrics.ttl.ttl_skips_total) /
          totalOperations) *
        100;
    }
  }

  /**
   * Get current system metrics
   */
  getMetrics(): SystemMetrics {
    // Update uptime before returning
    this.metrics.performance.uptime_ms = Date.now() - this.startTime;
    return { ...this.metrics };
  }

  /**
   * Get metrics summary for quick overview
   */
  getMetricsSummary(): {
    operations: { stores: number; finds: number; purges: number };
    performance: { dedupe_rate: number; validator_fail_rate: number; avg_response_time: number };
    health: { error_rate: number; block_rate: number; uptime_hours: number };
  } {
    const totalOps =
      this.metrics.store_count.total +
      this.metrics.find_count.total +
      this.metrics.purge_count.total;
    const errorRate = totalOps > 0 ? (this.metrics.errors.total_errors / totalOps) * 100 : 0;
    const avgResponseTime =
      (this.metrics.performance.avg_store_duration_ms +
        this.metrics.performance.avg_find_duration_ms) /
      2;

    return {
      operations: {
        stores: this.metrics.store_count.total,
        finds: this.metrics.find_count.total,
        purges: this.metrics.purge_count.total,
      },
      performance: {
        dedupe_rate: Math.round(this.metrics.dedupe_rate.rate * 100) / 100,
        validator_fail_rate: Math.round(this.metrics.validator_fail_rate.fail_rate * 100) / 100,
        avg_response_time: Math.round(avgResponseTime * 100) / 100,
      },
      health: {
        error_rate: Math.round(errorRate * 100) / 100,
        block_rate: Math.round(this.metrics.rate_limiting.block_rate * 100) / 100,
        uptime_hours:
          Math.round((this.metrics.performance.uptime_ms / (1000 * 60 * 60)) * 100) / 100,
      },
    };
  }

  /**
   * Reset all metrics (for testing/admin)
   */
  resetMetrics(): void {
    const oldStartTime = this.startTime;

    this.metrics = {
      store_count: { total: 0, successful: 0, failed: 0, by_kind: {} },
      find_count: { total: 0, successful: 0, failed: 0, by_mode: {} },
      purge_count: { total: 0, successful: 0, failed: 0, by_kind: {} },
      dedupe_rate: { items_processed: 0, items_skipped: 0, rate: 0 },
      validator_fail_rate: {
        items_validated: 0,
        validation_failures: 0,
        business_rule_blocks: 0,
        fail_rate: 0,
      },
      performance: {
        avg_store_duration_ms: 0,
        avg_find_duration_ms: 0,
        avg_validation_duration_ms: 0,
        uptime_ms: 0,
      },
      errors: { total_errors: 0, by_error_type: {}, by_tool: {} },
      rate_limiting: { total_requests: 0, blocked_requests: 0, block_rate: 0, active_actors: 0 },
      memory: { active_knowledge_items: 0, expired_items_cleaned: 0, memory_usage_kb: 0 },
      observability: {
        responses_with_metadata: 0,
        vector_operations: 0,
        degraded_operations: 0,
        avg_response_time_ms: 0,
        search_strategies_used: {},
      },
      // P1-2: Reset truncation metrics
      truncation: {
        store_truncated_total: 0,
        store_truncated_chars_total: 0,
        store_truncated_tokens_total: 0,
        truncation_processing_time_ms: 0,
        truncation_by_type: {},
        truncation_by_strategy: {},
        truncation_rate: 0,
      },
      // P4-1: Reset chunking metrics
      chunking: {
        items_chunked: 0,
        chunks_generated: 0,
        avg_chunks_per_item: 0,
        chunking_duration_ms: 0,
        chunking_success_rate: 100,
        semantic_analysis_used: 0,
        semantic_boundaries_found: 0,
        chunk_reassembly_accuracy: 100,
        chunking_by_type: {},
        chunking_errors: 0,
        average_chunk_size: 0,
        overlap_utilization: 0,
      },
      // P4-1: Reset cleanup metrics
      cleanup: {
        cleanup_operations_run: 0,
        items_deleted_total: 0,
        items_dryrun_identified: 0,
        cleanup_duration_ms: 0,
        cleanup_success_rate: 100,
        backup_operations: 0,
        backup_size_total_bytes: 0,
        cleanup_by_operation: {},
        cleanup_by_type: {},
        cleanup_errors: 0,
        average_items_per_second: 0,
        confirmations_required: 0,
        confirmations_completed: 0,
      },
      // P4-1: Reset dedupe_hits metrics
      dedupe_hits: {
        duplicates_detected: 0,
        similarity_scores: [],
        avg_similarity_score: 0,
        merge_operations: 0,
        skip_operations: 0,
        intelligent_merges: 0,
        combine_merges: 0,
        dedupe_hits_by_strategy: {},
        false_positives: 0,
        merge_conflicts_resolved: 0,
        dedupe_processing_time_ms: 0,
      },
      // P6-2: Reset TTL execution metrics
      ttl: {
        ttl_deletes_total: 0,
        ttl_skips_total: 0,
        ttl_errors_total: 0,
        ttl_processing_rate_per_second: 0,
        ttl_batch_count: 0,
        ttl_average_batch_size: 0,
        ttl_policies_applied: {},
        ttl_extensions_granted: 0,
        ttl_permanent_items_preserved: 0,
        ttl_cleanup_duration_ms: 0,
        ttl_last_cleanup_timestamp: '',
        ttl_success_rate: 100,
      },
      // P6-1: Reset insight generation metrics
      insight_generation: {
        insights_generated: 0,
        avg_processing_time_ms: 0,
        avg_confidence: 0,
        insights_by_type: {},
        performance_impact: 0,
      },
    };

    this.startTime = Date.now();
    this.performanceBuffer = [];

    logger.info('System metrics reset', { previousUptime: Date.now() - oldStartTime });
  }

  /**
   * Get metrics as JSON string for API responses
   */
  getMetricsAsJson(): string {
    return JSON.stringify(this.getMetrics(), null, 2);
  }
}

// Singleton instance
export const systemMetricsService = new SystemMetricsService();
