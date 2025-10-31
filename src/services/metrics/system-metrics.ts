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

import { logger } from '../../utils/logger.js';

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
}

export interface MetricUpdate {
  operation: 'store' | 'find' | 'purge' | 'validate' | 'dedupe' | 'error' | 'rate_limit';
  data: Record<string, any>;
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
      by_kind: {}
    },
    find_count: {
      total: 0,
      successful: 0,
      failed: 0,
      by_mode: {}
    },
    purge_count: {
      total: 0,
      successful: 0,
      failed: 0,
      by_kind: {}
    },
    dedupe_rate: {
      items_processed: 0,
      items_skipped: 0,
      rate: 0
    },
    validator_fail_rate: {
      items_validated: 0,
      validation_failures: 0,
      business_rule_blocks: 0,
      fail_rate: 0
    },
    performance: {
      avg_store_duration_ms: 0,
      avg_find_duration_ms: 0,
      avg_validation_duration_ms: 0,
      uptime_ms: 0
    },
    errors: {
      total_errors: 0,
      by_error_type: {},
      by_tool: {}
    },
    rate_limiting: {
      total_requests: 0,
      blocked_requests: 0,
      block_rate: 0,
      active_actors: 0
    },
    memory: {
      active_knowledge_items: 0,
      expired_items_cleaned: 0,
      memory_usage_kb: 0
    }
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
  private updateStoreMetrics(data: Record<string, any>, duration?: number): void {
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
  }

  /**
   * Update find operation metrics
   */
  private updateFindMetrics(data: Record<string, any>, duration?: number): void {
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
  }

  /**
   * Update purge operation metrics
   */
  private updatePurgeMetrics(data: Record<string, any>, _duration?: number): void {
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
  private updateValidationMetrics(data: Record<string, any>): void {
    this.metrics.validator_fail_rate.items_validated += Number(data.items_validated || 1);

    if (data.validation_failures) {
      this.metrics.validator_fail_rate.validation_failures += Number(data.validation_failures);
    }

    if (data.business_rule_blocks) {
      this.metrics.validator_fail_rate.business_rule_blocks += Number(data.business_rule_blocks);
    }

    // Calculate fail rate
    const totalFailures = this.metrics.validator_fail_rate.validation_failures +
                         this.metrics.validator_fail_rate.business_rule_blocks;
    this.metrics.validator_fail_rate.fail_rate = this.metrics.validator_fail_rate.items_validated > 0
      ? (totalFailures / this.metrics.validator_fail_rate.items_validated) * 100
      : 0;
  }

  /**
   * Update deduplication metrics
   */
  private updateDedupeMetrics(data: Record<string, any>): void {
    this.metrics.dedupe_rate.items_processed += Number(data.items_processed || 1);
    this.metrics.dedupe_rate.items_skipped += Number(data.items_skipped || 0);

    // Calculate dedupe rate
    this.metrics.dedupe_rate.rate = this.metrics.dedupe_rate.items_processed > 0
      ? (this.metrics.dedupe_rate.items_skipped / this.metrics.dedupe_rate.items_processed) * 100
      : 0;
  }

  /**
   * Update error metrics
   */
  private updateErrorMetrics(data: Record<string, any>): void {
    this.metrics.errors.total_errors++;

    if (data.error_type) {
      this.metrics.errors.by_error_type[data.error_type] =
        (this.metrics.errors.by_error_type[data.error_type] || 0) + 1;
    }

    if (data.tool) {
      this.metrics.errors.by_tool[data.tool] =
        (this.metrics.errors.by_tool[data.tool] || 0) + 1;
    }
  }

  /**
   * Update rate limiting metrics
   */
  private updateRateLimitMetrics(data: Record<string, any>): void {
    this.metrics.rate_limiting.total_requests += Number(data.total_requests || 0);
    this.metrics.rate_limiting.blocked_requests += Number(data.blocked_requests || 0);
    this.metrics.rate_limiting.active_actors = Number(data.active_actors || 0);

    // Calculate block rate
    this.metrics.rate_limiting.block_rate = this.metrics.rate_limiting.total_requests > 0
      ? (this.metrics.rate_limiting.blocked_requests / this.metrics.rate_limiting.total_requests) * 100
      : 0;
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
    const avg = this.performanceBuffer.reduce((sum, val) => sum + val, 0) / this.performanceBuffer.length;
    (this.metrics.performance as any)[metric] = Math.round(avg * 100) / 100; // Round to 2 decimal places
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
    const totalOps = this.metrics.store_count.total + this.metrics.find_count.total + this.metrics.purge_count.total;
    const errorRate = totalOps > 0 ? (this.metrics.errors.total_errors / totalOps) * 100 : 0;
    const avgResponseTime = (this.metrics.performance.avg_store_duration_ms +
                            this.metrics.performance.avg_find_duration_ms) / 2;

    return {
      operations: {
        stores: this.metrics.store_count.total,
        finds: this.metrics.find_count.total,
        purges: this.metrics.purge_count.total
      },
      performance: {
        dedupe_rate: Math.round(this.metrics.dedupe_rate.rate * 100) / 100,
        validator_fail_rate: Math.round(this.metrics.validator_fail_rate.fail_rate * 100) / 100,
        avg_response_time: Math.round(avgResponseTime * 100) / 100
      },
      health: {
        error_rate: Math.round(errorRate * 100) / 100,
        block_rate: Math.round(this.metrics.rate_limiting.block_rate * 100) / 100,
        uptime_hours: Math.round((this.metrics.performance.uptime_ms / (1000 * 60 * 60)) * 100) / 100
      }
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
      validator_fail_rate: { items_validated: 0, validation_failures: 0, business_rule_blocks: 0, fail_rate: 0 },
      performance: {
        avg_store_duration_ms: 0,
        avg_find_duration_ms: 0,
        avg_validation_duration_ms: 0,
        uptime_ms: 0
      },
      errors: { total_errors: 0, by_error_type: {}, by_tool: {} },
      rate_limiting: { total_requests: 0, blocked_requests: 0, block_rate: 0, active_actors: 0 },
      memory: { active_knowledge_items: 0, expired_items_cleaned: 0, memory_usage_kb: 0 }
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