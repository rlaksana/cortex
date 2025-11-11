
/**
 * Comprehensive Metrics Service for Cortex MCP
 *
 * Integrates structured logging with performance collection to provide:
 * - QPS (Queries Per Second) tracking
 * - Percentiles (p95, p99) for operations
 * - Deduplication rates
 * - TTL deletion metrics
 * - Embedding failure rates
 * - Real-time dashboards and alerting
 */

import { OperationType } from './operation-types.js';
import { performanceCollector } from './performance-collector.js';
// Local narrow aliases to avoid missing named exports from logger
type SearchStrategy = 'fts' | 'semantic' | 'graph' | string;
type DeduplicationStrategy = 'exact' | 'fuzzy' | string;
import { EventEmitter } from 'events';

/**
 * Real-time metrics for operations
 */
export interface RealTimeMetrics {
  // QPS metrics
  qps: {
    memory_store_qps: number;
    memory_find_qps: number;
    total_qps: number;
  };

  // Performance metrics
  performance: {
    store_p95_ms: number;
    find_p95_ms: number;
    store_p99_ms: number;
    find_p99_ms: number;
  };

  // Quality metrics
  quality: {
    dedupe_rate: number;
    ttl_deleted_rate: number;
    embedding_fail_rate: number;
    cache_hit_rate: number;
  };

  // System health
  system: {
    memory_usage_mb: number;
    cpu_usage_percent: number;
    active_connections: number;
  };

  timestamp: number;
}

/**
 * Historical metrics for trends
 */
export interface HistoricalMetrics {
  time_window_minutes: number;
  operation_metrics: Record<
    string,
    {
      count: number;
      average_latency: number;
      p95_latency: number;
      p99_latency: number;
      error_rate: number;
      qps: number;
    }
  >;
  quality_metrics: {
    dedupe_rate: number;
    ttl_deleted_rate: number;
    embedding_fail_rate: number;
    cache_hit_rate: number;
  };
  system_metrics: {
    memory_usage_mb: number;
    cpu_usage_percent: number;
  };
}

/**
 * Metrics aggregation configuration
 */
interface MetricsConfig {
  // QPS calculation window (seconds)
  qps_window_seconds: number;

  // Percentile calculation sample size
  percentile_sample_size: number;

  // Metrics retention (hours)
  retention_hours: number;

  // Alert thresholds
  alert_thresholds: {
    qps_threshold: number;
    p95_latency_threshold: number;
    error_rate_threshold: number;
    memory_usage_threshold: number;
  };

  // Export settings
  export_enabled: boolean;
  export_interval_seconds: number;
  export_formats: ('json' | 'prometheus' | 'csv')[];
}

/**
 * Comprehensive metrics service
 */
export class MetricsService extends EventEmitter {
  private config: MetricsConfig;
  private qpsTrackers: Map<string, number[]> = new Map();
  private qualityMetrics: Map<string, number[]> = new Map();
  private metricsHistory: RealTimeMetrics[] = [];
  private exportInterval: NodeJS.Timeout | null = null;

  constructor(config?: Partial<MetricsConfig>) {
    super();

    this.config = {
      qps_window_seconds: 60,
      percentile_sample_size: 1000,
      retention_hours: 24,
      alert_thresholds: {
        qps_threshold: 1000,
        p95_latency_threshold: 5000,
        error_rate_threshold: 5,
        memory_usage_threshold: 80,
      },
      export_enabled: true,
      export_interval_seconds: 30,
      export_formats: ['json', 'prometheus'],
      ...config,
    };

    this.initializeMetrics();
    this.setupPeriodicExport();
  }

  /**
   * Get singleton instance
   */
  public static getInstance(config?: Partial<MetricsConfig>): MetricsService {
    if (!(MetricsService as any).instance) {
      (MetricsService as any).instance = new MetricsService(config);
    }
    return (MetricsService as any).instance;
  }

  /**
   * Record an operation with metrics
   */
  recordOperation(
    operation: OperationType,
    latencyMs: number,
    success: boolean,
    metadata?: {
      strategy?: SearchStrategy;
      deduplication?: DeduplicationStrategy;
      result_count?: number;
      duplicates_found?: number;
      cache_hit?: boolean;
      ttl_hours?: number;
    }
  ): void {
    // Record in performance collector
    const endMetric = performanceCollector.startMetric(operation, metadata);
    endMetric();

    // Track QPS
    this.trackQPS(operation);

    // Track quality metrics
    if (metadata) {
      this.trackQualityMetrics(operation, metadata, success);
    }

    // Check for alerts
    this.checkAlerts(operation, latencyMs, success);

    // Emit for real-time monitoring
    this.emit('operation_recorded', {
      operation,
      latencyMs,
      success,
      metadata,
      timestamp: Date.now(),
    });
  }

  /**
   * Get real-time metrics
   */
  getRealTimeMetrics(): RealTimeMetrics {
    const now = Date.now();
    const windowStart = now - this.config.qps_window_seconds * 1000;

    // Calculate QPS
    const storeQPS = this.calculateQPS('memory_store', windowStart);
    const findQPS = this.calculateQPS('memory_find', windowStart);

    // Get performance summaries
    const storeSummary = performanceCollector.getSummary('memory_store');
    const findSummary = performanceCollector.getSummary('memory_find');

    // Calculate quality metrics
    const dedupeRate = this.calculateQualityMetric('dedupe_rate');
    const ttlDeletedRate = this.calculateQualityMetric('ttl_deleted_rate');
    const embeddingFailRate = this.calculateQualityMetric('embedding_fail_rate');
    const cacheHitRate = this.calculateQualityMetric('cache_hit_rate');

    // Get system metrics
    const memoryUsage = performanceCollector.getMemoryUsage();

    return {
      qps: {
        memory_store_qps: storeQPS,
        memory_find_qps: findQPS,
        total_qps: storeQPS + findQPS,
      },
      performance: {
        store_p95_ms: storeSummary?.p95 || 0,
        find_p95_ms: findSummary?.p95 || 0,
        store_p99_ms: storeSummary?.p99 || 0,
        find_p99_ms: findSummary?.p99 || 0,
      },
      quality: {
        dedupe_rate: dedupeRate,
        ttl_deleted_rate: ttlDeletedRate,
        embedding_fail_rate: embeddingFailRate,
        cache_hit_rate: cacheHitRate,
      },
      system: {
        memory_usage_mb: memoryUsage.heapUsed / (1024 * 1024),
        cpu_usage_percent: 0, // TODO: Implement CPU tracking
        active_connections: 0, // TODO: Implement connection tracking
      },
      timestamp: now,
    };
  }

  /**
   * Get historical metrics for trends
   */
  getHistoricalMetrics(timeWindowMinutes: number = 60): HistoricalMetrics {
    const trends = performanceCollector.getPerformanceTrends(timeWindowMinutes);

    const operationMetrics: Record<string, any> = {};

    for (const [operation, trend] of Object.entries(trends)) {
      operationMetrics[operation] = {
        count: trend.totalRequests,
        average_latency: trend.averageDuration,
        p95_latency: trend.p95Duration,
        p99_latency: trend.p99Duration,
        error_rate: trend.errorRate,
        qps: trend.requestsPerMinute / 60, // Convert to per-second
      };
    }

    return {
      time_window_minutes: timeWindowMinutes,
      operation_metrics: operationMetrics,
      quality_metrics: {
        dedupe_rate: this.calculateQualityMetric('dedupe_rate'),
        ttl_deleted_rate: this.calculateQualityMetric('ttl_deleted_rate'),
        embedding_fail_rate: this.calculateQualityMetric('embedding_fail_rate'),
        cache_hit_rate: this.calculateQualityMetric('cache_hit_rate'),
      },
      system_metrics: {
        memory_usage_mb: performanceCollector.getMemoryUsage().heapUsed / (1024 * 1024),
        cpu_usage_percent: 0,
      },
    };
  }

  /**
   * Export metrics in specified format
   */
  exportMetrics(format: 'json' | 'prometheus' | 'csv' = 'json'): string {
    const realTimeMetrics = this.getRealTimeMetrics();
    const historicalMetrics = this.getHistoricalMetrics(60);

    switch (format) {
      case 'prometheus':
        return this.exportPrometheusMetrics(realTimeMetrics, historicalMetrics);
      case 'csv':
        return this.exportCsvMetrics(realTimeMetrics, historicalMetrics);
      case 'json':
      default:
        return JSON.stringify(
          {
            real_time: realTimeMetrics,
            historical: historicalMetrics,
            timestamp: Date.now(),
          },
          null,
          2
        );
    }
  }

  /**
   * Get performance alerts
   */
  getAlerts(): Array<{
    type: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    message: string;
    current_value: number;
    threshold: number;
    timestamp: number;
  }> {
    const metrics = this.getRealTimeMetrics();
    const alerts: any[] = [];

    // QPS alerts
    if (metrics.qps.total_qps > this.config.alert_thresholds.qps_threshold) {
      alerts.push({
        type: 'high_qps',
        severity: 'medium',
        message: `QPS ${metrics.qps.total_qps} exceeds threshold ${this.config.alert_thresholds.qps_threshold}`,
        current_value: metrics.qps.total_qps,
        threshold: this.config.alert_thresholds.qps_threshold,
        timestamp: Date.now(),
      });
    }

    // Latency alerts
    if (metrics.performance.store_p95_ms > this.config.alert_thresholds.p95_latency_threshold) {
      alerts.push({
        type: 'high_latency',
        severity: 'high',
        message: `Store P95 latency ${metrics.performance.store_p95_ms}ms exceeds threshold ${this.config.alert_thresholds.p95_latency_threshold}ms`,
        current_value: metrics.performance.store_p95_ms,
        threshold: this.config.alert_thresholds.p95_latency_threshold,
        timestamp: Date.now(),
      });
    }

    // Error rate alerts
    const storeSummary = performanceCollector.getSummary('memory_store');
    const errorRate = storeSummary ? 100 - storeSummary.successRate : 0;
    if (errorRate > this.config.alert_thresholds.error_rate_threshold) {
      alerts.push({
        type: 'high_error_rate',
        severity: 'critical',
        message: `Error rate ${errorRate}% exceeds threshold ${this.config.alert_thresholds.error_rate_threshold}%`,
        current_value: errorRate,
        threshold: this.config.alert_thresholds.error_rate_threshold,
        timestamp: Date.now(),
      });
    }

    // Memory usage alerts
    if (metrics.system.memory_usage_mb > this.config.alert_thresholds.memory_usage_threshold) {
      alerts.push({
        type: 'high_memory_usage',
        severity: 'high',
        message: `Memory usage ${metrics.system.memory_usage_mb}MB exceeds threshold ${this.config.alert_thresholds.memory_usage_threshold}MB`,
        current_value: metrics.system.memory_usage_mb,
        threshold: this.config.alert_thresholds.memory_usage_threshold,
        timestamp: Date.now(),
      });
    }

    return alerts;
  }

  /**
   * Reset all metrics
   */
  resetMetrics(): void {
    performanceCollector.clearMetrics();
    this.qpsTrackers.clear();
    this.qualityMetrics.clear();
    this.metricsHistory = [];
    this.emit('metrics_reset');
  }

  /**
   * Record a gauge metric (single value that can go up or down)
   */
  recordGauge(
    name: string,
    value: number,
    labels?: Record<string, string>
  ): void {
    // Create a normalized key with labels
    const key = labels ? `${name}:${JSON.stringify(labels)}` : name;

    // Store gauge value
    if (!this.qualityMetrics.has(key)) {
      this.qualityMetrics.set(key, []);
    }
    const tracker = this.qualityMetrics.get(key)!;
    tracker.push(value);

    // Keep only recent values (last 100)
    if (tracker.length > 100) {
      tracker.splice(0, tracker.length - 100);
    }

    // Emit gauge event
    this.emit('gauge_recorded', {
      name,
      value,
      labels,
      timestamp: Date.now()
    });
  }

  /**
   * Record a counter metric (cumulative value that only increases)
   */
  recordCounter(
    name: string,
    increment: number = 1,
    labels?: Record<string, string>
  ): void {
    // Create a normalized key with labels
    const key = labels ? `${name}:${JSON.stringify(labels)}` : name;

    // Store counter value
    if (!this.qualityMetrics.has(key)) {
      this.qualityMetrics.set(key, [0]);
    }
    const tracker = this.qualityMetrics.get(key)!;
    const currentValue = tracker[tracker.length - 1] || 0;
    tracker.push(currentValue + increment);

    // Keep only recent values (last 100)
    if (tracker.length > 100) {
      tracker.splice(0, tracker.length - 100);
    }

    // Emit counter event
    this.emit('counter_recorded', {
      name,
      increment,
      value: currentValue + increment,
      labels,
      timestamp: Date.now()
    });
  }

  /**
   * Cleanup method
   */
  cleanup(): void {
    if (this.exportInterval) {
      clearInterval(this.exportInterval);
      this.exportInterval = null;
    }

    this.removeAllListeners();
    performanceCollector.cleanup();
  }

  // Private methods

  private initializeMetrics(): void {
    // Initialize QPS trackers for core operations
    this.qpsTrackers.set('memory_store', []);
    this.qpsTrackers.set('memory_find', []);

    // Initialize quality metrics trackers
    this.qualityMetrics.set('dedupe_rate', []);
    this.qualityMetrics.set('ttl_deleted_rate', []);
    this.qualityMetrics.set('embedding_fail_rate', []);
    this.qualityMetrics.set('cache_hit_rate', []);

    // Start performance collection
    performanceCollector.startCollection(30000); // 30 seconds
  }

  private trackQPS(operation: string): void {
    const tracker = this.qpsTrackers.get(operation);
    if (tracker) {
      const now = Date.now();
      tracker.push(now);

      // Keep only entries within the window
      const cutoff = now - this.config.qps_window_seconds * 1000;
      const index = tracker.findIndex((timestamp) => timestamp > cutoff);
      if (index > 0) {
        tracker.splice(0, index);
      }
    }
  }

  private trackQualityMetrics(operation: OperationType, metadata: any, success: boolean): void {
    // Track deduplication rate
    if (metadata.duplicates_found !== undefined) {
      const tracker = this.qualityMetrics.get('dedupe_rate')!;
      tracker.push(metadata.duplicates_found);
    }

    // Track TTL deletion rate
    if (metadata.ttl_hours && metadata.ttl_hours > 0) {
      const tracker = this.qualityMetrics.get('ttl_deleted_rate')!;
      tracker.push(1); // Track TTL-enabled items
    }

    // Track embedding failure rate
    if (operation === OperationType.EMBEDDING && !success) {
      const tracker = this.qualityMetrics.get('embedding_fail_rate')!;
      tracker.push(1);
    }

    // Track cache hit rate
    if (metadata.cache_hit !== undefined) {
      const tracker = this.qualityMetrics.get('cache_hit_rate')!;
      tracker.push(metadata.cache_hit ? 1 : 0);
    }
  }

  private calculateQPS(operation: string, windowStart: number): number {
    const tracker = this.qpsTrackers.get(operation);
    if (!tracker) return 0;

    const recentTimestamps = tracker.filter((timestamp) => timestamp > windowStart);
    const windowSeconds = this.config.qps_window_seconds;
    return recentTimestamps.length / windowSeconds;
  }

  private calculateQualityMetric(metricName: string): number {
    const tracker = this.qualityMetrics.get(metricName);
    if (!tracker || tracker.length === 0) return 0;

    // Calculate rate based on recent entries
    const recent = tracker.slice(-100); // Last 100 entries
    if (metricName === 'cache_hit_rate') {
      return (recent.filter(Boolean).length / recent.length) * 100;
    }

    // For other metrics, calculate average
    return recent.reduce((sum, value) => sum + value, 0) / recent.length;
  }

  private checkAlerts(operation: OperationType, latencyMs: number, success: boolean): void {
    // Check latency alerts
    if (latencyMs > this.config.alert_thresholds.p95_latency_threshold) {
      this.emit('alert', {
        type: 'high_latency',
        operation,
        latencyMs,
        threshold: this.config.alert_thresholds.p95_latency_threshold,
        timestamp: Date.now(),
      });
    }

    // Check error alerts
    if (!success) {
      this.emit('alert', {
        type: 'operation_error',
        operation,
        timestamp: Date.now(),
      });
    }
  }

  private setupPeriodicExport(): void {
    if (!this.config.export_enabled) return;

    this.exportInterval = setInterval(() => {
      const metrics = this.getRealTimeMetrics();
      this.metricsHistory.push(metrics);

      // Keep only recent history
      const maxHistory =
        (this.config.retention_hours * 60 * 60) / this.config.export_interval_seconds;
      if (this.metricsHistory.length > maxHistory) {
        this.metricsHistory = this.metricsHistory.slice(-Math.floor(maxHistory));
      }

      this.emit('metrics_exported', metrics);
    }, this.config.export_interval_seconds * 1000);
  }

  private exportPrometheusMetrics(
    realTime: RealTimeMetrics,
    _historical: HistoricalMetrics
  ): string {
    let output = '';

    // QPS metrics
    output += `# HELP cortex_qps Queries per second\n`;
    output += `# TYPE cortex_qps gauge\n`;
    output += `cortex_qps{operation="memory_store"} ${realTime.qps.memory_store_qps}\n`;
    output += `cortex_qps{operation="memory_find"} ${realTime.qps.memory_find_qps}\n`;
    output += `cortex_qps{operation="total"} ${realTime.qps.total_qps}\n`;

    // Latency metrics
    output += `# HELP cortex_latency_ms Operation latency in milliseconds\n`;
    output += `# TYPE cortex_latency_ms gauge\n`;
    output += `cortex_latency_ms{operation="memory_store",quantile="p95"} ${realTime.performance.store_p95_ms}\n`;
    output += `cortex_latency_ms{operation="memory_find",quantile="p95"} ${realTime.performance.find_p95_ms}\n`;
    output += `cortex_latency_ms{operation="memory_store",quantile="p99"} ${realTime.performance.store_p99_ms}\n`;
    output += `cortex_latency_ms{operation="memory_find",quantile="p99"} ${realTime.performance.find_p99_ms}\n`;

    // Quality metrics
    output += `# HELP cortex_quality_percent Quality metrics in percentage\n`;
    output += `# TYPE cortex_quality_percent gauge\n`;
    output += `cortex_quality_percent{metric="dedupe_rate"} ${realTime.quality.dedupe_rate}\n`;
    output += `cortex_quality_percent{metric="cache_hit_rate"} ${realTime.quality.cache_hit_rate}\n`;
    output += `cortex_quality_percent{metric="embedding_fail_rate"} ${realTime.quality.embedding_fail_rate}\n`;

    // System metrics
    output += `# HELP cortex_memory_mb Memory usage in MB\n`;
    output += `# TYPE cortex_memory_mb gauge\n`;
    output += `cortex_memory_mb ${realTime.system.memory_usage_mb}\n`;

    return output;
  }

  private exportCsvMetrics(realTime: RealTimeMetrics, _historical: HistoricalMetrics): string {
    const headers = [
      'timestamp',
      'store_qps',
      'find_qps',
      'total_qps',
      'store_p95_ms',
      'find_p95_ms',
      'store_p99_ms',
      'find_p99_ms',
      'dedupe_rate',
      'cache_hit_rate',
      'embedding_fail_rate',
      'memory_usage_mb',
    ];

    const row = [
      new Date(realTime.timestamp).toISOString(),
      realTime.qps.memory_store_qps,
      realTime.qps.memory_find_qps,
      realTime.qps.total_qps,
      realTime.performance.store_p95_ms,
      realTime.performance.find_p95_ms,
      realTime.performance.store_p99_ms,
      realTime.performance.find_p99_ms,
      realTime.quality.dedupe_rate,
      realTime.quality.cache_hit_rate,
      realTime.quality.embedding_fail_rate,
      realTime.system.memory_usage_mb,
    ];

    return `${headers.join(',')}\n${row.join(',')}`;
  }
}

// Export singleton instance with lazy initialization
export const metricsService = MetricsService.getInstance();
