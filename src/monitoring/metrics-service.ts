// EMERGENCY ROLLBACK: Enhanced monitoring type compatibility issues

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

import { EventEmitter } from 'events';

import { OperationType } from './operation-types.js';
import { performanceCollector } from './performance-collector.js';
import {
  type AlertSeverity,
  AlertState,
  createDefaultCollectorConfig,
  createTypedMetric,
  isTypedMetricQuery,
  type MetricsCollectorConfig,
  type MetricValidationResult,
  OutputFormat,
  TrendDirection,
  type TypedMetric,
  type TypedMetricAlert,
  type TypedMetricQuery,
  type TypedMetricQueryResult,
  type TypedMetricSeries,
  validateTypedMetric,
} from '../types/metrics-types.js';
import type {
  HistoricalMetrics,
  MetricsConfig,
  OperationMetadata,
  RealTimeMetrics,
} from '../types/monitoring-types.js';

// Re-export from monitoring-types for backward compatibility
export type { HistoricalMetrics, MetricsConfig, RealTimeMetrics } from '../types/monitoring-types.js';

/**
 * Comprehensive metrics service
 */
export class MetricsService extends EventEmitter {
  private static instance?: MetricsService;
  private config: MetricsConfig;
  private collectorConfig: MetricsCollectorConfig;
  private qpsTrackers: Map<string, number[]> = new Map();
  private qualityMetrics: Map<string, number[]> = new Map();
  private metricsHistory: RealTimeMetrics[] = [];
  private typedMetrics: Map<string, TypedMetric> = new Map();
  private metricSeries: Map<string, TypedMetricSeries> = new Map();
  private alerts: Map<string, TypedMetricAlert> = new Map();
  private exportInterval: NodeJS.Timeout | null = null;

  constructor(config?: Partial<MetricsConfig>, collectorConfig?: Partial<MetricsCollectorConfig>) {
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

    this.collectorConfig = {
      ...createDefaultCollectorConfig(),
      ...collectorConfig,
    };

    this.initializeMetrics();
    this.setupPeriodicExport();
  }

  /**
   * Get singleton instance
   */
  public static getInstance(config?: Partial<MetricsConfig>): MetricsService {
    if (!MetricsService.instance) {
      MetricsService.instance = new MetricsService(config);
    }
    return MetricsService.instance;
  }

  /**
   * Record an operation with metrics
   */
  recordOperation(
    operation: OperationType,
    latencyMs: number,
    success: boolean,
    metadata?: OperationMetadata
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
    const storeQPS = this.calculateQPS(OperationType.MEMORY_STORE, windowStart);
    const findQPS = this.calculateQPS(OperationType.MEMORY_FIND, windowStart);

    // Get performance summaries
    const storeSummary = performanceCollector.getSummary(OperationType.MEMORY_STORE);
    const findSummary = performanceCollector.getSummary(OperationType.MEMORY_FIND);

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

    const operationMetrics: Record<
      OperationType,
      {
        count: number;
        average_latency: number;
        p95_latency: number;
        p99_latency: number;
        error_rate: number;
        qps: number;
      }
    > = {} as Record<OperationType, {
      count: number;
      average_latency: number;
      p95_latency: number;
      p99_latency: number;
      error_rate: number;
      qps: number;
    }>;

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
    const alerts: Array<{
      type: string;
      severity: 'low' | 'medium' | 'high' | 'critical';
      message: string;
      current_value: number;
      threshold: number;
      timestamp: number;
    }> = [];

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
    const storeSummary = performanceCollector.getSummary(OperationType.MEMORY_STORE);
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
  recordGauge(name: string, value: number, labels?: Record<string, string>): void {
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
      timestamp: Date.now(),
    });
  }

  /**
   * Record a counter metric (cumulative value that only increases)
   */
  recordCounter(name: string, increment: number = 1, labels?: Record<string, string>): void {
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
      timestamp: Date.now(),
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

  // ============================================================================
  // New Typed Metrics Methods
  // ============================================================================

  /**
   * Record a typed metric with validation and enhanced features
   */
  recordTypedMetric(metric: TypedMetric): MetricValidationResult {
    // Validate the metric
    const validationResult = validateTypedMetric(metric);

    if (!validationResult.isValid) {
      // Log validation errors
      console.error('Typed metric validation failed:', {
        metric,
        errors: validationResult.errors,
      });

      // Still store the metric but mark as invalid
      const invalidMetric = createTypedMetric({
        ...metric,
        labels: {
          ...metric.labels,
          validationErrors: JSON.stringify(validationResult.errors),
          validationStatus: 'invalid',
        },
      });

      this.storeTypedMetric(invalidMetric);
      return validationResult;
    }

    // Log warnings if any
    if (validationResult.warnings.length > 0) {
      console.warn('Typed metric validation warnings:', {
        metric,
        warnings: validationResult.warnings,
      });
    }

    this.storeTypedMetric(metric);
    return validationResult;
  }

  /**
   * Store a typed metric in internal storage
   */
  private storeTypedMetric(metric: TypedMetric): void {
    this.typedMetrics.set(metric.id, metric);

    // Update or create metric series
    this.updateMetricSeries(metric);

    // Check for alerts
    this.checkMetricAlerts(metric);

    // Emit metric recorded event
    this.emit('typed_metric_recorded', {
      metric,
      timestamp: Date.now(),
    });
  }

  /**
   * Update metric series with new data point
   */
  private updateMetricSeries(metric: TypedMetric): void {
    const seriesKey = this.getSeriesKey(metric);
    let series = this.metricSeries.get(seriesKey);

    if (!series) {
      series = {
        id: seriesKey,
        name: metric.name,
        type: metric.type,
        category: metric.category,
        dimensions: metric.dimensions,
        labels: metric.labels,
        dataPoints: [],
        startTime: metric.timestamp,
        endTime: metric.timestamp,
        resolution: metric.interval || 60,
        totalPoints: 0,
        dataQuality: {
          completeness: 1.0,
          accuracy: metric.quality.accuracy,
          consistency: metric.quality.consistency,
          staleness: 0,
          gaps: 0,
          outliers: 0,
          lastUpdated: metric.timestamp,
        },
      };
      this.metricSeries.set(seriesKey, series);
    }

    // Add new data point
    const dataPoint = {
      timestamp: metric.timestamp,
      value: metric.value as number | string,
      quality: metric.quality.accuracy,
      annotations: metric.metadata as Record<string, unknown> | undefined,
    };

    series.dataPoints.push(dataPoint);
    series.totalPoints++;
    series.endTime = metric.timestamp;

    // Keep only recent data points based on retention policy
    const retentionPoints = (86400 / series.resolution) * 7; // 7 days worth
    if (series.dataPoints.length > retentionPoints) {
      series.dataPoints = series.dataPoints.slice(-retentionPoints);
    }

    // Update statistics
    this.updateSeriesStatistics(series);
  }

  /**
   * Update series statistics
   */
  private updateSeriesStatistics(series: TypedMetricSeries): void {
    const numericValues = series.dataPoints
      .map((dp) => (typeof dp.value === 'number' ? dp.value : null))
      .filter((val): val is number => val !== null);

    if (numericValues.length === 0) {
      return;
    }

    const sorted = numericValues.slice().sort((a, b) => a - b);
    const sum = numericValues.reduce((acc, val) => acc + val, 0);
    const mean = sum / numericValues.length;

    series.statistics = {
      count: numericValues.length,
      sum,
      average: mean,
      median: sorted[Math.floor(sorted.length / 2)],
      min: sorted[0],
      max: sorted[sorted.length - 1],
      variance:
        numericValues.reduce((acc, val) => acc + Math.pow(val - mean, 2), 0) / numericValues.length,
      standardDeviation: Math.sqrt(
        numericValues.reduce((acc, val) => acc + Math.pow(val - mean, 2), 0) / numericValues.length
      ),
      percentiles: {
        50: sorted[Math.floor(sorted.length * 0.5)],
        90: sorted[Math.floor(sorted.length * 0.9)],
        95: sorted[Math.floor(sorted.length * 0.95)],
        99: sorted[Math.floor(sorted.length * 0.99)],
      },
      trend: this.calculateTrend(numericValues),
      seasonality: undefined, // Complex analysis would go here
    };
  }

  /**
   * Calculate trend direction
   */
  private calculateTrend(values: number[]): import('../types/metrics-types.js').TrendDirection {
    if (values.length < 2) return 'unknown' as import('../types/metrics-types.js').TrendDirection;

    const firstHalf = values.slice(0, Math.floor(values.length / 2));
    const secondHalf = values.slice(Math.floor(values.length / 2));

    const firstAvg = firstHalf.reduce((a, b) => a + b, 0) / firstHalf.length;
    const secondAvg = secondHalf.reduce((a, b) => a + b, 0) / secondHalf.length;

    const change = (secondAvg - firstAvg) / firstAvg;

    // Calculate volatility
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const variance = values.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / values.length;
    const volatility = Math.sqrt(variance) / mean;

    if (volatility > 0.3) return TrendDirection.VOLATILE;
    if (change > 0.05) return TrendDirection.INCREASING;
    if (change < -0.05) return TrendDirection.DECREASING;
    return TrendDirection.STABLE;
  }

  /**
   * Generate series key for metric
   */
  private getSeriesKey(metric: TypedMetric): string {
    const dimensions = metric.dimensions
      .map((d) => `${d.name}:${d.value}`)
      .sort()
      .join(',');

    const labels = Object.entries(metric.labels)
      .map(([k, v]) => `${k}:${v}`)
      .sort()
      .join(',');

    return `${metric.name}:${metric.type}:${dimensions}:${labels}`;
  }

  /**
   * Query typed metrics with advanced filtering
   */
  queryTypedMetrics(query: TypedMetricQuery): TypedMetricQueryResult {
    const startTime = Date.now();

    if (!isTypedMetricQuery(query)) {
      throw new Error('Invalid metric query provided');
    }

    // Filter series based on query criteria
    let filteredSeries = Array.from(this.metricSeries.values());

    // Apply filters
    if (query.metricNames && query.metricNames.length > 0) {
      filteredSeries = filteredSeries.filter((series) => query.metricNames!.includes(series.name));
    }

    if (query.metricTypes && query.metricTypes.length > 0) {
      filteredSeries = filteredSeries.filter((series) => query.metricTypes!.includes(series.type));
    }

    if (query.metricCategories && query.metricCategories.length > 0) {
      filteredSeries = filteredSeries.filter((series) =>
        query.metricCategories!.includes(series.category)
      );
    }

    if (query.components && query.components.length > 0) {
      filteredSeries = filteredSeries.filter((series) =>
        query.components!.some((comp) => series.labels.component === comp)
      );
    }

    // Apply time range filtering
    const queryStart = new Date(query.timeRange.start).getTime();
    const queryEnd = new Date(query.timeRange.end).getTime();

    filteredSeries = filteredSeries
      .map((series) => {
        const filteredDataPoints = series.dataPoints.filter((dp) => {
          const timestamp = new Date(dp.timestamp).getTime();
          return timestamp >= queryStart && timestamp <= queryEnd;
        });

        return {
          ...series,
          dataPoints: filteredDataPoints,
          totalPoints: filteredDataPoints.length,
        };
      })
      .filter((series) => series.totalPoints > 0);

    // Apply aggregation if specified
    if (query.aggregation) {
      filteredSeries = this.applyAggregation(filteredSeries, query.aggregation);
    }

    // Apply ordering
    if (query.orderBy && query.orderBy.length > 0) {
      filteredSeries = this.applyOrdering(filteredSeries, query.orderBy);
    }

    // Apply pagination
    const totalCount = filteredSeries.length;
    const offset = query.offset || 0;
    const limit = query.limit || 100;
    const paginatedSeries = filteredSeries.slice(offset, offset + limit);

    const executionTime = Date.now() - startTime;

    return {
      query,
      series: paginatedSeries,
      totalCount,
      hasMore: offset + limit < totalCount,
      nextOffset: offset + limit < totalCount ? offset + limit : undefined,
      executionTime,
      cached: false,
    };
  }

  /**
   * Apply aggregation to metric series
   */
  private applyAggregation(series: TypedMetricSeries[], aggregation: unknown): TypedMetricSeries[] {
    // This is a simplified implementation
    // In production, would need more sophisticated aggregation logic
    return series.map((s) => {
      const aggregatedDataPoints = this.aggregateDataPoints(s.dataPoints, aggregation);
      return {
        ...s,
        dataPoints: aggregatedDataPoints,
        aggregation: aggregation as import('../types/metrics-types.js').MetricAggregation,
      };
    });
  }

  /**
   * Aggregate data points
   */
  private aggregateDataPoints(dataPoints: import('../types/metrics-types.js').TypedMetricDataPoint[], aggregation: unknown): import('../types/metrics-types.js').TypedMetricDataPoint[] {
    // Simplified aggregation - in production would implement windowed aggregation
    const agg = aggregation as { function?: string; field?: string; direction?: string };
    // TypedMetricDataPoint is already imported at the top of the file

    if (agg.function === 'avg' && dataPoints.length > 0) {
      const numericValues = dataPoints
        .map((dp) => {
          return typeof dp.value === 'number' ? dp.value : Number(dp.value) || 0;
        })
        .filter((val) => !isNaN(val));

      if (numericValues.length > 0) {
        const avg = numericValues.reduce((a, b) => a + b, 0) / numericValues.length;
        const lastPoint = dataPoints[dataPoints.length - 1] as { timestamp?: string };
        return [
          {
            timestamp: lastPoint.timestamp || new Date().toISOString(),
            value: avg,
            quality: 1.0,
            annotations: { aggregation: 'avg' },
          },
        ];
      }
    }

    // Ensure we return the correct type
    return dataPoints.map(dp => ({
      timestamp: dp.timestamp || new Date().toISOString(),
      value: dp.value,
      quality: dp.quality ?? 1.0,
      annotations: dp.annotations
    }));
  }

  /**
   * Apply ordering to metric series
   */
  private applyOrdering(series: TypedMetricSeries[], orderBy: unknown[]): TypedMetricSeries[] {
    return series.sort((a, b) => {
      for (const orderSpec of orderBy) {
        const order = orderSpec as { field?: string; direction?: string };
        let comparison = 0;

        switch (order.field) {
          case 'name':
            comparison = a.name.localeCompare(b.name);
            break;
          case 'timestamp':
            comparison = new Date(a.endTime).getTime() - new Date(b.endTime).getTime();
            break;
          case 'value':
            const aLastValue = a.dataPoints[a.dataPoints.length - 1]?.value;
            const bLastValue = b.dataPoints[b.dataPoints.length - 1]?.value;
            if (typeof aLastValue === 'number' && typeof bLastValue === 'number') {
              comparison = aLastValue - bLastValue;
            }
            break;
        }

        if (comparison !== 0) {
          return order.direction === 'DESC' ? -comparison : comparison;
        }
      }

      return 0;
    });
  }

  /**
   * Create a metric alert
   */
  createMetricAlert(
    alert: Omit<TypedMetricAlert, 'id' | 'state' | 'stateHistory' | 'metadata'>
  ): string {
    const alertId = `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    const fullAlert: TypedMetricAlert = {
      ...alert,
      id: alertId,
      state: AlertState.OK,
      stateHistory: [],
      metadata: {
        created: new Date().toISOString(),
        updated: new Date().toISOString(),
        createdBy: 'system',
        updatedBy: 'system',
        tags: [],
        owner: 'system',
        team: 'platform',
        service: 'metrics-service',
        runbook: '/docs/runbooks/metrics-alerts',
        documentation: '/docs/metrics',
      },
    };

    this.alerts.set(alertId, fullAlert);

    this.emit('metric_alert_created', { alert: fullAlert });

    return alertId;
  }

  /**
   * Check for metric alerts based on threshold conditions
   */
  private checkMetricAlerts(metric: TypedMetric): void {
    for (const alert of Array.from(this.alerts.values())) {
      if (!alert.enabled) continue;

      // Check if this metric matches the alert's query
      const queryResult = this.queryTypedMetrics(alert.condition.metricQuery);
      const matchingSeries = queryResult.series.find(
        (series) =>
          series.name === metric.name && this.dimensionsMatch(series.dimensions, metric.dimensions)
      );

      if (matchingSeries) {
        const latestValue = matchingSeries.dataPoints[matchingSeries.dataPoints.length - 1]?.value;
        if (typeof latestValue === 'number') {
          this.evaluateAlertCondition(alert, latestValue);
        }
      }
    }
  }

  /**
   * Check if dimensions match
   */
  private dimensionsMatch(seriesDimensions: unknown[], metricDimensions: unknown[]): boolean {
    if (seriesDimensions.length !== metricDimensions.length) return false;

    return seriesDimensions.every((sd) => {
      if (!sd || typeof sd !== 'object' || !('name' in sd) || !('value' in sd)) {
        return false;
      }

      const seriesDim = sd as { name: unknown; value: unknown };

      return metricDimensions.some((md) => {
        if (!md || typeof md !== 'object' || !('name' in md) || !('value' in md)) {
          return false;
        }

        const metricDim = md as { name: unknown; value: unknown };
        return seriesDim.name === metricDim.name && seriesDim.value === metricDim.value;
      });
    });
  }

  /**
   * Evaluate alert condition
   */
  private evaluateAlertCondition(alert: TypedMetricAlert, value: number): void {
    const currentState = alert.state;
    let newState = currentState;

    // Check each threshold
    for (const threshold of alert.condition.thresholds) {
      if (!threshold.enabled) continue;

      let triggered = false;
      // Use threshold.condition for operator and value according to slo-interfaces definition
      const operator = threshold.condition?.operator || 'gt';
      const valueThreshold = threshold.condition?.value || threshold.threshold;

      switch (operator) {
        case 'gt':
          triggered = value > valueThreshold;
          break;
        case 'gte':
          triggered = value >= valueThreshold;
          break;
        case 'lt':
          triggered = value < valueThreshold;
          break;
        case 'lte':
          triggered = value <= valueThreshold;
          break;
        case 'eq':
          triggered = value === valueThreshold;
          break;
      }

      if (triggered) {
        if (threshold.severity === 'critical') {
          newState = AlertState.CRITICAL;
        } else if (threshold.severity === 'error' && newState !== AlertState.CRITICAL) {
          newState = AlertState.WARNING;
        }
        break;
      }
    }

    // Update alert state if changed
    if (newState !== currentState) {
      const transition = {
        from: currentState,
        to: newState,
        timestamp: new Date().toISOString(),
        reason: `Value ${value} crossed threshold`,
        value,
        threshold: alert.condition.thresholds[0]?.condition?.value || alert.condition.thresholds[0]?.threshold || 0,
      };

      alert.stateHistory.push(transition);
      alert.state = newState;
      alert.metadata.updated = new Date().toISOString();

      this.emit('metric_alert_state_changed', {
        alert,
        previousState: currentState,
        newState,
        transition,
      });
    }
  }

  /**
   * Get all metric alerts
   */
  getMetricAlerts(): TypedMetricAlert[] {
    return Array.from(this.alerts.values());
  }

  /**
   * Get metric alerts by severity
   */
  getMetricAlertsBySeverity(severity: AlertSeverity): TypedMetricAlert[] {
    return Array.from(this.alerts.values()).filter((alert) => alert.severity === severity);
  }

  /**
   * Export typed metrics in specified format
   */
  exportTypedMetrics(format: OutputFormat = OutputFormat.JSON, query?: TypedMetricQuery): string {
    const queryResult = query
      ? this.queryTypedMetrics(query)
      : ({ series: Array.from(this.metricSeries.values()) } as TypedMetricQueryResult);

    switch (format) {
      case OutputFormat.PROMETHEUS:
        return this.exportPrometheusFormat(queryResult.series);
      case OutputFormat.CSV:
        return this.exportCsvFormat(queryResult.series);
      case OutputFormat.JSON:
      default:
        return JSON.stringify(
          {
            query: queryResult.query,
            series: queryResult.series,
            totalCount: queryResult.totalCount,
            executionTime: queryResult.executionTime,
            timestamp: Date.now(),
          },
          null,
          2
        );
    }
  }

  /**
   * Export metrics in Prometheus format
   */
  private exportPrometheusFormat(series: TypedMetricSeries[]): string {
    let output = '';

    for (const s of series) {
      const latestPoint = s.dataPoints[s.dataPoints.length - 1];
      if (!latestPoint || typeof latestPoint.value !== 'number') continue;

      // Create metric name with dimensions
      const metricName = s.name.replace(/[^a-zA-Z0-9_]/g, '_');
      const dimensions = [
        ...s.dimensions.map((d) => `${d.name}="${d.value}"`),
        ...Object.entries(s.labels).map(([k, v]) => `${k}="${v}"`),
      ];

      const fullMetricName =
        dimensions.length > 0 ? `${metricName}{${dimensions.join(',')}}` : metricName;

      output += `${fullMetricName} ${latestPoint.value} ${new Date(latestPoint.timestamp).getTime() / 1000}\n`;
    }

    return output;
  }

  /**
   * Export metrics in CSV format
   */
  private exportCsvFormat(series: TypedMetricSeries[]): string {
    const headers = ['timestamp', 'metric_name', 'metric_type', 'value', 'quality'];
    const dimensionNames = Array.from(
      new Set(series.flatMap((s) => s.dimensions.map((d) => d.name)))
    );
    const labelNames = Array.from(new Set(series.flatMap((s) => Object.keys(s.labels))));

    headers.push(...dimensionNames, ...labelNames);

    const rows = [headers.join(',')];

    for (const s of series) {
      for (const point of s.dataPoints) {
        const row = [point.timestamp, s.name, s.type, point.value, point.quality];

        // Add dimensions
        for (const dimName of dimensionNames) {
          const dim = s.dimensions.find((d) => d.name === dimName);
          row.push(dim ? `"${dim.value}"` : '');
        }

        // Add labels
        for (const labelName of labelNames) {
          const label = s.labels[labelName];
          row.push(label ? `"${label}"` : '');
        }

        rows.push(row.join(','));
      }
    }

    return rows.join('\n');
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

  private trackQualityMetrics(
    operation: OperationType,
    metadata: OperationMetadata,
    success: boolean
  ): void {
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
