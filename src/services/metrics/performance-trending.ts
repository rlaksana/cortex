/**
 * P4-1: Performance Trending and Time-Series Data Collection
 *
 * Provides comprehensive performance trending analysis and time-series
 * data collection for system metrics. Supports historical analysis,
 * performance patterns, and trend detection.
 *
 * Features:
 * - Time-series data collection with configurable retention
 * - Performance trend analysis and pattern detection
 * - Resource utilization tracking over time
 * - Automated anomaly detection
 * - Performance alerts and threshold monitoring
 * - Export capabilities for external monitoring systems
 *
 * @module services/metrics/performance-trending
 */

import { logger } from '@/utils/logger.js';
import { systemMetricsService, type SystemMetrics } from './system-metrics.js';

// === Type Definitions ===

export interface TimeSeriesDataPoint {
  timestamp: number;
  metrics: Partial<SystemMetrics>;
  derived: {
    operations_per_second: number;
    error_rate: number;
    memory_utilization: number;
    response_time_trend: 'improving' | 'stable' | 'degrading';
    throughput_trend: 'increasing' | 'stable' | 'decreasing';
  };
}

export interface TrendAnalysis {
  period: {
    start: number;
    end: number;
    duration_ms: number;
  };
  performance: {
    avg_response_time: number;
    response_time_trend: 'improving' | 'stable' | 'degrading';
    response_time_change_percent: number;
  };
  throughput: {
    operations_per_second: number;
    throughput_trend: 'increasing' | 'stable' | 'decreasing';
    throughput_change_percent: number;
  };
  reliability: {
    error_rate: number;
    availability: number;
    success_rate: number;
  };
  resources: {
    memory_utilization: number;
    memory_trend: 'increasing' | 'stable' | 'decreasing';
    actor_utilization: number;
  };
  anomalies: Array<{
    timestamp: number;
    type: 'performance_spike' | 'error_burst' | 'memory_leak' | 'throughput_drop';
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    metrics_affected: string[];
  }>;
}

export interface PerformanceAlert {
  id: string;
  timestamp: number;
  severity: 'info' | 'warning' | 'error' | 'critical';
  category: 'performance' | 'reliability' | 'resource' | 'rate_limit';
  title: string;
  description: string;
  current_value: number;
  threshold: number;
  trend_direction: 'increasing' | 'decreasing' | 'stable';
  recommendations: string[];
  resolved: boolean;
  resolved_at?: number;
}

export interface TrendingConfig {
  /** Time-series data retention period in hours */
  retention_hours: number;
  /** Data collection interval in seconds */
  collection_interval_seconds: number;
  /** Maximum data points to retain in memory */
  max_data_points: number;
  /** Performance alert thresholds */
  thresholds: {
    response_time_ms: number;
    error_rate_percent: number;
    memory_utilization_percent: number;
    throughput_ops_per_second: number;
    rate_limit_block_rate_percent: number;
  };
  /** Anomaly detection sensitivity */
  anomaly_detection: {
    enabled: boolean;
    sensitivity: 'low' | 'medium' | 'high';
    min_data_points: number;
  };
}

/**
 * Service for performance trending and time-series analysis
 */
export class PerformanceTrendingService {
  private timeSeriesData: TimeSeriesDataPoint[] = [];
  private alerts: PerformanceAlert[] = [];
  private collectionInterval: NodeJS.Timeout | null = null;
  private lastCollectedMetrics: Partial<SystemMetrics> | null = null;

  private readonly config: TrendingConfig = {
    retention_hours: 24,
    collection_interval_seconds: 30,
    max_data_points: 2880, // 24 hours at 30-second intervals
    thresholds: {
      response_time_ms: 1000,
      error_rate_percent: 5.0,
      memory_utilization_percent: 80.0,
      throughput_ops_per_second: 1.0,
      rate_limit_block_rate_percent: 10.0,
    },
    anomaly_detection: {
      enabled: true,
      sensitivity: 'medium',
      min_data_points: 10,
    },
  };

  constructor(config?: Partial<TrendingConfig>) {
    if (config) {
      this.config = { ...this.config, ...config };
    }

    logger.info('PerformanceTrendingService initialized', {
      retentionHours: this.config.retention_hours,
      collectionInterval: this.config.collection_interval_seconds,
      anomalyDetection: this.config.anomaly_detection.enabled,
    });
  }

  /**
   * Start automatic data collection
   */
  startCollection(): void {
    if (this.collectionInterval) {
      logger.warn('Performance trending collection already started');
      return;
    }

    logger.info('Starting performance trending collection', {
      intervalSeconds: this.config.collection_interval_seconds,
    });

    this.collectionInterval = setInterval(() => {
      this.collectMetrics();
    }, this.config.collection_interval_seconds * 1000);

    // Collect initial metrics immediately
    this.collectMetrics();
  }

  /**
   * Stop automatic data collection
   */
  stopCollection(): void {
    if (this.collectionInterval) {
      clearInterval(this.collectionInterval);
      this.collectionInterval = null;
      logger.info('Performance trending collection stopped');
    }
  }

  /**
   * Collect current metrics and store as time-series data point
   */
  private collectMetrics(): void {
    try {
      const currentMetrics = systemMetricsService.getMetrics();
      const now = Date.now();

      // Calculate derived metrics
      const derived = this.calculateDerivedMetrics(currentMetrics, now);

      const dataPoint: TimeSeriesDataPoint = {
        timestamp: now,
        metrics: currentMetrics,
        derived,
      };

      // Add to time-series data
      this.timeSeriesData.push(dataPoint);

      // Enforce retention limits
      this.enforceRetention();

      // Check for alerts and anomalies
      if (this.config.anomaly_detection.enabled) {
        this.checkAlerts(dataPoint);
        this.detectAnomalies(dataPoint);
      }

      this.lastCollectedMetrics = currentMetrics;
    } catch (error) {
      logger.error('Failed to collect metrics for trending', { error });
    }
  }

  /**
   * Calculate derived metrics from raw system metrics
   */
  private calculateDerivedMetrics(
    metrics: SystemMetrics,
    timestamp: number
  ): TimeSeriesDataPoint['derived'] {
    const totalOps =
      metrics.store_count.total + metrics.find_count.total + metrics.purge_count.total;
    const totalErrors = metrics.errors.total_errors;

    // Calculate operations per second
    const opsPerSecond =
      this.timeSeriesData.length > 0 ? this.calculateOpsPerSecond(totalOps, timestamp) : 0;

    // Calculate error rate
    const errorRate = totalOps > 0 ? (totalErrors / totalOps) * 100 : 0;

    // Calculate memory utilization (simplified)
    const memoryUtilization = Math.min(100, (metrics.memory.memory_usage_kb / (1024 * 1024)) * 100); // Convert to GB percentage

    // Determine trends based on recent data points
    const responseTimeTrend = this.determineResponseTimeTrend(
      metrics.performance.avg_store_duration_ms
    );
    const throughputTrend = this.determineThroughputTrend(opsPerSecond);

    return {
      operations_per_second: opsPerSecond,
      error_rate: errorRate,
      memory_utilization: memoryUtilization,
      response_time_trend: responseTimeTrend,
      throughput_trend: throughputTrend,
    };
  }

  /**
   * Calculate operations per second based on recent data
   */
  private calculateOpsPerSecond(totalOps: number, timestamp: number): number {
    if (this.timeSeriesData.length === 0) return 0;

    // Use last 5 minutes of data for calculation
    const fiveMinutesAgo = timestamp - 5 * 60 * 1000;
    const recentData = this.timeSeriesData.filter((dp) => dp.timestamp >= fiveMinutesAgo);

    if (recentData.length < 2) return 0;

    const oldestRecent = recentData[0];
    const totalRecentOps = totalOps;
    const timeDiffSeconds = (timestamp - oldestRecent.timestamp) / 1000;

    return timeDiffSeconds > 0
      ? (totalRecentOps - this.getTotalOpsFromDataPoint(oldestRecent)) / timeDiffSeconds
      : 0;
  }

  /**
   * Determine response time trend
   */
  private determineResponseTimeTrend(
    currentResponseTime: number
  ): 'improving' | 'stable' | 'degrading' {
    if (this.timeSeriesData.length < 5) return 'stable';

    const recentPoints = this.timeSeriesData.slice(-5);
    const avgRecentResponseTime =
      recentPoints.reduce(
        (sum, dp) =>
          sum +
          (dp.metrics.performance?.avg_store_duration_ms || 0) +
          (dp.metrics.performance?.avg_find_duration_ms || 0),
        0
      ) /
      (recentPoints.length * 2);

    const changePercent =
      ((currentResponseTime - avgRecentResponseTime) / avgRecentResponseTime) * 100;

    if (changePercent > 10) return 'degrading';
    if (changePercent < -10) return 'improving';
    return 'stable';
  }

  /**
   * Determine throughput trend
   */
  private determineThroughputTrend(
    currentThroughput: number
  ): 'increasing' | 'stable' | 'decreasing' {
    if (this.timeSeriesData.length < 5) return 'stable';

    const recentPoints = this.timeSeriesData.slice(-5);
    const avgRecentThroughput =
      recentPoints.reduce((sum, dp) => sum + dp.derived.operations_per_second, 0) /
      recentPoints.length;

    const changePercent = ((currentThroughput - avgRecentThroughput) / avgRecentThroughput) * 100;

    if (changePercent > 15) return 'increasing';
    if (changePercent < -15) return 'decreasing';
    return 'stable';
  }

  /**
   * Enforce data retention limits
   */
  private enforceRetention(): void {
    const retentionMs = this.config.retention_hours * 60 * 60 * 1000;
    const cutoffTime = Date.now() - retentionMs;

    // Remove old data points
    this.timeSeriesData = this.timeSeriesData.filter((dp) => dp.timestamp >= cutoffTime);

    // Enforce maximum data points limit
    if (this.timeSeriesData.length > this.config.max_data_points) {
      const excess = this.timeSeriesData.length - this.config.max_data_points;
      this.timeSeriesData = this.timeSeriesData.slice(excess);
    }

    // Clean up old resolved alerts
    const alertRetentionMs = retentionMs / 2; // Keep alerts longer
    const alertCutoffTime = Date.now() - alertRetentionMs;
    this.alerts = this.alerts.filter(
      (alert) => !alert.resolved || (alert.resolved_at && alert.resolved_at >= alertCutoffTime)
    );
  }

  /**
   * Check for performance alerts based on thresholds
   */
  private checkAlerts(dataPoint: TimeSeriesDataPoint): void {
    const alerts: PerformanceAlert[] = [];

    // Response time alert
    const avgResponseTime =
      ((dataPoint.metrics.performance?.avg_store_duration_ms || 0) +
        (dataPoint.metrics.performance?.avg_find_duration_ms || 0)) /
      2;
    if (avgResponseTime > this.config.thresholds.response_time_ms) {
      alerts.push(
        this.createAlert(
          'performance',
          'warning',
          'High Response Time',
          `Average response time (${avgResponseTime.toFixed(2)}ms) exceeds threshold (${this.config.thresholds.response_time_ms}ms)`,
          avgResponseTime,
          this.config.thresholds.response_time_ms,
          [
            'Consider optimizing database queries',
            'Check system resources',
            'Review recent code changes',
          ]
        )
      );
    }

    // Error rate alert
    if (dataPoint.derived.error_rate > this.config.thresholds.error_rate_percent) {
      alerts.push(
        this.createAlert(
          'reliability',
          'error',
          'High Error Rate',
          `Error rate (${dataPoint.derived.error_rate.toFixed(2)}%) exceeds threshold (${this.config.thresholds.error_rate_percent}%)`,
          dataPoint.derived.error_rate,
          this.config.thresholds.error_rate_percent,
          [
            'Check system logs for error patterns',
            'Review recent deployments',
            'Monitor external dependencies',
          ]
        )
      );
    }

    // Memory utilization alert
    if (dataPoint.derived.memory_utilization > this.config.thresholds.memory_utilization_percent) {
      alerts.push(
        this.createAlert(
          'resource',
          'warning',
          'High Memory Utilization',
          `Memory utilization (${dataPoint.derived.memory_utilization.toFixed(2)}%) exceeds threshold (${this.config.thresholds.memory_utilization_percent}%)`,
          dataPoint.derived.memory_utilization,
          this.config.thresholds.memory_utilization_percent,
          [
            'Monitor for memory leaks',
            'Consider increasing memory allocation',
            'Review data retention policies',
          ]
        )
      );
    }

    // Rate limiting alert
    const rateLimitBlockRate =
      ((dataPoint.metrics.rate_limiting?.blocked_requests || 0) /
        Math.max(dataPoint.metrics.rate_limiting?.total_requests || 1, 1)) *
      100;
    if (rateLimitBlockRate > this.config.thresholds.rate_limit_block_rate_percent) {
      alerts.push(
        this.createAlert(
          'rate_limit',
          'info',
          'High Rate Limit Blocking',
          `Rate limit block rate (${rateLimitBlockRate.toFixed(2)}%) exceeds threshold (${this.config.thresholds.rate_limit_block_rate_percent}%)`,
          rateLimitBlockRate,
          this.config.thresholds.rate_limit_block_rate_percent,
          [
            'Consider adjusting rate limits',
            'Monitor for abusive clients',
            'Implement client-side backoff',
          ]
        )
      );
    }

    // Add new alerts (avoid duplicates)
    alerts.forEach((alert) => {
      const existingAlert = this.alerts.find(
        (existing) =>
          existing.title === alert.title &&
          existing.resolved === false &&
          Date.now() - existing.timestamp < 60000 // Within last minute
      );

      if (!existingAlert) {
        this.alerts.push(alert);
        logger.warn('Performance alert triggered', { alert });
      }
    });
  }

  /**
   * Detect performance anomalies
   */
  private detectAnomalies(dataPoint: TimeSeriesDataPoint): void {
    if (this.timeSeriesData.length < this.config.anomaly_detection.min_data_points) {
      return;
    }

    const recentData = this.timeSeriesData.slice(-10);

    // Simple anomaly detection based on statistical deviation
    const responseTimes = recentData.map(
      (dp) =>
        ((dp.metrics.performance?.avg_store_duration_ms || 0) +
          (dp.metrics.performance?.avg_find_duration_ms || 0)) /
        2
    );
    const avgResponseTime = responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length;
    const responseTimeStdDev = Math.sqrt(
      responseTimes.reduce((sum, rt) => sum + Math.pow(rt - avgResponseTime, 2), 0) /
        responseTimes.length
    );

    const currentResponseTime =
      ((dataPoint.metrics.performance?.avg_store_duration_ms || 0) +
        (dataPoint.metrics.performance?.avg_find_duration_ms || 0)) /
      2;

    // Check for performance spikes (3 standard deviations from mean)
    if (Math.abs(currentResponseTime - avgResponseTime) > 3 * responseTimeStdDev) {
      logger.warn('Performance anomaly detected', {
        type: 'performance_spike',
        current: currentResponseTime,
        average: avgResponseTime,
        stdDev: responseTimeStdDev,
      });
    }
  }

  /**
   * Create a performance alert
   */
  private createAlert(
    category: PerformanceAlert['category'],
    severity: PerformanceAlert['severity'],
    title: string,
    description: string,
    currentValue: number,
    threshold: number,
    recommendations: string[]
  ): PerformanceAlert {
    return {
      id: `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: Date.now(),
      severity,
      category,
      title,
      description,
      current_value: currentValue,
      threshold,
      trend_direction: 'stable', // Could be calculated based on historical data
      recommendations,
      resolved: false,
    };
  }

  /**
   * Get trend analysis for a specific time period
   */
  getTrendAnalysis(periodHours: number = 1): TrendAnalysis {
    const now = Date.now();
    const periodStart = now - periodHours * 60 * 60 * 1000;

    const periodData = this.timeSeriesData.filter((dp) => dp.timestamp >= periodStart);

    if (periodData.length === 0) {
      return this.createEmptyTrendAnalysis(periodStart, now);
    }

    // Calculate metrics for the period
    const responseTimes = periodData.map(
      (dp) =>
        ((dp.metrics.performance?.avg_store_duration_ms || 0) +
          (dp.metrics.performance?.avg_find_duration_ms || 0)) /
        2
    );
    const avgResponseTime = responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length;

    const throughputs = periodData.map((dp) => dp.derived.operations_per_second);
    const avgThroughput = throughputs.reduce((a, b) => a + b, 0) / throughputs.length;

    const errorRates = periodData.map((dp) => dp.derived.error_rate);
    const avgErrorRate = errorRates.reduce((a, b) => a + b, 0) / errorRates.length;

    // Calculate trends
    const responseTimeTrend = this.determineResponseTimeTrend(avgResponseTime);
    const throughputTrend = this.determineThroughputTrend(avgThroughput);

    return {
      period: {
        start: periodStart,
        end: now,
        duration_ms: now - periodStart,
      },
      performance: {
        avg_response_time: avgResponseTime,
        response_time_trend: responseTimeTrend,
        response_time_change_percent: this.calculateTrendPercent(responseTimes),
      },
      throughput: {
        operations_per_second: avgThroughput,
        throughput_trend: throughputTrend,
        throughput_change_percent: this.calculateTrendPercent(throughputs),
      },
      reliability: {
        error_rate: avgErrorRate,
        availability: Math.max(0, 100 - avgErrorRate),
        success_rate: Math.max(0, 100 - avgErrorRate),
      },
      resources: {
        memory_utilization: periodData[periodData.length - 1]?.derived.memory_utilization || 0,
        memory_trend: 'stable', // Could be calculated more precisely
        actor_utilization:
          periodData[periodData.length - 1]?.metrics.rate_limiting?.active_actors || 0,
      },
      anomalies: [], // Could be populated from anomaly detection
    };
  }

  /**
   * Get current performance alerts
   */
  getActiveAlerts(): PerformanceAlert[] {
    return this.alerts.filter((alert) => !alert.resolved);
  }

  /**
   * Resolve an alert
   */
  resolveAlert(alertId: string): void {
    const alert = this.alerts.find((a) => a.id === alertId);
    if (alert && !alert.resolved) {
      alert.resolved = true;
      alert.resolved_at = Date.now();
      logger.info('Performance alert resolved', { alertId, title: alert.title });
    }
  }

  /**
   * Export metrics for external monitoring systems
   */
  exportMetrics(format: 'json' | 'prometheus' = 'json'): string {
    const latestMetrics = this.timeSeriesData[this.timeSeriesData.length - 1];

    if (!latestMetrics) {
      return '';
    }

    if (format === 'prometheus') {
      return this.formatAsPrometheus(latestMetrics);
    }

    return JSON.stringify(
      {
        timestamp: latestMetrics.timestamp,
        metrics: latestMetrics.metrics,
        derived: latestMetrics.derived,
        alerts: this.getActiveAlerts(),
      },
      null,
      2
    );
  }

  /**
   * Get current service status
   */
  getStatus(): {
    collecting: boolean;
    dataPointsCount: number;
    activeAlertsCount: number;
    retentionHours: number;
    collectionInterval: number;
    oldestDataPoint?: number;
    newestDataPoint?: number;
  } {
    return {
      collecting: this.collectionInterval !== null,
      dataPointsCount: this.timeSeriesData.length,
      activeAlertsCount: this.getActiveAlerts().length,
      retentionHours: this.config.retention_hours,
      collectionInterval: this.config.collection_interval_seconds,
      oldestDataPoint: this.timeSeriesData[0]?.timestamp,
      newestDataPoint: this.timeSeriesData[this.timeSeriesData.length - 1]?.timestamp,
    };
  }

  // === Helper Methods ===

  private getTotalOpsFromDataPoint(dataPoint: TimeSeriesDataPoint): number {
    return (
      (dataPoint.metrics.store_count?.total || 0) +
      (dataPoint.metrics.find_count?.total || 0) +
      (dataPoint.metrics.purge_count?.total || 0)
    );
  }

  private createEmptyTrendAnalysis(start: number, end: number): TrendAnalysis {
    return {
      period: { start, end, duration_ms: end - start },
      performance: {
        avg_response_time: 0,
        response_time_trend: 'stable',
        response_time_change_percent: 0,
      },
      throughput: {
        operations_per_second: 0,
        throughput_trend: 'stable',
        throughput_change_percent: 0,
      },
      reliability: { error_rate: 0, availability: 100, success_rate: 100 },
      resources: { memory_utilization: 0, memory_trend: 'stable', actor_utilization: 0 },
      anomalies: [],
    };
  }

  private calculateTrend(values: number[]): 'increasing' | 'stable' | 'decreasing' {
    if (values.length < 2) return 'stable';

    const firstHalf = values.slice(0, Math.floor(values.length / 2));
    const secondHalf = values.slice(Math.floor(values.length / 2));

    const firstAvg = firstHalf.reduce((a, b) => a + b, 0) / firstHalf.length;
    const secondAvg = secondHalf.reduce((a, b) => a + b, 0) / secondHalf.length;

    const changePercent = ((secondAvg - firstAvg) / firstAvg) * 100;

    if (changePercent > 5) return 'increasing';
    if (changePercent < -5) return 'decreasing';
    return 'stable';
  }

  private calculateTrendPercent(values: number[]): number {
    if (values.length < 2) return 0;

    const first = values[0];
    const last = values[values.length - 1];

    return first !== 0 ? ((last - first) / first) * 100 : 0;
  }

  private formatAsPrometheus(dataPoint: TimeSeriesDataPoint): string {
    const timestamp = Math.floor(dataPoint.timestamp / 1000);
    const metrics = dataPoint.metrics;
    const derived = dataPoint.derived;

    const prometheusMetrics = [
      `# HELP cortex_response_time_ms Average response time in milliseconds`,
      `# TYPE cortex_response_time_ms gauge`,
      `cortex_response_time_ms ${((metrics.performance?.avg_store_duration_ms || 0) + (metrics.performance?.avg_find_duration_ms || 0)) / 2} ${timestamp}`,

      `# HELP cortex_operations_per_second Current operations per second`,
      `# TYPE cortex_operations_per_second gauge`,
      `cortex_operations_per_second ${derived.operations_per_second} ${timestamp}`,

      `# HELP cortex_error_rate_percent Error rate percentage`,
      `# TYPE cortex_error_rate_percent gauge`,
      `cortex_error_rate_percent ${derived.error_rate} ${timestamp}`,

      `# HELP cortex_memory_utilization_percent Memory utilization percentage`,
      `# TYPE cortex_memory_utilization_percent gauge`,
      `cortex_memory_utilization_percent ${derived.memory_utilization} ${timestamp}`,

      `# HELP cortex_active_actors Number of active rate limit actors`,
      `# TYPE cortex_active_actors gauge`,
      `cortex_active_actors ${metrics.rate_limiting?.active_actors || 0} ${timestamp}`,
    ];

    return prometheusMetrics.join('\n') + '\n';
  }

  /**
   * Graceful shutdown
   */
  destroy(): void {
    this.stopCollection();
    logger.info('PerformanceTrendingService destroyed');
  }
}

// Singleton instance
export const performanceTrendingService = new PerformanceTrendingService();
