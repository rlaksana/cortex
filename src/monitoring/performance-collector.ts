// EMERGENCY ROLLBACK: Final batch of type compatibility issues

/**
 * Performance Metrics Collector for Cortex MCP
 * Collects and aggregates performance metrics for key operations
 */

import { EventEmitter } from 'events';

import { OperationType } from './operation-types.js';
import type { OperationMetadata } from '../types/monitoring-types.js';
import { logger } from '../utils/logger.js';

export interface PerformanceMetric {
  operation: OperationType;
  startTime: number;
  endTime: number;
  duration: number;
  success: boolean;
  metadata?: OperationMetadata;
  tags?: string[];
}

export interface PerformanceSummary {
  operation: OperationType;
  count: number;
  totalDuration: number;
  averageDuration: number;
  minDuration: number;
  maxDuration: number;
  p95: number;
  p99: number;
  successRate: number;
  errorCount: number;
  timestamp: number;
}

export interface PerformanceAlert {
  operation: OperationType;
  alertType: 'slow_query' | 'high_error_rate' | 'memory_usage' | 'connection_pool' | 'rate_limit';
  threshold: number;
  currentValue: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  timestamp: number;
  correlationId?: string;
  userId?: string;
}

export class PerformanceCollector extends EventEmitter {
  private metrics: Map<OperationType, PerformanceMetric[]> = new Map();
  private summaries: Map<OperationType, PerformanceSummary> = new Map();
  private alertThresholds: Map<OperationType, { duration: number; errorRate: number }> = new Map();
  private collectionInterval: NodeJS.Timeout | null = null;
  private maxMetricsPerOperation = 500; // Reduced from 1000 to 500 for lower memory usage
  private lastCleanupTime = 0;
  private cleanupIntervalMs = 5 * 60 * 1000; // Cleanup every 5 minutes instead of every minute
  private batchMetrics: PerformanceMetric[] = []; // Batch metrics for less frequent processing
  private batchSize = 100; // Process metrics in batches
  private lastBatchProcess = 0;
  private batchProcessIntervalMs = 1000; // Process batches every second

  constructor() {
    super();
    // Set max listeners to prevent memory leak warnings
    this.setMaxListeners(50);
    this.setupDefaultThresholds();
  }

  /**
   * Start recording a performance metric
   */
  startMetric(operation: OperationType, metadata?: OperationMetadata, tags?: string[]): () => void {
    const startTime = Date.now();

    return () => {
      const endTime = Date.now();
      const duration = endTime - startTime;

      const metric: PerformanceMetric = {
        operation,
        startTime,
        endTime,
        duration,
        success: true,
      };

      if (metadata !== undefined) {
        metric.metadata = metadata;
      }
      if (tags !== undefined) {
        metric.tags = tags;
      }

      this.recordMetric(metric);
    };
  }

  /**
   * Record a performance metric
   */
  recordMetric(metric: PerformanceMetric): void {
    // Add to batch for processing
    this.batchMetrics.push(metric);

    // Process batch if it's full or if enough time has passed
    const now = Date.now();
    if (
      this.batchMetrics.length >= this.batchSize ||
      now - this.lastBatchProcess >= this.batchProcessIntervalMs
    ) {
      this.processBatch();
      this.lastBatchProcess = now;
    }

    // Emit metric for real-time monitoring (but skip batch processing for real-time needs)
    if (this.listenerCount('metric') > 0) {
      this.emit('metric', metric);
    }
  }

  /**
   * Process a batch of metrics to reduce overhead
   */
  private processBatch(): void {
    if (this.batchMetrics.length === 0) return;

    const batchToProcess = this.batchMetrics.splice(0, this.batchSize);

    // Group metrics by operation for more efficient processing
    const metricsByOperation = new Map<OperationType, PerformanceMetric[]>();

    for (const metric of batchToProcess) {
      const operationMetrics = metricsByOperation.get(metric.operation) || [];
      operationMetrics.push(metric);
      metricsByOperation.set(metric.operation, operationMetrics);
    }

    // Process each operation's metrics
    for (const [operation, newMetrics] of Array.from(metricsByOperation.entries())) {
      const operationMetrics = this.metrics.get(operation) || [];

      // Add new metrics
      operationMetrics.push(...newMetrics);

      // Keep only the most recent metrics
      if (operationMetrics.length > this.maxMetricsPerOperation) {
        const excessCount = operationMetrics.length - this.maxMetricsPerOperation;
        operationMetrics.splice(0, excessCount);
      }

      this.metrics.set(operation, operationMetrics);

      // Update summary (only once per batch per operation)
      this.updateSummary(operation);

      // Check for alerts (only once per batch per operation)
      this.checkAlerts(operation);
    }
  }

  /**
   * Record an error for an operation
   */
  recordError(operation: OperationType, error: Error, metadata?: OperationMetadata): void {
    const metric: PerformanceMetric = {
      operation,
      startTime: Date.now(),
      endTime: Date.now(),
      duration: 0,
      success: false,
      metadata: {
        ...metadata,
        error: error.message,
        stack: error.stack,
      },
    };

    this.recordMetric(metric);
  }

  /**
   * Get performance summary for an operation
   */
  getSummary(operation: OperationType): PerformanceSummary | null {
    // Process any pending batch metrics to ensure up-to-date summaries
    if (this.batchMetrics.length > 0) {
      this.processBatch();
    }
    return this.summaries.get(operation) || null;
  }

  /**
   * Get all performance summaries
   */
  getAllSummaries(): PerformanceSummary[] {
    // Process any pending batch metrics to ensure up-to-date summaries
    if (this.batchMetrics.length > 0) {
      this.processBatch();
    }
    return Array.from(this.summaries.values());
  }

  /**
   * Get recent metrics for an operation
   */
  getRecentMetrics(operation: OperationType, limit: number = 100): PerformanceMetric[] {
    const metrics = this.metrics.get(operation) || [];
    return metrics.slice(-limit);
  }

  /**
   * Get performance metrics for a time range
   */
  getMetricsInTimeRange(
    operation: OperationType,
    startTime: number,
    endTime: number
  ): PerformanceMetric[] {
    const metrics = this.metrics.get(operation) || [];
    return metrics.filter((metric) => metric.startTime >= startTime && metric.endTime <= endTime);
  }

  /**
   * Configure alert thresholds for an operation
   */
  setAlertThreshold(
    operation: OperationType,
    durationThreshold: number,
    errorRateThreshold: number
  ): void {
    this.alertThresholds.set(operation, {
      duration: durationThreshold,
      errorRate: errorRateThreshold,
    });
  }

  /**
   * Force process any pending batch metrics (for testing scenarios)
   */
  processPendingBatch(): void {
    if (this.batchMetrics.length > 0) {
      this.processBatch();
      this.lastBatchProcess = Date.now();
    }
  }

  /**
   * Get performance trends for dashboard
   */
  getPerformanceTrends(timeWindowMinutes: number = 60): Record<
    OperationType,
    {
      operation: OperationType;
      timeWindow: number;
      totalRequests: number;
      successfulRequests: number;
      failedRequests: number;
      successRate: number;
      averageDuration: number;
      p95Duration: number;
      p99Duration: number;
      requestsPerMinute: number;
      errorRate: number;
      timestamp: number;
    }
  > {
    const now = Date.now();
    const windowStart = now - timeWindowMinutes * 60 * 1000;
    const trends: Record<
      string,
      {
        operation: OperationType;
        timeWindow: number;
        totalRequests: number;
        successfulRequests: number;
        failedRequests: number;
        successRate: number;
        averageDuration: number;
        p95Duration: number;
        p99Duration: number;
        requestsPerMinute: number;
        errorRate: number;
        timestamp: number;
      }
    > = {};

      for (const operation of Array.from(this.metrics.keys())) {
      const recentMetrics = this.getMetricsInTimeRange(operation, windowStart, now);

      if (recentMetrics.length === 0) continue;

      const successMetrics = recentMetrics.filter((m) => m.success);
      const errorMetrics = recentMetrics.filter((m) => !m.success);

      trends[operation] = {
        operation,
        timeWindow: timeWindowMinutes,
        totalRequests: recentMetrics.length,
        successfulRequests: successMetrics.length,
        failedRequests: errorMetrics.length,
        successRate: (successMetrics.length / recentMetrics.length) * 100,
        averageDuration: this.calculateAverage(successMetrics.map((m) => m.duration)),
        p95Duration: this.calculatePercentile(
          successMetrics.map((m) => m.duration),
          95
        ),
        p99Duration: this.calculatePercentile(
          successMetrics.map((m) => m.duration),
          99
        ),
        requestsPerMinute: recentMetrics.length / timeWindowMinutes,
        errorRate: (errorMetrics.length / recentMetrics.length) * 100,
        timestamp: now,
      };
    }

    return trends;
  }

  /**
   * Start automated collection
   */
  startCollection(intervalMs: number = 60000): void {
    if (this.collectionInterval) {
      clearInterval(this.collectionInterval);
    }

    this.collectionInterval = setInterval(() => {
      this.collectSystemMetrics();
      // Cleanup less frequently to reduce overhead
      const now = Date.now();
      if (now - this.lastCleanupTime >= this.cleanupIntervalMs) {
        this.cleanupOldMetrics();
        this.lastCleanupTime = now;
      }
    }, intervalMs);

    logger.info({ intervalMs }, 'Performance collection started');
  }

  /**
   * Stop automated collection
   */
  stopCollection(): void {
    if (this.collectionInterval) {
      clearInterval(this.collectionInterval);
      this.collectionInterval = null;
    }

    logger.info('Performance collection stopped');
  }

  /**
   * Clear all metrics
   */
  clearMetrics(): void {
    this.processBatch(); // Process any remaining batch metrics
    this.metrics.clear();
    this.summaries.clear();
    this.batchMetrics = [];
    if (this.listenerCount('cleared') > 0) {
      this.emit('cleared');
    }
  }

  /**
   * Get memory usage statistics
   */
  getMemoryUsage(): {
    rss: number;
    heapTotal: number;
    heapUsed: number;
    external: number;
    arrayBuffers: number;
    timestamp: number;
  } {
    const usage = process.memoryUsage();
    return {
      rss: usage.rss,
      heapTotal: usage.heapTotal,
      heapUsed: usage.heapUsed,
      external: usage.external,
      arrayBuffers: usage.arrayBuffers,
      timestamp: Date.now(),
    };
  }

  /**
   * Export metrics for external monitoring systems
   */
  exportMetrics(format: 'prometheus' | 'json' = 'json'): string {
    if (format === 'prometheus') {
      return this.exportPrometheusMetrics();
    }

    return JSON.stringify(
      {
        summaries: this.getAllSummaries(),
        trends: this.getPerformanceTrends(),
        memory: this.getMemoryUsage(),
        timestamp: Date.now(),
      },
      null,
      2
    );
  }

  private updateSummary(operation: OperationType): void {
    const metrics = this.metrics.get(operation) || [];
    if (metrics.length === 0) return;

    const successMetrics = metrics.filter((m) => m.success);
    const errorMetrics = metrics.filter((m) => !m.success);

    const durations = successMetrics.map((m) => m.duration);
    const summary: PerformanceSummary = {
      operation,
      count: metrics.length,
      totalDuration: durations.reduce((sum, d) => sum + d, 0),
      averageDuration: this.calculateAverage(durations),
      minDuration: Math.min(...durations),
      maxDuration: Math.max(...durations),
      p95: this.calculatePercentile(durations, 95),
      p99: this.calculatePercentile(durations, 99),
      successRate: (successMetrics.length / metrics.length) * 100,
      errorCount: errorMetrics.length,
      timestamp: Date.now(),
    };

    this.summaries.set(operation, summary);
  }

  private checkAlerts(operation: OperationType): void {
    const summary = this.summaries.get(operation);
    const threshold = this.alertThresholds.get(operation);

    if (!summary || !threshold) return;

    // Check duration alert
    if (summary.averageDuration > threshold.duration) {
      const alert: PerformanceAlert = {
        operation,
        alertType: 'slow_query',
        threshold: threshold.duration,
        currentValue: summary.averageDuration,
        severity: this.getSeverity(summary.averageDuration, threshold.duration),
        message: `Average duration ${summary.averageDuration}ms exceeds threshold ${threshold.duration}ms`,
        timestamp: Date.now(),
      };

      if (this.listenerCount('alert') > 0) {
        this.emit('alert', alert);
      }
      logger.warn(alert, 'Performance alert triggered');
    }

    // Check error rate alert
    const errorRate = 100 - summary.successRate;
    if (errorRate > threshold.errorRate) {
      const alert: PerformanceAlert = {
        operation,
        alertType: 'high_error_rate',
        threshold: threshold.errorRate,
        currentValue: errorRate,
        severity: this.getSeverity(errorRate, threshold.errorRate),
        message: `Error rate ${errorRate}% exceeds threshold ${threshold.errorRate}%`,
        timestamp: Date.now(),
      };

      if (this.listenerCount('alert') > 0) {
        this.emit('alert', alert);
      }
      logger.warn(alert, 'Error rate alert triggered');
    }
  }

  private setupDefaultThresholds(): void {
    // Database operations
    this.setAlertThreshold(OperationType.MEMORY_STORE, 1000, 5); // 1s, 5% error rate
    this.setAlertThreshold(OperationType.MEMORY_FIND, 2000, 5); // 2s, 5% error rate
    this.setAlertThreshold(OperationType.DATABASE_STATS, 500, 2); // 500ms, 2% error rate

    // Embedding operations
    this.setAlertThreshold(OperationType.EMBEDDING, 5000, 10); // 5s, 10% error rate
    this.setAlertThreshold(OperationType.SEARCH, 1000, 3); // 1s, 3% error rate

    // Authentication operations
    this.setAlertThreshold(OperationType.AUTH, 200, 1); // 200ms, 1% error rate
    this.setAlertThreshold(OperationType.AUTHENTICATION, 300, 2); // 300ms, 2% error rate
  }

  private collectSystemMetrics(): void {
    const memoryUsage = this.getMemoryUsage();

    // Check memory usage alerts
    const heapUsedMB = memoryUsage.heapUsed / (1024 * 1024);
    const heapTotalMB = memoryUsage.heapTotal / (1024 * 1024);
    const memoryUsagePercent = (heapUsedMB / heapTotalMB) * 100;

    if (memoryUsagePercent > 90) {
      const alert: PerformanceAlert = {
        operation: OperationType.SYSTEM,
        alertType: 'memory_usage',
        threshold: 90,
        currentValue: memoryUsagePercent,
        severity: 'critical',
        message: `Memory usage ${memoryUsagePercent.toFixed(2)}% exceeds 90% threshold`,
        timestamp: Date.now(),
      };

      if (this.listenerCount('alert') > 0) {
        this.emit('alert', alert);
      }
      logger.error(alert, 'Critical memory usage alert');
    }

    if (this.listenerCount('system_metrics') > 0) {
      this.emit('system_metrics', memoryUsage);
    }
  }

  private cleanupOldMetrics(): void {
    const cutoffTime = Date.now() - 24 * 60 * 60 * 1000; // Keep 24 hours

    for (const [operation, metrics] of Array.from(this.metrics.entries())) {
      const filteredMetrics = metrics.filter((m) => m.startTime > cutoffTime);
      this.metrics.set(operation, filteredMetrics);
    }
  }

  private calculateAverage(numbers: number[]): number {
    if (numbers.length === 0) return 0;
    return numbers.reduce((sum, n) => sum + n, 0) / numbers.length;
  }

  private calculatePercentile(numbers: number[], percentile: number): number {
    if (numbers.length === 0) return 0;

    const sorted = [...numbers].sort((a, b) => a - b);
    const index = Math.ceil((percentile / 100) * sorted.length) - 1;
    return sorted[Math.max(0, index)];
  }

  private getSeverity(current: number, threshold: number): 'low' | 'medium' | 'high' | 'critical' {
    const ratio = current / threshold;

    if (ratio >= 2) return 'critical';
    if (ratio >= 1.5) return 'high';
    if (ratio >= 1.2) return 'medium';
    return 'low';
  }

  private exportPrometheusMetrics(): string {
    let output = '';

    for (const summary of Array.from(this.summaries.values())) {
      output += `# HELP cortex_operation_duration_seconds Time taken for operations\n`;
      output += `# TYPE cortex_operation_duration_seconds gauge\n`;
      output += `cortex_operation_duration_seconds{operation="${summary.operation}",quantile="avg"} ${summary.averageDuration / 1000}\n`;
      output += `cortex_operation_duration_seconds{operation="${summary.operation}",quantile="p95"} ${summary.p95 / 1000}\n`;
      output += `cortex_operation_duration_seconds{operation="${summary.operation}",quantile="p99"} ${summary.p99 / 1000}\n`;

      output += `# HELP cortex_operation_success_rate Success rate of operations\n`;
      output += `# TYPE cortex_operation_success_rate gauge\n`;
      output += `cortex_operation_success_rate{operation="${summary.operation}"} ${summary.successRate}\n`;

      output += `# HELP cortex_operation_count Total number of operations\n`;
      output += `# TYPE cortex_operation_count counter\n`;
      output += `cortex_operation_count{operation="${summary.operation}"} ${summary.count}\n`;
    }

    const memory = this.getMemoryUsage();
    output += `# HELP nodejs_memory_usage_bytes Memory usage in bytes\n`;
    output += `# TYPE nodejs_memory_usage_bytes gauge\n`;
    output += `nodejs_memory_usage_bytes{type="rss"} ${memory.rss}\n`;
    output += `nodejs_memory_usage_bytes{type="heap_used"} ${memory.heapUsed}\n`;
    output += `nodejs_memory_usage_bytes{type="heap_total"} ${memory.heapTotal}\n`;

    return output;
  }

  /**
   * Cleanup method to properly dispose of resources
   */
  public cleanup(): void {
    if (this.collectionInterval) {
      clearInterval(this.collectionInterval);
      this.collectionInterval = null;
    }

    this.metrics.clear();
    this.summaries.clear();
    this.alertThresholds.clear();
    this.batchMetrics = [];

    // Remove all event listeners to prevent memory leaks
    this.removeAllListeners();
  }
}

// Singleton instance
export const performanceCollector = new PerformanceCollector();
