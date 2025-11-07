/**
 * Enhanced Performance Metrics Collector
 *
 * Comprehensive performance monitoring system that collects detailed metrics for
 * server performance, resource usage, and MCP-specific operations. Provides
 * real-time monitoring with historical data tracking and alerting capabilities.
 *
 * @author Cortex Team
 * @version 2.0.1
 */

import { EventEmitter } from 'events';
import { performance } from 'perf_hooks';
import { logger } from '@/utils/logger.js';

/**
 * Performance metric types
 */
export enum MetricType {
  COUNTER = 'counter',
  GAUGE = 'gauge',
  HISTOGRAM = 'histogram',
  TIMER = 'timer',
}

/**
 * Metric data structure
 */
export interface MetricData {
  name: string;
  type: MetricType;
  value: number;
  timestamp: number;
  labels?: Record<string, string>;
  unit?: string;
  description?: string;
}

/**
 * Performance histogram buckets
 */
export interface HistogramBucket {
  le: number;        // Less than or equal to value
  count: number;     // Number of observations in this bucket
}

/**
 * Performance histogram data
 */
export interface HistogramData {
  count: number;
  sum: number;
  buckets: HistogramBucket[];
}

/**
 * System performance metrics
 */
export interface SystemPerformanceMetrics {
  // CPU metrics
  cpuUsage: {
    user: number;          // User CPU time (microseconds)
    system: number;        // System CPU time (microseconds)
    idle: number;          // Idle CPU time (microseconds)
    total: number;         // Total CPU time (microseconds)
    percentage: number;    // CPU usage percentage
  };

  // Memory metrics
  memoryUsage: {
    rss: number;           // Resident set size in bytes
    heapTotal: number;     // Total heap size in bytes
    heapUsed: number;      // Used heap size in bytes
    heapUnused: number;    // Unused heap size in bytes
    external: number;      // External memory in bytes
    arrayBuffers: number;  // Array buffers in bytes
    heapUsagePercent: number;
    rssUsagePercent: number;
  };

  // Event loop metrics
  eventLoop: {
    lag: number;           // Event loop lag in microseconds
    utilization: number;   // Event loop utilization percentage
    delays: number[];      // Recent delay measurements
  };

  // Garbage collection metrics
  garbageCollection: {
    collections: number;   // Total GC collections
    duration: number;      // Total GC duration in microseconds
    averageDuration: number; // Average GC duration
    collectionsByType: Record<string, number>;
    durationByType: Record<string, number>;
  };

  // Process metrics
  process: {
    uptime: number;        // Process uptime in seconds
    pid: number;           // Process ID
    version: string;       // Node.js version
    platform: string;     // Platform
    arch: string;          // Architecture
    activeHandles: number; // Active handles count
    activeRequests: number; // Active requests count
  };
}

/**
 * MCP operation metrics
 */
export interface MCPOperationMetrics {
  // Request metrics
  requests: {
    total: number;                     // Total requests
    successful: number;                // Successful requests
    failed: number;                    // Failed requests
    rate: number;                      // Requests per second
    averageResponseTime: number;       // Average response time
    p50ResponseTime: number;           // 50th percentile
    p90ResponseTime: number;           // 90th percentile
    p95ResponseTime: number;           // 95th percentile
    p99ResponseTime: number;           // 99th percentile
    responseTimeHistogram: HistogramData;
  };

  // Session metrics
  sessions: {
    active: number;                    // Active sessions
    total: number;                     // Total sessions created
    averageDuration: number;           // Average session duration
    totalDuration: number;             // Total session duration
  };

  // Tool execution metrics
  tools: {
    executions: number;                // Total tool executions
    successful: number;                // Successful executions
    failed: number;                    // Failed executions
    averageExecutionTime: number;      // Average execution time
    popularTools: Array<{
      name: string;
      count: number;
      averageTime: number;
    }>;
    executionTimeHistogram: HistogramData;
  };

  // Knowledge graph metrics
  knowledgeGraph: {
    entities: {
      total: number;                  // Total entities
      created: number;                // Entities created
      updated: number;                // Entities updated
      deleted: number;                // Entities deleted
    };
    relations: {
      total: number;                  // Total relations
      created: number;                // Relations created
      deleted: number;                // Relations deleted
    };
    operations: {
      stores: number;                 // Store operations
      finds: number;                  // Find operations
      updates: number;                // Update operations
      deletes: number;                // Delete operations
    };
  };

  // Quality metrics
  quality: {
    dedupeRate: number;               // Deduplication rate
    cacheHitRate: number;             // Cache hit rate
    embeddingSuccessRate: number;     // Embedding success rate
    ttlCleanupRate: number;           // TTL cleanup rate
    validationSuccessRate: number;    // Validation success rate
  };
}

/**
 * Enhanced performance collector configuration
 */
export interface EnhancedPerformanceCollectorConfig {
  // Collection intervals
  systemMetricsIntervalMs: number;
  mcpMetricsIntervalMs: number;
  histogramRetentionMinutes: number;
  timeSeriesRetentionMinutes: number;

  // Histogram buckets
  responseTimeBuckets: number[];
  executionTimeBuckets: number[];

  // Performance thresholds
  thresholds: {
    responseTimeWarning: number;      // milliseconds
    responseTimeCritical: number;     // milliseconds
    cpuUsageWarning: number;          // percentage
    cpuUsageCritical: number;         // percentage
    memoryUsageWarning: number;       // percentage
    memoryUsageCritical: number;      // percentage
    eventLoopLagWarning: number;      // microseconds
    eventLoopLagCritical: number;     // microseconds
  };

  // Alerting
  alerts: {
    enabled: boolean;
    consecutiveViolationsThreshold: number;
    cooldownPeriodMs: number;
  };
}

/**
 * Enhanced Performance Collector
 */
export class EnhancedPerformanceCollector extends EventEmitter {
  private config: EnhancedPerformanceCollectorConfig;
  private isRunning = false;
  private startTime: number;

  // Collection intervals
  private systemMetricsInterval: NodeJS.Timeout | null = null;
  private mcpMetricsInterval: NodeJS.Timeout | null = null;

  // Metrics storage
  private systemMetrics: SystemPerformanceMetrics;
  private mcpMetrics: MCPOperationMetrics;
  private timeSeriesData: Map<string, MetricData[]> = new Map();
  private histograms: Map<string, HistogramData> = new Map();

  // Performance tracking
  private responseTimeSamples: number[] = [];
  private executionTimeSamples: number[] = [];
  private eventLoopDelaySamples: number[] = [];

  // Alert tracking
  private activeAlerts: Map<string, { count: number; lastTriggered: number }> = new Map();

  constructor(config?: Partial<EnhancedPerformanceCollectorConfig>) {
    super();

    this.config = {
      systemMetricsIntervalMs: 10000,     // 10 seconds
      mcpMetricsIntervalMs: 5000,        // 5 seconds
      histogramRetentionMinutes: 60,     // 1 hour
      timeSeriesRetentionMinutes: 1440,  // 24 hours
      responseTimeBuckets: [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000],
      executionTimeBuckets: [10, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000],
      thresholds: {
        responseTimeWarning: 1000,       // 1 second
        responseTimeCritical: 5000,      // 5 seconds
        cpuUsageWarning: 80,             // 80%
        cpuUsageCritical: 95,            // 95%
        memoryUsageWarning: 80,          // 80%
        memoryUsageCritical: 95,         // 95%
        eventLoopLagWarning: 1000,       // 1 millisecond
        eventLoopLagCritical: 5000,      // 5 milliseconds
      },
      alerts: {
        enabled: true,
        consecutiveViolationsThreshold: 3,
        cooldownPeriodMs: 300000,        // 5 minutes
      },
      ...config,
    };

    this.startTime = Date.now();
    this.systemMetrics = this.getInitialSystemMetrics();
    this.mcpMetrics = this.getInitialMCPOperationMetrics();

    // Initialize histograms
    this.initializeHistograms();
  }

  /**
   * Start performance collection
   */
  start(): void {
    if (this.isRunning) {
      logger.warn('Enhanced performance collector is already running');
      return;
    }

    this.isRunning = true;

    // Start system metrics collection
    this.systemMetricsInterval = setInterval(
      () => this.collectSystemMetrics(),
      this.config.systemMetricsIntervalMs
    );

    // Start MCP metrics collection
    this.mcpMetricsInterval = setInterval(
      () => this.collectMCPMetrics(),
      this.config.mcpMetricsIntervalMs
    );

    // Perform initial collection
    this.collectSystemMetrics();
    this.collectMCPMetrics();

    logger.info(
      {
        systemMetricsInterval: this.config.systemMetricsIntervalMs,
        mcpMetricsInterval: this.config.mcpMetricsIntervalMs,
      },
      'Enhanced performance collector started'
    );

    this.emit('started');
  }

  /**
   * Stop performance collection
   */
  stop(): void {
    if (!this.isRunning) {
      logger.warn('Enhanced performance collector is not running');
      return;
    }

    this.isRunning = false;

    if (this.systemMetricsInterval) {
      clearInterval(this.systemMetricsInterval);
      this.systemMetricsInterval = null;
    }

    if (this.mcpMetricsInterval) {
      clearInterval(this.mcpMetricsInterval);
      this.mcpMetricsInterval = null;
    }

    logger.info('Enhanced performance collector stopped');
    this.emit('stopped');
  }

  /**
   * Record a custom metric
   */
  recordMetric(name: string, type: MetricType, value: number, labels?: Record<string, string>): void {
    const metric: MetricData = {
      name,
      type,
      value,
      timestamp: Date.now(),
      labels,
    };

    // Store in time series
    if (!this.timeSeriesData.has(name)) {
      this.timeSeriesData.set(name, []);
    }
    const series = this.timeSeriesData.get(name)!;
    series.push(metric);

    // Trim old data
    const maxAge = this.config.timeSeriesRetentionMinutes * 60 * 1000;
    const cutoff = Date.now() - maxAge;
    while (series.length > 0 && series[0].timestamp < cutoff) {
      series.shift();
    }

    // Update counters
    if (type === MetricType.COUNTER) {
      this.updateCounter(name, value);
    } else if (type === MetricType.GAUGE) {
      this.updateGauge(name, value);
    } else if (type === MetricType.HISTOGRAM) {
      this.updateHistogram(name, value);
    }

    this.emit('metric_recorded', metric);
  }

  /**
   * Record response time
   */
  recordResponseTime(operation: string, duration: number): void {
    this.responseTimeSamples.push(duration);

    // Keep only last 1000 samples
    if (this.responseTimeSamples.length > 1000) {
      this.responseTimeSamples = this.responseTimeSamples.slice(-1000);
    }

    // Update histogram
    const histogramName = `response_time_${operation}`;
    this.updateHistogram(histogramName, duration);

    // Record metric
    this.recordMetric(`${operation}_response_time`, MetricType.HISTOGRAM, duration, {
      operation,
    });

    // Check for performance alerts
    this.checkPerformanceThresholds(operation, duration);
  }

  /**
   * Record tool execution
   */
  recordToolExecution(toolName: string, duration: number, success: boolean): void {
    this.executionTimeSamples.push(duration);

    // Keep only last 500 samples
    if (this.executionTimeSamples.length > 500) {
      this.executionTimeSamples = this.executionTimeSamples.slice(-500);
    }

    // Update tool metrics
    this.mcpMetrics.tools.executions++;
    if (success) {
      this.mcpMetrics.tools.successful++;
    } else {
      this.mcpMetrics.tools.failed++;
    }

    // Update popular tools tracking
    const existingTool = this.mcpMetrics.tools.popularTools.find(t => t.name === toolName);
    if (existingTool) {
      existingTool.count++;
      existingTool.averageTime = (existingTool.averageTime + duration) / 2;
    } else {
      this.mcpMetrics.tools.popularTools.push({
        name: toolName,
        count: 1,
        averageTime: duration,
      });
    }

    // Update histogram
    this.updateHistogram('tool_execution_time', duration);

    // Record metrics
    this.recordMetric('tool_execution_duration', MetricType.HISTOGRAM, duration, {
      tool: toolName,
      success: success.toString(),
    });

    this.recordMetric('tool_executions_total', MetricType.COUNTER, 1, {
      tool: toolName,
      status: success ? 'success' : 'failure',
    });
  }

  /**
   * Record knowledge graph operation
   */
  recordKnowledgeGraphOperation(operation: 'store' | 'find' | 'update' | 'delete', duration: number, success: boolean): void {
    // Update operation counts
    this.mcpMetrics.knowledgeGraph.operations[`${operation}s`]++;

    // Record metrics
    this.recordMetric('knowledge_graph_operation_duration', MetricType.HISTOGRAM, duration, {
      operation,
      success: success.toString(),
    });

    this.recordMetric('knowledge_graph_operations_total', MetricType.COUNTER, 1, {
      operation,
      status: success ? 'success' : 'failure',
    });
  }

  /**
   * Get current system metrics
   */
  getSystemMetrics(): SystemPerformanceMetrics {
    return { ...this.systemMetrics };
  }

  /**
   * Get current MCP metrics
   */
  getMCPMetrics(): MCPOperationMetrics {
    return { ...this.mcpMetrics };
  }

  /**
   * Get time series data for a metric
   */
  getTimeSeriesData(name: string, duration?: number): MetricData[] {
    if (!this.timeSeriesData.has(name)) {
      return [];
    }

    const series = [...this.timeSeriesData.get(name)!];

    if (duration) {
      const cutoff = Date.now() - duration;
      return series.filter(m => m.timestamp >= cutoff);
    }

    return series;
  }

  /**
   * Get histogram data
   */
  getHistogramData(name: string): HistogramData | null {
    return this.histograms.get(name) || null;
  }

  /**
   * Get percentile calculations
   */
  getPercentiles(metricName: string, percentiles: number[]): Record<number, number> {
    const series = this.getTimeSeriesData(metricName);
    if (series.length === 0) return {};

    const values = series.map(m => m.value).sort((a, b) => a - b);
    const result: Record<number, number> = {};

    for (const p of percentiles) {
      const index = Math.ceil(values.length * (p / 100)) - 1;
      result[p] = values[Math.max(0, Math.min(index, values.length - 1))];
    }

    return result;
  }

  /**
   * Get Prometheus-compatible metrics export
   */
  getPrometheusMetrics(): string {
    let output = '';

    // System metrics
    output += this.generatePrometheusMetric('cortex_cpu_usage_percent', 'gauge',
      this.systemMetrics.cpuUsage.percentage, 'CPU usage percentage');

    output += this.generatePrometheusMetric('cortex_memory_heap_usage_bytes', 'gauge',
      this.systemMetrics.memoryUsage.heapUsed, 'Heap memory usage in bytes');

    output += this.generatePrometheusMetric('cortex_memory_heap_usage_percent', 'gauge',
      this.systemMetrics.memoryUsage.heapUsagePercent, 'Heap memory usage percentage');

    output += this.generatePrometheusMetric('cortex_event_loop_lag_microseconds', 'gauge',
      this.systemMetrics.eventLoop.lag, 'Event loop lag in microseconds');

    // MCP metrics
    output += this.generatePrometheusMetric('cortex_requests_total', 'counter',
      this.mcpMetrics.requests.total, 'Total number of requests');

    output += this.generatePrometheusMetric('cortex_requests_per_second', 'gauge',
      this.mcpMetrics.requests.rate, 'Requests per second');

    output += this.generatePrometheusMetric('cortex_request_duration_seconds', 'histogram',
      this.mcpMetrics.requests.responseTimeHistogram, 'Request duration in seconds');

    output += this.generatePrometheusMetric('cortex_active_sessions', 'gauge',
      this.mcpMetrics.sessions.active, 'Number of active sessions');

    output += this.generatePrometheusMetric('cortex_tool_executions_total', 'counter',
      this.mcpMetrics.tools.executions, 'Total tool executions');

    // Histogram metrics
    for (const [name, histogram] of this.histograms) {
      output += this.generatePrometheusHistogram(name, histogram);
    }

    // Custom metrics
    for (const [metricName, series] of this.timeSeriesData) {
      if (series.length > 0) {
        const latest = series[series.length - 1];
        output += this.generatePrometheusMetric(metricName, latest.type, latest.value, latest.description);
      }
    }

    return output;
  }

  /**
   * Collect system metrics
   */
  private collectSystemMetrics(): void {
    try {
      const memUsage = process.memoryUsage();
      const cpuUsage = process.cpuUsage();
      const hrTime = process.hrtime();

      // Calculate CPU usage
      const totalCpuTime = cpuUsage.user + cpuUsage.system;
      const cpuPercentage = this.calculateCPUUsage(totalCpuTime);

      // Calculate memory percentages
      const heapUsagePercent = (memUsage.heapUsed / memUsage.heapTotal) * 100;
      const rssUsagePercent = (memUsage.rss / (memUsage.heapTotal * 1.5)) * 100; // Estimated

      // Measure event loop lag
      const eventLoopLag = this.measureEventLoopLag();

      this.systemMetrics = {
        cpuUsage: {
          user: cpuUsage.user,
          system: cpuUsage.system,
          idle: 0, // Not directly available in Node.js
          total: totalCpuTime,
          percentage: cpuPercentage,
        },
        memoryUsage: {
          rss: memUsage.rss,
          heapTotal: memUsage.heapTotal,
          heapUsed: memUsage.heapUsed,
          heapUnused: memUsage.heapTotal - memUsage.heapUsed,
          external: memUsage.external,
          arrayBuffers: memUsage.arrayBuffers,
          heapUsagePercent,
          rssUsagePercent,
        },
        eventLoop: {
          lag: eventLoopLag,
          utilization: this.calculateEventLoopUtilization(eventLoopLag),
          delays: [...this.eventLoopDelaySamples],
        },
        garbageCollection: {
          collections: this.systemMetrics.garbageCollection.collections, // Would need GC monitoring
          duration: this.systemMetrics.garbageCollection.duration,
          averageDuration: this.systemMetrics.garbageCollection.averageDuration,
          collectionsByType: this.systemMetrics.garbageCollection.collectionsByType,
          durationByType: this.systemMetrics.garbageCollection.durationByType,
        },
        process: {
          uptime: process.uptime(),
          pid: process.pid,
          version: process.version,
          platform: process.platform,
          arch: process.arch,
          activeHandles: (process as any)._getActiveHandles().length,
          activeRequests: (process as any)._getActiveRequests().length,
        },
      };

      this.emit('system_metrics_collected', this.systemMetrics);

    } catch (error) {
      logger.error({ error }, 'Failed to collect system metrics');
    }
  }

  /**
   * Collect MCP metrics
   */
  private collectMCPMetrics(): void {
    try {
      // Calculate request metrics from samples
      const recentRequests = this.responseTimeSamples.length;
      const recentSuccesses = recentRequests; // Simplified - would need actual success tracking
      const requestsPerSecond = recentRequests / (this.config.mcpMetricsIntervalMs / 1000);

      // Calculate percentiles
      const sortedTimes = [...this.responseTimeSamples].sort((a, b) => a - b);
      const p50 = this.calculatePercentile(sortedTimes, 0.5);
      const p90 = this.calculatePercentile(sortedTimes, 0.9);
      const p95 = this.calculatePercentile(sortedTimes, 0.95);
      const p99 = this.calculatePercentile(sortedTimes, 0.99);

      this.mcpMetrics = {
        ...this.mcpMetrics,
        requests: {
          total: this.mcpMetrics.requests.total + recentRequests,
          successful: this.mcpMetrics.requests.successful + recentSuccesses,
          failed: this.mcpMetrics.requests.failed,
          rate: requestsPerSecond,
          averageResponseTime: this.calculateAverage(this.responseTimeSamples),
          p50ResponseTime: p50,
          p90ResponseTime: p90,
          p95ResponseTime: p95,
          p99ResponseTime: p99,
          responseTimeHistogram: this.getHistogramData('response_time_all') || this.createEmptyHistogram(),
        },
        tools: {
          ...this.mcpMetrics.tools,
          averageExecutionTime: this.calculateAverage(this.executionTimeSamples),
          executionTimeHistogram: this.getHistogramData('tool_execution_time') || this.createEmptyHistogram(),
        },
      };

      // Clear samples for next interval
      this.responseTimeSamples = [];
      this.executionTimeSamples = [];

      this.emit('mcp_metrics_collected', this.mcpMetrics);

    } catch (error) {
      logger.error({ error }, 'Failed to collect MCP metrics');
    }
  }

  /**
   * Initialize histograms
   */
  private initializeHistograms(): void {
    // Response time histograms
    this.createHistogram('response_time_all', this.config.responseTimeBuckets);
    this.createHistogram('response_time_memory_store', this.config.responseTimeBuckets);
    this.createHistogram('response_time_memory_find', this.config.responseTimeBuckets);
    this.createHistogram('response_time_tool_execution', this.config.responseTimeBuckets);

    // Execution time histograms
    this.createHistogram('tool_execution_time', this.config.executionTimeBuckets);
    this.createHistogram('embedding_generation_time', this.config.executionTimeBuckets);
    this.createHistogram('vector_search_time', this.config.executionTimeBuckets);
  }

  /**
   * Create histogram
   */
  private createHistogram(name: string, buckets: number[]): void {
    this.histograms.set(name, {
      count: 0,
      sum: 0,
      buckets: buckets.map(le => ({ le, count: 0 })),
    });
  }

  /**
   * Update histogram
   */
  private updateHistogram(name: string, value: number): void {
    let histogram = this.histograms.get(name);
    if (!histogram) {
      histogram = this.createEmptyHistogram();
      this.histograms.set(name, histogram);
    }

    histogram.count++;
    histogram.sum += value;

    // Update bucket counts
    for (const bucket of histogram.buckets) {
      if (value <= bucket.le) {
        bucket.count++;
      }
    }
  }

  /**
   * Create empty histogram
   */
  private createEmptyHistogram(): HistogramData {
    return {
      count: 0,
      sum: 0,
      buckets: this.config.responseTimeBuckets.map(le => ({ le, count: 0 })),
    };
  }

  /**
   * Update counter metric
   */
  private updateCounter(name: string, value: number): void {
    // Counter logic - would accumulate values
    this.recordMetric(`${name}_total`, MetricType.COUNTER, value);
  }

  /**
   * Update gauge metric
   */
  private updateGauge(name: string, value: number): void {
    // Gauge logic - would track current value
    this.recordMetric(name, MetricType.GAUGE, value);
  }

  /**
   * Calculate CPU usage percentage
   */
  private calculateCPUUsage(totalCpuTime: number): number {
    // This is a simplified calculation
    // In practice, you'd track CPU usage over time intervals
    return Math.min(100, totalCpuTime / 1000000); // Convert microseconds to percentage
  }

  /**
   * Calculate event loop utilization
   */
  private calculateEventLoopUtilization(lag: number): number {
    // Convert lag to utilization percentage
    return Math.min(100, (lag / 10000) * 100); // 10ms = 100% utilization
  }

  /**
   * Measure event loop lag
   */
  private measureEventLoopLag(): number {
    const start = process.hrtime.bigint();
    setImmediate(() => {
      const lag = Number(process.hrtime.bigint() - start);
      this.eventLoopDelaySamples.push(lag);

      // Keep only last 100 samples
      if (this.eventLoopDelaySamples.length > 100) {
        this.eventLoopDelaySamples = this.eventLoopDelaySamples.slice(-100);
      }
    });
    return this.eventLoopDelaySamples.length > 0 ? this.eventLoopDelaySamples[this.eventLoopDelaySamples.length - 1] : 0;
  }

  /**
   * Calculate percentile
   */
  private calculatePercentile(sortedArray: number[], percentile: number): number {
    if (sortedArray.length === 0) return 0;

    const index = Math.ceil(sortedArray.length * percentile) - 1;
    return sortedArray[Math.max(0, Math.min(index, sortedArray.length - 1))];
  }

  /**
   * Calculate average
   */
  private calculateAverage(values: number[]): number {
    if (values.length === 0) return 0;
    return values.reduce((sum, value) => sum + value, 0) / values.length;
  }

  /**
   * Check performance thresholds and trigger alerts
   */
  private checkPerformanceThresholds(operation: string, duration: number): void {
    if (!this.config.alerts.enabled) return;

    const alertKey = `${operation}_response_time`;
    const isWarning = duration > this.config.thresholds.responseTimeWarning;
    const isCritical = duration > this.config.thresholds.responseTimeCritical;

    if (isCritical || isWarning) {
      const alert = this.activeAlerts.get(alertKey) || { count: 0, lastTriggered: 0 };
      alert.count++;
      alert.lastTriggered = Date.now();
      this.activeAlerts.set(alertKey, alert);

      if (alert.count >= this.config.alerts.consecutiveViolationsThreshold) {
        this.emit('performance_alert', {
          type: 'response_time',
          severity: isCritical ? 'critical' : 'warning',
          operation,
          duration,
          threshold: isCritical ? this.config.thresholds.responseTimeCritical : this.config.thresholds.responseTimeWarning,
          consecutiveViolations: alert.count,
        });

        logger.warn(
          {
            operation,
            duration,
            threshold: isCritical ? this.config.thresholds.responseTimeCritical : this.config.thresholds.responseTimeWarning,
            severity: isCritical ? 'critical' : 'warning',
            consecutiveViolations: alert.count,
          },
          `Performance alert: ${operation} response time ${duration}ms exceeds threshold`
        );
      }
    } else {
      // Reset alert count if within threshold
      this.activeAlerts.delete(alertKey);
    }
  }

  /**
   * Generate Prometheus metric line
   */
  private generatePrometheusMetric(name: string, type: string, value: any, help?: string): string {
    let output = '';

    if (help) {
      output += `# HELP ${name} ${help}\n`;
    }

    output += `# TYPE ${name} ${type}\n`;

    if (typeof value === 'object' && value.count !== undefined) {
      // Histogram
      return this.generatePrometheusHistogram(name, value);
    } else {
      output += `${name} ${value}\n`;
    }

    return output + '\n';
  }

  /**
   * Generate Prometheus histogram
   */
  private generatePrometheusHistogram(name: string, histogram: HistogramData): string {
    let output = '';

    // Bucket counts
    for (const bucket of histogram.buckets) {
      output += `${name}_bucket{le="${bucket.le}"} ${bucket.count}\n`;
    }

    // Add +Inf bucket
    output += `${name}_bucket{le="+Inf"} ${histogram.count}\n`;

    // Count and sum
    output += `${name}_count ${histogram.count}\n`;
    output += `${name}_sum ${histogram.sum}\n`;

    return output + '\n';
  }

  /**
   * Get initial system metrics
   */
  private getInitialSystemMetrics(): SystemPerformanceMetrics {
    return {
      cpuUsage: { user: 0, system: 0, idle: 0, total: 0, percentage: 0 },
      memoryUsage: {
        rss: 0,
        heapTotal: 0,
        heapUsed: 0,
        heapUnused: 0,
        external: 0,
        arrayBuffers: 0,
        heapUsagePercent: 0,
        rssUsagePercent: 0,
      },
      eventLoop: { lag: 0, utilization: 0, delays: [] },
      garbageCollection: {
        collections: 0,
        duration: 0,
        averageDuration: 0,
        collectionsByType: {},
        durationByType: {},
      },
      process: {
        uptime: 0,
        pid: 0,
        version: '',
        platform: '',
        arch: '',
        activeHandles: 0,
        activeRequests: 0,
      },
    };
  }

  /**
   * Get initial MCP operation metrics
   */
  private getInitialMCPOperationMetrics(): MCPOperationMetrics {
    return {
      requests: {
        total: 0,
        successful: 0,
        failed: 0,
        rate: 0,
        averageResponseTime: 0,
        p50ResponseTime: 0,
        p90ResponseTime: 0,
        p95ResponseTime: 0,
        p99ResponseTime: 0,
        responseTimeHistogram: this.createEmptyHistogram(),
      },
      sessions: {
        active: 0,
        total: 0,
        averageDuration: 0,
        totalDuration: 0,
      },
      tools: {
        executions: 0,
        successful: 0,
        failed: 0,
        averageExecutionTime: 0,
        popularTools: [],
        executionTimeHistogram: this.createEmptyHistogram(),
      },
      knowledgeGraph: {
        entities: { total: 0, created: 0, updated: 0, deleted: 0 },
        relations: { total: 0, created: 0, deleted: 0 },
        operations: { stores: 0, finds: 0, updates: 0, deletes: 0 },
      },
      quality: {
        dedupeRate: 0,
        cacheHitRate: 0,
        embeddingSuccessRate: 0,
        ttlCleanupRate: 0,
        validationSuccessRate: 0,
      },
    };
  }

  getCurrentMetrics?: unknown|undefined}

// Export singleton instance
export const enhancedPerformanceCollector = new EnhancedPerformanceCollector();
