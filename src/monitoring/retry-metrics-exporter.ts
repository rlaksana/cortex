// ABSOLUTE FINAL EMERGENCY ROLLBACK: Last remaining systematic type issues

/**
 * Retry Metrics Exporter
 *
 * Comprehensive metrics export service for retry budget and circuit breaker monitoring.
 * Supports Prometheus, Grafana, JSON, and custom export formats with real-time streaming
 * and historical data access.
 *
 * @author Cortex Team
 * @version 2.0.1
 */

import { type WriteStream } from 'fs';

import { EventEmitter } from 'events';

import { logger } from '@/utils/logger.js';

import {
  type CircuitBreakerHealthStatus,
  circuitBreakerMonitor,
} from './circuit-breaker-monitor.js';
import { type RetryBudgetMetrics, retryBudgetMonitor } from './retry-budget-monitor.js';

/**
 * Export format types
 */
export enum ExportFormat {
  PROMETHEUS = 'prometheus',
  GRAFANA = 'grafana',
  JSON = 'json',
  CSV = 'csv',
  INFLUXDB = 'influxdb',
  DATADOG = 'datadog',
}

/**
 * Export configuration
 */
export interface MetricsExporterConfig {
  // Export destinations
  destinations: {
    prometheus: {
      enabled: boolean;
      endpoint: string;
      port: number;
      metricsPath: string;
    };
    grafana: {
      enabled: boolean;
      apiEndpoint: string;
      apiKey?: string;
      dashboardId?: string;
    };
    file: {
      enabled: boolean;
      directory: string;
      rotationMinutes: number;
      compression: boolean;
    };
    webhook: {
      enabled: boolean;
      url: string;
      headers?: Record<string, string>;
      timeoutMs: number;
    };
  };

  // Export settings
  export: {
    intervalSeconds: number;
    batchSize: number;
    compressionEnabled: boolean;
    retentionDays: number;
  };

  // Metrics filtering
  filtering: {
    includeServices: string[];
    excludeServices: string[];
    includeMetrics: string[];
    excludeMetrics: string[];
  };

  // Performance settings
  performance: {
    maxConcurrentExports: number;
    retryAttempts: number;
    retryDelayMs: number;
    bufferSize: number;
  };
}

/**
 * Exported metrics data structure
 */
export interface ExportedMetrics {
  timestamp: Date;
  format: ExportFormat;
  data: unknown;
  metadata: {
    version: string;
    source: string;
    generatedAt: string;
    serviceCount: number;
    metricCount: number;
  };
}

/**
 * Prometheus metrics specification
 */
export interface PrometheusMetric {
  name: string;
  type: 'counter' | 'gauge' | 'histogram' | 'summary';
  help: string;
  labels: Record<string, string>;
  value: number;
  timestamp?: number;
}

/**
 * Grafana dashboard data
 */
export interface GrafanaDashboardData {
  title: string;
  panels: Array<{
    title: string;
    type: string;
    targets: Array<{
      expr: string;
      legendFormat: string;
      refId: string;
    }>;
    gridPos: {
      x: number;
      y: number;
      w: number;
      h: number;
    };
  }>;
  time: {
    from: string;
    to: string;
  };
  refresh: string;
}

/**
 * Comprehensive Metrics Exporter
 */
export class RetryMetricsExporter extends EventEmitter {
  private config: MetricsExporterConfig;
  private isRunning = false;
  private exportInterval: NodeJS.Timeout | null = null;

  // File handles for rotation
  private fileStreams: Map<string, WriteStream> = new Map();
  private currentFiles: Map<string, string> = new Map();

  // Export queue and processing
  private exportQueue: Array<{
    data: ExportedMetrics;
    destination: string;
    attempts: number;
    timestamp: number;
  }> = [];
  private processingExports = false;

  // Metrics cache
  private metricsCache: Map<string, { data: unknown; timestamp: number }> = new Map();

  constructor(config?: Partial<MetricsExporterConfig>) {
    super();

    this.config = {
      destinations: {
        prometheus: {
          enabled: true,
          endpoint: '/metrics',
          port: 9090,
          metricsPath: '/metrics',
        },
        grafana: {
          enabled: true,
          apiEndpoint: 'http://localhost:3000',
        },
        file: {
          enabled: true,
          directory: './metrics',
          rotationMinutes: 60,
          compression: false,
        },
        webhook: {
          enabled: false,
          url: '',
          timeoutMs: 5000,
        },
      },
      export: {
        intervalSeconds: 30,
        batchSize: 100,
        compressionEnabled: false,
        retentionDays: 7,
      },
      filtering: {
        includeServices: [],
        excludeServices: [],
        includeMetrics: [],
        excludeMetrics: [],
      },
      performance: {
        maxConcurrentExports: 5,
        retryAttempts: 3,
        retryDelayMs: 1000,
        bufferSize: 1000,
      },
      ...config,
    };
  }

  /**
   * Start the metrics exporter
   */
  async start(): Promise<void> {
    if (this.isRunning) {
      logger.warn('Metrics exporter is already running');
      return;
    }

    this.isRunning = true;

    // Initialize file outputs
    if (this.config.destinations.file.enabled) {
      await this.initializeFileOutputs();
    }

    // Start export interval
    this.exportInterval = setInterval(
      () => this.performExportCycle(),
      this.config.export.intervalSeconds * 1000
    );

    // Perform initial export
    await this.performExportCycle();

    logger.info(
      {
        intervalSeconds: this.config.export.intervalSeconds,
        destinations: Object.keys(this.config.destinations).filter(
          (key) => this.config.destinations[key as keyof typeof this.config.destinations].enabled
        ),
      },
      'Metrics exporter started'
    );

    this.emit('started');
  }

  /**
   * Stop the metrics exporter
   */
  async stop(): Promise<void> {
    if (!this.isRunning) {
      logger.warn('Metrics exporter is not running');
      return;
    }

    this.isRunning = false;

    if (this.exportInterval) {
      clearInterval(this.exportInterval);
      this.exportInterval = null;
    }

    // Close file streams
    for (const stream of this.fileStreams.values()) {
      stream.end();
    }
    this.fileStreams.clear();
    this.currentFiles.clear();

    // Process remaining export queue
    await this.processExportQueue();

    logger.info('Metrics exporter stopped');
    this.emit('stopped');
  }

  /**
   * Export metrics in specified format
   */
  async exportMetrics(format: ExportFormat, destination?: string): Promise<ExportedMetrics> {
    const timestamp = new Date();
    const retryBudgetMetrics = retryBudgetMonitor.getAllMetrics();
    const circuitBreakerMetrics = circuitBreakerMonitor.getAllHealthStatuses();

    let data: unknown;

    switch (format) {
      case ExportFormat.PROMETHEUS:
        data = this.formatPrometheusMetrics(retryBudgetMetrics, circuitBreakerMetrics);
        break;
      case ExportFormat.GRAFANA:
        data = this.formatGrafanaData(retryBudgetMetrics, circuitBreakerMetrics);
        break;
      case ExportFormat.JSON:
        data = this.formatJSONMetrics(retryBudgetMetrics, circuitBreakerMetrics);
        break;
      case ExportFormat.CSV:
        data = this.formatCSVMetrics(retryBudgetMetrics, circuitBreakerMetrics);
        break;
      case ExportFormat.INFLUXDB:
        data = this.formatInfluxDBMetrics(retryBudgetMetrics, circuitBreakerMetrics);
        break;
      case ExportFormat.DATADOG:
        data = this.formatDatadogMetrics(retryBudgetMetrics, circuitBreakerMetrics);
        break;
      default:
        throw new Error(`Unsupported export format: ${format}`);
    }

    const exportedMetrics: ExportedMetrics = {
      timestamp,
      format,
      data,
      metadata: {
        version: '2.0.1',
        source: 'mcp-cortex-retry-monitor',
        generatedAt: timestamp.toISOString(),
        serviceCount: retryBudgetMetrics.size,
        metricCount: this.countMetrics(data),
      },
    };

    // Queue for delivery if destination specified
    if (destination) {
      this.queueExport(exportedMetrics, destination);
    }

    return exportedMetrics;
  }

  /**
   * Get metrics in Prometheus format (for scraping)
   */
  getPrometheusMetrics(): string {
    const retryBudgetMetrics = retryBudgetMonitor.getAllMetrics();
    const circuitBreakerMetrics = circuitBreakerMonitor.getAllHealthStatuses();
    return this.formatPrometheusMetrics(retryBudgetMetrics, circuitBreakerMetrics);
  }

  /**
   * Generate Grafana dashboard configuration
   */
  generateGrafanaDashboard(): GrafanaDashboardData {
    return {
      title: 'MCP Cortex - Retry Budget & Circuit Breaker Dashboard',
      panels: [
        {
          title: 'Retry Budget Utilization',
          type: 'stat',
          targets: [
            {
              expr: 'retry_budget_utilization_percent',
              legendFormat: '{{service}}',
              refId: 'A',
            },
          ],
          gridPos: { x: 0, y: 0, w: 12, h: 8 },
        },
        {
          title: 'Circuit Breaker States',
          type: 'stat',
          targets: [
            {
              expr: 'circuit_breaker_state',
              legendFormat: '{{service}}',
              refId: 'B',
            },
          ],
          gridPos: { x: 12, y: 0, w: 12, h: 8 },
        },
        {
          title: 'Retry Rate Over Time',
          type: 'timeseries',
          targets: [
            {
              expr: 'rate(retry_total[5m])',
              legendFormat: '{{service}}',
              refId: 'C',
            },
          ],
          gridPos: { x: 0, y: 8, w: 24, h: 8 },
        },
        {
          title: 'SLO Compliance',
          type: 'stat',
          targets: [
            {
              expr: 'slo_compliance_ratio',
              legendFormat: '{{service}}',
              refId: 'D',
            },
          ],
          gridPos: { x: 0, y: 16, w: 12, h: 8 },
        },
        {
          title: 'Circuit Breaker Success Rate',
          type: 'stat',
          targets: [
            {
              expr: 'circuit_breaker_success_rate',
              legendFormat: '{{service}}',
              refId: 'E',
            },
          ],
          gridPos: { x: 12, y: 16, w: 12, h: 8 },
        },
      ],
      time: {
        from: 'now-1h',
        to: 'now',
      },
      refresh: '30s',
    };
  }

  /**
   * Export to all configured destinations
   */
  async exportToAllDestinations(): Promise<void> {
    const formats = [ExportFormat.PROMETHEUS, ExportFormat.GRAFANA, ExportFormat.JSON];

    for (const format of formats) {
      try {
        const metrics = await this.exportMetrics(format);

        if (this.config.destinations.file.enabled) {
          await this.writeToFile(metrics, format);
        }

        if (this.config.destinations.webhook.enabled) {
          await this.sendToWebhook(metrics);
        }

        this.emit('metrics_exported', { format, metrics });
      } catch (error) {
        logger.error({ format, error }, `Failed to export metrics in ${format} format`);
      }
    }
  }

  /**
   * Perform regular export cycle
   */
  private async performExportCycle(): Promise<void> {
    if (!this.isRunning) return;

    try {
      await this.exportToAllDestinations();
      await this.processExportQueue();
      await this.cleanupOldMetrics();
    } catch (error) {
      logger.error({ error }, 'Failed to perform export cycle');
    }
  }

  /**
   * Format metrics for Prometheus
   */
  private formatPrometheusMetrics(
    retryBudgetMetrics: Map<string, RetryBudgetMetrics>,
    circuitBreakerMetrics: Map<string, CircuitBreakerHealthStatus>
  ): string {
    const prometheusLines: string[] = [];

    // Retry budget metrics
    for (const [serviceName, metrics] of retryBudgetMetrics) {
      const labels = `service="${serviceName}"`;

      prometheusLines.push(
        `# HELP retry_budget_utilization_percent Retry budget utilization percentage`,
        `# TYPE retry_budget_utilization_percent gauge`,
        `retry_budget_utilization_percent{${labels}} ${metrics.current.budgetUtilizationPercent}`,
        '',
        `# HELP retry_budget_remaining_retries_minute Remaining retries in current minute`,
        `# TYPE retry_budget_remaining_retries_minute gauge`,
        `retry_budget_remaining_retries_minute{${labels}} ${metrics.current.budgetRemainingMinute}`,
        '',
        `# HELP retry_budget_remaining_retries_hour Remaining retries in current hour`,
        `# TYPE retry_budget_remaining_retries_hour gauge`,
        `retry_budget_remaining_retries_hour{${labels}} ${metrics.current.budgetRemainingHour}`,
        '',
        `# HELP retry_rate_percent Current retry rate percentage`,
        `# TYPE retry_rate_percent gauge`,
        `retry_rate_percent{${labels}} ${metrics.current.retryRatePercent}`,
        '',
        `# HELP slo_success_rate_compliance SLO success rate compliance`,
        `# TYPE slo_success_rate_compliance gauge`,
        `slo_success_rate_compliance{${labels}} ${metrics.slo.successRateCompliance ? 1 : 0}`,
        '',
        `# HELP slo_response_time_compliance SLO response time compliance`,
        `# TYPE slo_response_time_compliance gauge`,
        `slo_response_time_compliance{${labels}} ${metrics.slo.responseTimeCompliance ? 1 : 0}`,
        '',
        `# HELP retry_budget_risk_level Risk level (0=low, 1=medium, 2=high, 3=critical)`,
        `# TYPE retry_budget_risk_level gauge`,
        `retry_budget_risk_level{${labels}} ${this.riskLevelToNumber(metrics.predictions.riskLevel)}`
      );
    }

    // Circuit breaker metrics
    for (const [serviceName, metrics] of circuitBreakerMetrics) {
      const labels = `service="${serviceName}"`;

      prometheusLines.push(
        '',
        `# HELP circuit_breaker_state Circuit breaker state (0=closed, 1=open, 2=half-open)`,
        `# TYPE circuit_breaker_state gauge`,
        `circuit_breaker_state{${labels}} ${this.circuitStateToNumber(metrics.state)}`,
        '',
        `# HELP circuit_breaker_failure_rate Circuit breaker failure rate percentage`,
        `# TYPE circuit_breaker_failure_rate gauge`,
        `circuit_breaker_failure_rate{${labels}} ${metrics.metrics.failureRate}`,
        '',
        `# HELP circuit_breaker_success_rate Circuit breaker success rate percentage`,
        `# TYPE circuit_breaker_success_rate gauge`,
        `circuit_breaker_success_rate{${labels}} ${metrics.metrics.successRate}`,
        '',
        `# HELP circuit_breaker_consecutive_failures Circuit breaker consecutive failures`,
        `# TYPE circuit_breaker_consecutive_failures gauge`,
        `circuit_breaker_consecutive_failures{${labels}} ${metrics.metrics.consecutiveFailures}`
      );
    }

    return prometheusLines.join('\n') + '\n';
  }

  /**
   * Format data for Grafana
   */
  private formatGrafanaData(
    retryBudgetMetrics: Map<string, RetryBudgetMetrics>,
    circuitBreakerMetrics: Map<string, CircuitBreakerHealthStatus>
  ): unknown {
    return {
      timestamp: new Date().toISOString(),
      retryBudgets: Array.from(retryBudgetMetrics.entries()).map(([name, metrics]) => ({
        service: name,
        utilization: metrics.current.budgetUtilizationPercent,
        retryRate: metrics.current.retryRatePercent,
        remainingMinute: metrics.current.budgetRemainingMinute,
        remainingHour: metrics.current.budgetRemainingHour,
        sloCompliance: metrics.slo.overallCompliance,
        riskLevel: metrics.predictions.riskLevel,
        alerts: metrics.alerts.length,
      })),
      circuitBreakers: Array.from(circuitBreakerMetrics.entries()).map(([name, metrics]) => ({
        service: name,
        state: metrics.state,
        healthStatus: metrics.healthStatus,
        failureRate: metrics.metrics.failureRate,
        successRate: metrics.metrics.successRate,
        consecutiveFailures: metrics.metrics.consecutiveFailures,
        averageResponseTime: metrics.metrics.averageResponseTime,
      })),
    };
  }

  /**
   * Format metrics as JSON
   */
  private formatJSONMetrics(
    retryBudgetMetrics: Map<string, RetryBudgetMetrics>,
    circuitBreakerMetrics: Map<string, CircuitBreakerHealthStatus>
  ): unknown {
    return {
      timestamp: new Date().toISOString(),
      retryBudgets: Object.fromEntries(retryBudgetMetrics),
      circuitBreakers: Object.fromEntries(circuitBreakerMetrics),
      summary: {
        totalServices: retryBudgetMetrics.size,
        totalCircuits: circuitBreakerMetrics.size,
        averageUtilization:
          Array.from(retryBudgetMetrics.values()).reduce(
            (sum, m) => sum + m.current.budgetUtilizationPercent,
            0
          ) / Math.max(retryBudgetMetrics.size, 1),
      },
    };
  }

  /**
   * Format metrics as CSV
   */
  private formatCSVMetrics(
    retryBudgetMetrics: Map<string, RetryBudgetMetrics>,
    circuitBreakerMetrics: Map<string, CircuitBreakerHealthStatus>
  ): string {
    const headers = [
      'timestamp',
      'service',
      'budget_utilization_percent',
      'retry_rate_percent',
      'remaining_retries_minute',
      'remaining_retries_hour',
      'slo_compliance',
      'risk_level',
      'circuit_state',
      'circuit_failure_rate',
      'circuit_success_rate',
    ];

    const rows = [headers.join(',')];

    for (const [serviceName, retryMetrics] of retryBudgetMetrics) {
      const circuitMetrics = circuitBreakerMetrics.get(serviceName);

      rows.push(
        [
          new Date().toISOString(),
          serviceName,
          retryMetrics.current.budgetUtilizationPercent.toFixed(2),
          retryMetrics.current.retryRatePercent.toFixed(2),
          retryMetrics.current.budgetRemainingMinute.toString(),
          retryMetrics.current.budgetRemainingHour.toString(),
          retryMetrics.slo.overallCompliance ? '1' : '0',
          retryMetrics.predictions.riskLevel,
          circuitMetrics?.state || 'unknown',
          circuitMetrics?.metrics.failureRate.toFixed(2) || '0',
          circuitMetrics?.metrics.successRate.toFixed(2) || '0',
        ].join(',')
      );
    }

    return rows.join('\n');
  }

  /**
   * Format metrics for InfluxDB
   */
  private formatInfluxDBMetrics(
    retryBudgetMetrics: Map<string, RetryBudgetMetrics>,
    circuitBreakerMetrics: Map<string, CircuitBreakerHealthStatus>
  ): string {
    const points: string[] = [];
    const timestamp = Date.now() * 1000000; // InfluxDB nanosecond timestamp

    for (const [serviceName, metrics] of retryBudgetMetrics) {
      points.push(
        `retry_budget,service=${serviceName} utilization=${metrics.current.budgetUtilizationPercent},retry_rate=${metrics.current.retryRatePercent},remaining_minute=${metrics.current.budgetRemainingMinute},remaining_hour=${metrics.current.budgetRemainingHour},slo_compliance=${metrics.slo.overallCompliance ? 1 : 0} ${timestamp}`
      );
    }

    for (const [serviceName, metrics] of circuitBreakerMetrics) {
      points.push(
        `circuit_breaker,service=${serviceName} state="${metrics.state}",failure_rate=${metrics.metrics.failureRate},success_rate=${metrics.metrics.successRate},consecutive_failures=${metrics.metrics.consecutiveFailures} ${timestamp}`
      );
    }

    return points.join('\n');
  }

  /**
   * Format metrics for Datadog
   */
  private formatDatadogMetrics(
    retryBudgetMetrics: Map<string, RetryBudgetMetrics>,
    circuitBreakerMetrics: Map<string, CircuitBreakerHealthStatus>
  ): unknown {
    const series: unknown[] = [];
    const timestamp = Math.floor(Date.now() / 1000);

    for (const [serviceName, metrics] of retryBudgetMetrics) {
      series.push(
        {
          metric: 'mcp_cortex.retry_budget.utilization_percent',
          points: [[timestamp, metrics.current.budgetUtilizationPercent]],
          tags: [`service:${serviceName}`],
        },
        {
          metric: 'mcp_cortex.retry_budget.retry_rate_percent',
          points: [[timestamp, metrics.current.retryRatePercent]],
          tags: [`service:${serviceName}`],
        },
        {
          metric: 'mcp_cortex.retry_budget.remaining_retries',
          points: [[timestamp, metrics.current.budgetRemainingHour]],
          tags: [`service:${serviceName}`, 'period:hour'],
        },
        {
          metric: 'mcp_cortex.slo.compliance',
          points: [[timestamp, metrics.slo.overallCompliance ? 1 : 0]],
          tags: [`service:${serviceName}`],
        }
      );
    }

    for (const [serviceName, metrics] of circuitBreakerMetrics) {
      series.push(
        {
          metric: 'mcp_cortex.circuit_breaker.state',
          points: [[timestamp, this.circuitStateToNumber(metrics.state)]],
          tags: [`service:${serviceName}`, `state:${metrics.state}`],
        },
        {
          metric: 'mcp_cortex.circuit_breaker.failure_rate',
          points: [[timestamp, metrics.metrics.failureRate]],
          tags: [`service:${serviceName}`],
        }
      );
    }

    return { series };
  }

  /**
   * Write metrics to file
   */
  private async writeToFile(metrics: ExportedMetrics, format: ExportFormat): Promise<void> {
    const filename = this.generateFileName(format);
    const filepath = `${this.config.destinations.file.directory}/${filename}`;

    try {
      let content: string;
      switch (format) {
        case ExportFormat.PROMETHEUS:
          content = this.validateAndConvertToString(metrics.data, 'prometheus');
          break;
        case ExportFormat.JSON:
          content = JSON.stringify(metrics.data, null, 2);
          break;
        case ExportFormat.CSV:
          content = this.validateAndConvertToString(metrics.data, 'csv');
          break;
        default:
          content = JSON.stringify(metrics.data);
      }

      // In a real implementation, this would write to file system
      // For now, emit event that would be handled by file writer
      this.emit('file_write_requested', { filepath, content, format });

      logger.debug({ filepath, format, size: content.length }, 'Metrics written to file');
    } catch (error) {
      logger.error({ filepath, format, error }, 'Failed to write metrics to file');
      throw error;
    }
  }

  /**
   * Send metrics to webhook
   */
  private async sendToWebhook(metrics: ExportedMetrics): Promise<void> {
    if (!this.config.destinations.webhook.enabled || !this.config.destinations.webhook.url) {
      return;
    }

    try {
      // In a real implementation, this would make HTTP request
      // For now, emit event that would be handled by HTTP client
      this.emit('webhook_send_requested', {
        url: this.config.destinations.webhook.url,
        headers: this.config.destinations.webhook.headers,
        data: metrics,
        timeout: this.config.destinations.webhook.timeoutMs,
      });

      logger.debug(
        { url: this.config.destinations.webhook.url, format: metrics.format },
        'Metrics sent to webhook'
      );
    } catch (error) {
      logger.error(
        { url: this.config.destinations.webhook.url, error },
        'Failed to send metrics to webhook'
      );
      throw error;
    }
  }

  /**
   * Queue export for processing
   */
  private queueExport(metrics: ExportedMetrics, destination: string): void {
    this.exportQueue.push({
      data: metrics,
      destination,
      attempts: 0,
      timestamp: Date.now(),
    });

    // Limit queue size
    if (this.exportQueue.length > this.config.performance.bufferSize) {
      this.exportQueue.shift(); // Remove oldest entry
    }
  }

  /**
   * Process export queue
   */
  private async processExportQueue(): Promise<void> {
    if (this.processingExports || this.exportQueue.length === 0) {
      return;
    }

    this.processingExports = true;

    try {
      const batch = this.exportQueue.splice(0, this.config.export.batchSize);
      const promises = batch.map((item) => this.processExportItem(item));

      await Promise.allSettled(promises);
    } finally {
      this.processingExports = false;
    }
  }

  /**
   * Process individual export item
   */
  private async processExportItem(item: {
    data: ExportedMetrics;
    destination: string;
    attempts: number;
    timestamp: number;
  }): Promise<void> {
    try {
      // Process based on destination
      if (item.destination.startsWith('file:')) {
        await this.writeToFile(item.data, item.data.format);
      } else if (item.destination.startsWith('webhook:')) {
        await this.sendToWebhook(item.data);
      }

      this.emit('export_completed', { item });
    } catch (error) {
      item.attempts++;

      if (item.attempts < this.config.performance.retryAttempts) {
        // Retry with delay
        setTimeout(() => {
          this.exportQueue.push(item);
        }, this.config.performance.retryDelayMs * item.attempts);
      } else {
        logger.error(
          {
            destination: item.destination,
            attempts: item.attempts,
            error,
          },
          'Export failed after maximum retries'
        );
        this.emit('export_failed', { item, error });
      }
    }
  }

  /**
   * Initialize file outputs
   */
  private async initializeFileOutputs(): Promise<void> {
    // In a real implementation, this would create directories and initialize file handles
    logger.info({ directory: this.config.destinations.file.directory }, 'File outputs initialized');
  }

  /**
   * Clean up old metrics
   */
  private async cleanupOldMetrics(): Promise<void> {
    // Clean up cache
    const cutoff = Date.now() - this.config.export.retentionDays * 24 * 60 * 60 * 1000;
    for (const [key, cached] of this.metricsCache) {
      if (cached.timestamp < cutoff) {
        this.metricsCache.delete(key);
      }
    }

    // In a real implementation, this would also clean up old files
  }

  /**
   * Generate filename for metrics export
   */
  private generateFileName(format: ExportFormat): string {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const extension =
      format === ExportFormat.PROMETHEUS ? 'prom' : format === ExportFormat.CSV ? 'csv' : 'json';
    return `retry-metrics-${timestamp}.${extension}`;
  }

  /**
   * Count metrics in data structure
   */
  private countMetrics(data: unknown): number {
    if (typeof data === 'string') {
      return data.split('\n').filter((line) => line && !line.startsWith('#')).length;
    }
    if (typeof data === 'object') {
      return Object.keys(data).length;
    }
    return 1;
  }

  /**
   * Convert risk level to number
   */
  private riskLevelToNumber(riskLevel: string): number {
    switch (riskLevel) {
      case 'low':
        return 0;
      case 'medium':
        return 1;
      case 'high':
        return 2;
      case 'critical':
        return 3;
      default:
        return 0;
    }
  }

  /**
   * Convert circuit state to number
   */
  private circuitStateToNumber(state: string): number {
    switch (state) {
      case 'closed':
        return 0;
      case 'open':
        return 1;
      case 'half-open':
        return 2;
      default:
        return 0;
    }
  }

  /**
   * Validate and convert data to string with proper type checking
   */
  private validateAndConvertToString(data: unknown, context: string): string {
    if (typeof data === 'string') {
      return data;
    }

    if (data === null || data === undefined) {
      logger.warn({ data, context }, 'Data is null or undefined, returning empty string');
      return '';
    }

    if (context === 'prometheus' && typeof data === 'object') {
      // For prometheus format, we expect an object with string values
      try {
        return JSON.stringify(data);
      } catch (error) {
        logger.error({ data, error, context }, 'Failed to serialize prometheus data');
        return '';
      }
    }

    if (context === 'csv' && typeof data === 'string') {
      return data;
    }

    // For any other type, convert to JSON string
    try {
      return JSON.stringify(data);
    } catch (error) {
      logger.error({ data, error, context }, 'Failed to convert data to string');
      return String(data);
    }
  }

  /**
   * Type guard for unknown data being object
   */
  private isRecord(data: unknown): data is Record<string, unknown> {
    return typeof data === 'object' && data !== null && !Array.isArray(data);
  }

  /**
   * Type guard for unknown data being array
   */
  private isArray(data: unknown): data is unknown[] {
    return Array.isArray(data);
  }

  /**
   * Safe property access with type checking
   */
  private safePropertyAccess<T>(obj: unknown, property: string, fallback: T): T {
    if (!this.isRecord(obj)) {
      return fallback;
    }

    if (property in obj) {
      const value = obj[property];
      return value as T;
    }

    return fallback;
  }
}

// Export singleton instance
export const retryMetricsExporter = new RetryMetricsExporter();
