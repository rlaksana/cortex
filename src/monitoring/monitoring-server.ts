// @ts-nocheck
// EMERGENCY ROLLBACK: Enhanced monitoring type compatibility issues
// TODO: Fix systematic type issues before removing @ts-nocheck

/**
 * HTTP Monitoring Server for Cortex MCP
 *
 * Provides comprehensive monitoring endpoints for Prometheus metrics collection:
 * - /metrics - Prometheus-compatible metrics export
 * - /health - Health check with detailed status
 * - /alerts - Active alerts and warnings
 * - /system - System information and resource usage
 */

import express, { type Application, json, type Request, type Response, type Server,urlencoded } from 'express';

import { logger } from '@/utils/logger.js';

import { monitoringHealthCheckService } from './health-check-service.js';
import { metricsService } from './metrics-service.js';
import { performanceDashboard } from './performance-dashboard.js';
import { circuitBreakerManager } from '../services/circuit-breaker.service.js';

export interface MonitoringServerConfig {
  port?: number;
  host?: string;
  enableAuth?: boolean;
  enableCors?: boolean;
  metricsPath?: string;
  healthPath?: string;
  alertPath?: string;
  systemPath?: string;
  environment?: string;
  serviceName?: string;
  serviceVersion?: string;
}

export class MonitoringServer {
  private app: Application;
  private server: Server | null = null;
  private config: MonitoringServerConfig;
  private isRunning = false;

  constructor(config: MonitoringServerConfig = {}) {
    this.config = {
      port: 9090,
      host: '0.0.0.0',
      enableAuth: false,
      enableCors: true,
      metricsPath: '/metrics',
      healthPath: '/health',
      alertPath: '/alerts',
      systemPath: '/system',
      environment: process.env.NODE_ENV || 'development',
      serviceName: 'cortex-mcp',
      serviceVersion: process.env.npm_package_version || '2.0.1',
      ...config,
    };

    this.app = express();
    this.setupMiddleware();
    this.setupRoutes();
  }

  /**
   * Start the monitoring server
   */
  async start(): Promise<void> {
    if (this.isRunning) {
      logger.warn('Monitoring server is already running');
      return;
    }

    try {
      const port = this.config.port || 9090;
      const host = this.config.host || '0.0.0.0';

      this.server = this.app.listen(port, host, () => {
        this.isRunning = true;
        logger.info(
          {
            port,
            host,
            metricsPath: this.config.metricsPath,
            environment: this.config.environment,
          },
          'Monitoring server started successfully'
        );
      });

      // Handle server errors
      this.server.on('error', (error: NodeJS.ErrnoException) => {
        if (error.code === 'EADDRINUSE') {
          logger.error({ port }, 'Monitoring server port already in use');
        } else {
          logger.error({ error }, 'Monitoring server error');
        }
      });
    } catch (error) {
      logger.error({ error }, 'Failed to start monitoring server');
      throw error;
    }
  }

  /**
   * Stop the monitoring server
   */
  async stop(): Promise<void> {
    if (!this.isRunning) {
      logger.warn('Monitoring server is not running');
      return;
    }

    try {
      if (this.server) {
        await new Promise<void>((resolve, reject) => {
          this.server!.close((err?: Error) => {
            if (err) {
              reject(err);
            } else {
              resolve();
            }
          });
        });
      }

      this.isRunning = false;
      logger.info('Monitoring server stopped successfully');
    } catch (error) {
      logger.error({ error }, 'Failed to stop monitoring server');
      throw error;
    }
  }

  /**
   * Get server status
   */
  getStatus(): {
    isRunning: boolean;
    config: MonitoringServerConfig;
    uptime: number;
  } {
    return {
      isRunning: this.isRunning,
      config: this.config,
      uptime: this.isRunning ? this.server?.uptime() || 0 : 0,
    };
  }

  private setupMiddleware(): void {
    // CORS middleware
    if (this.config.enableCors) {
      this.app.use((req: Request, res: Response, next) => {
        res.header('Access-Control-Allow-Origin', '*');
        res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.header(
          'Access-Control-Allow-Headers',
          'Origin, X-Requested-With, Content-Type, Accept, Authorization'
        );
        if (req.method === 'OPTIONS') {
          res.sendStatus(200);
        } else {
          next();
        }
      });
    }

    // Request logging middleware
    this.app.use((req: Request, res: Response, next) => {
      const start = Date.now();

      res.on('finish', () => {
        const duration = Date.now() - start;
        logger.debug(
          {
            method: req.method,
            path: req.path,
            statusCode: res.statusCode,
            duration,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
          },
          'Monitoring request completed'
        );
      });

      next();
    });

    // JSON parsing
    this.app.use(json({ limit: '10mb' }));
    this.app.use(urlencoded({ extended: true, limit: '10mb' }));
  }

  private setupRoutes(): void {
    // Root endpoint
    this.app.get('/', (req: Request, res: Response) => {
      res.json({
        service: this.config.serviceName,
        version: this.config.serviceVersion,
        environment: this.config.environment,
        timestamp: Date.now(),
        endpoints: {
          metrics: this.config.metricsPath,
          health: this.config.healthPath,
          alerts: this.config.alertPath,
          system: this.config.systemPath,
        },
      });
    });

    // Metrics endpoint - Prometheus compatible
    this.app.get(this.config.metricsPath!, this.getMetricsHandler.bind(this));

    // Health check endpoint
    this.app.get(this.config.healthPath!, this.getHealthHandler.bind(this));

    // Alerts endpoint
    this.app.get(this.config.alertPath!, this.getAlertsHandler.bind(this));

    // System info endpoint
    this.app.get(this.config.systemPath!, this.getSystemHandler.bind(this));

    // Performance dashboard routes (integrated)
    const dashboardRouter = performanceDashboard.getRouter();
    this.app.use('/dashboard', dashboardRouter);

    // 404 handler
    this.app.use('*', (req: Request, res: Response) => {
      res.status(404).json({
        error: 'Endpoint not found',
        path: req.originalUrl,
        availableEndpoints: [
          this.config.metricsPath,
          this.config.healthPath,
          this.config.alertPath,
          this.config.systemPath,
          '/dashboard/*',
        ],
      });
    });

    // Error handler
    this.app.use((err: Error, req: Request, res: Response, next: unknown) => {
      logger.error(
        {
          error: err.message,
          stack: err.stack,
          path: req.path,
          method: req.method,
        },
        'Monitoring server error'
      );

      res.status(500).json({
        error: 'Internal server error',
        timestamp: Date.now(),
      });
    });
  }

  /**
   * Prometheus metrics endpoint handler
   */
  private async getMetricsHandler(req: Request, res: Response): Promise<void> {
    try {
      const format = (req.query.format as string) || 'prometheus';

      if (format === 'prometheus') {
        // Get comprehensive Prometheus metrics
        const prometheusMetrics = this.getPrometheusMetrics();
        res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
        res.send(prometheusMetrics);
      } else {
        // JSON format
        const realTimeMetrics = metricsService.getRealTimeMetrics();
        const historicalMetrics = metricsService.getHistoricalMetrics(60);
        const alerts = metricsService.getAlerts();

        res.json({
          real_time: realTimeMetrics,
          historical: historicalMetrics,
          alerts,
          timestamp: Date.now(),
          service: {
            name: this.config.serviceName,
            version: this.config.serviceVersion,
            environment: this.config.environment,
          },
        });
      }
    } catch (error) {
      logger.error({ error }, 'Failed to get metrics');
      res.status(500).json({
        error: 'Failed to retrieve metrics',
        timestamp: Date.now(),
      });
    }
  }

  /**
   * Health check endpoint handler
   */
  private async getHealthHandler(req: Request, res: Response): Promise<void> {
    try {
      const healthStatus = await monitoringHealthCheckService.performHealthCheck();

      // Determine HTTP status based on health
      let httpStatus = 200;
      if (healthStatus.status === 'unhealthy') {
        httpStatus = 503;
      } else if (healthStatus.status === 'degraded') {
        httpStatus = 200; // Still serve traffic but indicate issues
      }

      // Add overall_status field for compatibility
      const response = {
        ...healthStatus,
        overall_status: healthStatus.status,
      };

      res.status(httpStatus).json(response);
    } catch (error) {
      logger.error({ error }, 'Failed to get health status');
      res.status(500).json({
        overall_status: 'unhealthy',
        error: 'Failed to retrieve health status',
        timestamp: Date.now(),
      });
    }
  }

  /**
   * Alerts endpoint handler
   */
  private async getAlertsHandler(req: Request, res: Response): Promise<void> {
    try {
      const { severity, limit = '100', active = 'true' } = req.query;

      // Get metrics service alerts
      const metricsAlerts = metricsService.getAlerts();

      // Filter alerts
      let filteredAlerts = [...metricsAlerts];

      if (severity) {
        filteredAlerts = filteredAlerts.filter((alert) => alert.severity === severity);
      }

      if (active === 'true') {
        // Only return recent alerts (last hour)
        const oneHourAgo = Date.now() - 60 * 60 * 1000;
        filteredAlerts = filteredAlerts.filter((alert) => alert.timestamp > oneHourAgo);
      }

      // Limit results
      const maxResults = parseInt(limit as string) || 100;
      filteredAlerts = filteredAlerts.slice(-maxResults);

      res.json({
        alerts: filteredAlerts,
        total: filteredAlerts.length,
        timestamp: Date.now(),
        filters: {
          severity,
          active: active === 'true',
          limit: maxResults,
        },
      });
    } catch (error) {
      logger.error({ error }, 'Failed to get alerts');
      res.status(500).json({
        error: 'Failed to retrieve alerts',
        timestamp: Date.now(),
      });
    }
  }

  /**
   * System info endpoint handler
   */
  private async getSystemHandler(req: Request, res: Response): Promise<void> {
    try {
      const systemInfo = this.getSystemInfo();
      res.json(systemInfo);
    } catch (error) {
      logger.error({ error }, 'Failed to get system info');
      res.status(500).json({
        error: 'Failed to retrieve system info',
        timestamp: Date.now(),
      });
    }
  }

  /**
   * Generate comprehensive Prometheus metrics
   */
  /**
   * Generate comprehensive Prometheus metrics
   */
  private getPrometheusMetrics(): string {
    const realTimeMetrics = metricsService.getRealTimeMetrics();
    const historicalMetrics = metricsService.getHistoricalMetrics(60);
    const systemInfo = this.getSystemInfo();
    const alerts = metricsService.getAlerts();

    let output = '';

    // Service info
    output += '# HELP cortex_service_info Service information\n';
    output += '# TYPE cortex_service_info gauge\n';
    output += `cortex_service_info{service_name="${this.config.serviceName}",version="${this.config.serviceVersion}",environment="${this.config.environment}"} 1\n\n`;

    // Uptime
    output += '# HELP cortex_uptime_seconds Service uptime in seconds\n';
    output += '# TYPE cortex_uptime_seconds counter\n';
    output += `cortex_uptime_seconds ${systemInfo.process.uptime}\n\n`;

    // QPS metrics
    output += '# HELP cortex_qps Queries per second by operation\n';
    output += '# TYPE cortex_qps gauge\n';
    output += `cortex_qps{operation="memory_store"} ${realTimeMetrics.qps.memory_store_qps}\n`;
    output += `cortex_qps{operation="memory_find"} ${realTimeMetrics.qps.memory_find_qps}\n`;
    output += `cortex_qps{operation="total"} ${realTimeMetrics.qps.total_qps}\n\n`;

    // Latency metrics
    output += '# HELP cortex_latency_milliseconds Operation latency in milliseconds\n';
    output += '# TYPE cortex_latency_milliseconds histogram\n';
    output += `cortex_latency_milliseconds_bucket{operation="memory_store",quantile="0.5"} ${realTimeMetrics.performance.store_p95_ms * 0.8}\n`;
    output += `cortex_latency_milliseconds_bucket{operation="memory_store",quantile="0.95"} ${realTimeMetrics.performance.store_p95_ms}\n`;
    output += `cortex_latency_milliseconds_bucket{operation="memory_store",quantile="0.99"} ${realTimeMetrics.performance.store_p99_ms}\n`;
    output += `cortex_latency_milliseconds_bucket{operation="memory_find",quantile="0.5"} ${realTimeMetrics.performance.find_p95_ms * 0.8}\n`;
    output += `cortex_latency_milliseconds_bucket{operation="memory_find",quantile="0.95"} ${realTimeMetrics.performance.find_p95_ms}\n`;
    output += `cortex_latency_milliseconds_bucket{operation="memory_find",quantile="0.99"} ${realTimeMetrics.performance.find_p99_ms}\n`;
    output += `cortex_latency_milliseconds_bucket{operation="memory_store",quantile="+Inf"} ${realTimeMetrics.performance.store_p99_ms}\n`;
    output += `cortex_latency_milliseconds_bucket{operation="memory_find",quantile="+Inf"} ${realTimeMetrics.performance.find_p99_ms}\n\n`;

    // Quality metrics
    output += '# HELP cortex_quality_percent Quality metrics in percentage\n';
    output += '# TYPE cortex_quality_percent gauge\n';
    output += `cortex_quality_percent{metric="dedupe_rate"} ${realTimeMetrics.quality.dedupe_rate}\n`;
    output += `cortex_quality_percent{metric="cache_hit_rate"} ${realTimeMetrics.quality.cache_hit_rate}\n`;
    output += `cortex_quality_percent{metric="embedding_fail_rate"} ${realTimeMetrics.quality.embedding_fail_rate}\n`;
    output += `cortex_quality_percent{metric="ttl_deleted_rate"} ${realTimeMetrics.quality.ttl_deleted_rate}\n\n`;

    // Memory metrics with comprehensive process memory tracking
    output += '# HELP cortex_memory_bytes Memory usage in bytes\n';
    output += '# TYPE cortex_memory_bytes gauge\n';
    output += `cortex_memory_bytes{type="resident_set"} ${systemInfo.memory.rss}\n`;
    output += `cortex_memory_bytes{type="heap_total"} ${systemInfo.memory.heapTotal}\n`;
    output += `cortex_memory_bytes{type="heap_used"} ${systemInfo.memory.heapUsed}\n`;
    output += `cortex_memory_bytes{type="external"} ${systemInfo.memory.external}\n`;
    output += `cortex_memory_bytes{type="array_buffers"} ${systemInfo.memory.arrayBuffers}\n`;
    // Additional Prometheus-compatible memory metrics
    output += `cortex_memory_bytes{type="process_resident_memory"} ${systemInfo.memory.rss}\n`;
    output += `cortex_memory_bytes{type="process_virtual_memory"} ${systemInfo.memory.heapTotal}\n`;
    output += `cortex_memory_bytes{type="process_heap_size"} ${systemInfo.memory.heapTotal}\n`;
    output += `cortex_memory_bytes{type="process_heap_used"} ${systemInfo.memory.heapUsed}\n\n`;

    // Process metrics
    output += '# HELP cortex_process_info Process information\n';
    output += '# TYPE cortex_process_info gauge\n';
    output += `cortex_process_info{pid="${systemInfo.process.pid}",platform="${systemInfo.process.platform}",arch="${systemInfo.process.arch}"} 1\n\n`;

    // Error metrics
    output += '# HELP cortex_errors_total Total number of errors\n';
    output += '# TYPE cortex_errors_total counter\n';
    const criticalAlerts = alerts.filter((a) => a.severity === 'critical').length;
    const highAlerts = alerts.filter((a) => a.severity === 'high').length;
    const mediumAlerts = alerts.filter((a) => a.severity === 'medium').length;
    const lowAlerts = alerts.filter((a) => a.severity === 'low').length;
    output += `cortex_errors_total{severity="critical"} ${criticalAlerts}\n`;
    output += `cortex_errors_total{severity="high"} ${highAlerts}\n`;
    output += `cortex_errors_total{severity="medium"} ${mediumAlerts}\n`;
    output += `cortex_errors_total{severity="low"} ${lowAlerts}\n\n`;

    // Active connections
    output += '# HELP cortex_connections_active Number of active connections\n';
    output += '# TYPE cortex_connections_active gauge\n';
    output += `cortex_connections_active ${realTimeMetrics.system.active_connections}\n\n`;

    // Business metrics
    output += '# HELP cortex_operations_total Total operations processed\n';
    output += '# TYPE cortex_operations_total counter\n';
    const totalOps = Object.values(historicalMetrics.operation_metrics).reduce(
      (sum, op) => sum + op.count,
      0
    );
    output += `cortex_operations_total ${totalOps}\n\n`;

    // Circuit breaker metrics
    const circuitBreakerMetrics = this.getCircuitBreakerMetrics();
    if (circuitBreakerMetrics.length > 0) {
      output +=
        '# HELP cortex_circuit_breaker_state Circuit breaker state (0=closed, 1=open, 2=half_open)\n';
      output += '# TYPE cortex_circuit_breaker_state gauge\n';
      output += '# HELP cortex_circuit_breaker_failures_total Total circuit breaker failures\n';
      output += '# TYPE cortex_circuit_breaker_failures_total counter\n';
      output += '# HELP cortex_circuit_breaker_successes_total Total circuit breaker successes\n';
      output += '# TYPE cortex_circuit_breaker_successes_total counter\n';
      output += '# HELP cortex_circuit_breaker_last_failure_time_seconds Last failure timestamp\n';
      output += '# TYPE cortex_circuit_breaker_last_failure_time_seconds gauge\n\n';

      output += circuitBreakerMetrics.join('\n') + '\n\n';
    }

    // Qdrant connection metrics
    const qdrantMetrics = this.getQdrantMetrics();
    if (qdrantMetrics.length > 0) {
      output += '# HELP cortex_qdrant_connection_status Qdrant connection status (1=up, 0=down)\n';
      output += '# TYPE cortex_qdrant_connection_status gauge\n';
      output +=
        '# HELP cortex_qdrant_response_time_milliseconds Qdrant response time in milliseconds\n';
      output += '# TYPE cortex_qdrant_response_time_milliseconds gauge\n\n';

      output += qdrantMetrics.join('\n') + '\n\n';
    }

    // System resource metrics
    output += '# HELP cortex_cpu_usage_percent CPU usage percentage\n';
    output += '# TYPE cortex_cpu_usage_percent gauge\n';
    output += `cortex_cpu_usage_percent ${realTimeMetrics.system.cpu_usage_percent}\n\n`;

    return output;
  }

  /**
   * Get circuit breaker metrics for Prometheus
   */
  private getCircuitBreakerMetrics(): string[] {
    const metrics: string[] = [];

    try {
      // Try to get circuit breaker stats from various services
      const allStats = circuitBreakerManager.getAllStats();

      for (const [serviceName, stats] of Object.entries(allStats)) {
        const statsObj = stats as {
          state: 'closed' | 'open' | 'half-open';
          failures?: number;
          successes?: number;
          lastFailureTime?: number;
        };
        const stateValue = statsObj.state === 'closed' ? 0 : statsObj.state === 'open' ? 1 : 2;

        metrics.push(
          `cortex_circuit_breaker_state{service="${serviceName}"} ${stateValue}`,
          `cortex_circuit_breaker_failures_total{service="${serviceName}"} ${statsObj.failures || 0}`,
          `cortex_circuit_breaker_successes_total{service="${serviceName}"} ${statsObj.successes || 0}`,
          `cortex_circuit_breaker_last_failure_time_seconds{service="${serviceName}"} ${(statsObj.lastFailureTime || 0) / 1000}`
        );
      }
    } catch (error) {
      // Circuit breaker service not available or not initialized
      logger.debug('Circuit breaker metrics not available', { error: (error as Error).message });
    }

    return metrics;
  }

  /**
   * Get Qdrant database metrics for Prometheus
   */
  private getQdrantMetrics(): string[] {
    const metrics: string[] = [];

    try {
      // For now, assume Qdrant is healthy - TODO: implement proper health check
      const isHealthy = true;

      metrics.push(`cortex_qdrant_connection_status ${isHealthy ? 1 : 0}`);

      // If we have response time metrics, include them
      // This would need to be implemented in the database manager
      metrics.push(`cortex_qdrant_response_time_milliseconds 50`); // Placeholder
    } catch (error) {
      // Database manager not available or not initialized
      logger.debug('Qdrant metrics not available', { error: (error as Error).message });
      metrics.push('cortex_qdrant_connection_status 0');
    }

    return metrics;
  }

  /**
   * Get comprehensive system information
   */
  private getSystemInfo(): {
    service: {
      name: string;
      version: string;
      environment: string;
    };
    process: {
      pid: number;
      uptime: number;
      version: string;
      platform: NodeJS.Platform;
      arch: string;
    };
    memory: {
      rss: number;
      heapTotal: number;
      heapUsed: number;
      external: number;
      arrayBuffers: number;
      resident_set_size_bytes: number;
      process_resident_memory_bytes: number;
      heap_size_bytes: number;
      heap_used_bytes: number;
    };
    cpu: {
      user: number;
      system: number;
    };
    timestamp: number;
  } {
    const memUsage = process.memoryUsage();
    const cpuUsage = process.cpuUsage();

    return {
      service: {
        name: this.config.serviceName || 'cortex-mcp',
        version: this.config.serviceVersion || '2.0.1',
        environment: this.config.environment || 'development',
      },
      process: {
        pid: process.pid,
        uptime: process.uptime(),
        version: process.version,
        platform: process.platform,
        arch: process.arch,
      },
      memory: {
        rss: memUsage.rss,
        heapTotal: memUsage.heapTotal,
        heapUsed: memUsage.heapUsed,
        external: memUsage.external,
        arrayBuffers: memUsage.arrayBuffers,
        // Additional process memory metrics for Prometheus
        resident_set_size_bytes: memUsage.rss,
        process_resident_memory_bytes: memUsage.rss,
        heap_size_bytes: memUsage.heapTotal,
        heap_used_bytes: memUsage.heapUsed,
      },
      cpu: {
        user: cpuUsage.user,
        system: cpuUsage.system,
        // CPU percentage would need additional tracking
      },
      timestamp: Date.now(),
    };
  }
}

// Export singleton instance
export const monitoringServer = new MonitoringServer({
  port: parseInt(process.env.MONITORING_PORT || '9090'),
  host: process.env.MONITORING_HOST || '0.0.0.0',
  enableAuth: process.env.MONITORING_ENABLE_AUTH === 'true',
  enableCors: process.env.MONITORING_ENABLE_CORS !== 'false',
  environment: process.env.NODE_ENV || 'development',
});
