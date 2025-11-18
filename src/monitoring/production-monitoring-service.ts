/**
 * Production Monitoring Service
 *
 * Comprehensive monitoring and observability service for production environments.
 * Integrates health checks, metrics collection, performance monitoring, and alerting.
 * Provides real-time insights into system health and performance.
 *
 * @author Cortex Team
 * @version 2.0.1
 */

import * as os from 'os';

import { EventEmitter } from 'events';

import { createChildLogger, type SimpleLogger } from '@/utils/logger.js';

import { ProductionHealthChecker } from './production-health-checker.js';

export interface MonitoringMetrics {
  system: {
    uptime: number;
    loadAverage: number[];
    memoryUsage: NodeJS.MemoryUsage;
    cpuUsage: NodeJS.CpuUsage;
    freeMemory: number;
    totalMemory: number;
  };
  application: {
    startTime: number;
    requestCount: number;
    errorCount: number;
    activeConnections: number;
    responseTime: {
      avg: number;
      p50: number;
      p95: number;
      p99: number;
    };
    throughput: number;
  };
  database: {
    connectionPool: {
      active: number;
      idle: number;
      total: number;
    };
    queryPerformance: {
      avgTime: number;
      slowQueries: number;
      totalQueries: number;
    };
  };
  health: {
    lastCheck: string;
    status: 'healthy' | 'degraded' | 'unhealthy';
    checks: Array<{
      name: string;
      status: string;
      duration: number;
    }>;
  };
}

export interface MonitoringConfig {
  enabled: boolean;
  intervalMs: number;
  healthCheckIntervalMs: number;
  metricsRetentionMs: number;
  alertThresholds: {
    errorRate: number;
    responseTime: number;
    memoryUsage: number;
    cpuUsage: number;
    diskUsage: number;
  };
  enablePerformanceMonitoring: boolean;
  enableHealthChecks: boolean;
  enableAlerting: boolean;
}

export interface Alert {
  id: string;
  type: 'error' | 'warning' | 'critical';
  source: string;
  message: string;
  timestamp: string;
  metadata: Record<string, unknown>;
  acknowledged: boolean;
  resolved: boolean;
}

export class ProductionMonitoringService extends EventEmitter {
  private config: MonitoringConfig;
  private logger: SimpleLogger;
  private healthChecker: ProductionHealthChecker;
  private metrics: MonitoringMetrics;
  private metricsHistory: MonitoringMetrics[] = [];
  private alerts: Map<string, Alert> = new Map();
  private intervals: NodeJS.Timeout[] = [];
  private requestMetrics: Array<{ duration: number; timestamp: number }> = [];
  private isRunning = false;

  constructor(config?: Partial<MonitoringConfig>) {
    super();

    this.logger = createChildLogger({ component: 'production-monitoring' });
    this.healthChecker = new ProductionHealthChecker();

    this.config = {
      enabled: true,
      intervalMs: parseInt(process.env.MONITORING_INTERVAL_MS || '30000'),
      healthCheckIntervalMs: parseInt(process.env.HEALTH_CHECK_INTERVAL_MS || '60000'),
      metricsRetentionMs: parseInt(process.env.METRICS_RETENTION_MS || '3600000'),
      alertThresholds: {
        errorRate: parseFloat(process.env.ALERT_ERROR_RATE_THRESHOLD || '0.05'),
        responseTime: parseFloat(process.env.ALERT_RESPONSE_TIME_THRESHOLD || '5000'),
        memoryUsage: parseFloat(process.env.ALERT_MEMORY_USAGE_THRESHOLD || '0.85'),
        cpuUsage: parseFloat(process.env.ALERT_CPU_USAGE_THRESHOLD || '0.80'),
        diskUsage: parseFloat(process.env.ALERT_DISK_USAGE_THRESHOLD || '0.90'),
      },
      enablePerformanceMonitoring: process.env.ENABLE_PERFORMANCE_MONITORING === 'true',
      enableHealthChecks: process.env.ENABLE_HEALTH_CHECKS === 'true',
      enableAlerting: process.env.ENABLE_ALERTING === 'true',
      ...config,
    };

    this.initializeMetrics();
  }

  /**
   * Initialize metrics collection
   */
  private initializeMetrics(): void {
    const now = Date.now();
    this.metrics = {
      system: {
        uptime: 0,
        loadAverage: os.loadavg(),
        memoryUsage: process.memoryUsage(),
        cpuUsage: process.cpuUsage(),
        freeMemory: os.freemem(),
        totalMemory: os.totalmem(),
      },
      application: {
        startTime: now,
        requestCount: 0,
        errorCount: 0,
        activeConnections: 0,
        responseTime: {
          avg: 0,
          p50: 0,
          p95: 0,
          p99: 0,
        },
        throughput: 0,
      },
      database: {
        connectionPool: {
          active: 0,
          idle: 0,
          total: 0,
        },
        queryPerformance: {
          avgTime: 0,
          slowQueries: 0,
          totalQueries: 0,
        },
      },
      health: {
        lastCheck: new Date().toISOString(),
        status: 'healthy',
        checks: [],
      },
    };
  }

  /**
   * Start the monitoring service
   */
  async start(): Promise<void> {
    if (this.isRunning) {
      this.logger.warn({ message: 'Monitoring service is already running' });
      return;
    }

    this.logger.info({ message: 'Starting production monitoring service' });

    try {
      // Start metrics collection
      if (this.config.enabled) {
        const metricsInterval = setInterval(() => {
          this.collectMetrics();
        }, this.config.intervalMs);
        this.intervals.push(metricsInterval);
      }

      // Start health checks
      if (this.config.enableHealthChecks) {
        const healthCheckInterval = setInterval(async () => {
          await this.performHealthChecks();
        }, this.config.healthCheckIntervalMs);
        this.intervals.push(healthCheckInterval);

        // Perform initial health check
        await this.performHealthChecks();
      }

      // Start metrics cleanup
      const cleanupInterval = setInterval(() => {
        this.cleanupOldMetrics();
      }, this.config.metricsRetentionMs / 2);
      this.intervals.push(cleanupInterval);

      this.isRunning = true;
      this.logger.info({
        message: 'Production monitoring service started successfully',
        metricsInterval: this.config.intervalMs,
        healthCheckInterval: this.config.healthCheckIntervalMs,
        alertingEnabled: this.config.enableAlerting,
      });

      this.emit('started');
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      this.logger.error({ error: errorMsg }, 'Failed to start monitoring service');
      throw error;
    }
  }

  /**
   * Stop the monitoring service
   */
  async stop(): Promise<void> {
    if (!this.isRunning) {
      return;
    }

    this.logger.info({ message: 'Stopping production monitoring service' });

    // Clear all intervals
    this.intervals.forEach((interval) => clearInterval(interval));
    this.intervals = [];

    this.isRunning = false;
    this.logger.info({ message: 'Production monitoring service stopped' });

    this.emit('stopped');
  }

  /**
   * Collect system and application metrics
   */
  private collectMetrics(): void {
    try {
      // Update system metrics
      this.metrics.system = {
        uptime: process.uptime(),
        loadAverage: os.loadavg(),
        memoryUsage: process.memoryUsage(),
        cpuUsage: process.cpuUsage(),
        freeMemory: os.freemem(),
        totalMemory: os.totalmem(),
      };

      // Update application metrics
      this.metrics.application.throughput = this.calculateThroughput();
      this.metrics.application.responseTime = this.calculateResponseTimePercentiles();

      // Store metrics in history
      this.metricsHistory.push({ ...this.metrics });

      // Check for alerts
      if (this.config.enableAlerting) {
        this.checkAlertThresholds();
      }

      // Emit metrics update
      this.emit('metrics', this.metrics);
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      this.logger.error({ error: errorMsg }, 'Error collecting metrics');
    }
  }

  /**
   * Perform health checks
   */
  private async performHealthChecks(): Promise<void> {
    try {
      const healthResult = await this.healthChecker.performPostStartupHealthCheck();

      this.metrics.health = {
        lastCheck: new Date().toISOString(),
        status: healthResult.status,
        checks: healthResult.checks.map((check) => ({
          name: check.name,
          status: check.status,
          duration: check.duration,
        })),
      };

      // Check for health-related alerts
      if (healthResult.status === 'unhealthy') {
        this.createAlert('critical', 'health-check', 'System health check failed', {
          issues: healthResult.issues,
        });
      } else if (healthResult.status === 'degraded') {
        this.createAlert(
          'warning',
          'health-check',
          'System health check indicates degraded performance',
          { issues: healthResult.issues }
        );
      }

      this.emit('health-check', healthResult);
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      this.logger.error({ error: errorMsg }, 'Error performing health checks');

      this.createAlert('critical', 'health-check', 'Health check system error', {
        error: errorMsg,
      });
    }
  }

  /**
   * Record a request for performance metrics
   */
  recordRequest(duration: number, error: boolean = false): void {
    if (!this.config.enablePerformanceMonitoring) {
      return;
    }

    // Update counters
    this.metrics.application.requestCount++;
    if (error) {
      this.metrics.application.errorCount++;
    }

    // Store request duration for percentile calculations
    this.requestMetrics.push({
      duration,
      timestamp: Date.now(),
    });

    // Clean old request metrics (keep only last 10,000)
    if (this.requestMetrics.length > 10000) {
      this.requestMetrics = this.requestMetrics.slice(-5000);
    }

    // Check for performance alerts
    if (this.config.enableAlerting && duration > this.config.alertThresholds.responseTime) {
      this.createAlert('warning', 'performance', `Slow request detected: ${duration}ms`, {
        duration,
        threshold: this.config.alertThresholds.responseTime,
      });
    }
  }

  /**
   * Update database metrics
   */
  updateDatabaseMetrics(metrics: {
    connectionPool?: { active: number; idle: number; total: number };
    queryPerformance?: { avgTime: number; slowQueries: number; totalQueries: number };
  }): void {
    if (metrics.connectionPool) {
      this.metrics.database.connectionPool = {
        ...this.metrics.database.connectionPool,
        ...metrics.connectionPool,
      };
    }

    if (metrics.queryPerformance) {
      this.metrics.database.queryPerformance = {
        ...this.metrics.database.queryPerformance,
        ...metrics.queryPerformance,
      };
    }
  }

  /**
   * Update active connections count
   */
  updateActiveConnections(count: number): void {
    this.metrics.application.activeConnections = count;
  }

  /**
   * Calculate throughput (requests per second)
   */
  private calculateThroughput(): number {
    const timeWindow = 60000; // 1 minute
    const now = Date.now();
    const recentRequests = this.requestMetrics.filter(
      (metric) => now - metric.timestamp < timeWindow
    );

    return (recentRequests.length / timeWindow) * 1000;
  }

  /**
   * Calculate response time percentiles
   */
  private calculateResponseTimePercentiles(): {
    avg: number;
    p50: number;
    p95: number;
    p99: number;
  } {
    if (this.requestMetrics.length === 0) {
      return { avg: 0, p50: 0, p95: 0, p99: 0 };
    }

    const durations = this.requestMetrics.map((m) => m.duration).sort((a, b) => a - b);
    const len = durations.length;

    return {
      avg: durations.reduce((sum, d) => sum + d, 0) / len,
      p50: durations[Math.floor(len * 0.5)],
      p95: durations[Math.floor(len * 0.95)],
      p99: durations[Math.floor(len * 0.99)],
    };
  }

  /**
   * Check alert thresholds
   */
  private checkAlertThresholds(): void {
    const memUsage = this.metrics.system.memoryUsage;
    const totalMem = this.metrics.system.totalMemory;
    const memUsagePercent = memUsage.heapUsed / totalMem;

    if (memUsagePercent > this.config.alertThresholds.memoryUsage) {
      this.createAlert(
        'warning',
        'memory',
        `High memory usage: ${(memUsagePercent * 100).toFixed(1)}%`,
        {
          used: memUsage.heapUsed,
          total: totalMem,
          threshold: this.config.alertThresholds.memoryUsage,
        }
      );
    }

    const loadAvg = this.metrics.system.loadAverage[0];
    const cpuCount = os.cpus().length;
    const loadPercent = (loadAvg / cpuCount) * 100;

    if (loadPercent > this.config.alertThresholds.cpuUsage * 100) {
      this.createAlert('warning', 'cpu', `High CPU usage: ${loadPercent.toFixed(1)}%`, {
        loadAverage: loadAvg,
        cpuCount,
        threshold: this.config.alertThresholds.cpuUsage,
      });
    }

    const errorRate =
      this.metrics.application.errorCount / Math.max(this.metrics.application.requestCount, 1);
    if (errorRate > this.config.alertThresholds.errorRate) {
      this.createAlert('error', 'error-rate', `High error rate: ${(errorRate * 100).toFixed(2)}%`, {
        errorCount: this.metrics.application.errorCount,
        requestCount: this.metrics.application.requestCount,
        threshold: this.config.alertThresholds.errorRate,
      });
    }
  }

  /**
   * Create an alert
   */
  private createAlert(
    type: 'error' | 'warning' | 'critical',
    source: string,
    message: string,
    metadata: Record<string, unknown> = {}
  ): void {
    const id = `${source}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const alert: Alert = {
      id,
      type,
      source,
      message,
      timestamp: new Date().toISOString(),
      metadata,
      acknowledged: false,
      resolved: false,
    };

    this.alerts.set(id, alert);
    this.logger.warn({ message: `Alert created: ${message}`, id, type, source });

    this.emit('alert', alert);
  }

  /**
   * Clean up old metrics
   */
  private cleanupOldMetrics(): void {
    const cutoffTime = Date.now() - this.config.metricsRetentionMs;
    this.metricsHistory = this.metricsHistory.filter(
      (metrics) => metrics.application.startTime > cutoffTime
    );

    // Clean old request metrics
    this.requestMetrics = this.requestMetrics.filter((metric) => metric.timestamp > cutoffTime);

    // Clean old resolved alerts
    const resolvedAlertCutoff = Date.now() - this.config.metricsRetentionMs * 2;
    for (const [id, alert] of this.alerts.entries()) {
      if (alert.resolved && new Date(alert.timestamp).getTime() < resolvedAlertCutoff) {
        this.alerts.delete(id);
      }
    }
  }

  /**
   * Get current metrics
   */
  getMetrics(): MonitoringMetrics {
    return { ...this.metrics };
  }

  /**
   * Get metrics history
   */
  getMetricsHistory(limit?: number): MonitoringMetrics[] {
    if (limit) {
      return this.metricsHistory.slice(-limit);
    }
    return [...this.metricsHistory];
  }

  /**
   * Get active alerts
   */
  getActiveAlerts(): Alert[] {
    return Array.from(this.alerts.values()).filter((alert) => !alert.resolved);
  }

  /**
   * Get all alerts
   */
  getAllAlerts(): Alert[] {
    return Array.from(this.alerts.values());
  }

  /**
   * Acknowledge an alert
   */
  acknowledgeAlert(alertId: string): boolean {
    const alert = this.alerts.get(alertId);
    if (alert) {
      alert.acknowledged = true;
      this.logger.info({ message: `Alert acknowledged: ${alertId}`, alertId });
      this.emit('alert-acknowledged', alert);
      return true;
    }
    return false;
  }

  /**
   * Resolve an alert
   */
  resolveAlert(alertId: string): boolean {
    const alert = this.alerts.get(alertId);
    if (alert) {
      alert.resolved = true;
      this.logger.info({ message: `Alert resolved: ${alertId}`, alertId });
      this.emit('alert-resolved', alert);
      return true;
    }
    return false;
  }

  /**
   * Get monitoring status
   */
  getStatus(): {
    isRunning: boolean;
    uptime: number;
    metricsCollected: number;
    activeAlerts: number;
    lastHealthCheck: string;
  } {
    return {
      isRunning: this.isRunning,
      uptime: this.isRunning ? Date.now() - this.metrics.application.startTime : 0,
      metricsCollected: this.metricsHistory.length,
      activeAlerts: this.getActiveAlerts().length,
      lastHealthCheck: this.metrics.health.lastCheck,
    };
  }

  /**
   * Generate monitoring report
   */
  generateReport(): {
    summary: {
      uptime: number;
      totalRequests: number;
      errorRate: number;
      avgResponseTime: number;
      activeAlerts: number;
    };
    system: MonitoringMetrics['system'];
    application: MonitoringMetrics['application'];
    health: MonitoringMetrics['health'];
    alerts: Alert[];
  } {
    const activeAlerts = this.getActiveAlerts();
    const errorRate =
      this.metrics.application.errorCount / Math.max(this.metrics.application.requestCount, 1);

    return {
      summary: {
        uptime: Date.now() - this.metrics.application.startTime,
        totalRequests: this.metrics.application.requestCount,
        errorRate,
        avgResponseTime: this.metrics.application.responseTime.avg,
        activeAlerts: activeAlerts.length,
      },
      system: this.metrics.system,
      application: this.metrics.application,
      health: this.metrics.health,
      alerts: activeAlerts,
    };
  }
}

export default ProductionMonitoringService;
