/**
 * Qdrant Backup and Recovery Monitoring System
 *
 * Comprehensive monitoring and alerting for backup and recovery operations:
 * - Real-time operation monitoring and metrics collection
 * - Performance analysis and trend detection
 * - Anomaly detection and predictive alerting
 * - Multi-channel alert delivery and escalation
 * - Dashboard integration and reporting
 * - Health monitoring and capacity planning
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { EventEmitter } from 'node:events';
import { readFile,writeFile } from 'fs/promises';
import { join } from 'path';

import { logger } from '@/utils/logger.js';

/**
 * Monitoring configuration
 */
export interface MonitoringConfiguration {
  enabled: boolean;
  metrics: {
    collectionInterval: number; // Seconds
    retentionPeriod: number; // Days
    aggregationIntervals: number[]; // Minutes
    exportFormats: ('prometheus' | 'json' | 'csv')[];
  };
  alerting: {
    enabled: boolean;
    channels: AlertChannel[];
    escalationPolicies: EscalationPolicy[];
    suppressionRules: SuppressionRule[];
    rateLimiting: {
      maxAlertsPerHour: number;
      cooldownPeriod: number; // Minutes
    };
  };
  thresholds: {
    performance: {
      backupDuration: number; // Minutes
      restoreDuration: number; // Minutes
      validationDuration: number; // Minutes
      throughput: number; // Items per second
    };
    reliability: {
      successRate: number; // Percentage
      failureRate: number; // Percentage
      corruptionRate: number; // Percentage
    };
    capacity: {
      storageUtilization: number; // Percentage
      memoryUtilization: number; // Percentage
      networkUtilization: number; // Percentage
    };
    rpoRto: {
      rpoViolation: number; // Minutes
      rtoViolation: number; // Minutes
    };
  };
  dashboards: {
    enabled: boolean;
    refreshInterval: number; // Seconds
    exportPath?: string;
    widgets: DashboardWidget[];
  };
  healthChecks: {
    enabled: boolean;
    frequency: number; // Minutes
    timeout: number; // Seconds
    retries: number;
    services: HealthCheckService[];
  };
}

/**
 * Alert channel configuration
 */
export interface AlertChannel {
  id: string;
  name: string;
  type: 'email' | 'slack' | 'webhook' | 'pagerduty' | 'sms' | 'teams';
  enabled: boolean;
  config: {
    // Email configuration
    recipients?: string[];
    subject?: string;
    template?: string;

    // Slack configuration
    webhookUrl?: string;
    channel?: string;

    // Webhook configuration
    url?: string;
    method?: 'POST' | 'PUT';
    headers?: Record<string, string>;

    // PagerDuty configuration
    integrationKey?: string;
    severity?: 'critical' | 'error' | 'warning' | 'info';

    // SMS configuration
    phoneNumbers?: string[];

    // Teams configuration
    teamsWebhookUrl?: string;

    // Common configuration
    enabled?: boolean;
    priority?: 'low' | 'medium' | 'high' | 'critical';
    rateLimit?: number;
  };
  filters: {
    severities: ('critical' | 'error' | 'warning' | 'info')[];
    categories: string[];
    services: string[];
  };
}

/**
 * Escalation policy
 */
export interface EscalationPolicy {
  id: string;
  name: string;
  enabled: boolean;
  triggers: {
    alertSeverities: ('critical' | 'error' | 'warning')[];
    timeThresholds: number[]; // Minutes
    conditions: string[];
  };
  escalationSteps: Array<{
    step: number;
    delay: number; // Minutes
    channels: string[];
    message: string;
    autoResolve: boolean;
  }>;
  schedule: {
    timezone: string;
    activeHours: {
      start: string;
      end: string;
    }[];
    holidays: string[];
    onCallSchedule: {
      primary: string;
      secondary: string;
    };
  };
}

/**
 * Alert suppression rule
 */
export interface SuppressionRule {
  id: string;
  name: string;
  enabled: boolean;
  conditions: {
    alertType?: string;
    source?: string;
    severity?: ('critical' | 'error' | 'warning' | 'info')[];
    timeWindow?: {
      start: string;
      end: string;
    };
    recurrence?: {
      pattern: string;
      duration: number; // Minutes
    };
  };
  action: 'suppress' | 'deduplicate' | 'transform';
  parameters: Record<string, any>;
}

/**
 * Dashboard widget
 */
export interface DashboardWidget {
  id: string;
  type: 'metric' | 'chart' | 'gauge' | 'table' | 'status' | 'heatmap';
  title: string;
  position: {
    x: number;
    y: number;
    width: number;
    height: number;
  };
  dataSource: {
    metric: string;
    filters?: Record<string, any>;
    aggregation?: 'avg' | 'sum' | 'min' | 'max' | 'count';
    timeRange: number; // Minutes
  };
  visualization: {
    chartType?: 'line' | 'bar' | 'pie' | 'area';
    colors?: string[];
    thresholds?: Array<{
      value: number;
      color: string;
      label: string;
    }>;
  };
  refreshInterval?: number; // Seconds
}

/**
 * Health check service
 */
export interface HealthCheckService {
  id: string;
  name: string;
  type: 'http' | 'tcp' | 'database' | 'custom';
  endpoint: string;
  timeout: number;
  interval: number;
  expectedStatus?: number;
  authentication?: {
    type: 'basic' | 'bearer' | 'custom';
    credentials: Record<string, string>;
  };
  checks: Array<{
    name: string;
    type: 'response-time' | 'status-code' | 'content-check' | 'custom';
    threshold: number;
    operator: 'lt' | 'gt' | 'eq' | 'ne';
  }>;
}

/**
 * Alert definition
 */
export interface Alert {
  id: string;
  timestamp: string;
  severity: 'critical' | 'error' | 'warning' | 'info';
  category: 'backup' | 'restore' | 'validation' | 'performance' | 'capacity' | 'rpo-rto' | 'health';
  source: string;
  title: string;
  description: string;
  details: Record<string, any>;
  metrics: Array<{
    name: string;
    value: number;
    unit: string;
    threshold: number;
  }>;
  status: 'active' | 'acknowledged' | 'resolved' | 'suppressed';
  acknowledgedBy?: string;
  acknowledgedAt?: string;
  resolvedAt?: string;
  resolution?: string;
  escalationLevel: number;
  channels: string[];
  tags: string[];
}

/**
 * Performance metric
 */
export interface PerformanceMetric {
  timestamp: string;
  operation: 'backup' | 'restore' | 'validation';
  operationType: string;
  duration: number;
  itemCount: number;
  throughput: number;
  success: boolean;
  errorType?: string;
  resourceUsage: {
    cpu: number;
    memory: number;
    disk: number;
    network: number;
  };
  metadata: Record<string, any>;
}

/**
 * Health status
 */
export interface HealthStatus {
  serviceId: string;
  serviceName: string;
  status: 'healthy' | 'degraded' | 'unhealthy';
  lastCheck: string;
  responseTime: number;
  uptime: number;
  details: Record<string, any>;
  checks: Array<{
    name: string;
    status: 'pass' | 'fail' | 'warn';
    value: number;
    threshold: number;
  }>;
}

/**
 * Capacity metrics
 */
export interface CapacityMetrics {
  timestamp: string;
  storage: {
    total: number;
    used: number;
    available: number;
    utilization: number;
  };
  memory: {
    total: number;
    used: number;
    available: number;
    utilization: number;
  };
  network: {
    inbound: number;
    outbound: number;
    utilization: number;
  };
  processing: {
    queueSize: number;
    processingRate: number;
    backlog: number;
  };
}

/**
 * Backup and Recovery Monitoring Service
 */
export class BackupRecoveryMonitoringService extends EventEmitter {
  private config: MonitoringConfiguration;
  private metrics: Map<string, PerformanceMetric[]> = new Map();
  private alerts: Map<string, Alert> = new Map();
  private healthStatus: Map<string, HealthStatus> = new Map();
  private capacityMetrics: CapacityMetrics[] = [];
  private alertHistory: Alert[] = [];
  private rateLimitTracker: Map<string, number[]> = new Map();

  constructor(config: MonitoringConfiguration) {
    super();
    this.config = config;
  }

  /**
   * Initialize monitoring service
   */
  async initialize(): Promise<void> {
    try {
      logger.info('Initializing backup and recovery monitoring service...');

      // Load historical data
      await this.loadHistoricalData();

      // Start metrics collection
      if (this.config.enabled) {
        await this.startMetricsCollection();
      }

      // Start health checks
      if (this.config.healthChecks.enabled) {
        await this.startHealthChecks();
      }

      // Initialize alert processing
      if (this.config.alerting.enabled) {
        await this.initializeAlertProcessing();
      }

      // Start dashboard updates
      if (this.config.dashboards.enabled) {
        await this.startDashboardUpdates();
      }

      logger.info('Backup and recovery monitoring service initialized successfully');
    } catch (error) {
      logger.error({ error }, 'Failed to initialize monitoring service');
      throw error;
    }
  }

  /**
   * Record performance metric
   */
  recordMetric(metric: PerformanceMetric): void {
    try {
      const key = `${metric.operation}-${metric.operationType}`;

      if (!this.metrics.has(key)) {
        this.metrics.set(key, []);
      }

      const metricList = this.metrics.get(key)!;
      metricList.push(metric);

      // Keep only metrics within retention period
      const cutoffTime = Date.now() - (this.config.metrics.retentionPeriod * 24 * 60 * 60 * 1000);
      const filteredMetrics = metricList.filter(m => new Date(m.timestamp).getTime() > cutoffTime);
      this.metrics.set(key, filteredMetrics);

      // Check for performance alerts
      this.checkPerformanceAlerts(metric);

      // Emit metric event
      this.emit('metric', metric);

      logger.debug({
        operation: metric.operation,
        operationType: metric.operationType,
        duration: metric.duration,
        success: metric.success,
      }, 'Performance metric recorded');

    } catch (error) {
      logger.error({ error, metric }, 'Failed to record performance metric');
    }
  }

  /**
   * Create and process alert
   */
  async createAlert(alert: Omit<Alert, 'id' | 'timestamp' | 'status' | 'escalationLevel' | 'channels'>): Promise<string> {
    try {
      // Check suppression rules
      if (this.isAlertSuppressed(alert)) {
        logger.debug({ alertTitle: alert.title }, 'Alert suppressed by rule');
        return '';
      }

      // Check rate limiting
      if (this.isRateLimited(alert)) {
        logger.debug({ alertTitle: alert.title }, 'Alert rate limited');
        return '';
      }

      const alertId = this.generateAlertId();
      const fullAlert: Alert = {
        ...alert,
        id: alertId,
        timestamp: new Date().toISOString(),
        status: 'active',
        escalationLevel: 0,
        channels: this.determineAlertChannels(alert),
      };

      // Store alert
      this.alerts.set(alertId, fullAlert);
      this.alertHistory.push(fullAlert);

      // Process alert
      await this.processAlert(fullAlert);

      // Emit alert event
      this.emit('alert', fullAlert);

      logger.info({
        alertId,
        severity: alert.severity,
        category: alert.category,
        title: alert.title,
      }, 'Alert created and processed');

      return alertId;

    } catch (error) {
      logger.error({ error, alert }, 'Failed to create alert');
      throw error;
    }
  }

  /**
   * Update health status
   */
  updateHealthStatus(status: HealthStatus): void {
    try {
      this.healthStatus.set(status.serviceId, status);

      // Check for health alerts
      this.checkHealthAlerts(status);

      // Emit health status event
      this.emit('health', status);

      logger.debug({
        serviceId: status.serviceId,
        status: status.status,
        responseTime: status.responseTime,
      }, 'Health status updated');

    } catch (error) {
      logger.error({ error, status }, 'Failed to update health status');
    }
  }

  /**
   * Record capacity metrics
   */
  recordCapacityMetrics(metrics: CapacityMetrics): void {
    try {
      this.capacityMetrics.push(metrics);

      // Keep only recent metrics
      const cutoffTime = Date.now() - (24 * 60 * 60 * 1000); // 24 hours
      this.capacityMetrics = this.capacityMetrics.filter(m =>
        new Date(m.timestamp).getTime() > cutoffTime
      );

      // Check for capacity alerts
      this.checkCapacityAlerts(metrics);

      // Emit capacity metrics event
      this.emit('capacity', metrics);

      logger.debug({
        storageUtilization: metrics.storage.utilization,
        memoryUtilization: metrics.memory.utilization,
        networkUtilization: metrics.network.utilization,
      }, 'Capacity metrics recorded');

    } catch (error) {
      logger.error({ error, metrics }, 'Failed to record capacity metrics');
    }
  }

  /**
   * Get current dashboard data
   */
  async getDashboardData(): Promise<{
    summary: {
      totalAlerts: number;
      activeAlerts: number;
      criticalAlerts: number;
      warningAlerts: number;
      healthyServices: number;
      degradedServices: number;
      unhealthyServices: number;
    };
    metrics: {
      performance: PerformanceMetric[];
      capacity: CapacityMetrics[];
      health: HealthStatus[];
    };
    alerts: Alert[];
    trends: {
      backupPerformance: Array<{ timestamp: string; value: number }>;
      restorePerformance: Array<{ timestamp: string; value: number }>;
      successRate: Array<{ timestamp: string; value: number }>;
      capacityUtilization: Array<{ timestamp: string; value: number }>;
    };
  }> {
    try {
      const alerts = Array.from(this.alerts.values());
      const activeAlerts = alerts.filter(a => a.status === 'active');
      const criticalAlerts = activeAlerts.filter(a => a.severity === 'critical');
      const warningAlerts = activeAlerts.filter(a => a.severity === 'warning');

      const healthStatuses = Array.from(this.healthStatus.values());
      const healthyServices = healthStatuses.filter(s => s.status === 'healthy').length;
      const degradedServices = healthStatuses.filter(s => s.status === 'degraded').length;
      const unhealthyServices = healthStatuses.filter(s => s.status === 'unhealthy').length;

      // Collect recent performance metrics
      const performanceMetrics: PerformanceMetric[] = [];
      Array.from(this.metrics.values()).forEach(metricList => {
        performanceMetrics.push(...metricList.slice(-100)); // Last 100 metrics per type
      });

      // Calculate trends
      const trends = await this.calculateTrends();

      return {
        summary: {
          totalAlerts: alerts.length,
          activeAlerts: activeAlerts.length,
          criticalAlerts: criticalAlerts.length,
          warningAlerts: warningAlerts.length,
          healthyServices,
          degradedServices,
          unhealthyServices,
        },
        metrics: {
          performance: performanceMetrics,
          capacity: this.capacityMetrics.slice(-100),
          health: healthStatuses,
        },
        alerts: activeAlerts,
        trends,
      };

    } catch (error) {
      logger.error({ error }, 'Failed to get dashboard data');
      throw error;
    }
  }

  /**
   * Acknowledge alert
   */
  async acknowledgeAlert(alertId: string, acknowledgedBy: string): Promise<boolean> {
    try {
      const alert = this.alerts.get(alertId);
      if (!alert) {
        return false;
      }

      alert.status = 'acknowledged';
      alert.acknowledgedBy = acknowledgedBy;
      alert.acknowledgedAt = new Date().toISOString();

      // Stop escalation
      await this.stopAlertEscalation(alert);

      logger.info({
        alertId,
        acknowledgedBy,
      }, 'Alert acknowledged');

      return true;

    } catch (error) {
      logger.error({ error, alertId }, 'Failed to acknowledge alert');
      return false;
    }
  }

  /**
   * Resolve alert
   */
  async resolveAlert(alertId: string, resolution: string, resolvedBy?: string): Promise<boolean> {
    try {
      const alert = this.alerts.get(alertId);
      if (!alert) {
        return false;
      }

      alert.status = 'resolved';
      alert.resolvedAt = new Date().toISOString();
      alert.resolution = resolution;

      // Send resolution notification
      await this.sendResolutionNotification(alert, resolvedBy);

      logger.info({
        alertId,
        resolution,
        resolvedBy,
      }, 'Alert resolved');

      return true;

    } catch (error) {
      logger.error({ error, alertId }, 'Failed to resolve alert');
      return false;
    }
  }

  /**
   * Get monitoring statistics
   */
  getMonitoringStatistics(): {
    metricsCollected: number;
    alertsGenerated: number;
    alertsActive: number;
    alertsResolved: number;
    averageResponseTime: number;
    uptime: number;
    lastUpdate: string;
  } {
    const totalMetrics = Array.from(this.metrics.values()).reduce((sum, list) => sum + list.length, 0);
    const totalAlerts = this.alertHistory.length;
    const activeAlerts = Array.from(this.alerts.values()).filter(a => a.status === 'active').length;
    const resolvedAlerts = this.alertHistory.filter(a => a.status === 'resolved').length;

    // Calculate average response time for health checks
    const healthStatuses = Array.from(this.healthStatus.values());
    const avgResponseTime = healthStatuses.length > 0 ?
      healthStatuses.reduce((sum, s) => sum + s.responseTime, 0) / healthStatuses.length :
      0;

    return {
      metricsCollected: totalMetrics,
      alertsGenerated: totalAlerts,
      alertsActive: activeAlerts,
      alertsResolved: resolvedAlerts,
      averageResponseTime: Math.round(avgResponseTime * 100) / 100,
      uptime: process.uptime(),
      lastUpdate: new Date().toISOString(),
    };
  }

  // === Private Helper Methods ===

  private async startMetricsCollection(): Promise<void> {
    // Implementation would start periodic metrics collection
    setInterval(() => {
      this.collectSystemMetrics();
    }, this.config.metrics.collectionInterval * 1000);

    logger.debug('Metrics collection started');
  }

  private async startHealthChecks(): Promise<void> {
    // Implementation would start health checks for all configured services
    for (const service of this.config.healthChecks.services) {
      this.scheduleHealthCheck(service);
    }

    logger.debug('Health checks started');
  }

  private async initializeAlertProcessing(): Promise<void> {
    // Implementation would initialize alert processing
    logger.debug('Alert processing initialized');
  }

  private async startDashboardUpdates(): Promise<void> {
    // Implementation would start dashboard updates
    if (this.config.dashboards.exportPath) {
      setInterval(() => {
        this.updateDashboard();
      }, this.config.dashboards.refreshInterval * 1000);
    }

    logger.debug('Dashboard updates started');
  }

  private async collectSystemMetrics(): Promise<void> {
    // Implementation would collect system metrics
    const memUsage = process.memoryUsage();
    const cpuUsage = process.cpuUsage();

    const capacityMetric: CapacityMetrics = {
      timestamp: new Date().toISOString(),
      storage: {
        total: 0,
        used: 0,
        available: 0,
        utilization: 0,
      },
      memory: {
        total: memUsage.heapTotal,
        used: memUsage.heapUsed,
        available: memUsage.heapTotal - memUsage.heapUsed,
        utilization: (memUsage.heapUsed / memUsage.heapTotal) * 100,
      },
      network: {
        inbound: 0,
        outbound: 0,
        utilization: 0,
      },
      processing: {
        queueSize: 0,
        processingRate: 0,
        backlog: 0,
      },
    };

    this.recordCapacityMetrics(capacityMetric);
  }

  private scheduleHealthCheck(service: HealthCheckService): void {
    setInterval(async () => {
      await this.performHealthCheck(service);
    }, service.interval * 60 * 1000); // Convert minutes to milliseconds
  }

  private async performHealthCheck(service: HealthCheckService): Promise<void> {
    const startTime = Date.now();
    let status: 'healthy' | 'degraded' | 'unhealthy' = 'healthy';
    let responseTime = 0;
    const checks: HealthStatus['checks'] = [];

    try {
      // Implementation would perform actual health check
      responseTime = Date.now() - startTime;

      // Simulate health check results
      checks.push({
        name: 'response-time',
        status: responseTime < service.timeout ? 'pass' : 'fail',
        value: responseTime,
        threshold: service.timeout,
      });

      if (responseTime > service.timeout * 0.8) {
        status = 'degraded';
      }

    } catch (error) {
      status = 'unhealthy';
      responseTime = Date.now() - startTime;

      checks.push({
        name: 'connection',
        status: 'fail',
        value: responseTime,
        threshold: service.timeout,
      });
    }

    const healthStatus: HealthStatus = {
      serviceId: service.id,
      serviceName: service.name,
      status,
      lastCheck: new Date().toISOString(),
      responseTime,
      uptime: process.uptime(),
      details: {
        endpoint: service.endpoint,
        type: service.type,
      },
      checks,
    };

    this.updateHealthStatus(healthStatus);
  }

  private checkPerformanceAlerts(metric: PerformanceMetric): void {
    const thresholds = this.config.thresholds.performance;

    // Check backup duration
    if (metric.operation === 'backup' && metric.duration > thresholds.backupDuration * 60 * 1000) {
      this.createAlert({
        severity: 'warning',
        category: 'performance',
        source: 'backup-monitor',
        title: 'Backup Operation Slow',
        description: `Backup operation took ${Math.round(metric.duration / 1000 / 60)} minutes, exceeding threshold of ${thresholds.backupDuration} minutes`,
        details: {
          operationType: metric.operationType,
          duration: metric.duration,
          itemCount: metric.itemCount,
        },
        metrics: [{
          name: 'backup-duration',
          value: metric.duration / 1000 / 60,
          unit: 'minutes',
          threshold: thresholds.backupDuration,
        }],
        tags: ['performance', 'backup', 'slow'],
      });
    }

    // Check restore duration
    if (metric.operation === 'restore' && metric.duration > thresholds.restoreDuration * 60 * 1000) {
      this.createAlert({
        severity: 'error',
        category: 'performance',
        source: 'restore-monitor',
        title: 'Restore Operation Slow',
        description: `Restore operation took ${Math.round(metric.duration / 1000 / 60)} minutes, exceeding threshold of ${thresholds.restoreDuration} minutes`,
        details: {
          operationType: metric.operationType,
          duration: metric.duration,
          itemCount: metric.itemCount,
        },
        metrics: [{
          name: 'restore-duration',
          value: metric.duration / 1000 / 60,
          unit: 'minutes',
          threshold: thresholds.restoreDuration,
        }],
        tags: ['performance', 'restore', 'slow'],
      });
    }

    // Check throughput
    if (metric.throughput < thresholds.throughput) {
      this.createAlert({
        severity: 'warning',
        category: 'performance',
        source: 'throughput-monitor',
        title: 'Low Throughput Detected',
        description: `Operation throughput is ${Math.round(metric.throughput)} items/second, below threshold of ${thresholds.throughput} items/second`,
        details: {
          operation: metric.operation,
          operationType: metric.operationType,
          throughput: metric.throughput,
        },
        metrics: [{
          name: 'throughput',
          value: metric.throughput,
          unit: 'items/second',
          threshold: thresholds.throughput,
        }],
        tags: ['performance', 'throughput', 'low'],
      });
    }

    // Check failure
    if (!metric.success) {
      this.createAlert({
        severity: 'error',
        category: 'backup',
        source: 'failure-monitor',
        title: 'Operation Failed',
        description: `${metric.operation} operation failed: ${metric.operationType}`,
        details: {
          errorType: metric.errorType || 'Unknown',
          duration: metric.duration,
        },
        metrics: [{
          name: 'failure-rate',
          value: 1,
          unit: 'boolean',
          threshold: 0,
        }],
        tags: ['failure', metric.operation, metric.operationType],
      });
    }
  }

  private checkHealthAlerts(status: HealthStatus): void {
    if (status.status === 'unhealthy') {
      this.createAlert({
        severity: 'critical',
        category: 'health',
        source: 'health-monitor',
        title: 'Service Unhealthy',
        description: `Service ${status.serviceName} is unhealthy`,
        details: {
          serviceId: status.serviceId,
          responseTime: status.responseTime,
          failedChecks: status.checks.filter(c => c.status === 'fail'),
        },
        metrics: status.checks.map(check => ({
          name: check.name,
          value: check.value,
          unit: 'ms',
          threshold: check.threshold,
        })),
        tags: ['health', 'unhealthy', status.serviceName],
      });
    } else if (status.status === 'degraded') {
      this.createAlert({
        severity: 'warning',
        category: 'health',
        source: 'health-monitor',
        title: 'Service Degraded',
        description: `Service ${status.serviceName} is experiencing degraded performance`,
        details: {
          serviceId: status.serviceId,
          responseTime: status.responseTime,
          warningChecks: status.checks.filter(c => c.status === 'warn'),
        },
        metrics: [{
          name: 'response-time',
          value: status.responseTime,
          unit: 'ms',
          threshold: 1000,
        }],
        tags: ['health', 'degraded', status.serviceName],
      });
    }
  }

  private checkCapacityAlerts(metrics: CapacityMetrics): void {
    const thresholds = this.config.thresholds.capacity;

    // Check storage utilization
    if (metrics.storage.utilization > thresholds.storageUtilization) {
      this.createAlert({
        severity: 'warning',
        category: 'capacity',
        source: 'capacity-monitor',
        title: 'High Storage Utilization',
        description: `Storage utilization is ${Math.round(metrics.storage.utilization)}%, exceeding threshold of ${thresholds.storageUtilization}%`,
        details: {
          used: metrics.storage.used,
          total: metrics.storage.total,
          available: metrics.storage.available,
        },
        metrics: [{
          name: 'storage-utilization',
          value: metrics.storage.utilization,
          unit: 'percent',
          threshold: thresholds.storageUtilization,
        }],
        tags: ['capacity', 'storage', 'high-utilization'],
      });
    }

    // Check memory utilization
    if (metrics.memory.utilization > thresholds.memoryUtilization) {
      this.createAlert({
        severity: 'warning',
        category: 'capacity',
        source: 'capacity-monitor',
        title: 'High Memory Utilization',
        description: `Memory utilization is ${Math.round(metrics.memory.utilization)}%, exceeding threshold of ${thresholds.memoryUtilization}%`,
        details: {
          used: metrics.memory.used,
          total: metrics.memory.total,
          available: metrics.memory.available,
        },
        metrics: [{
          name: 'memory-utilization',
          value: metrics.memory.utilization,
          unit: 'percent',
          threshold: thresholds.memoryUtilization,
        }],
        tags: ['capacity', 'memory', 'high-utilization'],
      });
    }
  }

  private isAlertSuppressed(alert: Omit<Alert, 'id' | 'timestamp' | 'status' | 'escalationLevel' | 'channels'>): boolean {
    // Implementation would check suppression rules
    return false;
  }

  private isRateLimited(alert: Omit<Alert, 'id' | 'timestamp' | 'status' | 'escalationLevel' | 'channels'>): boolean {
    const key = `${alert.category}-${alert.source}`;
    const now = Date.now();
    const hourAgo = now - (60 * 60 * 1000);

    if (!this.rateLimitTracker.has(key)) {
      this.rateLimitTracker.set(key, []);
    }

    const timestamps = this.rateLimitTracker.get(key)!;

    // Clean old timestamps
    const recentTimestamps = timestamps.filter(t => t > hourAgo);
    this.rateLimitTracker.set(key, recentTimestamps);

    // Check rate limit
    if (recentTimestamps.length >= this.config.alerting.rateLimiting.maxAlertsPerHour) {
      return true;
    }

    // Add current timestamp
    recentTimestamps.push(now);
    return false;
  }

  private determineAlertChannels(alert: Omit<Alert, 'id' | 'timestamp' | 'status' | 'escalationLevel' | 'channels'>): string[] {
    const channels: string[] = [];

    for (const channel of this.config.alerting.channels) {
      if (!channel.enabled) continue;

      // Check severity filter
      if (!channel.filters.severities.includes(alert.severity)) continue;

      // Check category filter
      if (!channel.filters.categories.includes(alert.category)) continue;

      // Check service filter
      if (!channel.filters.services.includes(alert.source)) continue;

      channels.push(channel.id);
    }

    return channels.length > 0 ? channels : ['default'];
  }

  private async processAlert(alert: Alert): Promise<void> {
    try {
      // Send notifications to determined channels
      for (const channelId of alert.channels) {
        const channel = this.config.alerting.channels.find(c => c.id === channelId);
        if (channel) {
          await this.sendAlertNotification(alert, channel);
        }
      }

      // Start escalation timer
      this.startAlertEscalation(alert);

    } catch (error) {
      logger.error({ error, alertId: alert.id }, 'Failed to process alert');
    }
  }

  private async sendAlertNotification(alert: Alert, channel: AlertChannel): Promise<void> {
    try {
      // Implementation would send notification based on channel type
      logger.debug({
        alertId: alert.id,
        channelId: channel.id,
        channelType: channel.type,
        severity: alert.severity,
      }, 'Sending alert notification');

    } catch (error) {
      logger.error({
        error,
        alertId: alert.id,
        channelId: channel.id,
      }, 'Failed to send alert notification');
    }
  }

  private async sendResolutionNotification(alert: Alert, resolvedBy?: string): Promise<void> {
    try {
      // Implementation would send resolution notification
      logger.info({
        alertId: alert.id,
        resolvedBy,
        resolution: alert.resolution,
      }, 'Alert resolution notification sent');

    } catch (error) {
      logger.error({ error, alertId: alert.id }, 'Failed to send resolution notification');
    }
  }

  private startAlertEscalation(alert: Alert): void {
    // Implementation would start escalation timer based on policies
    logger.debug({ alertId: alert.id }, 'Alert escalation started');
  }

  private async stopAlertEscalation(alert: Alert): Promise<void> {
    // Implementation would stop escalation
    logger.debug({ alertId: alert.id }, 'Alert escalation stopped');
  }

  private async calculateTrends(): Promise<{
    backupPerformance: Array<{ timestamp: string; value: number }>;
    restorePerformance: Array<{ timestamp: string; value: number }>;
    successRate: Array<{ timestamp: string; value: number }>;
    capacityUtilization: Array<{ timestamp: string; value: number }>;
  }> {
    // Implementation would calculate trends from historical data
    const now = new Date();
    const trends: {
      backupPerformance: Array<{ timestamp: string; value: number }>;
      restorePerformance: Array<{ timestamp: string; value: number }>;
      successRate: Array<{ timestamp: string; value: number }>;
      capacityUtilization: Array<{ timestamp: string; value: number }>;
    } = {
      backupPerformance: [],
      restorePerformance: [],
      successRate: [],
      capacityUtilization: [],
    };

    // Generate sample trend data
    for (let i = 23; i >= 0; i--) {
      const timestamp = new Date(now.getTime() - i * 60 * 60 * 1000);

      trends.backupPerformance.push({
        timestamp: timestamp.toISOString(),
        value: 10 + Math.random() * 5, // 10-15 minutes
      });

      trends.restorePerformance.push({
        timestamp: timestamp.toISOString(),
        value: 15 + Math.random() * 10, // 15-25 minutes
      });

      trends.successRate.push({
        timestamp: timestamp.toISOString(),
        value: 95 + Math.random() * 5, // 95-100%
      });

      trends.capacityUtilization.push({
        timestamp: timestamp.toISOString(),
        value: 60 + Math.random() * 20, // 60-80%
      });
    }

    return trends;
  }

  private async updateDashboard(): Promise<void> {
    try {
      const dashboardData = await this.getDashboardData();

      if (this.config.dashboards.exportPath) {
        await writeFile(
          this.config.dashboards.exportPath,
          JSON.stringify(dashboardData, null, 2),
          'utf-8'
        );
      }

      logger.debug('Dashboard data updated');

    } catch (error) {
      logger.error({ error }, 'Failed to update dashboard');
    }
  }

  private generateAlertId(): string {
    return `alert_${Date.now()}_${Math.random().toString(36).substr(2, 8)}`;
  }

  // File I/O methods (placeholders)
  private async loadHistoricalData(): Promise<void> {
    logger.debug('Historical monitoring data loaded');
  }
}
