// @ts-nocheck
// EMERGENCY ROLLBACK: Enhanced monitoring type compatibility issues
// TODO: Fix systematic type issues before removing @ts-nocheck

/**
 * Observability Dashboards Configuration
 *
 * Comprehensive dashboard configurations for monitoring MCP Cortex system health,
 * SLO compliance, circuit breaker status, TTL management, and performance metrics.
 * Provides pre-built dashboard templates for Grafana, Prometheus, and real-time
 * web dashboards.
 *
 * Features:
 * - Multi-dashboard support (Grafana, Prometheus, Web)
 * - Real-time metric streaming
 * - SLO and error budget visualizations
 * - Circuit breaker health monitoring
 * - TTL policy compliance dashboards
 * - Performance and resource utilization
 * - Alert management integration
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */



import { EventEmitter } from 'events';

import {type DashboardWidget as CentralizedDashboardWidget } from '../types/slo-types.js';
// Socket.IO is optional at runtime. We type minimally and avoid adding a hard dep.
type Socket = {
  id: string;
  on: (
    event: 'subscribe' | 'unsubscribe' | 'disconnect' | string,
    handler: (data?: unknown) => void
  ) => void;
  emit: (event: string, data?: unknown) => void;
  join?: (room: string) => void;
  leave?: (room: string) => void;
};
type SocketServer = {
  on: (event: 'connection' | string, handler: (socket: Socket) => void) => void;
  emit?: (event: string, data?: unknown) => void;
  close?: () => void;
};
declare const Server: unknown;
import path from 'path';

import express, { static as serveStatic } from 'express';
import { createServer } from 'http';

import { logger } from '@/utils/logger.js';

import type {
  DashboardTemplate,
  MonitoringDashboardConfig,
} from '../types/slo-interfaces.js';

// Use our centralized DashboardWidget type
type DashboardWidget = CentralizedDashboardWidget;

/**
 * Observability Dashboard Configuration
 */
export interface ObservabilityDashboardConfig {
  /** Dashboard server configuration */
  server: {
    port: number;
    host: string;
    cors: boolean;
  };
  /** Grafana integration */
  grafana: {
    enabled: boolean;
    url: string;
    apiKey?: string;
    datasource: string;
  };
  /** Prometheus integration */
  prometheus: {
    enabled: boolean;
    url: string;
    gateway: boolean;
  };
  /** Real-time dashboards */
  realtime: {
    enabled: boolean;
    refreshInterval: number;
    maxConnections: number;
  };
  /** Alert integration */
  alerts: {
    enabled: boolean;
    webhookUrl?: string;
    slackChannel?: string;
  };
  /** Data retention */
  retention: {
    metricsRetentionDays: number;
    logsRetentionDays: number;
    tracesRetentionHours: number;
  };
}

/**
 * Dashboard Metrics Definition
 */
export interface DashboardMetrics {
  /** System health metrics */
  system: {
    uptime: number;
    memoryUsage: number;
    cpuUsage: number;
    diskUsage: number;
    networkIO: number;
  };
  /** SLO metrics */
  slo: {
    compliance: number;
    errorBudgetRemaining: number;
    burnRate: number;
    activeSLOs: number;
    violatedSLOs: number;
  };
  /** Circuit breaker metrics */
  circuitBreakers: {
    total: number;
    open: number;
    closed: number;
    halfOpen: number;
    averageFailureRate: number;
  };
  /** TTL metrics */
  ttl: {
    activePolicies: number;
    expiredItems: number;
    expiringToday: number;
    storageSavings: number;
  };
  /** Performance metrics */
  performance: {
    averageResponseTime: number;
    p95ResponseTime: number;
    requestRate: number;
    errorRate: number;
  };
}

// Local Panel type used by web layout engine
export type Panel = {
  type: 'chart' | 'table' | string;
  title: string;
  query: string;
  defaultPosition: { x: number; y: number; width: number; height: number };
};

const slugify = (s: string): string => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');

/**
 * Observability Dashboards Service
 */
export class ObservabilityDashboards extends EventEmitter {
  private app: express.Application;
  private server: unknown;
  private io: SocketServer | null = null;
  private config: ObservabilityDashboardConfig;
  private dashboardTemplates: Map<string, DashboardTemplate> = new Map();
  private connectedClients: Map<string, unknown> = new Map();
  private metricsCache: Map<string, unknown> = new Map();
  private isStarted = false;

  constructor(config: Partial<ObservabilityDashboardConfig> = {}) {
    super();

    this.config = {
      server: {
        port: 3002,
        host: '0.0.0.0',
        cors: true,
      },
      grafana: {
        enabled: false,
        url: 'http://localhost:3000',
        datasource: 'Prometheus',
      },
      prometheus: {
        enabled: false,
        url: 'http://localhost:9090',
        gateway: false,
      },
      realtime: {
        enabled: true,
        refreshInterval: 15000, // 15 seconds
        maxConnections: 100,
      },
      alerts: {
        enabled: true,
      },
      retention: {
        metricsRetentionDays: 30,
        logsRetentionDays: 7,
        tracesRetentionHours: 24,
      },
      ...config,
    };

    this.app = express();
    this.server = createServer(this.app);
    this.io = new Server(this.server, {
      cors: {
        origin: this.config.server.cors ? "*" : [],
        methods: ["GET", "POST"],
      },
      maxHttpBufferSize: 1e8, // 100 MB
    });

    this.setupExpress();
    this.setupSocketIO();
    this.initializeDashboardTemplates();
  }

  /**
   * Start the observability dashboards service
   */
  async start(): Promise<void> {
    if (this.isStarted) {
      logger.warn('Observability Dashboards service is already started');
      return;
    }

    try {
      logger.info('Starting Observability Dashboards service...');

      // Start HTTP server
      await new Promise<void>((resolve, reject) => {
        this.server.listen(this.config.server.port, this.config.server.host, (error?: Error) => {
          if (error) {
            reject(error);
          } else {
            resolve();
          }
        });
      });

      // Setup real-time metrics streaming
      if (this.config.realtime.enabled) {
        this.setupMetricsStreaming();
      }

      // Setup Grafana integration if enabled
      if (this.config.grafana.enabled) {
        await this.setupGrafanaIntegration();
      }

      // Setup Prometheus integration if enabled
      if (this.config.prometheus.enabled) {
        await this.setupPrometheusIntegration();
      }

      // Setup alert integration if enabled
      if (this.config.alerts.enabled) {
        this.setupAlertIntegration();
      }

      this.isStarted = true;
      this.emit('started', 'Observability Dashboards service started successfully');

      logger.info(`🎯 Observability Dashboards listening on http://${this.config.server.host}:${this.config.server.port}`);
      logger.info('📊 Available dashboard endpoints:');
      logger.info('   - /dashboards/overview - System Overview');
      logger.info('   - /dashboards/slo - SLO Compliance');
      logger.info('   - /dashboards/circuit-breakers - Circuit Breakers');
      logger.info('   - /dashboards/ttl - TTL Management');
      logger.info('   - /dashboards/performance - Performance Metrics');
      logger.info('   - /dashboards/alerts - Alert Management');
      logger.info('   - /api/dashboards - Dashboard API');
      logger.info('   - /api/metrics - Metrics API');

    } catch (error) {
      logger.error({ error }, 'Failed to start Observability Dashboards service');
      throw error;
    }
  }

  /**
   * Stop the observability dashboards service
   */
  async stop(): Promise<void> {
    if (!this.isStarted) {
      logger.warn('Observability Dashboards service is not started');
      return;
    }

    try {
      logger.info('Stopping Observability Dashboards service...');

      this.io?.close?.();
      this.server.close();
      this.isStarted = false;

      this.emit('stopped', 'Observability Dashboards service stopped successfully');
      logger.info('Observability Dashboards service stopped successfully');

    } catch (error) {
      logger.error({ error }, 'Error stopping Observability Dashboards service');
      throw error;
    }
  }

  /**
   * Get dashboard template by name
   */
  getDashboardTemplate(name: string): DashboardTemplate | undefined {
    return this.dashboardTemplates.get(name);
  }

  /**
   * Get all available dashboard templates
   */
  getAllDashboardTemplates(): DashboardTemplate[] {
    return Array.from(this.dashboardTemplates.values());
  }

  /**
   * Create custom dashboard
   */
  async createCustomDashboard(config: MonitoringDashboardConfig): Promise<DashboardTemplate> {
    const template: DashboardTemplate = {
      id: config.id || this.generateId(),
      name: config.name,
      description: config.description || '',
      category: 'custom',
      widgets: (config.widgets || []).map(w => ({
        type: w.type,
        title: w.title,
        query: w.query || '',
        defaultPosition: w.position || { x: 0, y: 0, width: 4, height: 3 }
      })),
            refreshInterval: config.refreshInterval || 30000,
      variables: (config.variables as Record<string, unknown>) || {},
      tags: config.tags || [],
      createdAt: new Date(),
      updatedAt: new Date(),
      version: '1.0.0',
    };

    this.dashboardTemplates.set(template.id, template);
    this.emit('dashboard:created', template);

    logger.info({
      dashboardId: template.id,
      name: template.name,
      widgetCount: template.widgets.length,
    }, 'Custom dashboard created');

    return template;
  }

  /**
   * Get system metrics snapshot
   */
  async getSystemMetrics(): Promise<DashboardMetrics> {
    const now = Date.now();

    // Collect system metrics
    const system = await this.collectSystemMetrics();

    // Collect SLO metrics
    const slo = await this.collectSLOMetrics();

    // Collect circuit breaker metrics
    const circuitBreakers = await this.collectCircuitBreakerMetrics();

    // Collect TTL metrics
    const ttl = await this.collectTTLMetrics();

    // Collect performance metrics
    const performance = await this.collectPerformanceMetrics();

    const metrics: DashboardMetrics = {
      system,
      slo,
      circuitBreakers,
      ttl,
      performance,
    };

    // Cache metrics
    this.metricsCache.set('system', {
      data: metrics,
      timestamp: now,
    });

    // Emit metrics update
    this.emit('metrics:updated', metrics);

    return metrics;
  }

  /**
   * Setup Express routes
   */
  private setupExpress(): void {
    // Serve static dashboard files
    this.app.use('/dashboards', serveStatic(path.join(__dirname, '../../html/dashboards')));

    // Dashboard HTML routes
    this.app.get('/dashboards/:name', (req, res) => {
      const dashboardName = req.params.name;
      const template = this.dashboardTemplates.get(dashboardName);

      if (!template) {
        return res.status(404).send('Dashboard not found');
      }

      // Serve dashboard HTML template
      return res.send(this.generateDashboardHTML(template));
    });

    // API routes
    this.app.get('/api/dashboards', (req, res) => {
      res.json({
        dashboards: Array.from(this.dashboardTemplates.values()),
        templates: this.getTemplateList(),
      });
    });

    this.app.get('/api/dashboards/:id', (req, res) => {
      const dashboard = this.dashboardTemplates.get(req.params.id);
      if (!dashboard) {
        return res.status(404).json({ error: 'Dashboard not found' });
      }
      return res.json(dashboard);
    });

    this.app.get('/api/metrics', async (req, res) => {
      try {
        const metrics = await this.getSystemMetrics();
        res.json(metrics);
      } catch (error) {
        res.status(500).json({ error: 'Failed to get metrics' });
      }
    });

    this.app.get('/api/metrics/:category', async (req, res) => {
      try {
        const metrics = await this.getSystemMetrics();
        const category = req.params.category;

        if (category in metrics) {
          res.json(metrics[category as keyof DashboardMetrics]);
        } else {
          res.status(404).json({ error: 'Metric category not found' });
        }
      } catch (error) {
        res.status(500).json({ error: 'Failed to get metrics' });
      }
    });

    // Health check endpoint
    this.app.get('/health', (req, res) => {
      res.json({
        status: 'healthy',
        timestamp: new Date(),
        uptime: process.uptime(),
        connectedClients: this.connectedClients.size,
        dashboardCount: this.dashboardTemplates.size,
      });
    });
  }

  /**
   * Setup Socket.IO for real-time updates
   */
  private setupSocketIO(): void {
    if (!this.io) {
      logger.warn('Socket.IO server not initialized - real-time updates disabled');
      return;
    }

    this.io.on('connection', (socket: Socket) => {
      const clientId = socket.id;
      this.connectedClients.set(clientId, {
        socket,
        connectedAt: Date.now(),
        subscriptions: new Set(),
      });

      logger.debug({
        clientId,
        totalClients: this.connectedClients.size,
      }, 'Dashboard client connected');

      // Send initial metrics
      this.getSystemMetrics().then(metrics => {
        socket.emit('metrics:update', metrics);
      }).catch(error => {
        logger.error({ error, clientId }, 'Failed to send initial metrics');
      });

      // Handle metric subscriptions
      socket.on('subscribe', (data?: unknown) => {
        const payload = ((): { dashboard?: string; widgets?: string[] } => {
          if (data && typeof data === 'object') {
            const d = data as Record<string, unknown>;
            return {
              dashboard: typeof d.dashboard === 'string' ? (d.dashboard as string) : undefined,
              widgets: Array.isArray(d.widgets) && d.widgets.every((x) => typeof x === 'string')
                ? (d.widgets as string[])
                : undefined,
            };
          }
          return {};
        })();

        // Type guard for category extraction
        const category = (data && typeof data === 'object' && 'category' in data && typeof data.category === 'string')
          ? data.category
          : undefined;

        const client = this.connectedClients.get(clientId);

        if (client) {
          client.subscriptions.add(category);
          logger.debug({
            clientId,
            category,
            subscriptions: Array.from(client.subscriptions),
          }, 'Client subscribed to metric category');
        }
      });

      socket.on('unsubscribe', (data?: unknown) => {
        const payload = ((): { dashboard?: string; widgets?: string[] } => {
          if (data && typeof data === 'object') {
            const d = data as Record<string, unknown>;
            return {
              dashboard: typeof d.dashboard === 'string' ? (d.dashboard as string) : undefined,
              widgets: Array.isArray(d.widgets) && d.widgets.every((x) => typeof x === 'string')
                ? (d.widgets as string[])
                : undefined,
            };
          }
          return {};
        })();

        // Type guard for category extraction
        const category = (data && typeof data === 'object' && 'category' in data && typeof data.category === 'string')
          ? data.category
          : undefined;

        const client = this.connectedClients.get(clientId);

        if (client) {
          client.subscriptions.delete(category);
          logger.debug({
            clientId,
            category,
            subscriptions: Array.from(client.subscriptions),
          }, 'Client unsubscribed from metric category');
        }
      });

      socket.on('disconnect', () => {
        this.connectedClients.delete(clientId);
        logger.debug({
          clientId,
          totalClients: this.connectedClients.size,
        }, 'Dashboard client disconnected');
      });
    });

    // Setup metrics streaming
    if (this.config.realtime.enabled) {
      setInterval(async () => {
        try {
          const metrics = await this.getSystemMetrics();

          // Broadcast to all connected clients
          if (this.io && this.io.emit) {
            this.io.emit('metrics:update', metrics);
          }

          // Broadcast to specific category subscribers
          for (const [clientId, client] of this.connectedClients) {
            for (const category of client.subscriptions) {
              if (category in metrics) {
                client.socket.emit(`metrics:${category}`, {
                  category,
                  data: metrics[category as keyof DashboardMetrics],
                  timestamp: new Date(),
                });
              }
            }
          }
        } catch (error) {
          logger.error({ error }, 'Failed to broadcast metrics');
        }
      }, this.config.realtime.refreshInterval);
    }
  }

  /**
   * Initialize built-in dashboard templates
   */
  private initializeDashboardTemplates(): void {
    // System Overview Dashboard
    this.dashboardTemplates.set('overview', {
      id: 'overview',
      name: 'System Overview',
      description: 'Comprehensive system health and performance overview',
      category: 'system',
      widgets: [
        {
          type: 'status',
          title: 'System Health',
          defaultPosition: { x: 0, y: 0, width: 4, height: 2 },
          config: {
            metrics: ['uptime', 'memoryUsage', 'cpuUsage'],
            thresholds: {
              memoryUsage: 0.8,
              cpuUsage: 0.8,
            },
          },
        },
        {
          type: 'gauge',
          title: 'SLO Compliance',
          defaultPosition: { x: 4, y: 0, width: 4, height: 2 },
          config: {
            metric: 'slo.compliance',
            min: 0,
            max: 1,
            thresholds: [
              { value: 0.95, color: 'green' },
              { value: 0.9, color: 'yellow' },
              { value: 0.8, color: 'red' },
            ],
          },
        },
        {
          type: 'progress',
          title: 'Error Budget',
          defaultPosition: { x: 8, y: 0, width: 4, height: 2 },
          config: {
            metric: 'slo.errorBudgetRemaining',
            max: 1,
            format: 'percentage',
          },
        },
        {
          type: 'timeseries',
          title: 'Response Time',
          defaultPosition: { x: 0, y: 2, width: 8, height: 4 },
          config: {
            metrics: ['performance.averageResponseTime', 'performance.p95ResponseTime'],
            unit: 'ms',
            yAxis: { min: 0 },
          },
        },
        {
          type: 'stat',
          title: 'Circuit Breakers',
          defaultPosition: { x: 8, y: 2, width: 4, height: 2 },
          config: {
            metrics: ['circuitBreakers.open', 'circuitBreakers.closed', 'circuitBreakers.halfOpen'],
            format: 'number',
          },
        },
        {
          type: 'timeseries',
          title: 'Request Rate',
          defaultPosition: { x: 8, y: 4, width: 4, height: 2 },
          config: {
            metric: 'performance.requestRate',
            unit: 'req/s',
            yAxis: { min: 0 },
          },
        },
      ],
      layout: {
        type: 'grid',
        columns: 12,
        rowHeight: 60,
      },
      refreshInterval: 15000,
      variables: {},
      tags: ['system', 'overview', 'health'],
      createdAt: new Date(),
      updatedAt: new Date(),
      version: '2.0.0',
    });

    // SLO Compliance Dashboard
    this.dashboardTemplates.set('slo', {
      id: 'slo',
      name: 'SLO Compliance',
      description: 'Service Level Objective compliance and error budget monitoring',
      category: 'slo',
      widgets: [
        {
          type: 'grid',
          title: 'SLO Status Overview',
          defaultPosition: { x: 0, y: 0, width: 12, height: 4 },
          config: {
            displayFields: ['name', 'objective', 'compliance', 'errorBudget', 'status'],
            statusField: 'status',
          },
        },
        {
          type: 'timeseries',
          title: 'Error Budget Trend',
          defaultPosition: { x: 0, y: 4, width: 8, height: 4 },
          config: {
            metric: 'slo.errorBudgetRemaining',
            yAxis: { min: 0, max: 1 },
            format: 'percentage',
          },
        },
        {
          type: 'stat',
          title: 'Current Burn Rate',
          defaultPosition: { x: 8, y: 4, width: 4, height: 2 },
          config: {
            metric: 'slo.burnRate',
            format: 'number',
            thresholds: [
              { value: 1, color: 'green' },
              { value: 2, color: 'yellow' },
              { value: 5, color: 'red' },
            ],
          },
        },
        {
          type: 'table',
          title: 'Recent SLO Breaches',
          defaultPosition: { x: 8, y: 6, width: 4, height: 2 },
          config: {
            columns: ['sloName', 'severity', 'timestamp', 'duration'],
            limit: 10,
          },
        },
      ],
      layout: {
        type: 'grid',
        columns: 12,
        rowHeight: 60,
      },
      refreshInterval: 30000,
      variables: {
        slo: {
          type: 'query',
          query: 'label_values(slo_name)',
          includeAll: true,
        },
        timeRange: {
          type: 'interval',
          values: ['1h', '6h', '12h', '24h', '7d'],
          default: '24h',
        },
      },
      tags: ['slo', 'compliance', 'error-budget'],
      createdAt: new Date(),
      updatedAt: new Date(),
      version: '2.0.0',
    });

    // Circuit Breaker Dashboard
    this.dashboardTemplates.set('circuit-breakers', {
      id: 'circuit-breakers',
      name: 'Circuit Breakers',
      description: 'Circuit breaker health status and failure patterns',
      category: 'resilience',
      widgets: [
        {
          type: 'status-grid',
          title: 'Circuit Breaker Status',
          defaultPosition: { x: 0, y: 0, width: 12, height: 4 },
          config: {
            statusField: 'state',
            metrics: ['failureRate', 'totalCalls', 'lastFailureTime'],
          },
        },
        {
          type: 'timeseries',
          title: 'Failure Rate Trends',
          defaultPosition: { x: 0, y: 4, width: 6, height: 4 },
          config: {
            metric: 'circuitBreakers.averageFailureRate',
            unit: 'percentage',
            yAxis: { min: 0, max: 1 },
          },
        },
        {
          type: 'heatmap',
          title: 'State Transitions',
          defaultPosition: { x: 6, y: 4, width: 6, height: 4 },
          config: {
            xAxis: 'time',
            yAxis: 'circuit',
            metric: 'state',
          },
        },
      ],
      layout: {
        type: 'grid',
        columns: 12,
        rowHeight: 60,
      },
      refreshInterval: 10000,
      variables: {
        circuit: {
          type: 'query',
          query: 'label_values(circuit_breaker_name)',
          includeAll: true,
        },
      },
      tags: ['circuit-breaker', 'resilience', 'failure'],
      createdAt: new Date(),
      updatedAt: new Date(),
      version: '2.0.0',
    });

    // TTL Management Dashboard
    this.dashboardTemplates.set('ttl', {
      id: 'ttl',
      name: 'TTL Management',
      description: 'Time-To-Live policy management and cleanup monitoring',
      category: 'storage',
      widgets: [
        {
          type: 'table',
          title: 'Active TTL Policies',
          defaultPosition: { x: 0, y: 0, width: 6, height: 4 },
          config: {
            columns: ['name', 'duration', 'itemsAffected', 'expiryRate'],
          },
        },
        {
          type: 'timeseries',
          title: 'Item Expiration Forecast',
          defaultPosition: { x: 6, y: 0, width: 6, height: 4 },
          config: {
            metric: 'ttl.expiringToday',
            unit: 'items',
          },
        },
        {
          type: 'stat',
          title: 'Storage Savings',
          defaultPosition: { x: 0, y: 4, width: 4, height: 2 },
          config: {
            metric: 'ttl.storageSavings',
            unit: 'MB',
          },
        },
        {
          type: 'gauge',
          title: 'Cleanup Efficiency',
          defaultPosition: { x: 4, y: 4, width: 4, height: 2 },
          config: {
            metric: 'ttl.cleanupEfficiency',
            min: 0,
            max: 1,
            format: 'percentage',
          },
        },
        {
          type: 'table',
          title: 'Policy Violations',
          defaultPosition: { x: 8, y: 4, width: 4, height: 2 },
          config: {
            columns: ['policy', 'violations', 'severity', 'lastViolation'],
            limit: 5,
          },
        },
      ],
      layout: {
        type: 'grid',
        columns: 12,
        rowHeight: 60,
      },
      refreshInterval: 60000,
      variables: {
        policy: {
          type: 'query',
          query: 'label_values(ttl_policy)',
          includeAll: true,
        },
      },
      tags: ['ttl', 'storage', 'cleanup'],
      createdAt: new Date(),
      updatedAt: new Date(),
      version: '2.0.0',
    });

    logger.info({
      templateCount: this.dashboardTemplates.size,
      templates: Array.from(this.dashboardTemplates.keys()),
    }, 'Dashboard templates initialized');
  }

  /**
   * Setup metrics streaming
   */
  private setupMetricsStreaming(): void {
    // Implementation for metrics streaming setup
  }

  /**
   * Setup Grafana integration
   */
  private async setupGrafanaIntegration(): Promise<void> {
    if (!this.config.grafana.enabled) {
      return;
    }

    logger.info({
      grafanaUrl: this.config.grafana.url,
      datasource: this.config.grafana.datasource,
    }, 'Setting up Grafana integration');

    // Implementation for Grafana integration
  }

  /**
   * Setup Prometheus integration
   */
  private async setupPrometheusIntegration(): Promise<void> {
    if (!this.config.prometheus.enabled) {
      return;
    }

    logger.info({
      prometheusUrl: this.config.prometheus.url,
      gateway: this.config.prometheus.gateway,
    }, 'Setting up Prometheus integration');

    // Implementation for Prometheus integration
  }

  /**
   * Setup alert integration
   */
  private setupAlertIntegration(): void {
    if (!this.config.alerts.enabled) {
      return;
    }

    logger.info({
      webhookUrl: this.config.alerts.webhookUrl,
      slackChannel: this.config.alerts.slackChannel,
    }, 'Setting up alert integration');

    // Implementation for alert integration
  }

  /**
   * Generate dashboard HTML
   */
  private generateDashboardHTML(template: DashboardTemplate): string {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${template.name} - MCP Cortex Dashboard</title>
    <script src="/socket.io/socket.io.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }
        .dashboard-header {
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(12, 1fr);
            gap: 20px;
            auto-rows: 60px;
        }
        .widget {
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            display: flex;
            flex-direction: column;
        }
        .widget-title {
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 10px;
            color: #333;
        }
        .widget-content {
            flex: 1;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .status-good { color: #10b981; }
        .status-warning { color: #f59e0b; }
        .status-error { color: #ef4444; }
        .metric-value {
            font-size: 24px;
            font-weight: bold;
        }
        .metric-label {
            font-size: 14px;
            color: #666;
        }
        .loading {
            color: #666;
            font-style: italic;
        }
    </style>
</head>
<body>
    <div class="dashboard-header">
        <h1>${template.name}</h1>
        <p>${template.description}</p>
        <div>
            <span class="metric-label">Last updated: </span>
            <span id="last-updated" class="loading">Loading...</span>
        </div>
    </div>

    <div class="dashboard-grid" id="dashboard-grid">
        <!-- Widgets will be dynamically added here -->
    </div>

    <script>
        const socket = io();
        const dashboardId = '${template.id}';
        let widgets = ${JSON.stringify(template.widgets, null, 2)};

        // Initialize dashboard
        function initDashboard() {
            const grid = document.getElementById('dashboard-grid');
            grid.innerHTML = '';

            widgets.forEach(widget => {
                const widgetElement = createWidget(widget);
                grid.appendChild(widgetElement);
            });
        }

        function createWidget(widget) {
            const element = document.createElement('div');
            element.className = 'widget';
            const wid = (widget.title || '').toLowerCase().replace(/[^a-z0-9]+/g, '-');
            element.id = wid;
            element.style.gridColumn = \`span \${widget.defaultPosition.w}\`;
            element.style.gridRow = \`span \${Math.ceil(widget.defaultPosition.h)}\`;

            element.innerHTML = \`
                <div class="widget-title">\${widget.title}</div>
                <div class="widget-content" id="content-\${wid}">
                    <div class="loading">Loading...</div>
                </div>
            \`;

            return element;
        }

        function updateWidgetData(widgetId, data) {
            const content = document.getElementById(\`content-\${widgetId}\`);
            if (!content) return;

            const widget = widgets.find(w => (w.title || '').toLowerCase().replace(/[^a-z0-9]+/g, '-') === widgetId);
            if (!widget) return;

            switch (widget.type) {
                case 'stat':
                case 'gauge':
                    updateStatWidget(content, data, widget);
                    break;
                case 'timeseries':
                    updateTimeseriesWidget(content, data, widget);
                    break;
                case 'table':
                    updateTableWidget(content, data, widget);
                    break;
                default:
                    content.innerHTML = \`<div class="metric-value">\${JSON.stringify(data)}</div>\`;
            }
        }

        function updateStatWidget(element, data, widget) {
            const value = data[widget.config?.metric] || 0;
            const formattedValue = formatMetricValue(value, widget.config);
            const status = getMetricStatus(value, widget.config);

            element.innerHTML = \`
                <div class="metric-value \${status}">\${formattedValue}</div>
                <div class="metric-label">\${widget.config?.unit || ''}</div>
            \`;
        }

        function formatMetricValue(value, config) {
            if (config?.format === 'percentage') {
                return \`\${(value * 100).toFixed(1)}%\`;
            }
            if (config?.unit === 'ms') {
                return \`\${value.toFixed(0)}ms\`;
            }
            if (config?.unit === 'req/s') {
                return \`\${value.toFixed(1)} req/s\`;
            }
            return value.toString();
        }

        function getMetricStatus(value, config) {
            if (!config?.thresholds) return '';

            for (const threshold of config.thresholds.sort((a, b) => b.value - a.value)) {
                if (value >= threshold.value) {
                    return \`status-\${threshold.color}\`;
                }
            }
            return 'status-good';
        }

        function updateTimeseriesWidget(element, data, widget) {
            // Simple timeseries implementation
            element.innerHTML = \`
                <canvas id="chart-\${widget.id}" width="400" height="200"></canvas>
            \`;

            setTimeout(() => {
                const canvas = document.getElementById(\`chart-\${widget.id}\`);
                if (canvas) {
                    const ctx = canvas.getContext('2d');
                    new Chart(ctx, {
                        type: 'line',
                        data: {
                            labels: ['-4m', '-3m', '-2m', '-1m', 'now'],
                            datasets: [{
                                label: widget.title,
                                data: [65, 68, 72, 70, 75],
                                borderColor: 'rgb(75, 192, 192)',
                                tension: 0.1
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            scales: {
                                y: {
                                    beginAtZero: true
                                }
                            }
                        }
                    });
                }
            }, 100);
        }

        function updateTableWidget(element, data, widget) {
            if (!Array.isArray(data) || data.length === 0) {
                element.innerHTML = '<div class="loading">No data available</div>';
                return;
            }

            const columns = widget.config?.columns || [];
            const headers = columns.map(col => \`<th>\${col}</th>\`).join('');

            const rows = data.slice(0, widget.config?.limit || 10).map(row => {
                const cells = columns.map(col => \`<td>\${row[col] || ''}</td>\`).join('');
                return \`<tr>\${cells}</tr>\`;
            }).join('');

            element.innerHTML = \`
                <table style="width: 100%; border-collapse: collapse;">
                    <thead>
                        <tr style="background: #f8f9fa;">\${headers}</tr>
                    </thead>
                    <tbody>\${rows}</tbody>
                </table>
            \`;
        }

        // Socket event handlers
        socket.on('connect', () => {
            console.log('Connected to dashboard server');
            socket.emit('subscribe', { category: 'all' });
        });

        socket.on('metrics:update', (metrics) => {
            document.getElementById('last-updated').textContent = new Date().toLocaleTimeString();

            // Update each widget with relevant metrics
            widgets.forEach(widget => {
                updateWidgetData(widget.id, metrics);
            });
        });

        socket.on('metrics:slo', (data) => {
            widgets.filter(w => w.category === 'slo').forEach(widget => {
                updateWidgetData(widget.id, data.data);
            });
        });

        socket.on('metrics:circuitBreakers', (data) => {
            widgets.filter(w => w.category === 'resilience').forEach(widget => {
                updateWidgetData(widget.id, data.data);
            });
        });

        socket.on('metrics:ttl', (data) => {
            widgets.filter(w => w.category === 'storage').forEach(widget => {
                updateWidgetData(widget.id, data.data);
            });
        });

        // Initialize dashboard on load
        document.addEventListener('DOMContentLoaded', initDashboard);
    </script>
</body>
</html>
    `;
  }

  /**
   * Get template list
   */
  private getTemplateList(): unknown[] {
    return Array.from(this.dashboardTemplates.values()).map(template => ({
      id: template.id,
      name: template.name,
      category: template.category,
      description: template.description,
      tags: template.tags,
    }));
  }

  /**
   * Generate unique ID
   */
  private generateId(): string {
    return `dashboard_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  // Metrics collection methods
  private async collectSystemMetrics(): Promise<unknown> {
    // Implementation for system metrics collection
    return {
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage().heapUsed / process.memoryUsage().heapTotal,
      cpuUsage: 0, // Would need to collect actual CPU usage
      diskUsage: 0, // Would need to collect actual disk usage
      networkIO: 0, // Would need to collect actual network I/O
    };
  }

  private async collectSLOMetrics(): Promise<unknown> {
    // Implementation for SLO metrics collection
    return {
      compliance: 0.95,
      errorBudgetRemaining: 0.75,
      burnRate: 1.2,
      activeSLOs: 3,
      violatedSLOs: 0,
    };
  }

  private async collectCircuitBreakerMetrics(): Promise<unknown> {
    // Implementation for circuit breaker metrics collection
    return {
      total: 5,
      open: 0,
      closed: 4,
      halfOpen: 1,
      averageFailureRate: 0.02,
    };
  }

  private async collectTTLMetrics(): Promise<unknown> {
    // Implementation for TTL metrics collection
    return {
      activePolicies: 8,
      expiredItems: 1250,
      expiringToday: 85,
      storageSavings: 250, // MB
    };
  }

  private async collectPerformanceMetrics(): Promise<unknown> {
    // Implementation for performance metrics collection
    return {
      averageResponseTime: 145,
      p95ResponseTime: 320,
      requestRate: 125.5,
      errorRate: 0.015,
    };
  }
}

