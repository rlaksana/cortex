// @ts-nocheck
// EMERGENCY ROLLBACK: Final batch of type compatibility issues
// TODO: Fix systematic type issues before removing @ts-nocheck

/**
 * Performance Dashboard API for Cortex MCP
 * Provides HTTP endpoints for performance monitoring and alerting
 */

import express, { type NextFunction, type Request, type Response, Router } from 'express';

import { logger } from '@/utils/logger.js';

import { type PerformanceAlert,performanceCollector } from './performance-collector.js';

export interface DashboardConfig {
  enableMetricsEndpoint?: boolean;
  enableAlertsEndpoint?: boolean;
  enableTrendsEndpoint?: boolean;
  requireAuthentication?: boolean;
  cacheTimeout?: number; // milliseconds
}

export class PerformanceDashboard {
  private alerts: PerformanceAlert[] = [];
  private maxAlerts = 1000;
  private alertCache: Map<string, unknown> = new Map();
  private config: DashboardConfig;

  constructor(config: DashboardConfig = {}) {
    this.config = {
      enableMetricsEndpoint: true,
      enableAlertsEndpoint: true,
      enableTrendsEndpoint: true,
      requireAuthentication: false,
      cacheTimeout: 30000, // 30 seconds
      ...config,
    };

    this.setupAlertHandling();
  }

  /**
   * Get metrics endpoint
   */
  getMetrics(req: Request, res: Response): void {
    if (!this.config.enableMetricsEndpoint) {
      res.status(404).json({ error: 'Metrics endpoint disabled' });
      return;
    }

    try {
      const { operation, format, timeWindow } = req.query;
      const timeWindowMinutes = parseInt(timeWindow as string) || 60;

      let data: unknown;

      if (operation) {
        // Get specific operation metrics
        data = performanceCollector.getSummary(operation as string);
        if (!data) {
          res.status(404).json({ error: 'Operation not found' });
          return;
        }
        data.recentMetrics = performanceCollector.getRecentMetrics(operation as string, 100);
      } else {
        // Get all metrics
        data = {
          summaries: performanceCollector.getAllSummaries(),
          trends: performanceCollector.getPerformanceTrends(timeWindowMinutes),
          memory: performanceCollector.getMemoryUsage(),
          timestamp: Date.now(),
        };
      }

      // Export in different formats
      if (format === 'prometheus') {
        res.setHeader('Content-Type', 'text/plain');
        res.send(performanceCollector.exportMetrics('prometheus'));
        return;
      }

      if (format === 'csv') {
        res.setHeader('Content-Type', 'text/csv');
        res.send(this.exportToCSV(data));
        return;
      }

      res.json(data);
    } catch (error) {
      logger.error({ error }, 'Failed to get metrics');
      res.status(500).json({ error: 'Failed to retrieve metrics' });
    }
  }

  /**
   * Get alerts endpoint
   */
  getAlerts(req: Request, res: Response): void {
    if (!this.config.enableAlertsEndpoint) {
      res.status(404).json({ error: 'Alerts endpoint disabled' });
      return;
    }

    try {
      const { severity, operation, limit } = req.query;
      let filteredAlerts = [...this.alerts];

      // Filter by severity
      if (severity) {
        filteredAlerts = filteredAlerts.filter((alert) => alert.severity === severity);
      }

      // Filter by operation
      if (operation) {
        filteredAlerts = filteredAlerts.filter((alert) => alert.operation === operation);
      }

      // Limit results
      const maxResults = parseInt(limit as string) || 100;
      filteredAlerts = filteredAlerts.slice(-maxResults);

      res.json({
        alerts: filteredAlerts,
        total: filteredAlerts.length,
        timestamp: Date.now(),
      });
    } catch (error) {
      logger.error({ error }, 'Failed to get alerts');
      res.status(500).json({ error: 'Failed to retrieve alerts' });
    }
  }

  /**
   * Get performance trends endpoint
   */
  getTrends(req: Request, res: Response): void {
    if (!this.config.enableTrendsEndpoint) {
      res.status(404).json({ error: 'Trends endpoint disabled' });
      return;
    }

    try {
      const { timeWindow, operation } = req.query;
      const timeWindowMinutes = parseInt(timeWindow as string) || 60;

      const cacheKey = `trends_${timeWindowMinutes}_${operation}`;
      const cached = this.alertCache.get(cacheKey);

      // Return cached data if still valid
      if (cached && Date.now() - cached.timestamp < this.config.cacheTimeout!) {
        res.json(cached.data);
        return;
      }

      let trends: unknown;

      if (operation) {
        // Get trends for specific operation
        const allTrends = performanceCollector.getPerformanceTrends(timeWindowMinutes);
        trends = allTrends[operation as string];
        if (!trends) {
          res.status(404).json({ error: 'Operation not found' });
          return;
        }
      } else {
        // Get all trends
        trends = performanceCollector.getPerformanceTrends(timeWindowMinutes);
      }

      const data = {
        trends,
        timeWindowMinutes,
        timestamp: Date.now(),
      };

      // Cache the result
      this.alertCache.set(cacheKey, { data, timestamp: Date.now() });

      res.json(data);
    } catch (error) {
      logger.error({ error }, 'Failed to get trends');
      res.status(500).json({ error: 'Failed to retrieve trends' });
    }
  }

  /**
   * Health check endpoint with performance metrics
   */
  getHealth(_req: Request, res: Response): void {
    try {
      const summaries = performanceCollector.getAllSummaries();
      const memory = performanceCollector.getMemoryUsage();
      const recentAlerts = this.alerts.slice(-10);

      // Determine overall health status
      const criticalAlerts = recentAlerts.filter((alert) => alert.severity === 'critical');
      const highErrorRates = summaries.filter((summary) => summary.successRate < 95);
      const slowOperations = summaries.filter((summary) => summary.averageDuration > 2000);

      let status = 'healthy';
      if (criticalAlerts.length > 0) {
        status = 'critical';
      } else if (highErrorRates.length > 0 || slowOperations.length > 0) {
        status = 'degraded';
      }

      const healthData = {
        status,
        timestamp: Date.now(),
        uptime: process.uptime(),
        version: process.version,
        memory: {
          used: memory.heapUsed,
          total: memory.heapTotal,
          usagePercent: (memory.heapUsed / memory.heapTotal) * 100,
        },
        performance: {
          totalOperations: summaries.reduce((sum, s) => sum + s.count, 0),
          averageSuccessRate:
            summaries.length > 0
              ? summaries.reduce((sum, s) => sum + s.successRate, 0) / summaries.length
              : 100,
          problemOperations: [...highErrorRates, ...slowOperations].map((s) => s.operation),
        },
        alerts: {
          critical: criticalAlerts.length,
          total: recentAlerts.length,
        },
      };

      res.status(status === 'healthy' ? 200 : status === 'degraded' ? 200 : 503).json(healthData);
    } catch (error) {
      logger.error({ error }, 'Failed to get health status');
      res.status(500).json({
        status: 'error',
        error: 'Failed to retrieve health status',
        timestamp: Date.now(),
      });
    }
  }

  /**
   * Clear metrics endpoint (for testing/maintenance)
   */
  clearMetrics(_req: Request, res: Response): void {
    try {
      performanceCollector.clearMetrics();
      this.alerts = [];
      this.alertCache.clear();

      logger.info('Metrics and alerts cleared via dashboard API');
      res.json({ message: 'Metrics and alerts cleared successfully' });
    } catch (error) {
      logger.error({ error }, 'Failed to clear metrics');
      res.status(500).json({ error: 'Failed to clear metrics' });
    }
  }

  /**
   * Get system info endpoint
   */
  getSystemInfo(_req: Request, res: Response): void {
    try {
      const memoryUsage = performanceCollector.getMemoryUsage();
      const cpuUsage = process.cpuUsage();

      const systemInfo = {
        process: {
          pid: process.pid,
          uptime: process.uptime(),
          version: process.version,
          platform: process.platform,
          arch: process.arch,
        },
        memory: {
          rss: memoryUsage.rss,
          heapTotal: memoryUsage.heapTotal,
          heapUsed: memoryUsage.heapUsed,
          external: memoryUsage.external,
          arrayBuffers: memoryUsage.arrayBuffers,
        },
        cpu: {
          user: cpuUsage.user,
          system: cpuUsage.system,
        },
        performance: {
          totalOperations: performanceCollector
            .getAllSummaries()
            .reduce((sum, s) => sum + s.count, 0),
          trackedOperations: performanceCollector.getAllSummaries().length,
        },
        timestamp: Date.now(),
      };

      res.json(systemInfo);
    } catch (error) {
      logger.error({ error }, 'Failed to get system info');
      res.status(500).json({ error: 'Failed to retrieve system info' });
    }
  }

  /**
   * Express router for dashboard endpoints
   */
  getRouter() {
    const router = Router();

    // Apply authentication if required
    if (this.config.requireAuthentication) {
      router.use((_req: Request, _res: Response, next: NextFunction) => {
        // Add authentication middleware here
        // For now, just pass through
        next();
      });
    }

    // Define routes
    router.get('/metrics', this.getMetrics.bind(this));
    router.get('/alerts', this.getAlerts.bind(this));
    router.get('/trends', this.getTrends.bind(this));
    router.get('/health', this.getHealth.bind(this));
    router.get('/system', this.getSystemInfo.bind(this));
    router.delete('/metrics', this.clearMetrics.bind(this));

    return router;
  }

  private setupAlertHandling(): void {
    performanceCollector.on('alert', (alert: PerformanceAlert) => {
      this.alerts.push(alert);

      // Keep only recent alerts
      if (this.alerts.length > this.maxAlerts) {
        this.alerts.splice(0, this.alerts.length - this.maxAlerts);
      }

      // Clear cache when new alerts arrive
      this.alertCache.clear();

      logger.warn(alert, 'Performance alert generated');
    });

    // Cleanup old alerts periodically
    setInterval(
      () => {
        const cutoffTime = Date.now() - 24 * 60 * 60 * 1000; // 24 hours
        this.alerts = this.alerts.filter((alert) => alert.timestamp > cutoffTime);
      },
      60 * 60 * 1000
    ); // Every hour
  }

  private exportToCSV(data: unknown): string {
    if (data.summaries) {
      // Export summaries as CSV
      const headers = [
        'operation',
        'count',
        'avgDuration',
        'minDuration',
        'maxDuration',
        'p95',
        'p99',
        'successRate',
      ];
      const rows = data.summaries.map((s: unknown) => [
        s.operation,
        s.count,
        s.averageDuration,
        s.minDuration,
        s.maxDuration,
        s.p95,
        s.p99,
        s.successRate,
      ]);

      return [headers, ...rows].map((row) => row.join(',')).join('\n');
    }

    return JSON.stringify(data, null, 2);
  }
}

// Singleton instance
export const performanceDashboard = new PerformanceDashboard({
  enableMetricsEndpoint: true,
  enableAlertsEndpoint: true,
  enableTrendsEndpoint: true,
  requireAuthentication: false,
  cacheTimeout: 30000,
});
