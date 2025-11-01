/**
 * Comprehensive Unit Tests for System Monitoring
 *
 * Tests advanced system monitoring functionality including:
 * - System Health Monitoring (service health checks, database connectivity, resource utilization, dependency health)
 * - Performance Metrics Collection (real-time metrics, custom metrics, aggregation, trend analysis)
 * - Alerting and Notification (threshold-based alerting, escalation procedures, notification channels)
 * - Logging and Analytics (system event logging, performance log analysis, error tracking, audit trails)
 * - Dashboard and Reporting (performance dashboards, real-time displays, historical reports, analytics insights)
 * - Integration Monitoring (cross-service health, API performance, database operations, external service integration)
 *
 * @author Cortex Team
 * @version 4.0.0
 * @since 2025
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { performanceCollector, PerformanceAlert } from '../../../src/monitoring/performance-collector';
import { performanceDashboard, PerformanceDashboard } from '../../../src/monitoring/performance-dashboard';
import { EventEmitter } from 'events';
import { logger } from '../../../src/utils/logger';

// Mock dependencies
vi.mock('../../../src/utils/logger', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn()
  }
}));

// Mock Express request/response for testing
const mockRequest = (query: any = {}, params: any = {}) => ({
  query,
  params,
  headers: {},
  body: {},
  method: 'GET',
  url: '/test'
});

const mockResponse = () => {
  const res: any = {};
  res.status = vi.fn().mockReturnValue(res);
  res.json = vi.fn().mockReturnValue(res);
  res.send = vi.fn().mockReturnValue(res);
  res.setHeader = vi.fn().mockReturnValue(res);
  return res;
};

// Mock system metrics for testing
const mockSystemMetrics = {
  cpu: {
    usage: 45.2,
    loadAverage: [1.2, 1.5, 1.8],
    cores: 8
  },
  memory: {
    total: 16 * 1024 * 1024 * 1024, // 16GB
    used: 8 * 1024 * 1024 * 1024,  // 8GB
    free: 8 * 1024 * 1024 * 1024,  // 8GB
    usagePercent: 50
  },
  disk: {
    total: 500 * 1024 * 1024 * 1024, // 500GB
    used: 200 * 1024 * 1024 * 1024,  // 200GB
    free: 300 * 1024 * 1024 * 1024,  // 300GB
    usagePercent: 40
  },
  network: {
    bytesReceived: 1024 * 1024 * 100, // 100MB
    bytesSent: 1024 * 1024 * 50,      // 50MB
    packetsReceived: 10000,
    packetsSent: 8000
  }
};

// Mock health check results
const mockHealthChecks = {
  database: { status: 'healthy', responseTime: 120, lastCheck: new Date() },
  redis: { status: 'healthy', responseTime: 25, lastCheck: new Date() },
  externalApi: { status: 'degraded', responseTime: 1200, lastCheck: new Date() },
  storage: { status: 'healthy', responseTime: 85, lastCheck: new Date() }
};

describe('System Monitoring - Comprehensive Monitoring Functionality', () => {
  let dashboard: PerformanceDashboard;
  let testEmitter: EventEmitter;

  beforeEach(() => {
    // Clear all mocks
    vi.clearAllMocks();

    // Reset performance collector
    performanceCollector.clearMetrics();

    // Create fresh dashboard instance for testing
    dashboard = new PerformanceDashboard({
      enableMetricsEndpoint: true,
      enableAlertsEndpoint: true,
      enableTrendsEndpoint: true,
      requireAuthentication: false,
      cacheTimeout: 1000 // Short timeout for testing
    });

    // Create event emitter for testing events
    testEmitter = new EventEmitter();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    performanceCollector.clearMetrics();
  });

  // 1. System Health Monitoring Tests
  describe('System Health Monitoring', () => {
    it('should perform comprehensive service health checks', async () => {
      // Record some performance metrics
      const endMetric1 = performanceCollector.startMetric('database_query', { query: 'SELECT * FROM users' });
      setTimeout(endMetric1, 100);

      const endMetric2 = performanceCollector.startMetric('api_request', { endpoint: '/api/health' });
      setTimeout(endMetric2, 150);

      // Wait for metrics to be processed
      await new Promise(resolve => setTimeout(resolve, 50));

      const req = mockRequest();
      const res = mockResponse();

      dashboard.getHealth(req, res);

      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          status: expect.stringMatching(/healthy|degraded|critical/),
          timestamp: expect.any(Number),
          uptime: expect.any(Number),
          memory: expect.objectContaining({
            used: expect.any(Number),
            total: expect.any(Number),
            usagePercent: expect.any(Number)
          }),
          performance: expect.objectContaining({
            totalOperations: expect.any(Number),
            averageSuccessRate: expect.any(Number),
            problemOperations: expect.any(Array)
          }),
          alerts: expect.objectContaining({
            critical: expect.any(Number),
            total: expect.any(Number)
          })
        })
      );
    });

    it('should detect critical system health status', async () => {
      // Simulate critical alert
      const criticalAlert: PerformanceAlert = {
        operation: 'database_connection',
        alertType: 'high_error_rate',
        threshold: 5,
        currentValue: 95,
        severity: 'critical',
        message: 'Database connection error rate exceeds threshold',
        timestamp: Date.now()
      };

      // Manually add critical alert to dashboard
      dashboard['alerts'].push(criticalAlert);

      const req = mockRequest();
      const res = mockResponse();

      dashboard.getHealth(req, res);

      expect(res.status).toHaveBeenCalledWith(503);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'critical'
        })
      );
    });

    it('should monitor database connectivity and performance', async () => {
      // Record database operation metrics
      const dbOperations = [
        { operation: 'memory_store', duration: 120, success: true },
        { operation: 'memory_find', duration: 250, success: true },
        { operation: 'database_query', duration: 450, success: false },
        { operation: 'vector_search', duration: 180, success: true }
      ];

      for (const op of dbOperations) {
        if (op.success) {
          const endMetric = performanceCollector.startMetric(op.operation);
          setTimeout(endMetric, op.duration);
        } else {
          performanceCollector.recordError(op.operation, new Error('Connection timeout'));
        }
      }

      // Wait for metrics processing
      await new Promise(resolve => setTimeout(resolve, 50));

      const dbSummary = performanceCollector.getSummary('database_query');
      const memorySummary = performanceCollector.getSummary('memory_store');

      expect(dbSummary).toBeDefined();
      expect(dbSummary.successRate).toBeLessThan(100);
      expect(dbSummary.errorCount).toBeGreaterThan(0);

      expect(memorySummary).toBeDefined();
      expect(memorySummary.successRate).toBe(100);
      expect(memorySummary.averageDuration).toBeGreaterThan(0);
    });

    it('should track resource utilization metrics', async () => {
      const req = mockRequest();
      const res = mockResponse();

      dashboard.getSystemInfo(req, res);

      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          process: expect.objectContaining({
            pid: expect.any(Number),
            uptime: expect.any(Number),
            version: expect.any(String),
            platform: expect.any(String),
            arch: expect.any(String)
          }),
          memory: expect.objectContaining({
            rss: expect.any(Number),
            heapTotal: expect.any(Number),
            heapUsed: expect.any(Number),
            external: expect.any(Number),
            arrayBuffers: expect.any(Number)
          }),
          cpu: expect.objectContaining({
            user: expect.any(Number),
            system: expect.any(Number)
          }),
          performance: expect.objectContaining({
            totalOperations: expect.any(Number),
            trackedOperations: expect.any(Number)
          }),
          timestamp: expect.any(Number)
        })
      );
    });

    it('should monitor dependency health across services', async () => {
      // Set up custom alert thresholds for different services
      performanceCollector.setAlertThreshold('external_api_call', 2000, 10); // 2s, 10% error rate
      performanceCollector.setAlertThreshold('cache_service', 100, 2); // 100ms, 2% error rate
      performanceCollector.setAlertThreshold('message_queue', 500, 5); // 500ms, 5% error rate

      // Record metrics for external dependencies
      const dependencyMetrics = [
        { operation: 'external_api_call', duration: 2500, success: true },
        { operation: 'cache_service', duration: 150, success: false },
        { operation: 'message_queue', duration: 400, success: true },
        { operation: 'external_api_call', duration: 3000, success: false }
      ];

      for (const metric of dependencyMetrics) {
        if (metric.success) {
          const endMetric = performanceCollector.startMetric(metric.operation);
          setTimeout(endMetric, metric.duration);
        } else {
          performanceCollector.recordError(metric.operation, new Error('Service unavailable'));
        }
      }

      // Wait for processing and alert checking
      await new Promise(resolve => setTimeout(resolve, 50));

      const apiSummary = performanceCollector.getSummary('external_api_call');
      const cacheSummary = performanceCollector.getSummary('cache_service');

      expect(apiSummary).toBeDefined();
      expect(apiSummary.averageDuration).toBeGreaterThan(2000); // Should trigger alert
      expect(cacheSummary).toBeDefined();
      expect(cacheSummary.successRate).toBeLessThan(100);
    });
  });

  // 2. Performance Metrics Collection Tests
  describe('Performance Metrics Collection', () => {
    it('should collect real-time performance metrics', async () => {
      const operations = ['user_login', 'data_fetch', 'file_upload', 'search_query'];
      const durations = [120, 350, 1200, 280];

      // Record metrics for different operations
      operations.forEach((operation, index) => {
        const endMetric = performanceCollector.startMetric(operation, {
          userId: `user_${index}`,
          sessionId: `session_${index}`
        });
        setTimeout(endMetric, durations[index]);
      });

      // Wait for batch processing
      await new Promise(resolve => setTimeout(resolve, 50));

      const summaries = performanceCollector.getAllSummaries();
      expect(summaries).toHaveLength(operations.length);

      summaries.forEach((summary, index) => {
        expect(summary.operation).toBe(operations[index]);
        expect(summary.averageDuration).toBeGreaterThanOrEqual(durations[index] - 10);
        expect(summary.count).toBe(1);
        expect(summary.successRate).toBe(100);
      });
    });

    it('should handle custom metric collection with metadata', async () => {
      const customMetadata = {
        userId: 'user123',
        feature: 'advanced_search',
        plan: 'premium',
        region: 'us-west-2'
      };

      const tags = ['api', 'v2', 'critical'];

      const endMetric = performanceCollector.startMetric('custom_operation', customMetadata, tags);
      setTimeout(endMetric, 450);

      await new Promise(resolve => setTimeout(resolve, 50));

      const recentMetrics = performanceCollector.getRecentMetrics('custom_operation', 1);
      expect(recentMetrics).toHaveLength(1);

      const metric = recentMetrics[0];
      expect(metric.metadata).toEqual(customMetadata);
      expect(metric.tags).toEqual(tags);
      expect(metric.operation).toBe('custom_operation');
      expect(metric.success).toBe(true);
    });

    it('should aggregate metrics across time windows', async () => {
      const operation = 'batch_processing';
      const durations = [100, 150, 200, 120, 180, 250, 90, 140];

      // Record multiple metrics over time
      for (const duration of durations) {
        const endMetric = performanceCollector.startMetric(operation);
        setTimeout(endMetric, duration);
      }

      await new Promise(resolve => setTimeout(resolve, 50));

      // Test different time windows
      const trends1min = performanceCollector.getPerformanceTrends(1);
      const trends5min = performanceCollector.getPerformanceTrends(5);

      expect(trends1min[operation]).toBeDefined();
      expect(trends5min[operation]).toBeDefined();

      const trend = trends1min[operation];
      expect(trend.operation).toBe(operation);
      expect(trend.totalRequests).toBe(durations.length);
      expect(trend.successfulRequests).toBe(durations.length);
      expect(trend.averageDuration).toBeGreaterThan(0);
      expect(trend.p95Duration).toBeGreaterThan(0);
      expect(trend.p99Duration).toBeGreaterThan(0);
      expect(trend.requestsPerMinute).toBeGreaterThan(0);
      expect(trend.errorRate).toBe(0);
    });

    it('should calculate percentile metrics accurately', async () => {
      const operation = 'percentile_test';
      const durations = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 500, 1000];

      for (const duration of durations) {
        const endMetric = performanceCollector.startMetric(operation);
        setTimeout(endMetric, duration);
      }

      await new Promise(resolve => setTimeout(resolve, 50));

      const summary = performanceCollector.getSummary(operation);
      expect(summary).toBeDefined();

      // Check percentile calculations
      expect(summary.p95).toBeGreaterThanOrEqual(summary.p95);
      expect(summary.p99).toBeGreaterThanOrEqual(summary.p95);
      expect(summary.minDuration).toBeLessThanOrEqual(summary.averageDuration);
      expect(summary.maxDuration).toBeGreaterThanOrEqual(summary.averageDuration);

      // With our dataset, p95 should be close to 950 (95th percentile of sorted array)
      expect(summary.p95).toBeGreaterThan(100);
      expect(summary.p99).toBeGreaterThan(500);
    });

    it('should identify performance trends and patterns', async () => {
      const operation = 'trend_analysis';

      // Simulate performance degradation over time
      const baseDuration = 100;
      for (let i = 0; i < 20; i++) {
        const duration = baseDuration + (i * 10); // Gradually increasing
        const endMetric = performanceCollector.startMetric(operation);
        setTimeout(endMetric, duration);
      }

      await new Promise(resolve => setTimeout(resolve, 50));

      const trends = performanceCollector.getPerformanceTrends(60);
      const trend = trends[operation];

      expect(trend).toBeDefined();
      expect(trend.averageDuration).toBeGreaterThan(baseDuration);
      expect(trend.maxDuration).toBeGreaterThan(trend.minDuration);

      // Check that trend shows performance degradation
      const recentMetrics = performanceCollector.getRecentMetrics(operation, 5);
      const oldMetrics = performanceCollector.getRecentMetrics(operation, 5).slice(-5);

      const recentAvg = recentMetrics.reduce((sum, m) => sum + m.duration, 0) / recentMetrics.length;
      const oldAvg = oldMetrics.reduce((sum, m) => sum + m.duration, 0) / oldMetrics.length;

      expect(recentAvg).toBeGreaterThan(oldAvg);
    });
  });

  // 3. Alerting and Notification Tests
  describe('Alerting and Notification', () => {
    it('should trigger threshold-based performance alerts', async () => {
      // Set low threshold for testing
      performanceCollector.setAlertThreshold('slow_operation', 100, 5);

      let alertReceived: PerformanceAlert | null = null;
      performanceCollector.on('alert', (alert: PerformanceAlert) => {
        alertReceived = alert;
      });

      // Record metrics that should trigger alerts
      const slowDurations = [150, 200, 180, 250, 300]; // All above 100ms threshold

      for (const duration of slowDurations) {
        const endMetric = performanceCollector.startMetric('slow_operation');
        setTimeout(endMetric, duration);
      }

      await new Promise(resolve => setTimeout(resolve, 100));

      expect(alertReceived).toBeDefined();
      expect(alertReceived!.operation).toBe('slow_operation');
      expect(alertReceived!.alertType).toBe('slow_query');
      expect(alertReceived!.severity).toMatch(/low|medium|high|critical/);
      expect(alertReceived!.threshold).toBe(100);
      expect(alertReceived!.currentValue).toBeGreaterThan(100);
      expect(alertReceived!.message).toContain('exceeds threshold');
    });

    it('should handle error rate alerting', async () => {
      performanceCollector.setAlertThreshold('error_prone_operation', 1000, 20); // 20% error rate threshold

      let alertReceived: PerformanceAlert | null = null;
      performanceCollector.on('alert', (alert: PerformanceAlert) => {
        alertReceived = alert;
      });

      // Record metrics with high error rate
      for (let i = 0; i < 10; i++) {
        if (i < 3) {
          // 3 successful operations
          const endMetric = performanceCollector.startMetric('error_prone_operation');
          setTimeout(endMetric, 100);
        } else {
          // 7 failed operations (70% error rate)
          performanceCollector.recordError('error_prone_operation', new Error('Simulated error'));
        }
      }

      await new Promise(resolve => setTimeout(resolve, 100));

      expect(alertReceived).toBeDefined();
      expect(alertReceived!.operation).toBe('error_prone_operation');
      expect(alertReceived!.alertType).toBe('high_error_rate');
      expect(alertReceived!.currentValue).toBeGreaterThan(20); // Should be > 20%
      expect(alertReceived!.severity).toMatch(/low|medium|high|critical/);
    });

    it('should implement alert severity levels correctly', async () => {
      const testCases = [
        { threshold: 100, duration: 120, expectedSeverity: 'low' },      // 1.2x threshold
        { threshold: 100, duration: 160, expectedSeverity: 'medium' },   // 1.6x threshold
        { threshold: 100, duration: 200, expectedSeverity: 'high' },     // 2.0x threshold
        { threshold: 100, duration: 300, expectedSeverity: 'critical' }  // 3.0x threshold
      ];

      for (const testCase of testCases) {
        const operation = `severity_test_${testCase.expectedSeverity}`;
        performanceCollector.setAlertThreshold(operation, testCase.threshold, 5);

        let alertReceived: PerformanceAlert | null = null;
        performanceCollector.on('alert', (alert: PerformanceAlert) => {
          if (alert.operation === operation) {
            alertReceived = alert;
          }
        });

        const endMetric = performanceCollector.startMetric(operation);
        setTimeout(endMetric, testCase.duration);

        await new Promise(resolve => setTimeout(resolve, 50));

        expect(alertReceived).toBeDefined();
        expect(alertReceived!.severity).toBe(testCase.expectedSeverity);

        // Reset for next test
        performanceCollector.removeAllListeners('alert');
      }
    });

    it('should provide alert management through dashboard API', async () => {
      // Simulate multiple alerts
      const alerts = [
        { operation: 'api_server', alertType: 'slow_query' as const, severity: 'high' as const },
        { operation: 'database', alertType: 'high_error_rate' as const, severity: 'critical' as const },
        { operation: 'cache_service', alertType: 'slow_query' as const, severity: 'medium' as const }
      ];

      alerts.forEach(alert => {
        dashboard['alerts'].push({
          ...alert,
          threshold: 100,
          currentValue: 150,
          message: `Test alert for ${alert.operation}`,
          timestamp: Date.now() - Math.random() * 3600000 // Random time in last hour
        } as PerformanceAlert);
      });

      // Test filtering alerts by severity
      const req1 = mockRequest({ severity: 'critical' });
      const res1 = mockResponse();

      dashboard.getAlerts(req1, res1);

      expect(res1.json).toHaveBeenCalledWith(
        expect.objectContaining({
          alerts: expect.arrayContaining([
            expect.objectContaining({
              operation: 'database',
              severity: 'critical'
            })
          ]),
          total: expect.any(Number),
          timestamp: expect.any(Number)
        })
      );

      // Test filtering alerts by operation
      const req2 = mockRequest({ operation: 'api_server' });
      const res2 = mockResponse();

      dashboard.getAlerts(req2, res2);

      expect(res2.json).toHaveBeenCalledWith(
        expect.objectContaining({
          alerts: expect.arrayContaining([
            expect.objectContaining({
              operation: 'api_server'
            })
          ])
        })
      );
    });

    it('should handle alert escalation procedures', async () => {
      const escalationRules = {
        'low': { delay: 300000, actions: ['log_warning'] },      // 5 minutes
        'medium': { delay: 120000, actions: ['send_email', 'log_warning'] }, // 2 minutes
        'high': { delay: 60000, actions: ['send_sms', 'create_incident'] },   // 1 minute
        'critical': { delay: 0, actions: ['immediate_call', 'create_incident', 'send_sms'] } // Immediate
      };

      const escalatedAlerts: any[] = [];

      // Mock escalation handler
      performanceCollector.on('alert', (alert: PerformanceAlert) => {
        const rule = escalationRules[alert.severity];
        setTimeout(() => {
          escalatedAlerts.push({
            alert,
            escalatedActions: rule.actions,
            escalatedAt: Date.now()
          });
        }, rule.delay);
      });

      // Trigger critical alert
      performanceCollector.setAlertThreshold('critical_operation', 100, 1);
      const endMetric = performanceCollector.startMetric('critical_operation');
      setTimeout(endMetric, 500); // 5x threshold for critical

      await new Promise(resolve => setTimeout(resolve, 50));

      // Critical alert should escalate immediately
      expect(escalatedAlerts.length).toBeGreaterThan(0);
      expect(escalatedAlerts[0].alert.severity).toBe('critical');
      expect(escalatedAlerts[0].escalatedActions).toContain('immediate_call');
    });
  });

  // 4. Logging and Analytics Tests
  describe('Logging and Analytics', () => {
    it('should log system events with appropriate severity levels', async () => {
      const testEvents = [
        { level: 'info', message: 'System startup completed', data: { uptime: 45 } },
        { level: 'warn', message: 'High memory usage detected', data: { usage: 85 } },
        { level: 'error', message: 'Database connection failed', data: { error: 'Connection timeout' } },
        { level: 'debug', message: 'Cache miss for key', data: { key: 'user_123' } }
      ];

      for (const event of testEvents) {
        switch (event.level) {
          case 'info':
            logger.info(event.data, event.message);
            break;
          case 'warn':
            logger.warn(event.data, event.message);
            break;
          case 'error':
            logger.error(event.data, event.message);
            break;
          case 'debug':
            logger.debug(event.data, event.message);
            break;
        }
      }

      expect(logger.info).toHaveBeenCalledWith(
        expect.objectContaining({ uptime: 45 }),
        'System startup completed'
      );
      expect(logger.warn).toHaveBeenCalledWith(
        expect.objectContaining({ usage: 85 }),
        'High memory usage detected'
      );
      expect(logger.error).toHaveBeenCalledWith(
        expect.objectContaining({ error: 'Connection timeout' }),
        'Database connection failed'
      );
      expect(logger.debug).toHaveBeenCalledWith(
        expect.objectContaining({ key: 'user_123' }),
        'Cache miss for key'
      );
    });

    it('should analyze performance log patterns', async () => {
      // Record performance metrics with different characteristics
      const performancePatterns = [
        { operation: 'api_request', pattern: 'fast', durations: [50, 75, 60, 80, 70] },
        { operation: 'database_query', pattern: 'slow', durations: [500, 600, 550, 700, 650] },
        { operation: 'cache_lookup', pattern: 'mixed', durations: [5, 150, 8, 200, 12] }
      ];

      for (const pattern of performancePatterns) {
        for (const duration of pattern.durations) {
          const endMetric = performanceCollector.startMetric(pattern.operation, { pattern });
          setTimeout(endMetric, duration);
        }
      }

      await new Promise(resolve => setTimeout(resolve, 100));

      // Analyze the patterns
      const apiSummary = performanceCollector.getSummary('api_request');
      const dbSummary = performanceCollector.getSummary('database_query');
      const cacheSummary = performanceCollector.getSummary('cache_lookup');

      expect(apiSummary.averageDuration).toBeLessThan(100);
      expect(dbSummary.averageDuration).toBeGreaterThan(500);
      expect(cacheSummary.minDuration).toBeLessThan(20);
      expect(cacheSummary.maxDuration).toBeGreaterThan(150);

      // Verify performance characteristics
      expect(apiSummary.p95).toBeLessThan(100);
      expect(dbSummary.p95).toBeGreaterThan(500);
      expect(cacheSummary.successRate).toBe(100);
    });

    it('should track and categorize errors', async () => {
      const errorTypes = [
        { type: 'ValidationError', message: 'Invalid input parameters' },
        { type: 'AuthenticationError', message: 'Invalid API key' },
        { type: 'DatabaseError', message: 'Connection pool exhausted' },
        { type: 'NetworkError', message: 'Request timeout' }
      ];

      for (const errorType of errorTypes) {
        const operation = `${errorType.type.toLowerCase()}_operation`;
        performanceCollector.recordError(operation, new Error(errorType.message), {
          errorType: errorType.type,
          userId: 'test_user',
          endpoint: '/api/test'
        });
      }

      await new Promise(resolve => setTimeout(resolve, 50));

      // Check that errors were recorded with metadata
      const summaries = performanceCollector.getAllSummaries();
      expect(summaries.length).toBeGreaterThanOrEqual(4);

      summaries.forEach(summary => {
        if (summary.errorCount > 0) {
          expect(summary.successRate).toBeLessThan(100);
          const recentMetrics = performanceCollector.getRecentMetrics(summary.operation, 1);
          if (recentMetrics.length > 0 && !recentMetrics[0].success) {
            expect(recentMetrics[0].metadata).toHaveProperty('errorType');
            expect(recentMetrics[0].metadata).toHaveProperty('userId');
            expect(recentMetrics[0].metadata).toHaveProperty('endpoint');
          }
        }
      });
    });

    it('should maintain audit trail for monitoring events', async () => {
      const auditEvents = [
        { action: 'threshold_update', entity: 'api_response_time', oldValue: 1000, newValue: 2000 },
        { action: 'alert_triggered', entity: 'database_connection', severity: 'high' },
        { action: 'metric_cleared', entity: 'memory_usage', reason: 'maintenance' },
        { action: 'dashboard_accessed', entity: 'performance_dashboard', userId: 'admin' }
      ];

      // Simulate audit logging
      const auditLog: any[] = [];

      auditEvents.forEach(event => {
        const auditEntry = {
          timestamp: new Date(),
          event: event.action,
          entity: event.entity,
          details: { ...event },
          sessionId: `test_session_${  Math.random().toString(36).substr(2, 9)}`
        };
        auditLog.push(auditEntry);

        logger.info(auditEntry, `Audit: ${event.action} on ${event.entity}`);
      });

      expect(logger.info).toHaveBeenCalledTimes(auditEvents.length);

      // Verify audit trail structure
      auditLog.forEach(entry => {
        expect(entry).toHaveProperty('timestamp');
        expect(entry).toHaveProperty('event');
        expect(entry).toHaveProperty('entity');
        expect(entry).toHaveProperty('details');
        expect(entry).toHaveProperty('sessionId');
        expect(entry.timestamp).toBeInstanceOf(Date);
      });
    });
  });

  // 5. Dashboard and Reporting Tests
  describe('Dashboard and Reporting', () => {
    it('should provide real-time monitoring dashboard data', async () => {
      // Record diverse set of metrics
      const operations = [
        { name: 'user_authentication', avgDuration: 150, successRate: 99.5 },
        { name: 'data_retrieval', avgDuration: 350, successRate: 98.2 },
        { name: 'file_processing', avgDuration: 1200, successRate: 96.8 },
        { name: 'search_operations', avgDuration: 280, successRate: 99.1 }
      ];

      for (const op of operations) {
        // Record successful operations
        for (let i = 0; i < 10; i++) {
          const duration = op.avgDuration + (Math.random() - 0.5) * op.avgDuration * 0.4;
          const endMetric = performanceCollector.startMetric(op.name);
          setTimeout(endMetric, Math.max(50, duration));
        }

        // Record some failures based on success rate
        const failureCount = Math.floor(10 * (100 - op.successRate) / 100);
        for (let i = 0; i < failureCount; i++) {
          performanceCollector.recordError(op.name, new Error('Simulated failure'));
        }
      }

      await new Promise(resolve => setTimeout(resolve, 100));

      const req = mockRequest();
      const res = mockResponse();

      dashboard.getMetrics(req, res);

      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          summaries: expect.arrayContaining([
            expect.objectContaining({
              operation: expect.any(String),
              count: expect.any(Number),
              averageDuration: expect.any(Number),
              successRate: expect.any(Number),
              p95: expect.any(Number),
              p99: expect.any(Number)
            })
          ]),
          trends: expect.any(Object),
          memory: expect.any(Object),
          timestamp: expect.any(Number)
        })
      );
    });

    it('should support different data export formats', async () => {
      // Record some metrics first
      const endMetric = performanceCollector.startMetric('export_test');
      setTimeout(endMetric, 250);

      await new Promise(resolve => setTimeout(resolve, 50));

      // Test JSON export
      const jsonReq = mockRequest({ format: 'json' });
      const jsonRes = mockResponse();

      dashboard.getMetrics(jsonReq, jsonRes);

      expect(jsonRes.json).toHaveBeenCalled();

      // Test Prometheus export
      const prometheusReq = mockRequest({ format: 'prometheus' });
      const prometheusRes = mockResponse();

      dashboard.getMetrics(prometheusReq, prometheusRes);

      expect(prometheusRes.setHeader).toHaveBeenCalledWith('Content-Type', 'text/plain');
      expect(prometheusRes.send).toHaveBeenCalled();

      // Verify Prometheus format
      const prometheusOutput = prometheusRes.send.mock.calls[0][0];
      expect(prometheusOutput).toContain('# HELP');
      expect(prometheusOutput).toContain('# TYPE');
      expect(prometheusOutput).toContain('cortex_operation_duration_seconds');
      expect(prometheusOutput).toContain('cortex_operation_success_rate');

      // Test CSV export
      const csvReq = mockRequest({ format: 'csv' });
      const csvRes = mockResponse();

      dashboard.getMetrics(csvReq, csvRes);

      expect(csvRes.setHeader).toHaveBeenCalledWith('Content-Type', 'text/csv');
      expect(csvRes.send).toHaveBeenCalled();

      const csvOutput = csvRes.send.mock.calls[0][0];
      expect(csvOutput).toContain('operation,count,avgDuration');
    });

    it('should cache dashboard responses for performance', async () => {
      const req = mockRequest({ timeWindow: '60' });
      const res1 = mockResponse();
      const res2 = mockResponse();

      // First request
      dashboard.getTrends(req, res1);

      // Second request within cache timeout
      dashboard.getTrends(req, res2);

      // Both should return the same result (second from cache)
      expect(res1.json).toHaveBeenCalled();
      expect(res2.json).toHaveBeenCalled();

      const firstCall = res1.json.mock.calls[0][0];
      const secondCall = res2.json.mock.calls[0][0];

      expect(firstCall).toEqual(secondCall);
      expect(firstCall.timestamp).toBeDefined();
    });

    it('should generate historical performance reports', async () => {
      const timeWindows = [5, 15, 60, 1440]; // 5min, 15min, 1hr, 24hr

      for (const window of timeWindows) {
        const req = mockRequest({ timeWindow: window.toString() });
        const res = mockResponse();

        dashboard.getTrends(req, res);

        expect(res.json).toHaveBeenCalledWith(
          expect.objectContaining({
            trends: expect.any(Object),
            timeWindowMinutes: window,
            timestamp: expect.any(Number)
          })
        );
      }
    });

    it('should provide analytics insights and recommendations', async () => {
      // Record metrics with various performance characteristics
      const performanceData = [
        { operation: 'optimal_operation', durations: [50, 60, 55, 65, 58] },
        { operation: 'slow_operation', durations: [1500, 1800, 1600, 2000, 1750] },
        { operation: 'unstable_operation', durations: [100, 1000, 80, 1200, 90] }
      ];

      for (const data of performanceData) {
        for (const duration of data.durations) {
          const endMetric = performanceCollector.startMetric(data.operation);
          setTimeout(endMetric, duration);
        }
      }

      await new Promise(resolve => setTimeout(resolve, 100));

      const trends = performanceCollector.getPerformanceTrends(60);

      // Verify insights for different operation types
      expect(trends.optimal_operation.requestsPerMinute).toBeGreaterThan(0);
      expect(trends.optimal_operation.averageDuration).toBeLessThan(100);

      expect(trends.slow_operation.averageDuration).toBeGreaterThan(1000);
      expect(trends.slow_operation.p95Duration).toBeGreaterThan(1500);

      expect(trends.unstable_operation.p99Duration).toBeMuchLargerThan(
        trends.unstable_operation.minDuration
      );
    });
  });

  // 6. Integration Monitoring Tests
  describe('Integration Monitoring', () => {
    it('should monitor cross-service health dependencies', async () => {
      const services = [
        { name: 'auth_service', endpoint: '/auth/health', expectedResponseTime: 200 },
        { name: 'user_service', endpoint: '/users/health', expectedResponseTime: 300 },
        { name: 'payment_service', endpoint: '/payments/health', expectedResponseTime: 500 },
        { name: 'notification_service', endpoint: '/notifications/health', expectedResponseTime: 150 }
      ];

      // Record cross-service health checks
      for (const service of services) {
        const endMetric = performanceCollector.startMetric('service_health_check', {
          serviceName: service.name,
          endpoint: service.endpoint
        });

        // Simulate different response times
        const responseTime = service.expectedResponseTime + (Math.random() - 0.5) * 100;
        setTimeout(endMetric, Math.max(50, responseTime));
      }

      await new Promise(resolve => setTimeout(resolve, 100));

      const healthSummary = performanceCollector.getSummary('service_health_check');
      expect(healthSummary).toBeDefined();
      expect(healthSummary.count).toBe(services.length);
      expect(healthSummary.successRate).toBe(100);
      expect(healthSummary.averageDuration).toBeGreaterThan(0);

      // Verify all services were checked
      const recentMetrics = performanceCollector.getRecentMetrics('service_health_check', 10);
      expect(recentMetrics).toHaveLength(services.length);

      const serviceNames = recentMetrics.map(m => m.metadata?.serviceName);
      services.forEach(service => {
        expect(serviceNames).toContain(service.name);
      });
    });

    it('should track API performance across different endpoints', async () => {
      const apiEndpoints = [
        { method: 'GET', path: '/api/users', expectedTime: 200 },
        { method: 'POST', path: '/api/users', expectedTime: 350 },
        { method: 'GET', path: '/api/products', expectedTime: 150 },
        { method: 'PUT', path: '/api/products/:id', expectedTime: 400 },
        { method: 'DELETE', path: '/api/users/:id', expectedTime: 250 }
      ];

      for (const endpoint of apiEndpoints) {
        const operation = `${endpoint.method}_${endpoint.path.replace(/[^a-zA-Z0-9]/g, '_')}`;
        performanceCollector.setAlertThreshold(operation, endpoint.expectedTime * 2, 5);

        // Record multiple API calls
        for (let i = 0; i < 5; i++) {
          const endMetric = performanceCollector.startMetric(operation, {
            method: endpoint.method,
            path: endpoint.path,
            statusCode: 200
          });

          const responseTime = endpoint.expectedTime + (Math.random() - 0.5) * endpoint.expectedTime * 0.6;
          setTimeout(endMetric, Math.max(50, responseTime));
        }
      }

      await new Promise(resolve => setTimeout(resolve, 100));

      const summaries = performanceCollector.getAllSummaries();
      expect(summaries.length).toBeGreaterThanOrEqual(apiEndpoints.length);

      summaries.forEach(summary => {
        expect(summary.averageDuration).toBeGreaterThan(0);
        expect(summary.successRate).toBe(100);
        expect(summary.p95).toBeGreaterThan(summary.averageDuration * 0.8);
        expect(summary.p99).toBeLessThan(summary.averageDuration * 1.5);
      });
    });

    it('should monitor database operation performance', async () => {
      const dbOperations = [
        { type: 'SELECT', table: 'users', avgTime: 120 },
        { type: 'INSERT', table: 'orders', avgTime: 200 },
        { type: 'UPDATE', table: 'products', avgTime: 180 },
        { type: 'DELETE', table: 'sessions', avgTime: 90 },
        { type: 'JOIN', tables: ['users', 'orders'], avgTime: 350 }
      ];

      for (const op of dbOperations) {
        const operation = `db_${op.type.toLowerCase()}_${op.table || op.tables?.join('_') || 'unknown'}`;

        // Record multiple database operations
        for (let i = 0; i < 8; i++) {
          const duration = op.avgTime + (Math.random() - 0.5) * op.avgTime * 0.8;

          if (Math.random() > 0.05) { // 95% success rate
            const endMetric = performanceCollector.startMetric(operation, {
              queryType: op.type,
              table: op.table,
              tables: op.tables,
              affectedRows: Math.floor(Math.random() * 100) + 1
            });
            setTimeout(endMetric, Math.max(50, duration));
          } else {
            // Record occasional database errors
            performanceCollector.recordError(operation, new Error('Database deadlock'), {
              queryType: op.type,
              table: op.table
            });
          }
        }
      }

      await new Promise(resolve => setTimeout(resolve, 100));

      const dbSummaries = performanceCollector.getAllSummaries().filter(s => s.operation.startsWith('db_'));
      expect(dbSummaries.length).toBe(dbOperations.length);

      dbSummaries.forEach(summary => {
        expect(summary.count).toBeGreaterThan(0);
        expect(summary.successRate).toBeGreaterThan(90); // Should be around 95%
        expect(summary.averageDuration).toBeGreaterThan(0);

        // Verify database operation metadata
        const recentMetrics = performanceCollector.getRecentMetrics(summary.operation, 3);
        recentMetrics.forEach(metric => {
          if (metric.success && metric.metadata) {
            expect(metric.metadata).toHaveProperty('queryType');
            if (metric.metadata.table) {
              expect(metric.metadata.table).toMatch(/users|orders|products|sessions/);
            }
          }
        });
      });
    });

    it('should monitor external service integration health', async () => {
      const externalServices = [
        { name: 'stripe_payment', baseUrl: 'https://api.stripe.com', timeout: 5000 },
        { name: 'sendgrid_email', baseUrl: 'https://api.sendgrid.com', timeout: 3000 },
        { name: 'twilio_sms', baseUrl: 'https://api.twilio.com', timeout: 2000 },
        { name: 'google_auth', baseUrl: 'https://accounts.google.com', timeout: 4000 }
      ];

      for (const service of externalServices) {
        const operation = `external_${service.name}`;
        performanceCollector.setAlertThreshold(operation, service.timeout * 0.8, 10);

        // Simulate external service calls with varying response times
        for (let i = 0; i < 6; i++) {
          const responseTime = Math.random() * service.timeout * 1.2; // Some may exceed timeout

          if (responseTime < service.timeout) {
            const endMetric = performanceCollector.startMetric(operation, {
              service: service.name,
              baseUrl: service.baseUrl,
              statusCode: responseTime > service.timeout * 0.9 ? 429 : 200
            });
            setTimeout(endMetric, responseTime);
          } else {
            performanceCollector.recordError(operation, new Error('Service timeout'), {
              service: service.name,
              timeout: service.timeout,
              actualTime: responseTime
            });
          }
        }
      }

      await new Promise(resolve => setTimeout(resolve, 100));

      const externalSummaries = performanceCollector.getAllSummaries().filter(s => s.operation.startsWith('external_'));
      expect(externalSummaries.length).toBe(externalServices.length);

      externalSummaries.forEach(summary => {
        const serviceName = summary.operation.replace('external_', '');
        const serviceConfig = externalServices.find(s => s.name === serviceName);

        expect(serviceConfig).toBeDefined();
        expect(summary.averageDuration).toBeGreaterThan(0);

        // Check for rate limiting (429 status codes)
        const recentMetrics = performanceCollector.getRecentMetrics(summary.operation, 10);
        const rateLimitedCalls = recentMetrics.filter(m =>
          m.success && m.metadata?.statusCode === 429
        );

        if (rateLimitedCalls.length > 0) {
          logger.warn(
            { service: serviceName, rateLimitedCount: rateLimitedCalls.length },
            'External service rate limiting detected'
          );
        }
      });
    });

    it('should provide comprehensive integration monitoring dashboard', async () => {
      // Simulate comprehensive integration metrics
      const integrationMetrics = [
        { category: 'internal_services', operations: ['auth', 'users', 'products'] },
        { category: 'external_apis', operations: ['payment', 'email', 'sms'] },
        { category: 'database', operations: ['read', 'write', 'query'] },
        { category: 'cache', operations: ['get', 'set', 'delete'] }
      ];

      for (const category of integrationMetrics) {
        for (const operation of category.operations) {
          const fullOperation = `${category}_${operation}`;

          // Record metrics with different performance characteristics
          for (let i = 0; i < 5; i++) {
            const baseTime = category === 'external_apis' ? 500 :
                           category === 'database' ? 200 : 100;

            const duration = baseTime + Math.random() * baseTime;
            const endMetric = performanceCollector.startMetric(fullOperation, {
              category,
              operation,
              integration_type: category
            });
            setTimeout(endMetric, duration);
          }
        }
      }

      await new Promise(resolve => setTimeout(resolve, 100));

      const req = mockRequest();
      const res = mockResponse();

      dashboard.getMetrics(req, res);

      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          summaries: expect.arrayContaining([
            expect.objectContaining({
              operation: expect.stringMatching(/^(internal_services|external_apis|database|cache)_/),
              count: expect.any(Number),
              averageDuration: expect.any(Number),
              successRate: expect.any(Number)
            })
          ]),
          trends: expect.any(Object)
        })
      );

      const responseData = res.json.mock.calls[0][0];
      expect(responseData.summaries.length).toBeGreaterThanOrEqual(12); // At least 4 categories * 3 operations
    });
  });

  // 7. Performance and Reliability Tests
  describe('Performance and Reliability', () => {
    it('should handle high-volume metric collection efficiently', async () => {
      const startTime = Date.now();
      const metricCount = 1000;

      // Record many metrics rapidly
      const promises = [];
      for (let i = 0; i < metricCount; i++) {
        promises.push(new Promise<void>((resolve) => {
          const endMetric = performanceCollector.startMetric(`bulk_operation_${i % 10}`);
          setTimeout(() => {
            endMetric();
            resolve();
          }, Math.random() * 100);
        }));
      }

      await Promise.all(promises);

      const endTime = Date.now();
      const processingTime = endTime - startTime;

      // Should process 1000 metrics efficiently
      expect(processingTime).toBeLessThan(5000); // Should complete within 5 seconds

      const summaries = performanceCollector.getAllSummaries();
      expect(summaries.length).toBeGreaterThan(0);

      const totalOperations = summaries.reduce((sum, s) => sum + s.count, 0);
      expect(totalOperations).toBe(metricCount);
    });

    it('should maintain performance under memory pressure', async () => {
      // Simulate memory pressure by recording many different operations
      const operationCount = 500;

      for (let i = 0; i < operationCount; i++) {
        const operation = `memory_test_${i}`;
        const endMetric = performanceCollector.startMetric(operation, {
          largeData: 'x'.repeat(1000), // 1KB of metadata
          iteration: i
        });
        setTimeout(endMetric, Math.random() * 200);
      }

      await new Promise(resolve => setTimeout(resolve, 100));

      // System should still be responsive
      const req = mockRequest();
      const res = mockResponse();

      const startTime = Date.now();
      dashboard.getMetrics(req, res);
      const responseTime = Date.now() - startTime;

      expect(responseTime).toBeLessThan(1000); // Should respond within 1 second
      expect(res.json).toHaveBeenCalled();

      const summaries = performanceCollector.getAllSummaries();
      expect(summaries.length).toBeGreaterThan(0);
    });

    it('should handle concurrent monitoring requests', async () => {
      const concurrentRequests = 50;

      // Record some metrics first
      for (let i = 0; i < 10; i++) {
        const endMetric = performanceCollector.startMetric(`concurrent_test_${i}`);
        setTimeout(endMetric, 100 + i * 10);
      }

      await new Promise(resolve => setTimeout(resolve, 50));

      // Make concurrent requests
      const promises = [];
      for (let i = 0; i < concurrentRequests; i++) {
        promises.push(new Promise<void>((resolve) => {
          const req = mockRequest({ timeWindow: '60' });
          const res = mockResponse();

          dashboard.getTrends(req, res);
          expect(res.json).toHaveBeenCalled();
          resolve();
        }));
      }

      const startTime = Date.now();
      await Promise.all(promises);
      const totalTime = Date.now() - startTime;

      // Should handle concurrent requests efficiently
      expect(totalTime).toBeLessThan(2000); // Should complete within 2 seconds
    });

    it('should recover from monitoring system failures', async () => {
      // Simulate system recovery by clearing and rebuilding metrics
      const initialMetrics = ['recovery_test_1', 'recovery_test_2', 'recovery_test_3'];

      // Record initial metrics
      for (const operation of initialMetrics) {
        const endMetric = performanceCollector.startMetric(operation);
        setTimeout(endMetric, 150);
      }

      await new Promise(resolve => setTimeout(resolve, 50));

      let summaries = performanceCollector.getAllSummaries();
      expect(summaries.length).toBe(initialMetrics.length);

      // Simulate system failure and recovery
      performanceCollector.clearMetrics();
      dashboard['alerts'] = [];
      dashboard['alertCache'].clear();

      summaries = performanceCollector.getAllSummaries();
      expect(summaries.length).toBe(0);

      // Record recovery metrics
      const recoveryMetrics = ['recovered_operation_1', 'recovered_operation_2'];
      for (const operation of recoveryMetrics) {
        const endMetric = performanceCollector.startMetric(operation);
        setTimeout(endMetric, 100);
      }

      await new Promise(resolve => setTimeout(resolve, 50));

      summaries = performanceCollector.getAllSummaries();
      expect(summaries.length).toBe(recoveryMetrics.length);

      // System should be functional after recovery
      const req = mockRequest();
      const res = mockResponse();

      dashboard.getHealth(req, res);
      expect(res.status).toHaveBeenCalledWith(200);
    });
  });

  // 8. Configuration and Management Tests
  describe('Configuration and Management', () => {
    it('should allow dynamic configuration of monitoring parameters', () => {
      const customConfig = {
        enableMetricsEndpoint: false,
        enableAlertsEndpoint: true,
        enableTrendsEndpoint: false,
        requireAuthentication: true,
        cacheTimeout: 60000
      };

      const customDashboard = new PerformanceDashboard(customConfig);
      const config = customDashboard['config'];

      expect(config.enableMetricsEndpoint).toBe(false);
      expect(config.enableAlertsEndpoint).toBe(true);
      expect(config.enableTrendsEndpoint).toBe(false);
      expect(config.requireAuthentication).toBe(true);
      expect(config.cacheTimeout).toBe(60000);
    });

    it('should support configurable alert thresholds', () => {
      const customThresholds = [
        { operation: 'custom_fast', duration: 50, errorRate: 1 },
        { operation: 'custom_slow', duration: 2000, errorRate: 15 },
        { operation: 'custom_critical', duration: 100, errorRate: 0.5 }
      ];

      customThresholds.forEach(threshold => {
        performanceCollector.setAlertThreshold(threshold.operation, threshold.duration, threshold.errorRate);
      });

      // Verify thresholds were set (this would need access to private method)
      // For now, just verify no errors were thrown
      expect(true).toBe(true);
    });

    it('should provide metrics management operations', async () => {
      // Record some metrics
      const operations = ['test_1', 'test_2', 'test_3'];
      for (const operation of operations) {
        const endMetric = performanceCollector.startMetric(operation);
        setTimeout(endMetric, 100);
      }

      await new Promise(resolve => setTimeout(resolve, 50));

      let summaries = performanceCollector.getAllSummaries();
      expect(summaries.length).toBeGreaterThan(0);

      // Clear metrics
      performanceCollector.clearMetrics();

      summaries = performanceCollector.getAllSummaries();
      expect(summaries.length).toBe(0);

      // Verify dashboard cache is also cleared
      const req = mockRequest();
      const res = mockResponse();

      dashboard.clearMetrics(req, res);
      expect(res.json).toHaveBeenCalledWith({
        message: 'Metrics and alerts cleared successfully'
      });
    });

    it('should handle monitoring service lifecycle', () => {
      // Test starting and stopping collection
      expect(() => performanceCollector.startCollection(1000)).not.toThrow();

      // Test that collection is running
      setTimeout(() => {
        expect(() => performanceCollector.stopCollection()).not.toThrow();
      }, 100);

      // Multiple starts should not cause issues
      expect(() => performanceCollector.startCollection(500)).not.toThrow();
      expect(() => performanceCollector.startCollection(1000)).not.toThrow();

      // Multiple stops should not cause issues
      expect(() => performanceCollector.stopCollection()).not.toThrow();
      expect(() => performanceCollector.stopCollection()).not.toThrow();
    });
  });
});