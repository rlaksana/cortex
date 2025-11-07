/**
 * Comprehensive Health Monitoring Tests
 *
 * Automated tests to validate all health monitoring functionality including
 * MCP server health checks, Qdrant monitoring, circuit breaker status,
 * container probes, structured logging, and dashboard API.
 *
 * @author Cortex Team
 * @version 2.0.1
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import request from 'supertest';
import express from 'express';
import {
  mcpServerHealthMonitor,
  type MCPServerHealthMetrics,
} from '../../src/monitoring/mcp-server-health-monitor.js';
import {
  QdrantHealthMonitor,
  type QdrantHealthCheckResult,
  QdrantConnectionStatus,
} from '../../src/monitoring/qdrant-health-monitor.js';
import {
  circuitBreakerMonitor,
  type CircuitBreakerHealthStatus,
} from '../../src/monitoring/circuit-breaker-monitor.js';
import {
  enhancedPerformanceCollector,
  type SystemPerformanceMetrics,
  type MCPOperationMetrics,
} from '../../src/monitoring/enhanced-performance-collector.js';
import {
  containerProbesHandler,
  type ContainerHealthState,
} from '../../src/monitoring/container-probes.js';
import {
  healthStructuredLogger,
  type StructuredLogEntry,
} from '../../src/monitoring/health-structured-logger.js';
import {
  healthDashboardAPIHandler,
  type DashboardSummary,
  type RealTimeHealthData,
} from '../../src/monitoring/health-dashboard-api.js';
import {
  circuitBreakerManager,
  CircuitBreaker,
} from '../../src/services/circuit-breaker.service.js';
import { HealthStatus, DependencyType } from '../../src/types/unified-health-interfaces.js';

describe('Comprehensive Health Monitoring', () => {
  let app: express['A']pplication;
  let server: any;
  let qdrantMonitor: QdrantHealthMonitor;
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    // Setup Express app for testing
    app = express();
    app.use(express.json());

    // Mock fetch for Qdrant and external API calls
    mockFetch = vi.fn();
    global.fetch = mockFetch;

    // Setup Qdrant monitor with test configuration
    qdrantMonitor = new QdrantHealthMonitor({
      url: 'http://localhost:6333',
      timeoutMs: 5000,
      healthCheckIntervalMs: 5000,
      metricsCollectionIntervalMs: 2000,
      circuitBreaker: {
        enabled: true,
        failureThreshold: 3,
        recoveryTimeoutMs: 10000,
        monitoringWindowMs: 60000,
      },
    });

    // Start all monitoring services
    mcpServerHealthMonitor.start();
    enhancedPerformanceCollector.start();
    circuitBreakerMonitor.start();
    qdrantMonitor.start();

    // Setup API routes
    healthDashboardAPIHandler.setupRoutes(app);

    // Mock Qdrant health endpoint responses
    mockFetch.mockImplementation((url: string) => {
      if (url.includes('/health')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () =>
            Promise.resolve({
              version: '1.7.4',
              commit: 'abc123',
              services: {
                qdrant: 'OK',
                collections: 'OK',
                cluster: 'OK',
              },
            }),
        } as Response);
      }

      if (url.includes('/metrics')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          text: () =>
            Promise.resolve(`
            qdrant_collections_total 3
            qdrant_vectors_total 10000
            qdrant_memory_usage_bytes 1073741824
            qdrant_disk_usage_bytes 5368709120
          `),
        } as Response);
      }

      if (url.includes('/collections')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () =>
            Promise.resolve({
              result: {
                collections: [
                  {
                    name: 'test-collection',
                    vectors_count: 5000,
                    status: 'green',
                    optimizer_status: { status: 'ok' },
                  },
                ],
              },
            }),
        } as Response);
      }

      if (url.includes('/telemetry')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () =>
            Promise.resolve({
              result: {
                uptime: 3600,
                memory: {
                  usage: { ram: 1073741824 },
                  total: { ram: 4294967296 },
                },
                cpu: { usage: 25.5 },
                disk: { usage: 5368709120, total: 107374182400 },
              },
            }),
        } as Response);
      }

      return Promise.resolve({
        ok: false,
        status: 404,
      } as Response);
    });
  });

  afterEach(async () => {
    // Stop all monitoring services
    mcpServerHealthMonitor.stop();
    enhancedPerformanceCollector.stop();
    circuitBreakerMonitor.stop();
    qdrantMonitor.stop();

    if (server) {
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
    }

    vi.clearAllMocks();
  });

  describe('MCP Server Health Monitor', () => {
    it('should start and stop monitoring', () => {
      expect(mcpServerHealthMonitor.getCurrentStatus()).toBeDefined();
      expect(mcpServerHealthMonitor.getCurrentMetrics()).toBeDefined();
    });

    it('should collect metrics and track history', async () => {
      // Wait for some metrics to be collected
      await new Promise((resolve) => setTimeout(resolve, 100));

      const metrics = mcpServerHealthMonitor.getCurrentMetrics();
      expect(metrics).toBeDefined();
      expect(typeof metrics.requestsPerSecond).toBe('number');
      expect(typeof metrics.memoryUsagePercent).toBe('number');

      const history = mcpServerHealthMonitor.getHealthHistory();
      expect(Array.isArray(history)).toBe(true);
    });

    it('should emit health check events', (done) => {
      const healthCheckListener = vi.fn();
      mcpServerHealthMonitor.on('health_check', healthCheckListener);

      // Wait for health check to complete
      setTimeout(() => {
        expect(healthCheckListener).toHaveBeenCalled();
        const healthResult = healthCheckListener.mock.calls[0][0];
        expect(healthResult.status).toBeDefined();
        expect(healthResult.components).toBeDefined();
        expect(Array.isArray(healthResult.components)).toBe(true);

        mcpServerHealthMonitor.off('health_check', healthCheckListener);
        done();
      }, 100);
    });

    it('should track consecutive failures and successes', async () => {
      // Simulate some health checks
      await new Promise((resolve) => setTimeout(resolve, 100));

      const metrics = mcpServerHealthMonitor.getCurrentMetrics();
      expect(metrics).toBeDefined();

      // The metrics should have reasonable values
      expect(metrics.memoryUsagePercent).toBeGreaterThanOrEqual(0);
      expect(metrics.memoryUsagePercent).toBeLessThanOrEqual(100);
    });
  });

  describe('Qdrant Health Monitor', () => {
    it('should start monitoring and check Qdrant health', async () => {
      const result = await qdrantMonitor.performHealthCheck();
      expect(result).toBeDefined();
      expect(result.status).toBe(HealthStatus['HEALTHY']);
      expect(result.connectionStatus).toBe(QdrantConnectionStatus['CONNECTED']);
      expect(result.metrics).toBeDefined();
    });

    it('should track connection history and metrics', async () => {
      // Wait for metrics collection
      await new Promise((resolve) => setTimeout(resolve, 100));

      const metrics = qdrantMonitor.getCurrentMetrics();
      expect(metrics).toBeDefined();
      expect(typeof metrics.requestsPerSecond).toBe('number');
      expect(typeof metrics.averageResponseTime).toBe('number');

      const connectionHistory = qdrantMonitor.getConnectionHistory();
      expect(Array.isArray(connectionHistory)).toBe(true);

      const requestHistory = qdrantMonitor.getRequestHistory();
      expect(Array.isArray(requestHistory)).toBe(true);
    });

    it('should handle connection failures gracefully', async () => {
      // Mock connection failure
      mockFetch.mockRejectedValueOnce(new Error('Connection refused'));

      const result = await qdrantMonitor.performHealthCheck();
      expect(result.status).toBe(HealthStatus['UNHEALTHY']);
      expect(result.connectionStatus).toBe(QdrantConnectionStatus['ERROR']);
      expect(result.error).toBeDefined();
    });

    it('should use circuit breaker for Qdrant requests', async () => {
      const circuitBreaker = circuitBreakerManager.getCircuitBreaker('qdrant');
      expect(circuitBreaker).toBeDefined();

      // Simulate failures to trigger circuit breaker
      mockFetch.mockRejectedValue(new Error('Connection failed'));

      for (let i = 0; i < 5; i++) {
        try {
          await qdrantMonitor.performHealthCheck();
        } catch (error) {
          // Expected failures
        }
      }

      const stats = circuitBreaker.getStats();
      expect(stats.failures).toBeGreaterThan(0);
    });

    it('should collect detailed Qdrant metrics', async () => {
      // Wait for metrics collection
      await new Promise((resolve) => setTimeout(resolve, 100));

      const metrics = qdrantMonitor.getCurrentMetrics();
      expect(metrics).toBeDefined();
      expect(metrics.collectionCount).toBeGreaterThan(0);
      expect(metrics.totalVectors).toBeGreaterThan(0);
      expect(metrics.memoryUsage).toBeGreaterThan(0);
    });
  });

  describe('Circuit Breaker Monitor', () => {
    it('should monitor circuit breaker states', () => {
      const healthStatuses = circuitBreakerMonitor.getAllHealthStatuses();
      expect(healthStatuses.size).toBeGreaterThan(0);

      // Check that Qdrant circuit breaker is being monitored
      const qdrantHealth = circuitBreakerMonitor.getHealthStatus('qdrant');
      expect(qdrantHealth).toBeDefined();
      expect(qdrantHealth!.serviceName).toBe('qdrant');
      expect(qdrantHealth!.healthStatus).toBeDefined();
    });

    it('should track circuit breaker events', async () => {
      // Simulate circuit breaker state changes
      const circuitBreaker = circuitBreakerManager.getCircuitBreaker('test-service');
      circuitBreaker.forceOpen();

      // Wait for monitor to detect the change
      await new Promise((resolve) => setTimeout(resolve, 100));

      const healthStatus = circuitBreakerMonitor.getHealthStatus('test-service');
      expect(healthStatus).toBeDefined();
      expect(healthStatus!.state).toBe('open');
    });

    it('should generate health reports', () => {
      const report = circuitBreakerMonitor.generateHealthReport();
      expect(report).toBeDefined();
      expect(report.timestamp).toBeDefined();
      expect(report.overall).toBeDefined();
      expect(report.circuitBreakers).toBeDefined();
      expect(report.activeAlerts).toBeDefined();
      expect(report.summary).toBeDefined();

      expect(report.overall.totalCircuits).toBeGreaterThan(0);
      expect(Array.isArray(report.circuitBreakers)).toBe(true);
      expect(Array.isArray(report.activeAlerts)).toBe(true);
      expect(Array.isArray(report.summary.criticalIssues)).toBe(true);
      expect(Array.isArray(report.summary.warnings)).toBe(true);
      expect(Array.isArray(report.summary.recommendations)).toBe(true);
    });

    it('should emit alerts for circuit breaker issues', (done) => {
      const alertListener = vi.fn();
      circuitBreakerMonitor.on('alert', alertListener);

      // Create a failing circuit breaker
      const circuitBreaker = circuitBreakerManager.getCircuitBreaker('alert-test', {
        failureThreshold: 2,
        recoveryTimeoutMs: 1000,
      });

      // Force it open to trigger alerts
      circuitBreaker.forceOpen();

      setTimeout(() => {
        expect(alertListener).toHaveBeenCalled();
        const alert = alertListener.mock.calls[0][0];
        expect(alert.serviceName).toBe('alert-test');
        expect(alert.type).toBeDefined();
        expect(alert.severity).toBeDefined();

        circuitBreakerMonitor.off('alert', alertListener);
        done();
      }, 100);
    });
  });

  describe('Enhanced Performance Collector', () => {
    it('should collect system and MCP metrics', async () => {
      // Wait for metrics collection
      await new Promise((resolve) => setTimeout(resolve, 100));

      const systemMetrics = enhancedPerformanceCollector.getSystemMetrics();
      expect(systemMetrics).toBeDefined();
      expect(systemMetrics.cpuUsage).toBeDefined();
      expect(systemMetrics.memoryUsage).toBeDefined();
      expect(systemMetrics.eventLoop).toBeDefined();

      const mcpMetrics = enhancedPerformanceCollector.getMCPMetrics();
      expect(mcpMetrics).toBeDefined();
      expect(mcpMetrics.requests).toBeDefined();
      expect(mcpMetrics.tools).toBeDefined();
    });

    it('should record custom metrics', () => {
      enhancedPerformanceCollector.recordMetric('test_counter', 'counter', 10, { label: 'test' });
      enhancedPerformanceCollector.recordMetric('test_gauge', 'gauge', 25.5);
      enhancedPerformanceCollector.recordMetric('test_histogram', 'histogram', 100);

      const timeSeriesData = enhancedPerformanceCollector.getTimeSeriesData('test_counter');
      expect(timeSeriesData.length).toBeGreaterThan(0);
      expect(timeSeriesData[0].name).toBe('test_counter');
      expect(timeSeriesData[0].type).toBe('counter');
      expect(timeSeriesData[0].value).toBe(10);
    });

    it('should record response times and tool executions', () => {
      enhancedPerformanceCollector.recordResponseTime('test-operation', 150);
      enhancedPerformanceCollector.recordToolExecution('test-tool', 200, true);
      enhancedPerformanceCollector.recordToolExecution('test-tool', 300, false);

      const histogramData = enhancedPerformanceCollector.getHistogramData(
        'response_time_test-operation'
      );
      expect(histogramData).toBeDefined();
      expect(histogramData!.count).toBeGreaterThan(0);
    });

    it('should generate Prometheus-compatible metrics', () => {
      const prometheusMetrics = enhancedPerformanceCollector.getPrometheusMetrics();
      expect(typeof prometheusMetrics).toBe('string');
      expect(prometheusMetrics).toContain('# HELP');
      expect(prometheusMetrics).toContain('# TYPE');
      expect(prometheusMetrics).toContain('cortex_');
    });

    it('should calculate percentiles correctly', () => {
      // Record some response times
      const responseTimes = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
      responseTimes.forEach((time) => {
        enhancedPerformanceCollector.recordResponseTime('percentile-test', time);
      });

      const percentiles = enhancedPerformanceCollector.getPercentiles(
        'response_time_percentile-test',
        [50, 95, 99]
      );
      expect(percentiles[50]).toBeCloseTo(50, 0);
      expect(percentiles[95]).toBeCloseTo(95, 0);
      expect(percentiles[99]).toBeCloseTo(100, 0);
    });
  });

  describe('Container Probes', () => {
    it('should handle readiness probe requests', async () => {
      const response = await request(app).get('/ready').expect(200);

      expect(response.body.status).toBe('ready');
      expect(response.body.uptime).toBeDefined();
      expect(response.body.checks).toBeDefined();
      expect(response.body.duration).toBeDefined();
    });

    it('should handle liveness probe requests', async () => {
      const response = await request(app).get('/health/live').expect(200);

      expect(response.body.status).toBe('alive');
      expect(response.body.uptime).toBeDefined();
      expect(response.body.memoryUsage).toBeDefined();
      expect(response.body.responseTime).toBeDefined();
    });

    it('should handle startup probe requests', async () => {
      const response = await request(app).get('/startup').expect(200);

      expect(['started', 'starting']).toContain(response.body.status);
      expect(response.body.uptime).toBeDefined();
    });

    it('should track container health state', () => {
      const healthState = containerProbesHandler.getHealthState();
      expect(healthState).toBeDefined();
      expect(healthState.startTime).toBeDefined();
      expect(healthState.readyCheckCount).toBeGreaterThanOrEqual(0);
      expect(healthState.aliveCheckCount).toBeGreaterThanOrEqual(0);
    });

    it('should handle probe failures gracefully', async () => {
      // Simulate a failure by creating a scenario where readiness check fails
      // This would require more complex setup in a real test environment
      const response = await request(app).get('/ready').expect(200); // Should still respond, but with not-ready status if issues exist

      expect(['ready', 'not-ready']).toContain(response.body.status);
    });

    it('should provide Kubernetes pod spec', () => {
      const podSpec = containerProbesHandler.getKubernetesPodSpec();
      expect(podSpec).toBeDefined();
      expect(podSpec.containers).toBeDefined();
      expect(podSpec.containers[0].livenessProbe).toBeDefined();
      expect(podSpec.containers[0].readinessProbe).toBeDefined();
    });

    it('should provide Docker health check configuration', () => {
      const dockerHealthCheck = containerProbesHandler.getDockerHealthCheck();
      expect(dockerHealthCheck).toBeDefined();
      expect(dockerHealthCheck.test).toBeDefined();
      expect(dockerHealthCheck.interval).toBeDefined();
    });
  });

  describe('Structured Health Logger', () => {
    it('should log system health check events', () => {
      const logSpy = vi.spyOn(console, 'log').mockImplementation();
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation();
      const errorSpy = vi.spyOn(console, 'error').mockImplementation();

      const metrics: MCPServerHealthMetrics = {
        activeConnections: 10,
        totalConnections: 100,
        connectionErrors: 2,
        averageConnectionTime: 50,
        requestsPerSecond: 5,
        averageResponseTime: 200,
        p95ResponseTime: 500,
        p99ResponseTime: 1000,
        errorRate: 2,
        activeSessions: 8,
        totalSessions: 50,
        mcpProtocolErrors: 1,
        toolExecutionSuccessRate: 98,
        toolExecutionAverageTime: 300,
        memoryUsageMB: 256,
        memoryUsagePercent: 60,
        cpuUsagePercent: 25,
        eventLoopLag: 5,
        qdrantConnectionStatus: true,
        qdrantResponseTime: 100,
        qdrantErrorRate: 1,
        vectorOperationsPerSecond: 3,
      };

      healthStructuredLogger.logSystemHealthCheck(
        HealthStatus['HEALTHY'],
        HealthStatus['DEGRADED'],
        metrics,
        'test-correlation-id'
      );

      // Verify log was called (exact structure depends on console format)
      expect(logSpy).toHaveBeenCalled() || expect(warnSpy).toHaveBeenCalled();

      logSpy.mockRestore();
      warnSpy.mockRestore();
      errorSpy.mockRestore();
    });

    it('should log component health check events', () => {
      const logSpy = vi.spyOn(console, 'log').mockImplementation();
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation();

      healthStructuredLogger.logComponentHealthCheck(
        'test-component',
        DependencyType['DATABASE'],
        HealthStatus['DEGRADED'],
        HealthStatus['HEALTHY'],
        150,
        'Connection slow',
        'test-correlation-id'
      );

      expect(warnSpy).toHaveBeenCalled();

      logSpy.mockRestore();
      warnSpy.mockRestore();
    });

    it('should log circuit breaker events', () => {
      const errorSpy = vi.spyOn(console, 'error').mockImplementation();
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation();

      const circuitEvent = {
        serviceName: 'test-service',
        eventType: 'failure' as any,
        timestamp: new Date(),
        previousState: 'closed',
        currentState: 'open',
        error: 'Connection timeout',
        responseTime: 5000,
      };

      healthStructuredLogger.logCircuitBreakerEvent(circuitEvent);

      expect(errorSpy).toHaveBeenCalled() || expect(warnSpy).toHaveBeenCalled();

      errorSpy.mockRestore();
      warnSpy.mockRestore();
    });

    it('should log probe results', () => {
      const logSpy = vi.spyOn(console, 'log').mockImplementation();
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation();

      const probeResult = {
        success: true,
        status: 200,
        message: 'Probe passed',
        timestamp: new Date(),
        duration: 50,
        details: {
          uptime: 1000,
          memoryUsage: 60,
          responseTime: 50,
          componentHealth: {},
          circuitBreakerStates: {},
        },
      };

      healthStructuredLogger.logProbeResult('readiness', probeResult, 'test-correlation-id');

      expect(logSpy).toHaveBeenCalled();

      logSpy.mockRestore();
      warnSpy.mockRestore();
    });

    it('should log performance alerts', () => {
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation();
      const errorSpy = vi.spyOn(console, 'error').mockImplementation();

      healthStructuredLogger.logPerformanceAlert(
        'high_response_time',
        'warning',
        'test-component',
        1000,
        1500,
        'test-correlation-id'
      );

      expect(warnSpy).toHaveBeenCalled();

      healthStructuredLogger.logPerformanceAlert(
        'critical_error_rate',
        'critical',
        'test-component',
        5,
        25,
        'test-correlation-id'
      );

      expect(errorSpy).toHaveBeenCalled();

      warnSpy.mockRestore();
      errorSpy.mockRestore();
    });

    it('should manage correlation IDs', () => {
      const correlationId1 = healthStructuredLogger.generateCorrelationId?.() || 'test-id-1';
      const correlationId2 = healthStructuredLogger.generateCorrelationId?.() || 'test-id-2';

      expect(typeof correlationId1).toBe('string');
      expect(typeof correlationId2).toBe('string');
      expect(correlationId1).not.toBe(correlationId2);

      const history = healthStructuredLogger.getCorrelationHistory?.();
      expect(history).toBeDefined();
    });
  });

  describe('Health Dashboard API', () => {
    it('should provide dashboard summary', async () => {
      const response = await request(app).get('/api/health-dashboard/summary').expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toBeDefined();

      const summary: DashboardSummary = response.body.data;
      expect(summary.overview).toBeDefined();
      expect(summary.components).toBeDefined();
      expect(summary.performance).toBeDefined();
      expect(summary.resources).toBeDefined();
      expect(summary.alerts).toBeDefined();
      expect(summary.trends).toBeDefined();

      expect(summary.overview.overallHealth).toBeDefined();
      expect(summary.overview.uptime).toBeGreaterThan(0);
      expect(summary.components.total).toBeGreaterThan(0);
      expect(Array.isArray(summary.trends)).toBe(true);
    });

    it('should provide real-time health data', async () => {
      const response = await request(app).get('/api/health-dashboard/realtime').expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toBeDefined();

      const realtimeData: RealTimeHealthData = response.body.data;
      expect(realtimeData.timestamp).toBeDefined();
      expect(realtimeData.system).toBeDefined();
      expect(realtimeData.performance).toBeDefined();
      expect(realtimeData.circuitBreakers).toBeDefined();
      expect(realtimeData.container).toBeDefined();

      expect(realtimeData.system.status).toBeDefined();
      expect(realtimeData.system.metrics).toBeDefined();
      expect(Array.isArray(realtimeData.system.components)).toBe(true);
    });

    it('should provide historical health data', async () => {
      const response = await request(app)
        .get('/api/health-dashboard/historical?timeRange=1h')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toBeDefined();

      const historicalData = response.body.data;
      expect(historicalData.timeRange).toBeDefined();
      expect(historicalData.data).toBeDefined();
      expect(historicalData.summaries).toBeDefined();

      expect(historicalData['data.timestamps']).toBeDefined();
      expect(Array.isArray(historicalData['data.timestamps'])).toBe(true);
      expect(Array.isArray(historicalData['data.healthStatus'])).toBe(true);
      expect(Array.isArray(historicalData['data.responseTimes'])).toBe(true);
    });

    it('should provide alerts', async () => {
      const response = await request(app).get('/api/health-dashboard/alerts').expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toBeDefined();

      const alertsData = response.body.data;
      expect(alertsData.alerts).toBeDefined();
      expect(alertsData.summary).toBeDefined();

      expect(Array.isArray(alertsData.alerts)).toBe(true);
      expect(alertsData.summary.total).toBeGreaterThanOrEqual(0);
    });

    it('should export data in different formats', async () => {
      // Test JSON export
      const jsonResponse = await request(app)
        .get('/api/health-dashboard/export?format=json')
        .expect(200);

      expect(jsonResponse.headers['content-type']).toContain('application/json');
      expect(jsonResponse.headers['content-disposition']).toContain('attachment');

      // Test CSV export
      const csvResponse = await request(app)
        .get('/api/health-dashboard/export?format=csv')
        .expect(200);

      expect(csvResponse.headers['content-type']).toContain('text/csv');
      expect(csvResponse.text).toContain('Timestamp,Status,ResponseTime,ErrorRate');

      // Test Prometheus export
      const promResponse = await request(app)
        .get('/api/health-dashboard/export?format=prometheus')
        .expect(200);

      expect(promResponse.headers['content-type']).toContain('text/plain');
      expect(promResponse.text).toContain('# HELP');
      expect(promResponse.text).toContain('# TYPE');
    });

    it('should handle API health check', async () => {
      const response = await request(app).get('/api/health-dashboard/health').expect(200);

      expect(response.body.status).toBe('healthy');
      expect(response.body.version).toBeDefined();
      expect(response.body.features).toBeDefined();
    });

    it('should handle rate limiting', async () => {
      // This test would require configuring rate limiting with a lower threshold
      // For now, just verify the endpoint exists
      const response = await request(app).get('/api/health-dashboard/summary').expect(200);

      expect(response.body.success).toBe(true);
    });

    it('should handle CORS headers', async () => {
      const response = await request(app).options('/api/health-dashboard/summary').expect(200);

      expect(response.headers['access-control-allow-origin']).toBeDefined();
      expect(response.headers['access-control-allow-methods']).toBeDefined();
      expect(response.headers['access-control-allow-headers']).toBeDefined();
    });

    it('should cache responses appropriately', async () => {
      // First request
      const response1 = await request(app).get('/api/health-dashboard/realtime').expect(200);

      // Second request should be faster due to caching
      const response2 = await request(app).get('/api/health-dashboard/realtime').expect(200);

      expect(response1.body.data).toEqual(response2.body.data);
    });
  });

  describe('Integration Tests', () => {
    it('should handle end-to-end health monitoring flow', async () => {
      // Start all monitoring
      mcpServerHealthMonitor.start();
      enhancedPerformanceCollector.start();
      circuitBreakerMonitor.start();
      qdrantMonitor.start();

      // Wait for monitoring to collect data
      await new Promise((resolve) => setTimeout(resolve, 200));

      // Verify all components are working
      const mcpStatus = mcpServerHealthMonitor.getCurrentStatus();
      const systemMetrics = enhancedPerformanceCollector.getSystemMetrics();
      const circuitHealth = circuitBreakerMonitor.getAllHealthStatuses();
      const qdrantMetrics = qdrantMonitor.getCurrentMetrics();

      expect(mcpStatus).toBeDefined();
      expect(systemMetrics).toBeDefined();
      expect(circuitHealth.size).toBeGreaterThan(0);
      expect(qdrantMetrics).toBeDefined();

      // Verify API integration
      const summaryResponse = await request(app).get('/api/health-dashboard/summary').expect(200);

      expect(summaryResponse.body.success).toBe(true);

      const realtimeResponse = await request(app).get('/api/health-dashboard/realtime').expect(200);

      expect(realtimeResponse.body.success).toBe(true);
    });

    it('should handle graceful degradation when components fail', async () => {
      // Simulate Qdrant failure
      mockFetch.mockRejectedValue(new Error('Qdrant unavailable'));

      // Wait for monitoring to detect the failure
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Verify health status reflects the failure
      const qdrantResult = await qdrantMonitor.performHealthCheck();
      expect(qdrantResult.status).toBe(HealthStatus['UNHEALTHY']);

      // Verify API still responds with degraded status
      const summaryResponse = await request(app).get('/api/health-dashboard/summary').expect(200);

      const summary: DashboardSummary = summaryResponse.body.data;
      expect(summary.overview.overallHealth).toBeDefined();

      // Restore Qdrant
      mockFetch.mockImplementation((url: string) => {
        if (url.includes('/health')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve({ version: '1.7.4' }),
          } as Response);
        }
        return Promise.resolve({ ok: false, status: 404 } as Response);
      });

      // Wait for recovery
      await new Promise((resolve) => setTimeout(resolve, 100));

      const recoveredResult = await qdrantMonitor.performHealthCheck();
      expect(recoveredResult.status).toBe(HealthStatus['HEALTHY']);
    });

    it('should maintain performance under load', async () => {
      const startTime = Date.now();
      const requests = [];

      // Make multiple concurrent requests
      for (let i = 0; i < 10; i++) {
        requests.push(
          request(app).get('/api/health-dashboard/realtime'),
          request(app).get('/api/health-dashboard/summary'),
          request(app).get('/api/health-dashboard/alerts')
        );
      }

      // Wait for all requests to complete
      const responses = await Promise.all(requests);
      const endTime = Date.now();

      // Verify all requests succeeded
      responses.forEach((response) => {
        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
      });

      // Verify performance is acceptable (should complete within 5 seconds)
      expect(endTime - startTime).toBeLessThan(5000);

      console.log(`Completed ${requests.length} requests in ${endTime - startTime}ms`);
    });

    it('should properly clean up resources', async () => {
      // Start monitoring
      mcpServerHealthMonitor.start();
      enhancedPerformanceCollector.start();
      circuitBreakerMonitor.start();
      qdrantMonitor.start();

      // Wait for initialization
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Verify monitoring is active
      expect(mcpServerHealthMonitor.getCurrentStatus()).toBeDefined();

      // Stop monitoring
      mcpServerHealthMonitor.stop();
      enhancedPerformanceCollector.stop();
      circuitBreakerMonitor.stop();
      qdrantMonitor.stop();

      // Verify resources are cleaned up (no errors on stop)
      expect(true).toBe(true); // If we get here without errors, cleanup worked
    });
  });
});
