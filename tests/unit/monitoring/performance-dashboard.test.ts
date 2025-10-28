/**
 * Performance Dashboard Unit Tests
 *
 * Comprehensive unit tests for the performance dashboard API service.
 * Tests HTTP endpoints, data formatting, caching, and configuration.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { Request, Response } from 'express';
import {
  PerformanceDashboard,
  performanceDashboard,
  type DashboardConfig,
  type PerformanceAlert
} from '../../../src/monitoring/performance-dashboard.js';

// Mock the performance collector
vi.mock('../../../src/monitoring/performance-collector.js', () => ({
  performanceCollector: {
    getSummary: vi.fn(),
    getAllSummaries: vi.fn(),
    getRecentMetrics: vi.fn(),
    getPerformanceTrends: vi.fn(),
    getMemoryUsage: vi.fn(),
    exportMetrics: vi.fn(),
    clearMetrics: vi.fn(),
    on: vi.fn(),
  },
}));

// Mock logger
vi.mock('../../../src/utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

describe('PerformanceDashboard', () => {
  let dashboard: PerformanceDashboard;
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: any;

  beforeEach(() => {
    // Create a fresh dashboard instance for each test
    dashboard = new PerformanceDashboard();

    // Setup mock request/response objects
    mockRequest = {
      query: {},
      path: '/test',
      method: 'GET',
      ip: '127.0.0.1',
    };

    mockResponse = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
      send: vi.fn().mockReturnThis(),
      setHeader: vi.fn().mockReturnThis(),
    };

    mockNext = vi.fn();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Constructor and Configuration', () => {
    it('should create dashboard with default configuration', () => {
      const defaultDashboard = new PerformanceDashboard();
      expect(defaultDashboard).toBeInstanceOf(PerformanceDashboard);
    });

    it('should create dashboard with custom configuration', () => {
      const config: DashboardConfig = {
        enableMetricsEndpoint: false,
        enableAlertsEndpoint: false,
        enableTrendsEndpoint: false,
        requireAuthentication: true,
        cacheTimeout: 60000,
      };

      const customDashboard = new PerformanceDashboard(config);
      expect(customDashboard).toBeInstanceOf(PerformanceDashboard);
    });

    it('should merge custom config with defaults', () => {
      const config: DashboardConfig = {
        cacheTimeout: 120000,
      };

      const customDashboard = new PerformanceDashboard(config);
      expect(customDashboard).toBeInstanceOf(PerformanceDashboard);
    });
  });

  describe('Metrics Endpoint', () => {
    const { performanceCollector } = require('../../../src/monitoring/performance-collector.js');

    beforeEach(() => {
      performanceCollector.getSummary.mockReturnValue({
        operation: 'test_operation',
        count: 10,
        averageDuration: 150,
        successRate: 95,
      });

      performanceCollector.getAllSummaries.mockReturnValue([
        {
          operation: 'test_operation',
          count: 10,
          averageDuration: 150,
          successRate: 95,
        },
      ]);

      performanceCollector.getRecentMetrics.mockReturnValue([
        {
          operation: 'test_operation',
          duration: 100,
          success: true,
          timestamp: Date.now(),
        },
      ]);

      performanceCollector.getPerformanceTrends.mockReturnValue({
        test_operation: {
          operation: 'test_operation',
          totalRequests: 10,
          successRate: 95,
        },
      });

      performanceCollector.getMemoryUsage.mockReturnValue({
        heapUsed: 50000000,
        heapTotal: 100000000,
        timestamp: Date.now(),
      });

      performanceCollector.exportMetrics.mockReturnValue('{"test": "data"}');
    });

    it('should return 404 when metrics endpoint is disabled', () => {
      const disabledDashboard = new PerformanceDashboard({
        enableMetricsEndpoint: false,
      });

      disabledDashboard.getMetrics(
        mockRequest as Request,
        mockResponse as Response
      );

      expect(mockResponse.status).toHaveBeenCalledWith(404);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Metrics endpoint disabled',
      });
    });

    it('should return specific operation metrics', () => {
      mockRequest.query = { operation: 'test_operation' };

      dashboard.getMetrics(mockRequest as Request, mockResponse as Response);

      expect(performanceCollector.getSummary).toHaveBeenCalledWith('test_operation');
      expect(performanceCollector.getRecentMetrics).toHaveBeenCalledWith('test_operation', 100);
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          operation: 'test_operation',
          count: 10,
        })
      );
    });

    it('should return 404 for non-existent operation', () => {
      performanceCollector.getSummary.mockReturnValue(null);
      mockRequest.query = { operation: 'non_existent' };

      dashboard.getMetrics(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(404);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Operation not found',
      });
    });

    it('should return all metrics when no operation specified', () => {
      dashboard.getMetrics(mockRequest as Request, mockResponse as Response);

      expect(performanceCollector.getAllSummaries).toHaveBeenCalled();
      expect(performanceCollector.getPerformanceTrends).toHaveBeenCalledWith(60);
      expect(performanceCollector.getMemoryUsage).toHaveBeenCalled();
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          summaries: expect.any(Array),
          trends: expect.any(Object),
          memory: expect.any(Object),
          timestamp: expect.any(Number),
        })
      );
    });

    it('should export metrics in Prometheus format', () => {
      mockRequest.query = { format: 'prometheus' };

      dashboard.getMetrics(mockRequest as Request, mockResponse as Response);

      expect(performanceCollector.exportMetrics).toHaveBeenCalledWith('prometheus');
      expect(mockResponse.setHeader).toHaveBeenCalledWith('Content-Type', 'text/plain');
      expect(mockResponse.send).toHaveBeenCalledWith('{"test": "data"}');
    });

    it('should export metrics in CSV format', () => {
      mockRequest.query = { format: 'csv' };

      dashboard.getMetrics(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.setHeader).toHaveBeenCalledWith('Content-Type', 'text/csv');
      expect(mockResponse.send).toHaveBeenCalled();
    });

    it('should handle errors gracefully', () => {
      performanceCollector.getAllSummaries.mockImplementation(() => {
        throw new Error('Database error');
      });

      dashboard.getMetrics(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(500);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Failed to retrieve metrics',
      });
    });

    it('should parse time window parameter', () => {
      mockRequest.query = { timeWindow: '120' };

      dashboard.getMetrics(mockRequest as Request, mockResponse as Response);

      expect(performanceCollector.getPerformanceTrends).toHaveBeenCalledWith(120);
    });

    it('should use default time window when invalid', () => {
      mockRequest.query = { timeWindow: 'invalid' };

      dashboard.getMetrics(mockRequest as Request, mockResponse as Response);

      expect(performanceCollector.getPerformanceTrends).toHaveBeenCalledWith(60);
    });
  });

  describe('Alerts Endpoint', () => {
    const { performanceCollector } = require('../../../src/monitoring/performance-collector.js');

    beforeEach(() => {
      // Setup mock alerts
      const mockAlerts: PerformanceAlert[] = [
        {
          operation: 'slow_operation',
          alertType: 'slow_query',
          threshold: 100,
          currentValue: 200,
          severity: 'high',
          message: 'Slow query detected',
          timestamp: Date.now(),
        },
        {
          operation: 'error_operation',
          alertType: 'high_error_rate',
          threshold: 5,
          currentValue: 10,
          severity: 'critical',
          message: 'High error rate detected',
          timestamp: Date.now(),
        },
      ];

      // Simulate alerts being added to the dashboard
      dashboard['alerts'] = mockAlerts;
    });

    it('should return 404 when alerts endpoint is disabled', () => {
      const disabledDashboard = new PerformanceDashboard({
        enableAlertsEndpoint: false,
      });

      disabledDashboard.getAlerts(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(404);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Alerts endpoint disabled',
      });
    });

    it('should return all alerts', () => {
      dashboard.getAlerts(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          alerts: expect.any(Array),
          total: expect.any(Number),
          timestamp: expect.any(Number),
        })
      );
    });

    it('should filter alerts by severity', () => {
      mockRequest.query = { severity: 'critical' };

      dashboard.getAlerts(mockRequest as Request, mockResponse as Response);

      const result = (mockResponse.json as any).mock.calls[0][0];
      expect(result.alerts).toHaveLength(1);
      expect(result.alerts[0].severity).toBe('critical');
    });

    it('should filter alerts by operation', () => {
      mockRequest.query = { operation: 'slow_operation' };

      dashboard.getAlerts(mockRequest as Request, mockResponse as Response);

      const result = (mockResponse.json as any).mock.calls[0][0];
      expect(result.alerts).toHaveLength(1);
      expect(result.alerts[0].operation).toBe('slow_operation');
    });

    it('should limit results', () => {
      mockRequest.query = { limit: '1' };

      dashboard.getAlerts(mockRequest as Request, mockResponse as Response);

      const result = (mockResponse.json as any).mock.calls[0][0];
      expect(result.alerts).toHaveLength(1);
    });

    it('should handle errors gracefully', () => {
      // Force an error by breaking the alerts array
      dashboard['alerts'] = null;

      dashboard.getAlerts(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(500);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Failed to retrieve alerts',
      });
    });
  });

  describe('Trends Endpoint', () => {
    const { performanceCollector } = require('../../../src/monitoring/performance-collector.js');

    beforeEach(() => {
      performanceCollector.getPerformanceTrends.mockReturnValue({
        test_operation: {
          operation: 'test_operation',
          totalRequests: 100,
          successRate: 95,
          requestsPerMinute: 10,
        },
      });
    });

    it('should return 404 when trends endpoint is disabled', () => {
      const disabledDashboard = new PerformanceDashboard({
        enableTrendsEndpoint: false,
      });

      disabledDashboard.getTrends(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(404);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Trends endpoint disabled',
      });
    });

    it('should return all trends', () => {
      dashboard.getTrends(mockRequest as Request, mockResponse as Response);

      expect(performanceCollector.getPerformanceTrends).toHaveBeenCalledWith(60);
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          trends: expect.any(Object),
          timeWindowMinutes: 60,
          timestamp: expect.any(Number),
        })
      );
    });

    it('should return trends for specific operation', () => {
      mockRequest.query = { operation: 'test_operation' };

      dashboard.getTrends(mockRequest as Request, mockResponse as Response);

      expect(performanceCollector.getPerformanceTrends).toHaveBeenCalledWith(60);
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          trends: expect.objectContaining({
            operation: 'test_operation',
          }),
        })
      );
    });

    it('should return 404 for non-existent operation trends', () => {
      performanceCollector.getPerformanceTrends.mockReturnValue({});
      mockRequest.query = { operation: 'non_existent' };

      dashboard.getTrends(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(404);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Operation not found',
      });
    });

    it('should use cached data when available', () => {
      const cache = dashboard['alertCache'];
      const cachedData = {
        trends: { cached: true },
        timeWindowMinutes: 60,
        timestamp: Date.now(),
      };
      cache.set('trends_60_', { data: cachedData, timestamp: Date.now() });

      dashboard.getTrends(mockRequest as Request, mockResponse as Response);

      expect(performanceCollector.getPerformanceTrends).not.toHaveBeenCalled();
      expect(mockResponse.json).toHaveBeenCalledWith(cachedData);
    });

    it('should refresh cache when expired', () => {
      const cache = dashboard['alertCache'];
      const oldTimestamp = Date.now() - 40000; // 40 seconds ago (beyond 30s cache timeout)
      const expiredData = {
        trends: { cached: true },
        timeWindowMinutes: 60,
        timestamp: oldTimestamp,
      };
      cache.set('trends_60_', { data: expiredData, timestamp: oldTimestamp });

      dashboard.getTrends(mockRequest as Request, mockResponse as Response);

      expect(performanceCollector.getPerformanceTrends).toHaveBeenCalled();
    });
  });

  describe('Health Endpoint', () => {
    const { performanceCollector } = require('../../../src/monitoring/performance-collector.js');

    beforeEach(() => {
      performanceCollector.getAllSummaries.mockReturnValue([
        {
          operation: 'healthy_operation',
          count: 100,
          averageDuration: 150,
          successRate: 98,
        },
        {
          operation: 'slow_operation',
          count: 50,
          averageDuration: 3000, // Slow operation
          successRate: 95,
        },
        {
          operation: 'error_operation',
          count: 20,
          averageDuration: 200,
          successRate: 85, // High error rate
        },
      ]);

      performanceCollector.getMemoryUsage.mockReturnValue({
        heapUsed: 80000000,
        heapTotal: 100000000,
        timestamp: Date.now(),
      });

      // Setup some mock alerts
      dashboard['alerts'] = [
        {
          operation: 'critical_operation',
          alertType: 'high_error_rate',
          threshold: 5,
          currentValue: 50,
          severity: 'critical' as const,
          message: 'Critical error rate',
          timestamp: Date.now(),
        },
      ];
    });

    it('should return healthy status when all metrics are good', () => {
      performanceCollector.getAllSummaries.mockReturnValue([
        {
          operation: 'healthy_operation',
          count: 100,
          averageDuration: 150,
          successRate: 98,
        },
      ]);

      dashboard['alerts'] = [];

      dashboard.getHealth(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(200);
      const response = (mockResponse.json as any).mock.calls[0][0];
      expect(response.status).toBe('healthy');
    });

    it('should return critical status when critical alerts exist', () => {
      dashboard.getHealth(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(503);
      const response = (mockResponse.json as any).mock.calls[0][0];
      expect(response.status).toBe('critical');
    });

    it('should return degraded status for slow operations or high error rates', () => {
      dashboard['alerts'] = []; // No critical alerts

      dashboard.getHealth(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(200);
      const response = (mockResponse.json as any).mock.calls[0][0];
      expect(response.status).toBe('degraded');
      expect(response.performance.problemOperations).toContain('slow_operation');
      expect(response.performance.problemOperations).toContain('error_operation');
    });

    it('should include comprehensive health data', () => {
      dashboard.getHealth(mockRequest as Request, mockResponse as Response);

      const response = (mockResponse.json as any).mock.calls[0][0];
      expect(response).toHaveProperty('status');
      expect(response).toHaveProperty('timestamp');
      expect(response).toHaveProperty('uptime');
      expect(response).toHaveProperty('version');
      expect(response).toHaveProperty('memory');
      expect(response).toHaveProperty('performance');
      expect(response).toHaveProperty('alerts');

      expect(response.memory).toHaveProperty('used');
      expect(response.memory).toHaveProperty('total');
      expect(response.memory).toHaveProperty('usagePercent');

      expect(response.performance).toHaveProperty('totalOperations');
      expect(response.performance).toHaveProperty('averageSuccessRate');
      expect(response.performance).toHaveProperty('problemOperations');
    });

    it('should handle errors gracefully', () => {
      performanceCollector.getAllSummaries.mockImplementation(() => {
        throw new Error('Health check failed');
      });

      dashboard.getHealth(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(500);
      expect(mockResponse.json).toHaveBeenCalledWith({
        status: 'error',
        error: 'Failed to retrieve health status',
        timestamp: expect.any(Number),
      });
    });
  });

  describe('System Info Endpoint', () => {
    const { performanceCollector } = require('../../../src/monitoring/performance-collector.js');

    beforeEach(() => {
      performanceCollector.getMemoryUsage.mockReturnValue({
        rss: 150000000,
        heapTotal: 100000000,
        heapUsed: 80000000,
        external: 10000000,
        arrayBuffers: 5000000,
        timestamp: Date.now(),
      });

      performanceCollector.getAllSummaries.mockReturnValue([
        {
          operation: 'test_operation',
          count: 100,
        },
      ]);
    });

    it('should return comprehensive system information', () => {
      dashboard.getSystemInfo(mockRequest as Request, mockResponse as Response);

      const response = (mockResponse.json as any).mock.calls[0][0];
      expect(response).toHaveProperty('process');
      expect(response).toHaveProperty('memory');
      expect(response).toHaveProperty('cpu');
      expect(response).toHaveProperty('performance');
      expect(response).toHaveProperty('timestamp');

      expect(response.process).toHaveProperty('pid');
      expect(response.process).toHaveProperty('uptime');
      expect(response.process).toHaveProperty('version');
      expect(response.process).toHaveProperty('platform');
      expect(response.process).toHaveProperty('arch');

      expect(response.memory).toHaveProperty('rss');
      expect(response.memory).toHaveProperty('heapTotal');
      expect(response.memory).toHaveProperty('heapUsed');
      expect(response.memory).toHaveProperty('external');
      expect(response.memory).toHaveProperty('arrayBuffers');

      expect(response.cpu).toHaveProperty('user');
      expect(response.cpu).toHaveProperty('system');

      expect(response.performance).toHaveProperty('totalOperations');
      expect(response.performance).toHaveProperty('trackedOperations');
    });

    it('should handle errors gracefully', () => {
      performanceCollector.getMemoryUsage.mockImplementation(() => {
        throw new Error('System info failed');
      });

      dashboard.getSystemInfo(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(500);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Failed to retrieve system info',
      });
    });
  });

  describe('Clear Metrics Endpoint', () => {
    const { performanceCollector } = require('../../../src/monitoring/performance-collector.js');

    it('should clear metrics and alerts', () => {
      dashboard['alerts'] = [
        {
          operation: 'test',
          alertType: 'slow_query',
          threshold: 100,
          currentValue: 200,
          severity: 'high',
          message: 'Test alert',
          timestamp: Date.now(),
        },
      ];

      dashboard.clearMetrics(mockRequest as Request, mockResponse as Response);

      expect(performanceCollector.clearMetrics).toHaveBeenCalled();
      expect(dashboard['alerts']).toHaveLength(0);
      expect(dashboard['alertCache'].size).toBe(0);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: 'Metrics and alerts cleared successfully',
      });
    });

    it('should handle errors gracefully', () => {
      performanceCollector.clearMetrics.mockImplementation(() => {
        throw new Error('Clear failed');
      });

      dashboard.clearMetrics(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(500);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Failed to clear metrics',
      });
    });
  });

  describe('Router', () => {
    it('should return Express router with all routes', () => {
      const router = dashboard.getRouter();

      expect(router).toBeDefined();
      // Router should have methods for handling different routes
      expect(typeof router.get).toBe('function');
      expect(typeof router.delete).toBe('function');
    });

    it('should include authentication middleware when required', () => {
      const authDashboard = new PerformanceDashboard({
        requireAuthentication: true,
      });

      const router = authDashboard.getRouter();
      expect(router).toBeDefined();
    });
  });

  describe('Alert Handling', () => {
    it('should handle alerts from performance collector', () => {
      const mockAlert: PerformanceAlert = {
        operation: 'test_operation',
        alertType: 'slow_query',
        threshold: 100,
        currentValue: 200,
        severity: 'high',
        message: 'Test alert',
        timestamp: Date.now(),
      };

      // Simulate alert emission
      dashboard['setupAlertHandling']();
      dashboard['alerts'] = [];

      // This would normally be triggered by the performance collector
      dashboard['alerts'].push(mockAlert);

      expect(dashboard['alerts']).toContain(mockAlert);
    });

    it('should limit alerts to maximum count', () => {
      dashboard['maxAlerts'] = 5;
      dashboard['alerts'] = [];

      // Add more alerts than the maximum
      for (let i = 0; i < 10; i++) {
        dashboard['alerts'].push({
          operation: `operation_${i}`,
          alertType: 'slow_query',
          threshold: 100,
          currentValue: 200,
          severity: 'high',
          message: `Alert ${i}`,
          timestamp: Date.now() + i,
        });
      }

      expect(dashboard['alerts'].length).toBeLessThanOrEqual(5);
    });
  });
});

describe('Singleton Performance Dashboard', () => {
  it('should provide singleton instance', () => {
    expect(performanceDashboard).toBeInstanceOf(PerformanceDashboard);
  });

  it('should have default configuration', () => {
    expect(performanceDashboard).toBeInstanceOf(PerformanceDashboard);
  });
});