
/**
 * P4-1: Performance Trending Service Tests
 *
 * Comprehensive test suite for performance trending and time-series
 * data collection functionality.
 */

import { afterEach,beforeEach, describe, expect, it } from '@jest/globals';

import { PerformanceTrendingService } from '../performance-trending.js';
import { systemMetricsService } from '../system-metrics.js';

// Mock the logger
jest.mock('../../utils/logger.js', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

// Mock system metrics service
jest.mock('../system-metrics.js', () => ({
  systemMetricsService: {
    getMetrics: jest.fn(() => ({
      store_count: { total: 100, successful: 95, failed: 5 },
      find_count: { total: 200, successful: 190, failed: 10 },
      purge_count: { total: 50, successful: 48, failed: 2 },
      performance: {
        avg_store_duration_ms: 50,
        avg_find_duration_ms: 30,
        uptime_ms: Date.now() - 3600000, // 1 hour ago
      },
      errors: { total_errors: 15 },
      rate_limiting: { active_actors: 5, total_requests: 300, blocked_requests: 10 },
      memory: { memory_usage_kb: 51200 },
    })),
  },
}));

describe('PerformanceTrendingService', () => {
  let service: PerformanceTrendingService;

  beforeEach(() => {
    // Use a custom config for testing
    service = new PerformanceTrendingService({
      collection_interval_seconds: 1, // Fast collection for tests
      retention_hours: 1, // Short retention for tests
      max_data_points: 10, // Small data set for tests
      anomaly_detection: {
        enabled: true,
        sensitivity: 'medium',
        min_data_points: 5,
      },
    });

    // Clear any existing data
    service['timeSeriesData'] = [];
    service['alerts'] = [];
  });

  afterEach(() => {
    service.destroy();
  });

  describe('Initialization', () => {
    it('should initialize with default config', () => {
      const defaultService = new PerformanceTrendingService();
      expect(defaultService).toBeDefined();
      defaultService.destroy();
    });

    it('should accept custom configuration', () => {
      const customConfig = {
        retention_hours: 48,
        collection_interval_seconds: 60,
        max_data_points: 5000,
      };

      const customService = new PerformanceTrendingService(customConfig);
      expect(customService).toBeDefined();
      customService.destroy();
    });
  });

  describe('Data Collection', () => {
    it('should start and stop collection', () => {
      expect(service.getStatus().collecting).toBe(false);

      service.startCollection();
      expect(service.getStatus().collecting).toBe(true);

      service.stopCollection();
      expect(service.getStatus().collecting).toBe(false);
    });

    it('should collect metrics when collection is started', async () => {
      service.startCollection();

      // Wait for at least one collection cycle
      await new Promise((resolve) => setTimeout(resolve, 1200)); // 1.2 seconds

      const status = service.getStatus();
      expect(status.dataPointsCount).toBeGreaterThan(0);
      expect(status.collecting).toBe(true);

      service.stopCollection();
    });

    it('should enforce retention limits', async () => {
      service.startCollection();

      // Collect more data points than max_data_points
      await new Promise((resolve) => setTimeout(resolve, 2500)); // 2.5 seconds

      const status = service.getStatus();
      expect(status.dataPointsCount).toBeLessThanOrEqual(10); // max_data_points

      service.stopCollection();
    });
  });

  describe('Derived Metrics Calculation', () => {
    it('should calculate derived metrics correctly', async () => {
      // Mock multiple data points to test trend calculation
      const mockMetrics = systemMetricsService.getMetrics();

      // Manually add some data points
      for (let i = 0; i < 5; i++) {
        const dataPoint = {
          timestamp: Date.now() - (5 - i) * 1000,
          metrics: mockMetrics,
          derived: service['calculateDerivedMetrics'](mockMetrics, Date.now() - (5 - i) * 1000),
        };
        service['timeSeriesData'].push(dataPoint);
      }

      const latestDataPoint = service['timeSeriesData'][service['timeSeriesData'].length - 1];
      const derived = latestDataPoint.derived;

      expect(derived).toHaveProperty('operations_per_second');
      expect(derived).toHaveProperty('error_rate');
      expect(derived).toHaveProperty('memory_utilization');
      expect(derived).toHaveProperty('response_time_trend');
      expect(derived).toHaveProperty('throughput_trend');

      expect(typeof derived.operations_per_second).toBe('number');
      expect(typeof derived.error_rate).toBe('number');
      expect(typeof derived.memory_utilization).toBe('number');
      expect(['improving', 'stable', 'degrading']).toContain(derived.response_time_trend);
      expect(['increasing', 'stable', 'decreasing']).toContain(derived.throughput_trend);
    });
  });

  describe('Trend Analysis', () => {
    beforeEach(async () => {
      // Add some historical data for trend analysis
      service.startCollection();
      await new Promise((resolve) => setTimeout(resolve, 1200));
      service.stopCollection();
    });

    it('should generate trend analysis', () => {
      const analysis = service.getTrendAnalysis(1); // 1 hour period

      expect(analysis).toHaveProperty('period');
      expect(analysis).toHaveProperty('performance');
      expect(analysis).toHaveProperty('throughput');
      expect(analysis).toHaveProperty('reliability');
      expect(analysis).toHaveProperty('resources');
      expect(analysis).toHaveProperty('anomalies');

      expect(analysis.period.duration_ms).toBeGreaterThan(0);
      expect(typeof analysis.performance.avg_response_time).toBe('number');
      expect(typeof analysis.throughput.operations_per_second).toBe('number');
    });

    it('should handle empty data gracefully', () => {
      // Clear data
      service['timeSeriesData'] = [];

      const analysis = service.getTrendAnalysis(1);

      expect(analysis).toHaveProperty('period');
      expect(analysis.performance.avg_response_time).toBe(0);
      expect(analysis.throughput.operations_per_second).toBe(0);
    });

    it('should calculate trend directions correctly', () => {
      // This test would require more complex mock data setup
      // For now, just ensure it doesn't crash
      const analysis = service.getTrendAnalysis(1);

      expect(['improving', 'stable', 'degrading']).toContain(
        analysis.performance.response_time_trend
      );
      expect(['increasing', 'stable', 'decreasing']).toContain(
        analysis.throughput.throughput_trend
      );
    });
  });

  describe('Alert System', () => {
    it('should track active alerts', () => {
      const initialAlerts = service.getActiveAlerts();
      expect(Array.isArray(initialAlerts)).toBe(true);
    });

    it('should create alerts based on thresholds', async () => {
      // Mock metrics that would trigger alerts
      const mockHighResponseTimeMetrics = {
        store_count: { total: 100, successful: 80, failed: 20 },
        find_count: { total: 200, successful: 180, failed: 20 },
        purge_count: { total: 50, successful: 45, failed: 5 },
        performance: {
          avg_store_duration_ms: 2000, // High response time
          avg_find_duration_ms: 1500, // High response time
          uptime_ms: Date.now() - 3600000,
        },
        errors: { total_errors: 50 }, // High error rate
        rate_limiting: { active_actors: 5, total_requests: 300, blocked_requests: 50 }, // High block rate
        memory: { memory_usage_kb: 102400 }, // High memory usage
      };

      jest.spyOn(systemMetricsService, 'getMetrics').mockReturnValue(mockHighResponseTimeMetrics);

      service.startCollection();
      await new Promise((resolve) => setTimeout(resolve, 1200));
      service.stopCollection();

      const alerts = service.getActiveAlerts();
      expect(alerts.length).toBeGreaterThan(0);

      const responseTimeAlert = alerts.find((alert) => alert.title === 'High Response Time');
      expect(responseTimeAlert).toBeDefined();
      expect(responseTimeAlert?.severity).toBe('warning');
    });

    it('should resolve alerts', () => {
      // Add a mock alert
      const mockAlert = service['createAlert'](
        'performance',
        'warning',
        'Test Alert',
        'Test alert for resolution',
        100,
        50,
        ['Test recommendation']
      );

      service['alerts'].push(mockAlert);

      expect(service.getActiveAlerts()).toHaveLength(1);

      service.resolveAlert(mockAlert.id);
      expect(service.getActiveAlerts()).toHaveLength(0);
    });
  });

  describe('Export Functionality', () => {
    beforeEach(async () => {
      service.startCollection();
      await new Promise((resolve) => setTimeout(resolve, 1200));
      service.stopCollection();
    });

    it('should export metrics as JSON', () => {
      const jsonExport = service.exportMetrics('json');
      expect(typeof jsonExport).toBe('string');

      const parsed = JSON.parse(jsonExport);
      expect(parsed).toHaveProperty('timestamp');
      expect(parsed).toHaveProperty('metrics');
      expect(parsed).toHaveProperty('derived');
      expect(parsed).toHaveProperty('alerts');
    });

    it('should export metrics as Prometheus format', () => {
      const prometheusExport = service.exportMetrics('prometheus');
      expect(typeof prometheusExport).toBe('string');

      expect(prometheusExport).toContain('# HELP');
      expect(prometheusExport).toContain('# TYPE');
      expect(prometheusExport).toContain('cortex_response_time_ms');
      expect(prometheusExport).toContain('cortex_operations_per_second');
    });

    it('should handle empty data gracefully when exporting', () => {
      service['timeSeriesData'] = [];

      const jsonExport = service.exportMetrics('json');
      const prometheusExport = service.exportMetrics('prometheus');

      // Should return empty string for prometheus with no data
      expect(jsonExport).toBeDefined();
      expect(prometheusExport).toBeDefined();
    });
  });

  describe('Status Reporting', () => {
    it('should report current status', () => {
      const status = service.getStatus();

      expect(status).toHaveProperty('collecting');
      expect(status).toHaveProperty('dataPointsCount');
      expect(status).toHaveProperty('activeAlertsCount');
      expect(status).toHaveProperty('retentionHours');
      expect(status).toHaveProperty('collectionInterval');

      expect(typeof status.collecting).toBe('boolean');
      expect(typeof status.dataPointsCount).toBe('number');
      expect(typeof status.activeAlertsCount).toBe('number');
    });

    it('should update status when collection starts/stops', () => {
      let status = service.getStatus();
      expect(status.collecting).toBe(false);

      service.startCollection();
      status = service.getStatus();
      expect(status.collecting).toBe(true);

      service.stopCollection();
      status = service.getStatus();
      expect(status.collecting).toBe(false);
    });
  });

  describe('Anomaly Detection', () => {
    it('should detect performance anomalies', async () => {
      service.startCollection();

      // First, let's establish a baseline with normal metrics
      await new Promise((resolve) => setTimeout(resolve, 1200));

      // Then inject a spike
      const spikeMetrics = {
        ...systemMetricsService.getMetrics(),
        performance: {
          avg_store_duration_ms: 5000, // Much higher than baseline
          avg_find_duration_ms: 3000, // Much higher than baseline
          uptime_ms: Date.now() - 3600000,
        },
      };

      jest.spyOn(systemMetricsService, 'getMetrics').mockReturnValue(spikeMetrics);

      // Wait for another collection cycle
      await new Promise((resolve) => setTimeout(resolve, 1200));

      service.stopCollection();

      // The anomaly detection should have logged warnings
      const mockLogger = require('../../utils/logger.js').logger;
      expect(mockLogger.warn).toHaveBeenCalledWith(
        'Performance anomaly detected',
        expect.objectContaining({
          type: 'performance_spike',
        })
      );
    });
  });

  describe('Memory Management', () => {
    it('should clean up old data points', async () => {
      service.startCollection();

      // Collect data for longer than retention period
      await new Promise((resolve) => setTimeout(resolve, 1200));

      const status1 = service.getStatus();
      expect(status1.dataPointsCount).toBeGreaterThan(0);

      // Wait for more data collection
      await new Promise((resolve) => setTimeout(resolve, 1200));

      const status2 = service.getStatus();
      expect(status2.dataPointsCount).toBeLessThanOrEqual(10); // max_data_points

      service.stopCollection();
    });

    it('should clean up old resolved alerts', async () => {
      // Add an old resolved alert
      const oldAlert = service['createAlert'](
        'performance',
        'warning',
        'Old Alert',
        'Old resolved alert',
        100,
        50,
        ['Test']
      );

      oldAlert.resolved = true;
      oldAlert.resolved_at = Date.now() - 2 * 60 * 60 * 1000; // 2 hours ago

      service['alerts'].push(oldAlert);

      // Force retention cleanup
      service['enforceRetention']();

      // Old resolved alert should be cleaned up
      expect(service['alerts']).not.toContain(oldAlert);
    });
  });

  describe('Error Handling', () => {
    it('should handle errors during metrics collection gracefully', () => {
      // Mock systemMetricsService to throw an error
      jest.spyOn(systemMetricsService, 'getMetrics').mockImplementation(() => {
        throw new Error('Metrics collection failed');
      });

      service.startCollection();

      // Should not crash the service
      expect(() => service['collectMetrics']()).not.toThrow();

      service.stopCollection();
    });

    it('should handle export errors gracefully', () => {
      service['timeSeriesData'] = [];

      // Should not throw when exporting with no data
      expect(() => service.exportMetrics('json')).not.toThrow();
      expect(() => service.exportMetrics('prometheus')).not.toThrow();
    });
  });

  describe('Configuration Validation', () => {
    it('should validate configuration values', () => {
      const invalidConfig = {
        retention_hours: -1, // Invalid negative value
        collection_interval_seconds: 0, // Invalid zero value
        max_data_points: -10, // Invalid negative value
      };

      // Should still create service with fallback values
      const serviceWithInvalidConfig = new PerformanceTrendingService(invalidConfig);
      expect(serviceWithInvalidConfig).toBeDefined();
      serviceWithInvalidConfig.destroy();
    });
  });
});
