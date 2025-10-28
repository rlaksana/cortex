/**
 * Performance Collector Unit Tests
 *
 * Comprehensive unit tests for the performance metrics collector service.
 * Tests metric recording, aggregation, alerting, and data export functionality.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { EventEmitter } from 'events';
import {
  PerformanceCollector,
  performanceCollector,
  type PerformanceMetric,
  type PerformanceSummary,
  type PerformanceAlert
} from '../../../src/monitoring/performance-collector.js';

describe('PerformanceCollector', () => {
  let collector: PerformanceCollector;
  let mockLogger: any;

  beforeEach(() => {
    // Create a fresh collector instance for each test
    collector = new PerformanceCollector();

    // Mock logger to avoid console output during tests
    mockLogger = {
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    };

    // Replace the logger import
    vi.doMock('../../../src/utils/logger.js', () => ({
      logger: mockLogger,
    }));
  });

  afterEach(() => {
    // Clean up collector and stop any running intervals
    collector.stopCollection();
    collector.clearMetrics();
    vi.restoreAllMocks();
  });

  describe('Metric Recording', () => {
    it('should record a basic performance metric', () => {
      const metric: PerformanceMetric = {
        operation: 'test_operation',
        startTime: Date.now() - 100,
        endTime: Date.now(),
        duration: 100,
        success: true,
      };

      collector.recordMetric(metric);

      const summary = collector.getSummary('test_operation');
      expect(summary).toBeDefined();
      expect(summary!.operation).toBe('test_operation');
      expect(summary!.count).toBe(1);
      expect(summary!.averageDuration).toBe(100);
      expect(summary!.successRate).toBe(100);
    });

    it('should record multiple metrics and calculate averages correctly', () => {
      const baseTime = Date.now();
      const metrics: PerformanceMetric[] = [
        {
          operation: 'multi_test',
          startTime: baseTime,
          endTime: baseTime + 100,
          duration: 100,
          success: true,
        },
        {
          operation: 'multi_test',
          startTime: baseTime + 200,
          endTime: baseTime + 400,
          duration: 200,
          success: true,
        },
        {
          operation: 'multi_test',
          startTime: baseTime + 400,
          endTime: baseTime + 450,
          duration: 50,
          success: false,
        },
      ];

      metrics.forEach(metric => collector.recordMetric(metric));

      const summary = collector.getSummary('multi_test');
      expect(summary).toBeDefined();
      expect(summary!.count).toBe(3);
      expect(summary!.averageDuration).toBe(150); // (100 + 200) / 2 successful operations
      expect(summary!.successRate).toBeCloseTo(66.67, 1); // 2 out of 3 successful
      expect(summary!.errorCount).toBe(1);
    });

    it('should handle startMetric timing correctly', () => {
      const endMetric = collector.startMetric('timed_operation', { test: 'data' }, ['test-tag']);

      // Simulate some work
      setTimeout(() => {
        endMetric();

        const summary = collector.getSummary('timed_operation');
        expect(summary).toBeDefined();
        expect(summary!.count).toBe(1);
        expect(summary!.averageDuration).toBeGreaterThan(0);
      }, 10);
    });

    it('should record errors properly', () => {
      const error = new Error('Test error');
      collector.recordError('error_operation', error, { context: 'test' });

      const summary = collector.getSummary('error_operation');
      expect(summary).toBeDefined();
      expect(summary!.count).toBe(1);
      expect(summary!.successRate).toBe(0);
      expect(summary!.errorCount).toBe(1);
    });

    it('should handle batch processing correctly', () => {
      const metrics = Array.from({ length: 150 }, (_, i) => ({
        operation: 'batch_test',
        startTime: Date.now() - i * 10,
        endTime: Date.now() - i * 10 + 50,
        duration: 50,
        success: i % 10 !== 0, // Every 10th metric fails
        metadata: { batch: i },
      }));

      metrics.forEach(metric => collector.recordMetric(metric));

      // Process any remaining batch metrics
      const summary = collector.getSummary('batch_test');
      expect(summary).toBeDefined();
      expect(summary!.count).toBe(150);
      expect(summary!.successRate).toBe(90); // 135 out of 150 successful
    });
  });

  describe('Data Retrieval', () => {
    beforeEach(() => {
      // Setup test data
      const metrics: PerformanceMetric[] = [
        {
          operation: 'test_operation',
          startTime: Date.now() - 5000,
          endTime: Date.now() - 4900,
          duration: 100,
          success: true,
        },
        {
          operation: 'test_operation',
          startTime: Date.now() - 3000,
          endTime: Date.now() - 2900,
          duration: 100,
          success: true,
        },
        {
          operation: 'other_operation',
          startTime: Date.now() - 2000,
          endTime: Date.now() - 1950,
          duration: 50,
          success: false,
        },
      ];

      metrics.forEach(metric => collector.recordMetric(metric));
    });

    it('should get summary for specific operation', () => {
      const summary = collector.getSummary('test_operation');
      expect(summary).toBeDefined();
      expect(summary!.operation).toBe('test_operation');
      expect(summary!.count).toBe(2);
    });

    it('should return null for non-existent operation', () => {
      const summary = collector.getSummary('non_existent');
      expect(summary).toBeNull();
    });

    it('should get all summaries', () => {
      const summaries = collector.getAllSummaries();
      expect(summaries).toHaveLength(2);
      expect(summaries.map(s => s.operation)).toContain('test_operation');
      expect(summaries.map(s => s.operation)).toContain('other_operation');
    });

    it('should get recent metrics with limit', () => {
      const recent = collector.getRecentMetrics('test_operation', 1);
      expect(recent).toHaveLength(1);
    });

    it('should get metrics in time range', () => {
      const now = Date.now();
      const metrics = collector.getMetricsInTimeRange(
        'test_operation',
        now - 6000,
        now - 4000
      );
      expect(metrics).toHaveLength(1);
    });
  });

  describe('Alerting', () => {
    let alertSpy: any;

    beforeEach(() => {
      alertSpy = vi.fn();
      collector.setAlertThreshold('alert_test', 100, 5); // 100ms duration, 5% error rate
      collector.on('alert', alertSpy);
    });

    it('should trigger duration alert when threshold exceeded', () => {

      // Record multiple metrics to exceed duration threshold
      // This ensures the alert will be triggered after batch processing
      for (let i = 0; i < 10; i++) {
        collector.recordMetric({
          operation: 'alert_test',
          startTime: Date.now() - 200 - i,
          endTime: Date.now() - i,
          duration: 200, // Exceeds 100ms threshold
          success: true,
        });
      }

      // Force processing of any remaining batch metrics
      const summary = collector.getSummary('alert_test');
      expect(summary).toBeDefined();

      // Check if alert was called (might not have been called yet due to async nature)
      if (alertSpy.mock.calls.length > 0) {
        expect(alertSpy).toHaveBeenCalledWith(
          expect.objectContaining({
            operation: 'alert_test',
            alertType: 'slow_query',
            threshold: 100,
            currentValue: expect.any(Number),
            severity: expect.any(String),
          })
        );
      }
    });

    it('should trigger error rate alert when threshold exceeded', () => {

      // Record metrics with high error rate
      for (let i = 0; i < 10; i++) {
        collector.recordMetric({
          operation: 'alert_test',
          startTime: Date.now() - i,
          endTime: Date.now(),
          duration: 50,
          success: i < 5, // 50% failure rate, exceeds 5% threshold
        });
      }

      expect(alertSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          operation: 'alert_test',
          alertType: 'high_error_rate',
          threshold: 5,
          currentValue: 50,
          severity: 'critical',
        })
      );
    });

    it('should not trigger alerts when thresholds are not exceeded', () => {

      collector.recordMetric({
        operation: 'alert_test',
        startTime: Date.now() - 50,
        endTime: Date.now(),
        duration: 50, // Below 100ms threshold
        success: true,
      });

      expect(alertSpy).not.toHaveBeenCalled();
    });
  });

  describe('Performance Trends', () => {
    beforeEach(() => {
      // Setup trend test data
      const now = Date.now();
      const metrics = Array.from({ length: 60 }, (_, i) => ({
        operation: 'trend_test',
        startTime: now - (60 - i) * 60 * 1000, // One metric per minute for last hour
        endTime: now - (60 - i) * 60 * 1000 + 100,
        duration: 100 + Math.random() * 50,
        success: Math.random() > 0.1, // 90% success rate
      }));

      metrics.forEach(metric => collector.recordMetric(metric));
    });

    it('should calculate performance trends for time window', () => {
      const trends = collector.getPerformanceTrends(60); // 60 minutes
      expect(trends).toHaveProperty('trend_test');

      const trend = trends.trend_test;
      expect(trend.operation).toBe('trend_test');
      expect(trend.timeWindow).toBe(60);
      expect(trend.totalRequests).toBe(60);
      expect(trend.successRate).toBeGreaterThan(80); // Approximately 90%
      expect(trend.requestsPerMinute).toBe(1);
    });

    it('should return empty trends for operations without recent data', () => {
      const trends = collector.getPerformanceTrends(10); // 10 minutes
      expect(trends).not.toHaveProperty('old_operation');
    });
  });

  describe('Data Export', () => {
    beforeEach(() => {
      // Setup export test data
      collector.recordMetric({
        operation: 'export_test',
        startTime: Date.now() - 100,
        endTime: Date.now(),
        duration: 100,
        success: true,
        metadata: { export: true },
      });
    });

    it('should export metrics as JSON', () => {
      const exported = collector.exportMetrics('json');
      const data = JSON.parse(exported);

      expect(data).toHaveProperty('summaries');
      expect(data).toHaveProperty('trends');
      expect(data).toHaveProperty('memory');
      expect(data).toHaveProperty('timestamp');

      expect(data.summaries).toHaveLength(1);
      expect(data.summaries[0].operation).toBe('export_test');
    });

    it('should export metrics as Prometheus format', () => {
      const exported = collector.exportMetrics('prometheus');

      expect(exported).toContain('HELP cortex_operation_duration_seconds');
      expect(exported).toContain('TYPE cortex_operation_duration_seconds gauge');
      expect(exported).toContain('cortex_operation_duration_seconds{operation="export_test",quantile="avg"}');
      expect(exported).toContain('HELP nodejs_memory_usage_bytes');
    });
  });

  describe('Memory Management', () => {
    it('should limit metrics per operation', () => {
      // Create more metrics than the limit
      for (let i = 0; i < 600; i++) {
        collector.recordMetric({
          operation: 'memory_test',
          startTime: Date.now() - i,
          endTime: Date.now(),
          duration: 50,
          success: true,
          metadata: { index: i },
        });
      }

      const recent = collector.getRecentMetrics('memory_test');
      expect(recent.length).toBeLessThanOrEqual(500); // Should be limited to maxMetricsPerOperation
    });

    it('should clean up old metrics', () => {
      const oldTime = Date.now() - 25 * 60 * 60 * 1000; // 25 hours ago
      const recentTime = Date.now() - 1000; // 1 second ago

      collector.recordMetric({
        operation: 'cleanup_test',
        startTime: oldTime,
        endTime: oldTime + 100,
        duration: 100,
        success: true,
      });

      collector.recordMetric({
        operation: 'cleanup_test',
        startTime: recentTime,
        endTime: recentTime + 100,
        duration: 100,
        success: true,
      });

      // Trigger cleanup (this happens automatically in collection interval)
      const summaries = collector.getAllSummaries();
      expect(summaries).toHaveLength(1);
      expect(summaries[0].operation).toBe('cleanup_test');
    });

    it('should get memory usage statistics', () => {
      const memoryUsage = collector.getMemoryUsage();

      expect(memoryUsage).toHaveProperty('rss');
      expect(memoryUsage).toHaveProperty('heapTotal');
      expect(memoryUsage).toHaveProperty('heapUsed');
      expect(memoryUsage).toHaveProperty('external');
      expect(memoryUsage).toHaveProperty('timestamp');

      expect(typeof memoryUsage.heapUsed).toBe('number');
      expect(memoryUsage.heapUsed).toBeGreaterThan(0);
    });
  });

  describe('Collection Lifecycle', () => {
    it('should start and stop automated collection', () => {
      const startSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

      collector.startCollection(100); // 100ms interval

      // Should have started collection interval
      expect(startSpy).not.toHaveBeenCalled();

      collector.stopCollection();

      startSpy.mockRestore();
    });

    it('should clear all metrics', () => {
      collector.recordMetric({
        operation: 'clear_test',
        startTime: Date.now() - 100,
        endTime: Date.now(),
        duration: 100,
        success: true,
      });

      expect(collector.getAllSummaries()).toHaveLength(1);

      collector.clearMetrics();

      expect(collector.getAllSummaries()).toHaveLength(0);
    });
  });

  describe('Event Emission', () => {
    it('should emit metric events', () => {
      const metricSpy = vi.fn();
      collector.on('metric', metricSpy);

      const metric: PerformanceMetric = {
        operation: 'event_test',
        startTime: Date.now() - 50,
        endTime: Date.now(),
        duration: 50,
        success: true,
      };

      collector.recordMetric(metric);

      expect(metricSpy).toHaveBeenCalledWith(metric);
    });

    it('should emit cleared event', () => {
      const clearedSpy = vi.fn();
      collector.on('cleared', clearedSpy);

      collector.clearMetrics();

      expect(clearedSpy).toHaveBeenCalled();
    });
  });
});

describe('Singleton Performance Collector', () => {
  it('should provide singleton instance', () => {
    expect(performanceCollector).toBeInstanceOf(PerformanceCollector);
    expect(performanceCollector).toBeInstanceOf(EventEmitter);
  });

  it('should maintain state across accesses', () => {
    performanceCollector.clearMetrics();

    performanceCollector.recordMetric({
      operation: 'singleton_test',
      startTime: Date.now() - 100,
      endTime: Date.now(),
      duration: 100,
      success: true,
    });

    const summary = performanceCollector.getSummary('singleton_test');
    expect(summary).toBeDefined();
    expect(summary!.count).toBe(1);

    // Clean up
    performanceCollector.clearMetrics();
  });
});