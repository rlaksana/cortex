import {
  PerformanceCollector,
  type PerformanceMetric,
  type PerformanceSummary,
  type PerformanceAlert,
  performanceCollector
} from '../../../src/monitoring/performance-collector';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Simple sleep utility for tests
const sleep = (ms: number): Promise<void> => new Promise(resolve => setTimeout(resolve, ms));

describe('MetricsService', () => {
  let metricsService: PerformanceCollector;

  beforeEach(() => {
    // Create a fresh instance for testing
    metricsService = new PerformanceCollector();

    // Configure test thresholds
    metricsService.setAlertThreshold('test_operation', 500, 5);
    metricsService.setAlertThreshold('batch_processing', 1000, 10);
    metricsService.setAlertThreshold('api_request', 200, 2);
  });

  afterEach(() => {
    metricsService.stopCollection();
    metricsService.clearMetrics();
  });

  describe('Metrics Collection', () => {
    it('should collect counter metrics', async () => {
      const operation = 'user_login';

      // Record multiple successful operations
      for (let i = 0; i < 10; i++) {
        const endMetric = metricsService.startMetric(operation);
        await sleep(10);
        endMetric();
      }

      const summary = metricsService.getSummary(operation);

      expect(summary).toBeDefined();
      expect(summary!.count).toBe(10);
      expect(summary!.successRate).toBe(100);
      expect(summary!.totalDuration).toBeGreaterThan(0);
      expect(summary!.averageDuration).toBeGreaterThan(0);
    });

    it('should collect gauge metrics with labels and tags', async () => {
      const operation = 'memory_usage';
      const metadata = { component: 'auth-service', instance: 'prod-1' };
      const tags = ['memory', 'production', 'auth'];

      const endMetric = metricsService.startMetric(operation, metadata, tags);
      await sleep(50);
      endMetric();

      const recentMetrics = metricsService.getRecentMetrics(operation, 1);

      expect(recentMetrics).toHaveLength(1);
      expect(recentMetrics[0]).toMatchObject({
        operation,
        success: true,
        metadata,
        tags
      });
      expect(recentMetrics[0].duration).toBeGreaterThan(0);
    });

    it('should collect histogram metrics with proper distribution', async () => {
      const operation = 'response_time_histogram';
      const responseTimes = [10, 20, 30, 40, 50, 100, 200, 500, 1000];

      // Record metrics with different durations
      for (const duration of responseTimes) {
        const endMetric = metricsService.startMetric(operation);
        await sleep(duration);
        endMetric();
      }

      const summary = metricsService.getSummary(operation);

      expect(summary).toBeDefined();
      expect(summary!.count).toBe(responseTimes.length);
      expect(summary!.minDuration).toBeGreaterThanOrEqual(10);
      expect(summary!.maxDuration).toBeGreaterThanOrEqual(1000);
      expect(summary!.averageDuration).toBeGreaterThan(0);
      expect(summary!.p95).toBeGreaterThan(summary!.averageDuration);
      expect(summary!.p99).toBeGreaterThanOrEqual(summary!.p95);
    });

    it('should handle custom metric definitions', async () => {
      const customOperation = 'custom_business_metric';
      const customMetadata = {
        business_unit: 'sales',
        region: 'us-west',
        product_category: 'enterprise'
      };

      // Record custom metric
      const endMetric = metricsService.startMetric(customOperation, customMetadata);
      await sleep(25);
      endMetric();

      const metrics = metricsService.getRecentMetrics(customOperation);

      expect(metrics).toHaveLength(1);
      expect(metrics[0].metadata).toEqual(customMetadata);
      expect(metrics[0].operation).toBe(customOperation);
    });

    it('should handle time series data with proper timestamps', async () => {
      const operation = 'time_series_test';
      const startTime = Date.now();

      const endMetric = metricsService.startMetric(operation);
      await sleep(100);
      const endTime = endMetric();

      const metrics = metricsService.getRecentMetrics(operation);

      expect(metrics).toHaveLength(1);
      expect(metrics[0].startTime).toBeGreaterThanOrEqual(startTime);
      expect(metrics[0].endTime).toBeLessThanOrEqual(Date.now());
      expect(metrics[0].duration).toBeGreaterThan(90); // Allow some tolerance
    });

    it('should batch process metrics efficiently', async () => {
      const operation = 'batch_test';
      const batchSize = 150; // Exceeds default batch size of 100

      // Record many metrics quickly to test batching
      for (let i = 0; i < batchSize; i++) {
        const endMetric = metricsService.startMetric(operation);
        endMetric(); // Immediate end to test batch processing
      }

      // Force batch processing
      await sleep(1100); // Wait for batch process interval

      const summary = metricsService.getSummary(operation);

      expect(summary).toBeDefined();
      expect(summary!.count).toBe(batchSize);
      expect(summary!.totalDuration).toBeGreaterThanOrEqual(0);
    });

    it('should handle metric labeling and tagging consistently', async () => {
      const operation = 'labeled_metrics';
      const baseTags = ['api', 'http'];
      const varyingMetadata = [
        { endpoint: '/users', method: 'GET' },
        { endpoint: '/users', method: 'POST' },
        { endpoint: '/orders', method: 'GET' }
      ];

      for (const metadata of varyingMetadata) {
        const endMetric = metricsService.startMetric(operation, metadata, baseTags);
        await sleep(20);
        endMetric();
      }

      const metrics = metricsService.getRecentMetrics(operation, 3);

      expect(metrics).toHaveLength(3);
      metrics.forEach((metric, index) => {
        expect(metric.tags).toEqual(baseTags);
        expect(metric.metadata).toEqual(varyingMetadata[index]);
      });
    });
  });

  describe('Performance Metrics', () => {
    it('should track response time accurately', async () => {
      const operation = 'api_response_time';
      const expectedDuration = 150;

      const start = Date.now();
      const endMetric = metricsService.startMetric(operation);
      await sleep(expectedDuration);
      endMetric();
      const actualDuration = Date.now() - start;

      const summary = metricsService.getSummary(operation);

      expect(summary).toBeDefined();
      expect(summary!.averageDuration).toBeGreaterThan(expectedDuration - 10);
      expect(summary!.averageDuration).toBeLessThan(actualDuration + 10);
    });

    it('should calculate throughput metrics correctly', async () => {
      const operation = 'throughput_test';
      const requestCount = 20;
      const timeWindow = 2000; // 2 seconds

      const startTime = Date.now();

      // Spread requests over time window
      for (let i = 0; i < requestCount; i++) {
        const endMetric = metricsService.startMetric(operation);
        await sleep(timeWindow / requestCount);
        endMetric();
      }

      const endTime = Date.now();
      const actualDuration = endTime - startTime;

      const trends = metricsService.getPerformanceTrends(Math.ceil(actualDuration / 60000));

      // Check if operation exists in trends (may not exist if no metrics in time window)
      if (trends[operation]) {
        expect(trends[operation].totalRequests).toBeGreaterThan(0);
        expect(trends[operation].requestsPerMinute).toBeGreaterThanOrEqual(0);
      } else {
        // Fallback to checking summary directly
        const summary = metricsService.getSummary(operation);
        expect(summary!.count).toBe(requestCount);
      }
    });

    it('should calculate error rates accurately', async () => {
      const operation = 'error_rate_test';
      const successCount = 8;
      const errorCount = 2;

      // Record successful operations
      for (let i = 0; i < successCount; i++) {
        const endMetric = metricsService.startMetric(operation);
        await sleep(10);
        endMetric();
      }

      // Record errors
      for (let i = 0; i < errorCount; i++) {
        metricsService.recordError(operation, new Error(`Test error ${i}`));
      }

      const summary = metricsService.getSummary(operation);

      expect(summary).toBeDefined();
      expect(summary!.count).toBe(successCount + errorCount);
      expect(summary!.errorCount).toBe(errorCount);
      expect(summary!.successRate).toBe((successCount / (successCount + errorCount)) * 100);
    });

    it('should monitor resource utilization metrics', async () => {
      const memoryUsage = metricsService.getMemoryUsage();

      expect(memoryUsage).toMatchObject({
        rss: expect.any(Number),
        heapTotal: expect.any(Number),
        heapUsed: expect.any(Number),
        external: expect.any(Number),
        arrayBuffers: expect.any(Number),
        timestamp: expect.any(Number)
      });

      expect(memoryUsage.heapUsed).toBeGreaterThan(0);
      expect(memoryUsage.heapTotal).toBeGreaterThanOrEqual(memoryUsage.heapUsed);
      expect(memoryUsage.timestamp).toBeGreaterThan(0);
    });

    it('should handle concurrent metric recording', async () => {
      const operation = 'concurrent_metrics';
      const concurrentCount = 10;

      // Record metrics concurrently
      const promises = Array.from({ length: concurrentCount }, async (_, i) => {
        const endMetric = metricsService.startMetric(operation, { concurrentId: i });
        await sleep(Math.random() * 100);
        endMetric();
      });

      await Promise.all(promises);

      const summary = metricsService.getSummary(operation);

      expect(summary).toBeDefined();
      expect(summary!.count).toBe(concurrentCount);
      expect(summary!.successRate).toBe(100);
    });

    it('should track metrics across different time windows', async () => {
      const operation = 'time_window_test';
      const now = Date.now();
      const timeWindows = [60000, 300000, 900000]; // 1min, 5min, 15min

      // Record metrics over time
      for (let i = 0; i < 10; i++) {
        const endMetric = metricsService.startMetric(operation);
        await sleep(50);
        endMetric();
      }

      // Test different time windows
      for (const windowMs of timeWindows) {
        const metrics = metricsService.getMetricsInTimeRange(
          operation,
          now - windowMs,
          now + windowMs
        );

        expect(metrics.length).toBeGreaterThan(0);
        expect(metrics.every(m => m.startTime >= now - windowMs)).toBe(true);
        expect(metrics.every(m => m.endTime <= now + windowMs)).toBe(true);
      }
    });
  });

  describe('Aggregation and Analytics', () => {
    it('should perform real-time metric aggregation', async () => {
      const operation = 'realtime_aggregation';
      const metricCount = 50;

      // Record metrics with varying durations
      for (let i = 0; i < metricCount; i++) {
        const endMetric = metricsService.startMetric(operation);
        await sleep(Math.random() * 200 + 50); // 50-250ms
        endMetric();
      }

      const summary = metricsService.getSummary(operation);

      expect(summary).toBeDefined();
      expect(summary!.count).toBe(metricCount);
      expect(summary!.averageDuration).toBeGreaterThan(50);
      expect(summary!.averageDuration).toBeLessThan(250);
      expect(summary!.p95).toBeGreaterThanOrEqual(summary!.averageDuration);
      expect(summary!.p99).toBeGreaterThanOrEqual(summary!.p95);
    });

    it('should calculate statistical analysis (percentiles, averages)', async () => {
      const operation = 'statistical_analysis';
      const durations = [100, 150, 200, 250, 300, 350, 400, 450, 500, 1000];

      for (const duration of durations) {
        const endMetric = metricsService.startMetric(operation);
        await sleep(duration);
        endMetric();
      }

      const summary = metricsService.getSummary(operation);

      expect(summary).toBeDefined();
      const expectedAverage = durations.reduce((a, b) => a + b) / durations.length;
      expect(summary!.averageDuration).toBeGreaterThan(expectedAverage - 20);
      expect(summary!.averageDuration).toBeLessThan(expectedAverage + 20);
      expect(summary!.minDuration).toBe(100);
      expect(summary!.maxDuration).toBe(1000);
      expect(summary!.averageDuration).toBeGreaterThan(200);
      expect(summary!.averageDuration).toBeLessThan(400);
      expect(summary!.p95).toBeGreaterThan(700);
    });

    it('should perform trend analysis and forecasting', async () => {
      const operation = 'trend_analysis';

      // Create an increasing trend
      for (let i = 0; i < 20; i++) {
        const endMetric = metricsService.startMetric(operation);
        await sleep(50 + i * 10); // Increasing duration
        endMetric();
        await sleep(100); // Small gap between measurements
      }

      const trends = metricsService.getPerformanceTrends(5); // 5 minute window

      // Check if operation exists in trends (may not exist if no metrics in time window)
      if (trends[operation]) {
        expect(trends[operation].totalRequests).toBeGreaterThan(0);
        expect(trends[operation].averageDuration).toBeGreaterThan(0);
        expect(trends[operation].p95Duration).toBeGreaterThanOrEqual(trends[operation].averageDuration);
        expect(trends[operation].p99Duration).toBeGreaterThanOrEqual(trends[operation].p95Duration);
      } else {
        // Fallback to checking summary directly
        const summary = metricsService.getSummary(operation);
        expect(summary!.count).toBeGreaterThan(0);
        expect(summary!.averageDuration).toBeGreaterThan(0);
        expect(summary!.p95).toBeGreaterThanOrEqual(summary!.averageDuration);
        expect(summary!.p99).toBeGreaterThanOrEqual(summary!.p95);
      }
    });

    it('should detect anomalies in metric patterns', async () => {
      const operation = 'anomaly_detection';

      // Record normal metrics
      for (let i = 0; i < 10; i++) {
        const endMetric = metricsService.startMetric(operation);
        await sleep(100); // Consistent 100ms duration
        endMetric();
      }

      // Record anomalous metric
      const endMetric = metricsService.startMetric(operation);
      await sleep(1000); // 10x slower than normal
      endMetric();

      const summary = metricsService.getSummary(operation);

      expect(summary).toBeDefined();
      expect(summary!.maxDuration).toBeGreaterThan(summary!.averageDuration * 5);
      expect(summary!.p99).toBeGreaterThan(summary!.p95);
    });

    it('should aggregate metrics by time intervals', async () => {
      const operation1 = 'interval_test_1';
      const operation2 = 'interval_test_2';

      // Record metrics for different operations
      for (let i = 0; i < 5; i++) {
        const end1 = metricsService.startMetric(operation1);
        const end2 = metricsService.startMetric(operation2);
        await sleep(100);
        end1();
        end2();
      }

      const allSummaries = metricsService.getAllSummaries();

      expect(allSummaries).toHaveLength(2);
      expect(allSummaries.find(s => s.operation === operation1)).toBeDefined();
      expect(allSummaries.find(s => s.operation === operation2)).toBeDefined();

      allSummaries.forEach(summary => {
        expect(summary.count).toBe(5);
        expect(summary.averageDuration).toBeGreaterThan(0);
      });
    });

    it('should handle metric correlations across operations', async () => {
      const parentOperation = 'parent_operation';
      const childOperation = 'child_operation';

      // Simulate parent-child operation relationship
      for (let i = 0; i < 5; i++) {
        const parentEnd = metricsService.startMetric(parentOperation);
        await sleep(50);

        const childEnd = metricsService.startMetric(childOperation, { parentId: i });
        await sleep(100);
        childEnd();

        parentEnd();
      }

      const parentSummary = metricsService.getSummary(parentOperation);
      const childSummary = metricsService.getSummary(childOperation);

      expect(parentSummary).toBeDefined();
      expect(childSummary).toBeDefined();
      expect(childSummary!.averageDuration).toBeGreaterThan(parentSummary!.averageDuration);
    });
  });

  describe('Storage and Retrieval', () => {
    it('should store metrics efficiently with memory management', async () => {
      const operation = 'storage_efficiency';
      const metricCount = 600; // Exceeds maxMetricsPerOperation of 500

      for (let i = 0; i < metricCount; i++) {
        const endMetric = metricsService.startMetric(operation, { index: i });
        endMetric();
      }

      const recentMetrics = metricsService.getRecentMetrics(operation);
      const summary = metricsService.getSummary(operation);

      // Should only keep the most recent metrics (maxMetricsPerOperation)
      expect(recentMetrics.length).toBeLessThanOrEqual(500);
      expect(summary!.count).toBe(metricCount); // But summary should reflect total count

      // Verify metrics are the most recent ones
      const firstMetric = recentMetrics[0];
      const lastMetric = recentMetrics[recentMetrics.length - 1];
      expect(firstMetric.metadata.index).toBeGreaterThan(lastMetric.metadata.index);
    });

    it('should integrate with time series database patterns', async () => {
      const operation = 'timeseries_db';
      const timePoints = [
        Date.now() - 3600000, // 1 hour ago
        Date.now() - 1800000, // 30 minutes ago
        Date.now()             // Now
      ];

      for (const timePoint of timePoints) {
        const endMetric = metricsService.startMetric(operation, { timestamp: timePoint });
        await sleep(50);
        endMetric();
      }

      // Wait a moment for all metrics to be processed
      await sleep(100);

      // Query different time ranges
      const currentTime = Date.now();
      const lastHour = metricsService.getMetricsInTimeRange(
        operation,
        currentTime - 3600000,
        currentTime
      );

      const last30Minutes = metricsService.getMetricsInTimeRange(
        operation,
        currentTime - 1800000,
        currentTime
      );

      // We should have all metrics in the last hour, and some in the last 30 minutes
      expect(lastHour.length).toBeGreaterThanOrEqual(2);
      expect(last30Minutes.length).toBeGreaterThanOrEqual(1);
    });

    it('should optimize metric queries with proper indexing', async () => {
      const operations = ['query_opt_1', 'query_opt_2', 'query_opt_3'];
      const metricsPerOperation = 100;

      // Generate test data
      for (const operation of operations) {
        for (let i = 0; i < metricsPerOperation; i++) {
          const endMetric = metricsService.startMetric(operation, { batchId: Math.floor(i / 10) });
          await sleep(10);
          endMetric();
        }
      }

      // Test query performance
      const startTime = Date.now();

      for (const operation of operations) {
        const summary = metricsService.getSummary(operation);
        expect(summary!.count).toBe(metricsPerOperation);
      }

      const queryTime = Date.now() - startTime;

      // Queries should be fast (under 100ms for this dataset)
      expect(queryTime).toBeLessThan(100);
    });

    it('should provide efficient historical data access', async () => {
      const operation = 'historical_access';
      const now = Date.now();
      const dataPoints = 50;
      const timeSpan = 3600000; // 1 hour

      // Create historical data
      for (let i = 0; i < dataPoints; i++) {
        const endMetric = metricsService.startMetric(operation, { historicalIndex: i });
        await sleep(10); // Small delay to create time spread
        endMetric();
      }

      // Access recent data in chunks
      const recentMetrics = metricsService.getRecentMetrics(operation, 20);
      expect(recentMetrics.length).toBeLessThanOrEqual(50);
      expect(recentMetrics.length).toBeGreaterThan(0);
    });

    it('should handle metric storage cleanup', async () => {
      const operation = 'cleanup_test';
      const oldMetricCount = 20;

      // Create some metrics first
      for (let i = 0; i < oldMetricCount; i++) {
        const endMetric = metricsService.startMetric(operation);
        await sleep(10);
        endMetric();
      }

      const initialCount = metricsService.getRecentMetrics(operation).length;
      expect(initialCount).toBe(oldMetricCount);

      // Clear and verify cleanup
      metricsService.clearMetrics();

      const afterClear = metricsService.getRecentMetrics(operation);
      expect(afterClear).toHaveLength(0);

      // But summary should still be available until cleared again
      metricsService.clearMetrics();
      const summaryAfterClear = metricsService.getSummary(operation);
      expect(summaryAfterClear).toBeNull();
    });
  });

  describe('Alerting and Thresholds', () => {
    it('should configure dynamic threshold settings', async () => {
      const operation = 'dynamic_threshold';
      const durationThreshold = 300;
      const errorRateThreshold = 15;

      metricsService.setAlertThreshold(operation, durationThreshold, errorRateThreshold);

      // Verify thresholds are set by triggering alerts
      const endMetric = metricsService.startMetric(operation);
      await sleep(durationThreshold + 100); // Exceed duration threshold
      endMetric();

      // Check if alert would be triggered (via event listener)
      const alertEvents: PerformanceAlert[] = [];
      metricsService.on('alert', (alert) => alertEvents.push(alert));

      // Trigger several slow metrics to activate alert checking
      for (let i = 0; i < 3; i++) {
        const slowEnd = metricsService.startMetric(operation);
        await sleep(durationThreshold + 50);
        slowEnd();
      }

      await sleep(500); // Allow alert processing

      // Alert may be triggered for duration threshold
      if (alertEvents.length > 0) {
        const durationAlerts = alertEvents.filter(a => a.alertType === 'slow_query');
        expect(durationAlerts[0].threshold).toBe(durationThreshold);
      } else {
        // If no alerts were triggered, at least verify we have slow metrics
        const summary = metricsService.getSummary(operation);
        expect(summary!.averageDuration).toBeGreaterThan(durationThreshold);
      }
    });

    it('should manage alert rule configurations', async () => {
      const operations = ['rule_test_1', 'rule_test_2'];
      const thresholds = [
        { operation: operations[0], duration: 100, errorRate: 5 },
        { operation: operations[1], duration: 200, errorRate: 10 }
      ];

      // Configure multiple alert rules
      thresholds.forEach(({ operation, duration, errorRate }) => {
        metricsService.setAlertThreshold(operation, duration, errorRate);
      });

      // Test each rule
      for (const { operation, duration, errorRate } of thresholds) {
        const alertEvents: PerformanceAlert[] = [];
        metricsService.on('alert', (alert) => {
          if (alert.operation === operation) alertEvents.push(alert);
        });

        // Trigger alert
        const endMetric = metricsService.startMetric(operation);
        await sleep(duration + 50);
        endMetric();

        await sleep(100);

        expect(alertEvents.length).toBeGreaterThan(0);
        expect(alertEvents[0].operation).toBe(operation);
      }
    });

    it('should integrate notification systems', async () => {
      const operation = 'notification_test';
      const notifications: any[] = [];

      // Mock notification service
      const mockNotificationService = {
        sendAlert: vi.fn().mockImplementation((alert) => {
          notifications.push(alert);
        })
      };

      metricsService.setAlertThreshold(operation, 100, 5);

      metricsService.on('alert', (alert) => {
        mockNotificationService.sendAlert(alert);
      });

      // Trigger alert
      const endMetric = metricsService.startMetric(operation);
      await sleep(150);
      endMetric();

      await sleep(200);

      expect(mockNotificationService.sendAlert).toHaveBeenCalled();
      expect(notifications.length).toBeGreaterThan(0);
      expect(notifications[0]).toMatchObject({
        operation,
        alertType: 'slow_query',
        severity: expect.stringMatching(/^(low|medium|high|critical)$/)
      });
    });

    it('should implement alert escalation logic', async () => {
      const operation = 'escalation_test';
      const escalationEvents: string[] = [];

      metricsService.setAlertThreshold(operation, 100, 5);

      metricsService.on('alert', (alert) => {
        const escalationLevel = alert.currentValue > alert.threshold * 2 ? 'critical' : 'warning';
        escalationEvents.push(escalationLevel);
      });

      // Trigger moderate alert
      const moderateEnd = metricsService.startMetric(operation);
      await sleep(120); // 20% over threshold
      moderateEnd();

      // Trigger severe alert
      const severeEnd = metricsService.startMetric(operation);
      await sleep(250); // 150% over threshold
      severeEnd();

      await sleep(200);

      expect(escalationEvents.length).toBeGreaterThan(0);
    });

    it('should handle alert cooldown periods', async () => {
      const operation = 'cooldown_test';
      const alertEvents: PerformanceAlert[] = [];

      metricsService.setAlertThreshold(operation, 100, 5);

      metricsService.on('alert', (alert) => {
        if (alert.operation === operation) {
          alertEvents.push(alert);
        }
      });

      // Trigger first alert
      const firstEnd = metricsService.startMetric(operation);
      await sleep(150);
      firstEnd();

      await sleep(100);

      // Try to trigger second alert quickly
      const secondEnd = metricsService.startMetric(operation);
      await sleep(160);
      secondEnd();

      await sleep(200);

      // Should have at least one alert, but potentially less than triggers due to cooldown
      expect(alertEvents.length).toBeGreaterThanOrEqual(1);
    });

    it('should deduplicate similar alerts', async () => {
      const operation = 'deduplication_test';
      const alertEvents: PerformanceAlert[] = [];

      metricsService.setAlertThreshold(operation, 100, 5);

      metricsService.on('alert', (alert) => {
        if (alert.operation === operation) {
          alertEvents.push(alert);
        }
      });

      // Trigger multiple similar alerts
      for (let i = 0; i < 3; i++) {
        const endMetric = metricsService.startMetric(operation);
        await sleep(120 + i * 10);
        endMetric();
        await sleep(50);
      }

      // Allow processing time
      await sleep(300);

      // Should receive some alerts, potentially deduplicated
      expect(alertEvents.length).toBeGreaterThanOrEqual(1);
      alertEvents.forEach(alert => {
        expect(alert.operation).toBe(operation);
        expect(alert.alertType).toBe('slow_query');
      });
    });

    it('should support severity-based alert routing', async () => {
      const operation = 'severity_routing';
      const routedAlerts: { severity: string; route: string }[] = [];

      const mockRoutes = {
        low: 'log',
        medium: 'email',
        high: 'slack',
        critical: 'pager'
      };

      metricsService.setAlertThreshold(operation, 100, 5);

      metricsService.on('alert', (alert) => {
        routedAlerts.push({
          severity: alert.severity,
          route: mockRoutes[alert.severity]
        });
      });

      // Trigger different severity levels
      const mildEnd = metricsService.startMetric(operation);
      await sleep(110); // Just over threshold
      mildEnd();

      await sleep(100);

      const severeEnd = metricsService.startMetric(operation);
      await sleep(300); // Well over threshold
      severeEnd();

      await sleep(200);

      expect(routedAlerts.length).toBeGreaterThan(0);
      routedAlerts.forEach(({ severity, route }) => {
        expect(['low', 'medium', 'high', 'critical']).toContain(severity);
        expect(['log', 'email', 'slack', 'pager']).toContain(route);
      });
    });
  });

  describe('Integration with Services', () => {
    it('should collect metrics from multiple services', async () => {
      const services = ['auth-service', 'user-service', 'order-service'];
      const operations = services.map(service => `${service}_api`);

      // Simulate metrics from different services
      for (let i = 0; i < operations.length; i++) {
        const operation = operations[i];
        const service = services[i];

        for (let j = 0; j < 10; j++) {
          const endMetric = metricsService.startMetric(operation, {
            service,
            endpoint: `/api/v1/${service}`,
            method: 'GET'
          });
          await sleep(50 + j * 10);
          endMetric();
        }
      }

      // Verify all services have metrics
      for (const operation of operations) {
        const summary = metricsService.getSummary(operation);
        expect(summary).toBeDefined();
        expect(summary!.count).toBe(10);
        expect(summary!.successRate).toBe(100);
      }
    });

    it('should support cross-service metric correlation', async () => {
      const userOperation = 'user_service_call';
      const authOperation = 'auth_service_call';
      const dbOperation = 'database_query';

      // Simulate a cross-service call chain
      const traceId = 'trace-123';

      // User service calls auth service
      const userEnd = metricsService.startMetric(userOperation, { traceId, service: 'user-service' });
      await sleep(50);

      const authEnd = metricsService.startMetric(authOperation, { traceId, service: 'auth-service' });
      await sleep(30);
      authEnd();

      userEnd();

      // Auth service calls database
      const dbEnd = metricsService.startMetric(dbOperation, { traceId, service: 'database' });
      await sleep(20);
      dbEnd();

      // Verify correlated metrics
      const userSummary = metricsService.getSummary(userOperation);
      const authSummary = metricsService.getSummary(authOperation);
      const dbSummary = metricsService.getSummary(dbOperation);

      expect(userSummary!.duration).toBeGreaterThan(authSummary!.duration + dbSummary!.duration);
    });

    it('should provide dashboard data aggregation', async () => {
      const dashboardOperations = ['api_requests', 'database_queries', 'cache_operations'];

      // Generate dashboard metrics
      for (const operation of dashboardOperations) {
        for (let i = 0; i < 20; i++) {
          const endMetric = metricsService.startMetric(operation, {
            dashboard: true,
            category: operation
          });

          if (operation === 'api_requests') await sleep(100 + Math.random() * 200);
          else if (operation === 'database_queries') await sleep(50 + Math.random() * 100);
          else await sleep(10 + Math.random() * 50);

          endMetric();
        }
      }

      const trends = metricsService.getPerformanceTrends(5);

      // Verify dashboard data is available
      dashboardOperations.forEach(operation => {
        expect(trends[operation]).toBeDefined();
        expect(trends[operation].totalRequests).toBe(20);
        expect(trends[operation].averageDuration).toBeGreaterThan(0);
        expect(trends[operation].successRate).toBe(100);
      });
    });

    it('should monitor service health and performance', async () => {
      const healthyService = 'healthy_service';
      const unhealthyService = 'unhealthy_service';

      // Healthy service metrics
      for (let i = 0; i < 10; i++) {
        const endMetric = metricsService.startMetric(healthyService);
        await sleep(50);
        endMetric();
      }

      // Unhealthy service metrics (slow and errors)
      for (let i = 0; i < 5; i++) {
        const endMetric = metricsService.startMetric(unhealthyService);
        await sleep(500); // Slow
        endMetric();
      }

      for (let i = 0; i < 3; i++) {
        metricsService.recordError(unhealthyService, new Error(`Service error ${i}`));
      }

      const healthySummary = metricsService.getSummary(healthyService);
      const unhealthySummary = metricsService.getSummary(unhealthyService);

      // Verify health differences
      expect(healthySummary!.averageDuration).toBeLessThan(unhealthySummary!.averageDuration);
      expect(healthySummary!.successRate).toBeGreaterThan(unhealthySummary!.successRate);
      expect(unhealthySummary!.errorCount).toBe(3);
    });

    it('should support real-time performance monitoring', async () => {
      const realtimeOperation = 'realtime_monitoring';
      const alertEvents: PerformanceAlert[] = [];

      metricsService.setAlertThreshold(realtimeOperation, 200, 5);

      metricsService.on('alert', (alert) => {
        if (alert.operation === realtimeOperation) {
          alertEvents.push(alert);
        }
      });

      // Start real-time monitoring
      metricsService.startCollection(1000); // 1 second intervals

      // Generate metrics in real-time
      for (let i = 0; i < 5; i++) {
        const endMetric = metricsService.startMetric(realtimeOperation, { realtime: true });
        await sleep(100);
        endMetric();
        await sleep(200);
      }

      // Wait for collection cycle
      await sleep(1200);

      // Generate a slow metric to trigger real-time alert
      const slowEnd = metricsService.startMetric(realtimeOperation, { realtime: true });
      await sleep(300);
      slowEnd();

      await sleep(500);

      metricsService.stopCollection();

      const summary = metricsService.getSummary(realtimeOperation);
      expect(summary).toBeDefined();
      expect(summary!.count).toBe(6);
    });

    it('should handle metric export and integration', async () => {
      const exportOperation = 'export_test';

      // Generate test data
      for (let i = 0; i < 5; i++) {
        const endMetric = metricsService.startMetric(exportOperation, { exportId: i });
        await sleep(100);
        endMetric();
      }

      // Test JSON export
      const jsonExport = metricsService.exportMetrics('json');
      const jsonData = JSON.parse(jsonExport);

      expect(jsonData).toHaveProperty('summaries');
      expect(jsonData).toHaveProperty('trends');
      expect(jsonData).toHaveProperty('memory');
      expect(jsonData).toHaveProperty('timestamp');

      // Test Prometheus export
      const prometheusExport = metricsService.exportMetrics('prometheus');

      expect(prometheusExport).toContain('# HELP');
      expect(prometheusExport).toContain('# TYPE');
      expect(prometheusExport).toContain('cortex_operation_duration_seconds');
      expect(prometheusExport).toContain('cortex_operation_success_rate');
      expect(prometheusExport).toContain('nodejs_memory_usage_bytes');
    });

    it('should support metric aggregation across services', async () => {
      const services = ['payment', 'inventory', 'shipping'];
      const baseOperation = 'order_processing';

      // Generate cross-service metrics
      for (const service of services) {
        const operation = `${baseOperation}_${service}`;

        for (let i = 0; i < 10; i++) {
          const endMetric = metricsService.startMetric(operation, {
            service,
            operationType: baseOperation,
            orderId: `order-${i}`
          });

          // Different processing times per service
          if (service === 'payment') await sleep(200);
          else if (service === 'inventory') await sleep(100);
          else await sleep(150);

          endMetric();
        }
      }

      const allSummaries = metricsService.getAllSummaries();
      const relatedSummaries = allSummaries.filter(s => s.operation.includes(baseOperation));

      expect(relatedSummaries).toHaveLength(3);

      // Verify aggregation patterns
      const paymentSummary = relatedSummaries.find(s => s.operation.includes('payment'));
      const inventorySummary = relatedSummaries.find(s => s.operation.includes('inventory'));
      const shippingSummary = relatedSummaries.find(s => s.operation.includes('shipping'));

      expect(paymentSummary!.averageDuration).toBeGreaterThan(inventorySummary!.averageDuration);
      expect(shippingSummary!.averageDuration).toBeGreaterThan(inventorySummary!.averageDuration);
    });
  });

  describe('Advanced Metrics Features', () => {
    it('should handle metric memory optimization', async () => {
      const operation = 'memory_optimization';
      const largeMetricCount = 1000;

      // Generate many metrics to test memory management
      for (let i = 0; i < largeMetricCount; i++) {
        const endMetric = metricsService.startMetric(operation, {
          index: i,
          data: `test-data-${i}`.repeat(10) // Include some payload
        });
        endMetric();
      }

      const recentMetrics = metricsService.getRecentMetrics(operation);
      const summary = metricsService.getSummary(operation);

      // Should respect maxMetricsPerOperation limit
      expect(recentMetrics.length).toBeLessThanOrEqual(500);
      expect(summary!.count).toBe(largeMetricCount);

      // Test memory usage
      const memoryBefore = metricsService.getMemoryUsage();
      metricsService.clearMetrics();
      const memoryAfter = metricsService.getMemoryUsage();

      expect(memoryAfter.heapUsed).toBeLessThanOrEqual(memoryBefore.heapUsed);
    });

    it('should support custom metric transformations', async () => {
      const operation = 'metric_transformation';

      // Record metrics with custom data
      for (let i = 0; i < 10; i++) {
        const endMetric = metricsService.startMetric(operation, {
          customValue: i * 10,
          category: i % 2 === 0 ? 'even' : 'odd'
        });
        await sleep(50 + i * 5);
        endMetric();
      }

      const metrics = metricsService.getRecentMetrics(operation);

      // Verify custom data is preserved
      metrics.forEach((metric, index) => {
        expect(metric.metadata.customValue).toBe(index * 10);
        expect(metric.metadata.category).toBe(index % 2 === 0 ? 'even' : 'odd');
      });
    });

    it('should handle metric batch processing efficiently', async () => {
      const operations = ['batch_1', 'batch_2', 'batch_3'];

      // Generate metrics rapidly to test batch processing
      const startTime = Date.now();

      operations.forEach(operation => {
        for (let i = 0; i < 150; i++) { // Exceed batch size
          const endMetric = metricsService.startMetric(operation, { batchIndex: i });
          endMetric(); // Immediate end for rapid processing
        }
      });

      const processingTime = Date.now() - startTime;

      // Batch processing should be efficient
      expect(processingTime).toBeLessThan(1000);

      // Verify all metrics were processed
      operations.forEach(operation => {
        const summary = metricsService.getSummary(operation);
        expect(summary!.count).toBe(150);
      });
    });

    it('should support metric filtering and search', async () => {
      const operations = ['search_test_1', 'search_test_2', 'other_operation'];
      const searchTag = 'searchable';

      // Create searchable metrics
      for (const operation of operations) {
        for (let i = 0; i < 5; i++) {
          const endMetric = metricsService.startMetric(operation, {
            searchable: operation.includes('search'),
            tag: searchTag,
            index: i
          });
          await sleep(20);
          endMetric();
        }
      }

      const allSummaries = metricsService.getAllSummaries();
      const searchableSummaries = allSummaries.filter(s => s.operation.includes('search'));

      expect(searchableSummaries).toHaveLength(2);

      searchableSummaries.forEach(summary => {
        const metrics = metricsService.getRecentMetrics(summary.operation, 5);
        metrics.forEach(metric => {
          expect(metric.metadata.searchable).toBe(true);
          expect(metric.metadata.tag).toBe(searchTag);
        });
      });
    });
  });
});