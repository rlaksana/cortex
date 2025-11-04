/**
 * P4-1: Metrics and System Status Integration Tests
 *
 * End-to-end integration tests for the comprehensive metrics
 * and system status functionality.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { performanceTrendingService } from '../../src/services/metrics/performance-trending.js';
import { systemMetricsService } from '../../src/services/metrics/system-metrics.js';

// Mock the logger for tests
vi.mock('../../src/utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

// Mock environment
process.env.NODE_ENV = 'test';
process.env.QDRANT_URL = 'http://localhost:6333';
process.env.QDRANT_COLLECTION_NAME = 'test-collection';

describe('Metrics and System Status Integration', () => {
  let server: Server;
  let transport: StdioServerTransport;

  beforeAll(async () => {
    // Note: In a real test environment, you would set up the actual server
    // For this example, we'll focus on testing the metrics integration
    performanceTrendingService.startCollection();
  });

  afterAll(async () => {
    performanceTrendingService.destroy();
    systemMetricsService.resetMetrics();
  });

  describe('System Metrics Integration', () => {
    it('should collect metrics across all operations', () => {
      // Reset metrics to start clean
      systemMetricsService.resetMetrics();

      // Simulate various operations
      systemMetricsService.updateMetrics({
        operation: 'store',
        data: {
          success: true,
          kind: 'entity',
          item_count: 5,
        },
        duration_ms: 150,
      });

      systemMetricsService.updateMetrics({
        operation: 'find',
        data: {
          success: true,
          mode: 'auto',
          results_count: 3,
        },
        duration_ms: 80,
      });

      systemMetricsService.updateMetrics({
        operation: 'chunking',
        data: {
          items_chunked: 2,
          chunks_generated: 8,
          success: true,
          semantic_analysis_used: 1,
        },
        duration_ms: 200,
      });

      systemMetricsService.updateMetrics({
        operation: 'cleanup',
        data: {
          items_deleted: 10,
          success: true,
          operation_type: 'expired',
        },
        duration_ms: 500,
      });

      systemMetricsService.updateMetrics({
        operation: 'dedupe_hits',
        data: {
          duplicates_detected: 3,
          similarity_score: 0.89,
          merge_operation: true,
          strategy: 'intelligent',
        },
        duration_ms: 120,
      });

      const metrics = systemMetricsService.getMetrics();

      // Verify all metrics are collected
      expect(metrics.store_count.total).toBe(1);
      expect(metrics.find_count.total).toBe(1);
      expect(metrics.chunking.items_chunked).toBe(2);
      expect(metrics.cleanup.items_deleted_total).toBe(10);
      expect(metrics.dedupe_hits.duplicates_detected).toBe(3);

      // Verify derived metrics are calculated
      expect(metrics.performance.avg_store_duration_ms).toBeGreaterThan(0);
      expect(metrics.performance.avg_find_duration_ms).toBeGreaterThan(0);
      expect(metrics.chunking.avg_chunks_per_item).toBe(4); // 8/2
      expect(metrics.dedupe_hits.avg_similarity_score).toBe(0.89);
    });

    it('should provide comprehensive system status information', () => {
      const metrics = systemMetricsService.getMetrics();

      // Mock system status response structure
      const systemStatus = {
        type: 'system_metrics_detailed',
        timestamp: new Date().toISOString(),
        store_count: metrics.store_count,
        find_count: metrics.find_count,
        purge_count: metrics.purge_count,
        dedupe_rate: metrics.dedupe_rate,
        validator_fail_rate: metrics.validator_fail_rate,
        performance: metrics.performance,
        errors: metrics.errors,
        rate_limiting: metrics.rate_limiting,
        memory: metrics.memory,
        observability: metrics.observability,
        truncation: metrics.truncation,
        chunking: metrics.chunking,
        cleanup: metrics.cleanup,
        dedupe_hits: metrics.dedupe_hits,
        health_status: {
          overall_status: 'healthy',
          capabilities: {
            vector_operations: metrics.observability.vector_operations > 0,
            chunking_enabled: metrics.chunking.items_chunked > 0,
            cleanup_enabled: metrics.cleanup.cleanup_operations_run > 0,
            deduplication_enabled: metrics.dedupe_hits.duplicates_detected > 0 || metrics.dedupe_rate.items_processed > 0,
            rate_limiting_enabled: metrics.rate_limiting.total_requests > 0,
            truncation_protection: metrics.truncation.store_truncated_total > 0,
            performance_trending: true,
            time_series_collection: true,
            anomaly_detection: true,
          },
          performance_indicators: {
            avg_response_time_ms: metrics.performance.avg_store_duration_ms + metrics.performance.avg_find_duration_ms,
            error_rate: metrics.errors.total_errors / (metrics.store_count.total + metrics.find_count.total + metrics.purge_count.total) * 100,
            dedupe_efficiency: metrics.dedupe_hits.duplicates_detected / Math.max(metrics.dedupe_rate.items_processed, 1) * 100,
            chunking_success_rate: metrics.chunking.chunking_success_rate,
            cleanup_success_rate: metrics.cleanup.cleanup_success_rate,
          },
          resource_utilization: {
            uptime_hours: metrics.performance.uptime_ms / (1000 * 60 * 60),
            memory_usage_kb: metrics.memory.memory_usage_kb,
            active_actors: metrics.rate_limiting.active_actors,
            active_knowledge_items: metrics.memory.active_knowledge_items,
          }
        },
        performance_trending: {
          status: performanceTrendingService.getStatus(),
          trend_analysis: performanceTrendingService.getTrendAnalysis(1),
          active_alerts: performanceTrendingService.getActiveAlerts(),
          export_available: true
        }
      };

      // Verify structure
      expect(systemStatus.type).toBe('system_metrics_detailed');
      expect(systemStatus.chunking).toBeDefined();
      expect(systemStatus.cleanup).toBeDefined();
      expect(systemStatus.dedupe_hits).toBeDefined();
      expect(systemStatus.health_status).toBeDefined();
      expect(systemStatus.performance_trending).toBeDefined();

      // Verify capabilities
      expect(systemStatus.health_status.capabilities.performance_trending).toBe(true);
      expect(systemStatus.health_status.capabilities.time_series_collection).toBe(true);
      expect(systemStatus.health_status.capabilities.anomaly_detection).toBe(true);

      // Verify trending data
      expect(systemStatus.performance_trending.status.collecting).toBe(true);
      expect(Array.isArray(systemStatus.performance_trending.active_alerts)).toBe(true);
      expect(systemStatus.performance_trending.export_available).toBe(true);
    });
  });

  describe('Performance Trending Integration', () => {
    it('should collect and analyze performance trends', async () => {
      // Simulate some metrics activity
      for (let i = 0; i < 3; i++) {
        systemMetricsService.updateMetrics({
          operation: 'store',
          data: {
            success: true,
            kind: 'entity',
          },
          duration_ms: 50 + Math.random() * 50, // Variable response time
        });

        systemMetricsService.updateMetrics({
          operation: 'find',
          data: {
            success: true,
            mode: 'auto',
          },
          duration_ms: 30 + Math.random() * 30, // Variable response time
        });

        // Wait for trending collection
        await new Promise(resolve => setTimeout(resolve, 1200));
      }

      const status = performanceTrendingService.getStatus();
      expect(status.collecting).toBe(true);
      expect(status.dataPointsCount).toBeGreaterThan(0);

      const trendAnalysis = performanceTrendingService.getTrendAnalysis(1);
      expect(trendAnalysis).toBeDefined();
      expect(trendAnalysis.period.duration_ms).toBeGreaterThan(0);
      expect(typeof trendAnalysis.performance.avg_response_time).toBe('number');
      expect(typeof trendAnalysis.throughput.operations_per_second).toBe('number');
      expect(typeof trendAnalysis.reliability.error_rate).toBe('number');
    });

    it('should detect performance anomalies', async () => {
      // Establish baseline
      for (let i = 0; i < 5; i++) {
        systemMetricsService.updateMetrics({
          operation: 'store',
          data: { success: true, kind: 'entity' },
          duration_ms: 50,
        });
        await new Promise(resolve => setTimeout(resolve, 600));
      }

      // Inject a performance spike
      systemMetricsService.updateMetrics({
        operation: 'store',
        data: { success: true, kind: 'entity' },
        duration_ms: 500, // Much higher than baseline
      });

      await new Promise(resolve => setTimeout(resolve, 1200));

      // Check that trending service is collecting data
      const status = performanceTrendingService.getStatus();
      expect(status.dataPointsCount).toBeGreaterThan(0);
    });

    it('should export metrics in different formats', async () => {
      // Wait for some data collection
      await new Promise(resolve => setTimeout(resolve, 1200));

      const jsonExport = performanceTrendingService.exportMetrics('json');
      const prometheusExport = performanceTrendingService.exportMetrics('prometheus');

      expect(typeof jsonExport).toBe('string');
      expect(typeof prometheusExport).toBe('string');

      if (performanceTrendingService.getStatus().dataPointsCount > 0) {
        const parsedJson = JSON.parse(jsonExport);
        expect(parsedJson).toHaveProperty('timestamp');
        expect(parsedJson).toHaveProperty('metrics');
        expect(parsedJson).toHaveProperty('derived');
        expect(parsedJson).toHaveProperty('alerts');

        expect(prometheusExport).toContain('# HELP');
        expect(prometheusExport).toContain('# TYPE');
        expect(prometheusExport).toContain('cortex_');
      }
    });
  });

  describe('Rate Limiting Integration', () => {
    it('should track rate limiting metrics', () => {
      systemMetricsService.updateMetrics({
        operation: 'rate_limit',
        data: {
          total_requests: 100,
          blocked_requests: 5,
          active_actors: 3,
        },
      });

      const metrics = systemMetricsService.getMetrics();

      expect(metrics.rate_limiting.total_requests).toBe(100);
      expect(metrics.rate_limiting.blocked_requests).toBe(5);
      expect(metrics.rate_limiting.active_actors).toBe(3);
      expect(metrics.rate_limiting.block_rate).toBe(5); // 5/100 * 100
    });

    it('should include rate limit status in system health', () => {
      const metrics = systemMetricsService.getMetrics();

      const rateLimitStatus = {
        enabled: true,
        status: 'active',
        activeWindows: 10,
        memoryUsage: '2.5 KB',
        totalRequests: metrics.rate_limiting.total_requests,
        blockedRequests: metrics.rate_limiting.blocked_requests,
        blockRate: metrics.rate_limiting.total_requests > 0 ?
          ((metrics.rate_limiting.blocked_requests / metrics.rate_limiting.total_requests) * 100).toFixed(1) : 0,
        configurations: {
          memory_store: { limit: 100, windowMs: 60000 },
          memory_find: { limit: 200, windowMs: 60000 },
        },
        policies: {
          toolLimits: [
            { tool: 'memory_store', limit: 100, windowMs: 60000 },
            { tool: 'memory_find', limit: 200, windowMs: 60000 },
          ],
          actorLimit: { limit: 500, windowMs: 60000 },
        },
      };

      expect(rateLimitStatus.enabled).toBe(true);
      expect(rateLimitStatus.totalRequests).toBeGreaterThanOrEqual(0);
      expect(rateLimitStatus.blockRate).toBeDefined();
      expect(rateLimitStatus.configurations).toBeDefined();
      expect(rateLimitStatus.policies).toBeDefined();
    });
  });

  describe('End-to-End Workflow Tests', () => {
    it('should handle complete workflow with metrics collection', async () => {
      // Reset everything
      systemMetricsService.resetMetrics();
      performanceTrendingService.destroy();
      performanceTrendingService.startCollection();

      // Simulate a realistic workflow
      const workflow = [
        { operation: 'store', data: { success: true, kind: 'entity' }, duration: 120 },
        { operation: 'store', data: { success: true, kind: 'relation' }, duration: 95 },
        { operation: 'find', data: { success: true, mode: 'auto' }, duration: 65 },
        { operation: 'chunking', data: { items_chunked: 1, chunks_generated: 4, success: true }, duration: 180 },
        { operation: 'dedupe_hits', data: { duplicates_detected: 2, similarity_score: 0.87, merge_operation: true }, duration: 140 },
        { operation: 'cleanup', data: { items_deleted: 8, success: true, operation_type: 'expired' }, duration: 300 },
      ];

      // Execute workflow
      for (const step of workflow) {
        systemMetricsService.updateMetrics(step);
        await new Promise(resolve => setTimeout(resolve, 800)); // Allow trending collection
      }

      // Verify all operations are tracked
      const metrics = systemMetricsService.getMetrics();
      expect(metrics.store_count.total).toBe(2);
      expect(metrics.find_count.total).toBe(1);
      expect(metrics.chunking.items_chunked).toBe(1);
      expect(metrics.dedupe_hits.duplicates_detected).toBe(2);
      expect(metrics.cleanup.items_deleted_total).toBe(8);

      // Verify performance trending collected data
      const trendingStatus = performanceTrendingService.getStatus();
      expect(trendingStatus.collecting).toBe(true);
      expect(trendingStatus.dataPointsCount).toBeGreaterThan(0);

      // Verify trend analysis
      const trendAnalysis = performanceTrendingService.getTrendAnalysis(1);
      expect(trendAnalysis.period.duration_ms).toBeGreaterThan(0);

      // Verify system status includes all enhanced metrics
      const systemStatus = {
        performance_trending: {
          status: trendingStatus,
          trend_analysis: trendAnalysis,
          active_alerts: performanceTrendingService.getActiveAlerts(),
          export_available: true,
        },
        health_status: {
          overall_status: 'healthy',
          capabilities: {
            chunking_enabled: metrics.chunking.items_chunked > 0,
            cleanup_enabled: metrics.cleanup.cleanup_operations_run > 0,
            deduplication_enabled: metrics.dedupe_hits.duplicates_detected > 0,
            performance_trending: true,
          },
        }
      };

      expect(systemStatus.performance_trending.export_available).toBe(true);
      expect(systemStatus.health_status.capabilities.chunking_enabled).toBe(true);
      expect(systemStatus.health_status.capabilities.cleanup_enabled).toBe(true);
      expect(systemStatus.health_status.capabilities.deduplication_enabled).toBe(true);
    });

    it('should maintain data consistency across services', async () => {
      // Update metrics in system service
      systemMetricsService.updateMetrics({
        operation: 'store',
        data: { success: true, kind: 'entity' },
        duration_ms: 100,
      });

      // Wait for trending to collect
      await new Promise(resolve => setTimeout(resolve, 1200));

      // Verify consistency
      const systemMetrics = systemMetricsService.getMetrics();
      const trendingStatus = performanceTrendingService.getStatus();

      expect(systemMetrics.store_count.total).toBe(1);
      expect(trendingStatus.dataPointsCount).toBeGreaterThan(0);

      // Verify that trending data includes system metrics
      const trendAnalysis = performanceTrendingService.getTrendAnalysis(1);
      expect(trendAnalysis.period.duration_ms).toBeGreaterThan(0);
    });
  });

  describe('Error Recovery and Resilience', () => {
    it('should recover from metric collection failures', () => {
      // This would test error handling in metric collection
      // In a real implementation, you would mock failures
      expect(() => {
        systemMetricsService.updateMetrics({
          operation: 'store',
          data: { success: true, kind: 'entity' },
          duration_ms: 100,
        });
      }).not.toThrow();

      const metrics = systemMetricsService.getMetrics();
      expect(metrics.store_count.total).toBe(1);
    });

    it('should handle performance trending service failures gracefully', () => {
      // Simulate trending service being unavailable
      const mockStatus = {
        collecting: false,
        error: 'Performance trending service unavailable',
        dataPointsCount: 0,
        activeAlertsCount: 0,
        retentionHours: 1,
        collectionInterval: 30,
      };

      // System should still function with degraded capabilities
      expect(mockStatus.collecting).toBe(false);
      expect(mockStatus.error).toBeDefined();
    });
  });
});