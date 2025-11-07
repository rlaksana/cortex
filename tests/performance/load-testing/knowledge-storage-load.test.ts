/**
 * Knowledge Storage Load Testing
 *
 * Comprehensive load testing for knowledge storage operations including
 * entities, observations, decisions, and tasks with performance validation
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { PerformanceHarness } from '../../../src/performance/performance-harness.js';
import {
  PerformanceTestConfig,
  PERFORMANCE_TEST_CONFIGS,
} from '../../../src/performance/performance-targets.js';
import { randomUUID } from 'crypto';

describe('Knowledge Storage Load Tests', () => {
  let harness: PerformanceHarness;
  const TEST_DATA_SIZE = 1000;

  beforeAll(async () => {
    harness = new PerformanceHarness('./artifacts/performance/knowledge-storage');

    // Prepare test data
    await prepareTestData();
  });

  afterAll(async () => {
    // Cleanup if needed
    console.log('Knowledge storage load tests completed');
  });

  describe('Entity Storage Performance', () => {
    it('should meet performance targets for entity storage', async () => {
      const config: PerformanceTestConfig = {
        name: 'entity_storage_performance',
        description: 'Performance test for entity storage operations',
        operationCount: 100,
        concurrency: 10,
        timeout: 30000,
        warmupIterations: 5,
        targets: [
          {
            name: 'store_latency_p95',
            description: '95th percentile latency for entity storage',
            target: 1000,
            max: 2000,
            unit: 'ms',
            type: 'latency',
            priority: 'critical',
            enabled: true,
          },
          {
            name: 'store_latency_p99',
            description: '99th percentile latency for entity storage',
            target: 2000,
            max: 5000,
            unit: 'ms',
            type: 'latency',
            priority: 'critical',
            enabled: true,
          },
          {
            name: 'store_throughput',
            description: 'Throughput for entity storage operations',
            target: 100,
            max: 50,
            unit: 'ops/s',
            type: 'throughput',
            priority: 'high',
            enabled: true,
          },
          {
            name: 'store_error_rate',
            description: 'Error rate for entity storage operations',
            target: 0,
            max: 5,
            unit: '%',
            type: 'error_rate',
            priority: 'critical',
            enabled: true,
          },
        ],
        categories: ['storage', 'critical', 'entity'],
        parameters: {
          entityType: 'entity',
          averageSize: 2048,
          sizeVariance: 0.3,
          relationshipCount: 3,
        },
      };

      const result = await harness.runTest(config);

      // Validate performance targets
      expect(result.validation.passed).toBe(true);

      if (result.validation.failures.length > 0) {
        console.error('Performance target failures:', result.validation.failures);
      }

      // Store as baseline for future comparisons
      await harness.storeBaseline(result);

      // Verify specific metrics
      expect(result.results.metrics.latencies.p95).toBeLessThan(2000);
      expect(result.results.metrics.latencies.p99).toBeLessThan(5000);
      expect(result.results.metrics.throughput).toBeGreaterThan(50);
      expect(result.results.metrics.errorRate).toBeLessThan(5);
    }, 60000);

    it('should handle concurrent entity storage without degradation', async () => {
      const config: PerformanceTestConfig = {
        name: 'concurrent_entity_storage',
        description: 'Concurrent entity storage performance test',
        operationCount: 500,
        concurrency: 50,
        timeout: 60000,
        warmupIterations: 10,
        targets: [
          {
            name: 'store_latency_p95',
            description: '95th percentile latency for concurrent entity storage',
            target: 1500, // Slightly relaxed for concurrency
            max: 3000,
            unit: 'ms',
            type: 'latency',
            priority: 'critical',
            enabled: true,
          },
          {
            name: 'store_throughput',
            description: 'Throughput for concurrent entity storage',
            target: 200,
            max: 100,
            unit: 'ops/s',
            type: 'throughput',
            priority: 'high',
            enabled: true,
          },
        ],
        categories: ['storage', 'concurrency', 'entity'],
        parameters: {
          entityType: 'entity',
          averageSize: 1024,
          sizeVariance: 0.5,
          concurrencyLevel: 'high',
        },
      };

      const result = await harness.runTest(config);

      expect(result.validation.passed).toBe(true);
      expect(result.results.summary.successRate).toBeGreaterThan(95);
      expect(result.metadata['systemMetrics'].memoryLeakDetected).toBe(false);
    }, 90000);
  });

  describe('Observation Storage Performance', () => {
    it('should meet performance targets for observation storage', async () => {
      const config: PerformanceTestConfig = {
        name: 'observation_storage_performance',
        description: 'Performance test for observation storage operations',
        operationCount: 150,
        concurrency: 15,
        timeout: 30000,
        warmupIterations: 5,
        targets: [
          {
            name: 'store_latency_p95',
            description: '95th percentile latency for observation storage',
            target: 800,
            max: 1500,
            unit: 'ms',
            type: 'latency',
            priority: 'critical',
            enabled: true,
          },
          {
            name: 'store_throughput',
            description: 'Throughput for observation storage operations',
            target: 150,
            max: 75,
            unit: 'ops/s',
            type: 'throughput',
            priority: 'high',
            enabled: true,
          },
        ],
        categories: ['storage', 'observation'],
        parameters: {
          entityType: 'observation',
          averageSize: 512,
          sizeVariance: 0.4,
          linkedEntities: 2,
        },
      };

      const result = await harness.runTest(config);

      expect(result.validation.passed).toBe(true);
      expect(result.results.metrics.latencies.p95).toBeLessThan(1500);
      expect(result.results.metrics.throughput).toBeGreaterThan(75);
    }, 60000);
  });

  describe('Decision Storage Performance', () => {
    it('should meet performance targets for decision storage', async () => {
      const config: PerformanceTestConfig = {
        name: 'decision_storage_performance',
        description: 'Performance test for decision storage operations',
        operationCount: 75,
        concurrency: 8,
        timeout: 30000,
        warmupIterations: 3,
        targets: [
          {
            name: 'store_latency_p95',
            description: '95th percentile latency for decision storage',
            target: 1200,
            max: 2500,
            unit: 'ms',
            type: 'latency',
            priority: 'critical',
            enabled: true,
          },
          {
            name: 'store_throughput',
            description: 'Throughput for decision storage operations',
            target: 50,
            max: 25,
            unit: 'ops/s',
            type: 'throughput',
            priority: 'high',
            enabled: true,
          },
        ],
        categories: ['storage', 'decision'],
        parameters: {
          entityType: 'decision',
          averageSize: 3072,
          sizeVariance: 0.2,
          complexityLevel: 'medium',
        },
      };

      const result = await harness.runTest(config);

      expect(result.validation.passed).toBe(true);
      expect(result.results.metrics.latencies.p95).toBeLessThan(2500);
      expect(result.results.metrics.throughput).toBeGreaterThan(25);
    }, 60000);
  });

  describe('Task Storage Performance', () => {
    it('should meet performance targets for task storage', async () => {
      const config: PerformanceTestConfig = {
        name: 'task_storage_performance',
        description: 'Performance test for task storage operations',
        operationCount: 100,
        concurrency: 12,
        timeout: 30000,
        warmupIterations: 5,
        targets: [
          {
            name: 'store_latency_p95',
            description: '95th percentile latency for task storage',
            target: 900,
            max: 1800,
            unit: 'ms',
            type: 'latency',
            priority: 'critical',
            enabled: true,
          },
          {
            name: 'store_throughput',
            description: 'Throughput for task storage operations',
            target: 80,
            max: 40,
            unit: 'ops/s',
            type: 'throughput',
            priority: 'high',
            enabled: true,
          },
        ],
        categories: ['storage', 'task'],
        parameters: {
          entityType: 'task',
          averageSize: 1536,
          sizeVariance: 0.3,
          dependencies: 3,
        },
      };

      const result = await harness.runTest(config);

      expect(result.validation.passed).toBe(true);
      expect(result.results.metrics.latencies.p95).toBeLessThan(1800);
      expect(result.results.metrics.throughput).toBeGreaterThan(40);
    }, 60000);
  });

  describe('Mixed Knowledge Storage Performance', () => {
    it('should handle mixed knowledge type storage efficiently', async () => {
      const config: PerformanceTestConfig = {
        name: 'mixed_knowledge_storage_performance',
        description: 'Performance test for mixed knowledge type storage',
        operationCount: 200,
        concurrency: 20,
        timeout: 45000,
        warmupIterations: 8,
        targets: [
          {
            name: 'store_latency_p95',
            description: '95th percentile latency for mixed knowledge storage',
            target: 1100,
            max: 2200,
            unit: 'ms',
            type: 'latency',
            priority: 'critical',
            enabled: true,
          },
          {
            name: 'store_throughput',
            description: 'Throughput for mixed knowledge storage',
            target: 120,
            max: 60,
            unit: 'ops/s',
            type: 'throughput',
            priority: 'high',
            enabled: true,
          },
        ],
        categories: ['storage', 'mixed', 'critical'],
        parameters: {
          entityTypes: ['entity', 'observation', 'decision', 'task'],
          typeDistribution: {
            entity: 0.4,
            observation: 0.3,
            decision: 0.15,
            task: 0.15,
          },
          averageSize: 1536,
          sizeVariance: 0.5,
        },
      };

      const result = await harness.runTest(config);

      expect(result.validation.passed).toBe(true);
      expect(result.results.metrics.latencies.p95).toBeLessThan(2200);
      expect(result.results.metrics.throughput).toBeGreaterThan(60);
      expect(result.results.summary.successRate).toBeGreaterThan(95);
    }, 90000);
  });

  describe('Knowledge Storage Stress Test', () => {
    it('should maintain performance under sustained load', async () => {
      const config: PerformanceTestConfig = {
        name: 'knowledge_storage_stress_test',
        description: 'Sustained load stress test for knowledge storage',
        operationCount: 1000,
        concurrency: 25,
        timeout: 120000,
        warmupIterations: 15,
        targets: [
          {
            name: 'store_latency_p95',
            description: '95th percentile latency under stress',
            target: 1500,
            max: 3000,
            unit: 'ms',
            type: 'latency',
            priority: 'critical',
            enabled: true,
          },
          {
            name: 'store_throughput',
            description: 'Throughput under sustained load',
            target: 100,
            max: 50,
            unit: 'ops/s',
            type: 'throughput',
            priority: 'high',
            enabled: true,
          },
          {
            name: 'memory_usage_peak',
            description: 'Peak memory usage during stress test',
            target: 512 * 1024 * 1024,
            max: 1024 * 1024 * 1024,
            unit: 'bytes',
            type: 'memory',
            priority: 'high',
            enabled: true,
          },
        ],
        categories: ['storage', 'stress', 'sustained'],
        parameters: {
          sustainedLoad: true,
          loadDuration: 60000,
          rampUpTime: 10000,
          entityTypes: ['entity', 'observation', 'decision', 'task'],
          averageSize: 2048,
        },
      };

      const result = await harness.runTest(config);

      expect(result.validation.passed).toBe(true);
      expect(result.results.metrics.latencies.p95).toBeLessThan(3000);
      expect(result.results.metrics.throughput).toBeGreaterThan(50);
      expect(result.metadata['systemMetrics'].memoryLeakDetected).toBe(false);
      expect(result.metadata['systemMetrics'].peakMemoryUsage).toBeLessThan(1024 * 1024 * 1024);
    }, 180000);
  });

  /**
   * Prepare test data for load testing
   */
  async function prepareTestData(): Promise<void> {
    console.log('Preparing test data for knowledge storage load tests...');

    // Generate test entities of different types and sizes
    const testEntities = [];

    for (let i = 0; i < TEST_DATA_SIZE; i++) {
      const types = ['entity', 'observation', 'decision', 'task'];
      const type = types[i % types.length];

      testEntities.push({
        id: randomUUID(),
        type,
        content: generateTestContent(type, i),
        timestamp: new Date().toISOString(),
        size: calculateContentSize(type),
      });
    }

    console.log(`Generated ${testEntities.length} test entities`);
  }

  /**
   * Generate test content based on entity type
   */
  function generateTestContent(type: string, index: number): string {
    const baseContent = `Test ${type} content ${index} `;
    const sizeMultipliers = {
      entity: 1.0,
      observation: 0.5,
      decision: 1.5,
      task: 0.75,
    };

    const multiplier = sizeMultipliers[type] || 1.0;
    const targetLength = Math.floor(1024 * multiplier);

    let content = baseContent;
    while (content.length < targetLength) {
      content += `Additional test data for ${type} ${index} `;
    }

    return content.substring(0, targetLength);
  }

  /**
   * Calculate content size for entity type
   */
  function calculateContentSize(type: string): number {
    const sizes = {
      entity: 1024,
      observation: 512,
      decision: 1536,
      task: 768,
    };

    return sizes[type] || 1024;
  }
});
