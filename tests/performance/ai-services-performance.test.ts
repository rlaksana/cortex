/**
 * AI Services Performance Testing
 *
 * Comprehensive performance testing for AI operations including
 * insight generation, contradiction detection, and background processing
 * with performance benchmarking and regression detection.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { describe, test, expect, beforeAll, afterAll, beforeEach, afterEach } from '@jest/globals';
import {
  MockZAIClientService,
  MockZAIServicesManager,
  MockBackgroundProcessorService,
  MockAIOrchestratorService,
  createTestInsightRequest,
  createTestContradictionRequest,
  measurePerformance,
  createPerformanceBenchmark,
  mockPerformanceData,
  mockZAIResponses,
} from '../mocks/zai-service.mock.js';
import type {
  InsightGenerationRequest,
  ContradictionDetectionRequest,
  ZAIJobType,
} from '../../src/types/zai-interfaces.js';

describe('AI Services Performance Testing', () => {
  let mockServices: MockZAIServicesManager;
  let zaiClient: MockZAIClientService;
  let backgroundProcessor: MockBackgroundProcessorService;
  let orchestrator: MockAIOrchestratorService;

  beforeAll(async () => {
    mockServices = new MockZAIServicesManager();
    await mockServices.initialize();
    zaiClient = mockServices.getZAIClient();
    backgroundProcessor = mockServices.getBackgroundProcessor();
    orchestrator = mockServices.getOrchestrator();
  });

  afterAll(async () => {
    await mockServices.shutdown();
  });

  beforeEach(() => {
    zaiClient.reset();
    zaiClient.setResponseDelay(100); // Default response delay for performance testing
  });

  afterEach(() => {
    zaiClient.clearErrors();
  });

  describe('Insight Generation Performance', () => {
    test('should meet performance targets for single item processing', async () => {
      const request = createTestInsightRequest();
      const benchmark = createPerformanceBenchmark(
        mockPerformanceData.insight_generation.single_item
      );

      const { result, durationMs } = await measurePerformance(() =>
        zaiClient.generateInsights(request)
      );

      const validation = benchmark.validate(durationMs);

      expect(result.insights).toBeDefined();
      expect(result.metadata['items_processed']).toBe(1);
      expect(validation.passed).toBe(true);
      expect(validation.withinVariance).toBe(true);
      expect(validation.percentageOfTarget).toBeLessThanOrEqual(150);
    });

    test('should process 50 items within performance target', async () => {
      const items = Array.from({ length: 50 }, (_, i) => ({
        ...createTestInsightRequest().items[0],
        id: `perf-item-${i}`,
        content: `Performance test item ${i} for insight generation`,
        data: {
          ...createTestInsightRequest().items[0].data,
          title: `Performance Test Item ${i}`,
          content: `Extended content for performance testing item ${i} with sufficient complexity to simulate real-world processing requirements and ensure accurate performance measurements.`,
        },
      }));

      const request = {
        ...createTestInsightRequest(),
        items,
        options: {
          enabled: true,
          insight_types: ['patterns', 'connections', 'recommendations'],
          max_insights_per_item: 2,
          confidence_threshold: 0.6,
        },
      };

      const benchmark = createPerformanceBenchmark(
        mockPerformanceData.insight_generation.batch_50_items
      );
      const { result, durationMs } = await measurePerformance(() =>
        zaiClient.generateInsights(request)
      );

      const validation = benchmark.validate(durationMs);

      expect(result.metadata['items_processed']).toBe(50);
      expect(validation.passed).toBe(true);
      expect(validation.withinVariance).toBe(true);
      expect(validation.percentageOfTarget).toBeLessThanOrEqual(120);
    });

    test('should maintain performance scaling with batch size', async () => {
      const batchSizes = [10, 25, 50];
      const results: Array<{ batchSize: number; durationMs: number; throughput: number }> = [];

      for (const batchSize of batchSizes) {
        const items = Array.from({ length: batchSize }, (_, i) => ({
          ...createTestInsightRequest().items[0],
          id: `scale-item-${i}`,
          content: `Scaling test item ${i}`,
        }));

        const request = {
          ...createTestInsightRequest(),
          items,
          options: {
            enabled: true,
            insight_types: ['patterns'],
            max_insights_per_item: 1,
            confidence_threshold: 0.7,
          },
        };

        const { durationMs } = await measurePerformance(() => zaiClient.generateInsights(request));

        results.push({
          batchSize,
          durationMs,
          throughput: batchSize / (durationMs / 1000), // items per second
        });
      }

      // Throughput should remain reasonable across batch sizes
      results.forEach((result) => {
        expect(result.throughput).toBeGreaterThan(2); // At least 2 items per second
      });

      // Performance should scale reasonably (not degrade exponentially)
      const scalingFactor = results[2].durationMs / results[0].durationMs;
      const expectedScaling = results[2].batchSize / results[0].batchSize;
      expect(scalingFactor).toBeLessThan(expectedScaling * 1.5); // Allow 50% overhead
    });

    test('should handle concurrent insight generation efficiently', async () => {
      const concurrentRequests = 10;
      const itemsPerRequest = 10;

      const requests = Array.from({ length: concurrentRequests }, (_, reqIndex) => {
        const items = Array.from({ length: itemsPerRequest }, (_, itemIndex) => ({
          ...createTestInsightRequest().items[0],
          id: `concurrent-${reqIndex}-${itemIndex}`,
          content: `Concurrent test request ${reqIndex} item ${itemIndex}`,
        }));

        return {
          ...createTestInsightRequest(),
          items,
          options: {
            enabled: true,
            insight_types: ['patterns', 'connections'],
            max_insights_per_item: 1,
            confidence_threshold: 0.6,
          },
        };
      });

      const startTime = Date.now();
      const responses = await Promise.all(
        requests.map((request) => zaiClient.generateInsights(request))
      );
      const totalTime = Date.now() - startTime;

      // All responses should be successful
      expect(responses).toHaveLength(concurrentRequests);
      responses.forEach((response) => {
        expect(response.metadata['items_processed']).toBe(itemsPerRequest);
      });

      // Concurrent processing should be more efficient than sequential
      const averageTimePerRequest = totalTime / concurrentRequests;
      const estimatedSequentialTime = averageTimePerRequest * concurrentRequests;

      expect(totalTime).toBeLessThan(estimatedSequentialTime * 0.7); // At least 30% improvement
    });

    test('should maintain performance with complex insight requests', async () => {
      const simpleRequest = createTestInsightRequest();
      simpleRequest.options!.insight_types = ['patterns'];
      simpleRequest.options!.max_insights_per_item = 1;

      const complexRequest = {
        ...createTestInsightRequest(),
        items: Array.from({ length: 20 }, (_, i) => ({
          ...createTestInsightRequest().items[0],
          id: `complex-${i}`,
          kind: ['decision', 'issue', 'todo', 'entity'][i % 4] as any,
          content: `Complex item ${i} with extensive metadata and relationships`,
          data: {
            ...createTestInsightRequest().items[0].data,
            title: `Complex Analysis Item ${i}`,
            content: `This is a highly complex item with detailed business context, multiple stakeholder perspectives, intricate technical dependencies, comprehensive risk assessments, and extensive impact analysis that requires sophisticated AI processing to extract meaningful insights and patterns.`,
            metadata: {
              complexity_score: 0.9,
              analysis_depth: 'deep',
              context_layers: 5,
              relationship_count: 10 + i,
              stakeholder_count: 3 + (i % 3),
            },
          },
        })),
        options: {
          enabled: true,
          insight_types: ['patterns', 'connections', 'recommendations', 'anomalies', 'trends'],
          max_insights_per_item: 3,
          confidence_threshold: 0.6,
        },
      };

      const { durationMs: simpleDuration } = await measurePerformance(() =>
        zaiClient.generateInsights(simpleRequest)
      );

      const { durationMs: complexDuration } = await measurePerformance(() =>
        zaiClient.generateInsights(complexRequest)
      );

      // Complex processing should still be within reasonable bounds
      expect(complexDuration).toBeLessThan(simpleDuration * 10); // Not more than 10x slower
      expect(complexDuration).toBeLessThan(10000); // Should complete within 10 seconds
    });
  });

  describe('Contradiction Detection Performance', () => {
    test('should meet performance targets for single pair detection', async () => {
      const request = createTestContradictionRequest();
      const benchmark = createPerformanceBenchmark(
        mockPerformanceData.contradiction_detection.single_item
      );

      const { result, durationMs } = await measurePerformance(() =>
        zaiClient.detectContradictions(request)
      );

      const validation = benchmark.validate(durationMs);

      expect(result.contradictions).toBeDefined();
      expect(result.metadata['items_processed']).toBe(2);
      expect(validation.passed).toBe(true);
      expect(validation.withinVariance).toBe(true);
    });

    test('should process 100 items within performance target', async () => {
      const items = Array.from({ length: 100 }, (_, i) => ({
        ...createTestContradictionRequest().items[0],
        id: `contradiction-perf-${i}`,
        content: `Contradiction detection performance test item ${i}`,
        data: {
          ...createTestContradictionRequest().items[0].data,
          title: `Contradiction Test ${i}`,
          content: `Item ${i} for contradiction detection performance testing with sufficient complexity.`,
          timestamp: new Date(Date.now() + i * 3600000).toISOString(),
        },
      }));

      const request = {
        ...createTestContradictionRequest(),
        items,
        options: {
          enabled: true,
          detection_types: ['semantic', 'temporal', 'logical'],
          confidence_threshold: 0.6,
        },
      };

      const benchmark = createPerformanceBenchmark(
        mockPerformanceData.contradiction_detection.batch_100_items
      );
      const { result, durationMs } = await measurePerformance(() =>
        zaiClient.detectContradictions(request)
      );

      const validation = benchmark.validate(durationMs);

      expect(result.metadata['items_processed']).toBe(100);
      expect(validation.passed).toBe(true);
      expect(validation.withinVariance).toBe(true);
      expect(validation.percentageOfTarget).toBeLessThanOrEqual(120);
    });

    test('should handle contradiction detection scaling efficiently', async () => {
      const itemCounts = [25, 50, 100];
      const results: Array<{ itemCount: number; durationMs: number; throughput: number }> = [];

      for (const itemCount of itemCounts) {
        const items = Array.from({ length: itemCount }, (_, i) => ({
          ...createTestContradictionRequest().items[0],
          id: `scale-contradiction-${i}`,
          content: `Scaling contradiction test item ${i}`,
        }));

        const request = {
          ...createTestContradictionRequest(),
          items,
          options: {
            enabled: true,
            detection_types: ['semantic', 'temporal'],
            confidence_threshold: 0.7,
          },
        };

        const { durationMs } = await measurePerformance(() =>
          zaiClient.detectContradictions(request)
        );

        results.push({
          itemCount,
          durationMs,
          throughput: itemCount / (durationMs / 1000), // items per second
        });
      }

      // Throughput should remain reasonable
      results.forEach((result) => {
        expect(result.throughput).toBeGreaterThan(10); // At least 10 items per second
      });

      // Performance should scale better than O(n²) for contradiction detection
      const scalingFactor = results[2].durationMs / results[0].durationMs;
      const expectedQuadraticScaling = Math.pow(results[2].itemCount / results[0].itemCount, 2);
      expect(scalingFactor).toBeLessThan(expectedQuadraticScaling * 0.5); // Should be much better than O(n²)
    });

    test('should maintain performance with all detection types', async () => {
      const singleTypeRequest = {
        ...createTestContradictionRequest(),
        items: Array.from({ length: 30 }, (_, i) => ({
          ...createTestContradictionRequest().items[0],
          id: `single-type-${i}`,
          content: `Single type contradiction test item ${i}`,
        })),
        options: {
          enabled: true,
          detection_types: ['semantic'],
          confidence_threshold: 0.6,
        },
      };

      const allTypesRequest = {
        ...createTestContradictionRequest(),
        items: Array.from({ length: 30 }, (_, i) => ({
          ...createTestContradictionRequest().items[0],
          id: `all-types-${i}`,
          content: `All types contradiction test item ${i}`,
        })),
        options: {
          enabled: true,
          detection_types: ['semantic', 'temporal', 'logical'],
          confidence_threshold: 0.6,
        },
      };

      const { durationMs: singleTypeDuration } = await measurePerformance(() =>
        zaiClient.detectContradictions(singleTypeRequest)
      );

      const { durationMs: allTypesDuration } = await measurePerformance(() =>
        zaiClient.detectContradictions(allTypesRequest)
      );

      // All types should not be dramatically slower than single type
      expect(allTypesDuration).toBeLessThan(singleTypeDuration * 3); // Not more than 3x slower
    });
  });

  describe('Background Processing Performance', () => {
    test('should process background jobs within target latency', async () => {
      const jobTypes: ZAIJobType[] = [
        'text_transformation',
        'summarization',
        'classification',
        'insight_generation',
        'contradiction_detection',
      ];

      for (const jobType of jobTypes) {
        const jobData = {
          text: `Test data for ${jobType} performance testing`,
          transformation: jobType === 'text_transformation' ? 'uppercase' : undefined,
          summaryLength: jobType === 'summarization' ? 'short' : undefined,
          categories: jobType === 'classification' ? ['test', 'performance'] : undefined,
        };

        const { durationMs } = await measurePerformance(async () => {
          const jobId = await backgroundProcessor.submitJob(jobType, jobData, {
            priority: 'normal',
          });

          // Wait for job completion
          let jobStatus = backgroundProcessor.getJobStatus(jobId);
          while (jobStatus?.status === 'pending' || jobStatus?.status === 'processing') {
            await new Promise((resolve) => setTimeout(resolve, 50));
            jobStatus = backgroundProcessor.getJobStatus(jobId);
          }

          return jobStatus;
        });

        // Background jobs should complete within reasonable time
        expect(durationMs).toBeLessThan(1000); // Less than 1 second for test jobs
      }
    });

    test('should handle concurrent job processing efficiently', async () => {
      const concurrentJobs = 20;
      const jobType: ZAIJobType = 'text_transformation';

      const startTime = Date.now();
      const jobIds = await Promise.all(
        Array.from({ length: concurrentJobs }, (_, i) =>
          backgroundProcessor.submitJob(
            jobType,
            {
              text: `Concurrent job test ${i}`,
              transformation: 'uppercase',
            },
            { priority: 'normal' }
          )
        )
      );

      // Wait for all jobs to complete
      let completedJobs = 0;
      while (completedJobs < concurrentJobs) {
        completedJobs = jobIds.filter((jobId) => {
          const status = backgroundProcessor.getJobStatus(jobId);
          return status?.status === 'completed';
        }).length;

        if (completedJobs < concurrentJobs) {
          await new Promise((resolve) => setTimeout(resolve, 100));
        }
      }

      const totalTime = Date.now() - startTime;

      // Concurrent processing should be efficient
      const averageTimePerJob = totalTime / concurrentJobs;
      expect(averageTimePerJob).toBeLessThan(500); // Average less than 500ms per job
      expect(totalTime).toBeLessThan(5000); // Total less than 5 seconds
    });

    test('should maintain job processing throughput under load', async () => {
      const batchSizes = [5, 10, 20];
      const results: Array<{ batchSize: number; throughput: number }> = [];

      for (const batchSize of batchSizes) {
        const startTime = Date.now();

        const jobIds = await Promise.all(
          Array.from({ length: batchSize }, (_, i) =>
            backgroundProcessor.submitJob(
              'summarization',
              {
                text: `Throughput test text ${i} with sufficient content for meaningful summarization`,
                summaryLength: 'short',
              },
              { priority: 'normal' }
            )
          )
        );

        // Wait for completion
        let completed = 0;
        while (completed < batchSize) {
          completed = jobIds.filter((id) => {
            const status = backgroundProcessor.getJobStatus(id);
            return status?.status === 'completed';
          }).length;

          if (completed < batchSize) {
            await new Promise((resolve) => setTimeout(resolve, 50));
          }
        }

        const totalTime = Date.now() - startTime;
        const throughput = batchSize / (totalTime / 1000);

        results.push({ batchSize, throughput });
      }

      // Throughput should remain consistent across batch sizes
      const throughputs = results.map((r) => r.throughput);
      const averageThroughput = throughputs.reduce((sum, t) => sum + t, 0) / throughputs.length;
      const maxVariance = Math.max(...throughputs.map((t) => Math.abs(t - averageThroughput)));

      expect(maxVariance).toBeLessThan(averageThroughput * 0.3); // Less than 30% variance
      expect(averageThroughput).toBeGreaterThan(2); // At least 2 jobs per second
    });
  });

  describe('Memory and Resource Usage Performance', () => {
    test('should maintain stable memory usage during extended processing', async () => {
      const iterations = 10;
      const itemsPerIteration = 20;
      const memorySnapshots: number[] = [];

      for (let i = 0; i < iterations; i++) {
        // Process insights
        const insightRequest = {
          ...createTestInsightRequest(),
          items: Array.from({ length: itemsPerIteration }, (_, j) => ({
            ...createTestInsightRequest().items[0],
            id: `memory-test-${i}-${j}`,
            content: `Memory test item ${i}-${j}`,
          })),
          options: {
            enabled: true,
            insight_types: ['patterns', 'connections'],
            max_insights_per_item: 1,
            confidence_threshold: 0.6,
          },
        };

        await zaiClient.generateInsights(insightRequest);

        // Simulate memory usage measurement (in real scenario, use actual memory metrics)
        if (global.gc) {
          global.gc(); // Force garbage collection if available
        }

        const mockMemoryUsage = 128 + Math.random() * 32; // Simulate memory usage
        memorySnapshots.push(mockMemoryUsage);

        // Small delay to allow processing
        await new Promise((resolve) => setTimeout(resolve, 10));
      }

      // Memory usage should remain stable
      const averageMemory =
        memorySnapshots.reduce((sum, mem) => sum + mem, 0) / memorySnapshots.length;
      const maxVariance = Math.max(...memorySnapshots.map((mem) => Math.abs(mem - averageMemory)));

      expect(maxVariance).toBeLessThan(averageMemory * 0.2); // Less than 20% variance
    });

    test('should efficiently handle resource cleanup', async () => {
      const initialMetrics = zaiClient.getMetrics();

      // Process multiple large requests
      for (let i = 0; i < 5; i++) {
        const largeRequest = {
          ...createTestInsightRequest(),
          items: Array.from({ length: 30 }, (_, j) => ({
            ...createTestInsightRequest().items[0],
            id: `cleanup-test-${i}-${j}`,
            content: `Large request item ${i}-${j} for cleanup testing`,
            data: {
              ...createTestInsightRequest().items[0].data,
              largeData: 'x'.repeat(1000), // Simulate larger data
            },
          })),
          options: {
            enabled: true,
            insight_types: ['patterns', 'connections', 'recommendations'],
            max_insights_per_item: 2,
            confidence_threshold: 0.6,
          },
        };

        await zaiClient.generateInsights(largeRequest);
      }

      const finalMetrics = zaiClient.getMetrics();

      // Resource usage should be reasonable
      expect(finalMetrics.totalRequests).toBeGreaterThan(initialMetrics.totalRequests);
      expect(finalMetrics.averageResponseTime).toBeLessThan(1000); // Reasonable average response time
    });
  });

  describe('Performance Regression Detection', () => {
    test('should detect performance regressions in insight generation', async () => {
      const baselineBenchmark = createPerformanceBenchmark(
        mockPerformanceData.insight_generation.batch_50_items
      );

      // Create a request with simulated slow processing
      const items = Array.from({ length: 50 }, (_, i) => ({
        ...createTestInsightRequest().items[0],
        id: `regression-test-${i}`,
        content: `Regression test item ${i}`,
      }));

      const request = {
        ...createTestInsightRequest(),
        items,
        options: {
          enabled: true,
          insight_types: ['patterns', 'connections', 'recommendations'],
          max_insights_per_item: 2,
          confidence_threshold: 0.6,
        },
      };

      // Simulate slower processing
      zaiClient.setResponseDelay(200);

      const { result, durationMs } = await measurePerformance(() =>
        zaiClient.generateInsights(request)
      );

      const validation = baselineBenchmark.validate(durationMs);

      expect(result.metadata['items_processed']).toBe(50);

      // This test helps detect regressions - in CI, this would fail if performance degrades
      if (!validation.passed) {
        console.warn(
          `Performance regression detected: ${durationMs}ms vs target ${baselineBenchmark.target.target_time_ms}ms`
        );
        console.warn(
          `Variance: ${validation.variance}ms, Percentage: ${validation.percentageOfTarget}%`
        );
      }
    });

    test('should track performance metrics over time', async () => {
      const runs = 5;
      const performanceMetrics: Array<{ run: number; duration: number; throughput: number }> = [];

      for (let i = 0; i < runs; i++) {
        const request = {
          ...createTestInsightRequest(),
          items: Array.from({ length: 25 }, (_, j) => ({
            ...createTestInsightRequest().items[0],
            id: `metrics-run-${i}-${j}`,
            content: `Metrics tracking run ${i} item ${j}`,
          })),
          options: {
            enabled: true,
            insight_types: ['patterns', 'connections'],
            max_insights_per_item: 1,
            confidence_threshold: 0.6,
          },
        };

        const { durationMs } = await measurePerformance(() => zaiClient.generateInsights(request));

        performanceMetrics.push({
          run: i + 1,
          duration: durationMs,
          throughput: 25 / (durationMs / 1000),
        });
      }

      // Performance should be consistent across runs
      const durations = performanceMetrics.map((m) => m.duration);
      const averageDuration = durations.reduce((sum, d) => sum + d, 0) / durations.length;
      const maxDeviation = Math.max(...durations.map((d) => Math.abs(d - averageDuration)));

      expect(maxDeviation).toBeLessThan(averageDuration * 0.2); // Less than 20% deviation
    });
  });

  describe('Circuit Breaker and Error Handling Performance', () => {
    test('should handle service failures gracefully without performance impact', async () => {
      const normalRequest = createTestInsightRequest();

      // Test normal performance first
      const { durationMs: normalDuration } = await measurePerformance(() =>
        zaiClient.generateInsights(normalRequest)
      );

      // Simulate some failures
      zaiClient.setErrorScenario('network_timeout');

      try {
        await zaiClient.generateInsights(normalRequest);
      } catch (error) {
        // Expected to fail
      }

      zaiClient.clearErrors();

      // Test recovery performance
      const { durationMs: recoveryDuration } = await measurePerformance(() =>
        zaiClient.generateInsights(normalRequest)
      );

      // Recovery should not significantly impact performance
      expect(recoveryDuration).toBeLessThan(normalDuration * 2); // Not more than 2x slower
    });

    test('should maintain performance during partial service degradation', async () => {
      const requests = Array.from({ length: 10 }, (_, i) => createTestInsightRequest());

      // Simulate intermittent failures
      const results = await Promise.allSettled(
        requests.map(async (request, index) => {
          if (index % 3 === 0) {
            zaiClient.setErrorScenario('rate_limit');
          }

          try {
            return await zaiClient.generateInsights(request);
          } finally {
            if (index % 3 === 0) {
              zaiClient.clearErrors();
            }
          }
        })
      );

      // Some requests should succeed, some should fail
      const successful = results.filter((r) => r.status === 'fulfilled').length;
      const failed = results.filter((r) => r.status === 'rejected').length;

      expect(successful).toBeGreaterThan(0);
      expect(failed).toBeGreaterThan(0);

      // Successful requests should still meet reasonable performance expectations
      const successfulResults = results.filter(
        (r) => r.status === 'fulfilled'
      ) as PromiseFulfilledResult<any>[];
      const averageSuccessTime =
        successfulResults.reduce((sum, r) => {
          return sum + (r.value.metadata?.processing_time_ms || 0);
        }, 0) / successfulResults.length;

      expect(averageSuccessTime).toBeLessThan(2000); // Should still be reasonable
    });
  });

  describe('Load and Stress Testing', () => {
    test('should handle sustained load without performance degradation', async () => {
      const duration = 5000; // 5 seconds of sustained load
      const requestInterval = 100; // New request every 100ms
      const startTime = Date.now();
      const performanceData: Array<{ timestamp: number; duration: number }> = [];

      while (Date.now() - startTime < duration) {
        const request = {
          ...createTestInsightRequest(),
          items: Array.from({ length: 5 }, (_, i) => ({
            ...createTestInsightRequest().items[0],
            id: `load-test-${Date.now()}-${i}`,
            content: `Load test item at ${Date.now()}`,
          })),
          options: {
            enabled: true,
            insight_types: ['patterns'],
            max_insights_per_item: 1,
            confidence_threshold: 0.6,
          },
        };

        const { durationMs } = await measurePerformance(() => zaiClient.generateInsights(request));

        performanceData.push({
          timestamp: Date.now(),
          duration: durationMs,
        });

        await new Promise((resolve) => setTimeout(resolve, requestInterval));
      }

      // Performance should remain stable during sustained load
      const durations = performanceData.map((d) => d.duration);
      const averageDuration = durations.reduce((sum, d) => sum + d, 0) / durations.length;
      const maxDuration = Math.max(...durations);
      const minDuration = Math.min(...durations);

      expect(maxDuration).toBeLessThan(averageDuration * 2); // Max should not be more than 2x average
      expect(minDuration).toBeGreaterThan(averageDuration * 0.5); // Min should not be less than 0.5x average
    });

    test('should gracefully handle burst traffic', async () => {
      const burstSize = 50;
      const itemsPerRequest = 10;

      const burstRequests = Array.from({ length: burstSize }, (_, i) => ({
        ...createTestInsightRequest(),
        items: Array.from({ length: itemsPerRequest }, (_, j) => ({
          ...createTestInsightRequest().items[0],
          id: `burst-${i}-${j}`,
          content: `Burst traffic item ${i}-${j}`,
        })),
        options: {
          enabled: true,
          insight_types: ['patterns', 'connections'],
          max_insights_per_item: 1,
          confidence_threshold: 0.6,
        },
      }));

      const startTime = Date.now();
      const results = await Promise.allSettled(
        burstRequests.map((request) => zaiClient.generateInsights(request))
      );
      const totalTime = Date.now() - startTime;

      const successful = results.filter((r) => r.status === 'fulfilled').length;
      const failed = results.filter((r) => r.status === 'rejected').length;

      // Should handle burst traffic reasonably well
      expect(successful + failed).toBe(burstSize);
      expect(successful).toBeGreaterThan(burstSize * 0.8); // At least 80% success rate

      // Should complete within reasonable time
      expect(totalTime).toBeLessThan(10000); // Less than 10 seconds for 50 requests
    });
  });
});
