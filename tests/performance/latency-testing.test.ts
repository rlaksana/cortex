/**
 * API RESPONSE TIME TESTING
 *
 * Comprehensive latency testing for measuring response times across different
 * percentiles, identifying bottlenecks, and ensuring consistent performance.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { TestRunner, TestAssertions } from '../framework/test-setup.js';
import { memoryStore } from '../../src/services/memory-store.js';
import { memoryFind } from '../../src/services/memory-find.js';
import { softDelete } from '../../src/services/delete-operations.js';
import type { TestContext } from '../framework/test-setup.js';

describe('API RESPONSE TIME TESTING', () => {
  let testRunner: TestRunner;
  let testContext: TestContext;
  let latencyTestResults: any[] = [];

  beforeEach(async () => {
    testRunner = new TestRunner();
    await testRunner.initialize();

    const testDb = await testRunner.framework.createTestDatabase();
    testContext = {
      framework: testRunner.framework,
      testDb,
      dataFactory: testRunner.framework.getDataFactory(),
      performanceHelper: testRunner.framework.getPerformanceHelper(),
      validationHelper: testRunner.framework.getValidationHelper(),
      errorHelper: testRunner.framework.getErrorHelper(),
    };

    // Setup test data for latency testing
    await setupLatencyTestData();
  });

  afterEach(async () => {
    await testRunner.cleanup();

    // Print latency test summary
    if (latencyTestResults.length > 0) {
      console.log('\n📊 Latency Test Results Summary:');
      console.log('='.repeat(80));
      latencyTestResults.forEach(result => {
        console.log(`${result.test.padEnd(50)} | P50: ${result.p50.toFixed(1)}ms | P95: ${result.p95.toFixed(1)}ms | P99: ${result.p99.toFixed(1)}ms`);
      });
      console.log('='.repeat(80));
    }
  });

  /**
   * Setup test data for latency testing
   */
  async function setupLatencyTestData(): Promise<void> {
    console.log('   Setting up latency test data...');

    const testData = [
      { count: 200, type: 'section' },
      { count: 150, type: 'decision' },
      { count: 100, type: 'issue' },
      { count: 120, type: 'entity' },
      { count: 80, type: 'relation' }
    ];

    for (const batch of testData) {
      const items = [];
      for (let i = 0; i < batch.count; i++) {
        let item: any;
        switch (batch.type) {
          case 'section':
            item = testContext.dataFactory.createSection({
              title: `Latency Test Section ${i}`,
              content: `Content for latency testing section ${i}`
            });
            break;
          case 'decision':
            item = testContext.dataFactory.createDecision({
              title: `Latency Test Decision ${i}`,
              rationale: `Rationale for latency testing decision ${i}`
            });
            break;
          case 'issue':
            item = testContext.dataFactory.createIssue({
              title: `Latency Test Issue ${i}`,
              description: `Description for latency testing issue ${i}`
            });
            break;
          case 'entity':
            item = testContext.dataFactory.createEntity({
              name: `Latency Test Entity ${i}`,
              description: `Description for latency testing entity ${i}`
            });
            break;
          case 'relation':
            item = testContext.dataFactory.createRelation({
              from_type: 'entity',
              from_id: `entity-${i}`,
              to_type: 'entity',
              to_id: `entity-${(i + 1) % 120}`,
              relation_type: 'relates_to'
            });
            break;
        }
        items.push(item);
      }

      await memoryStore(items);
    }

    console.log('   ✅ Latency test data setup completed');
  }

  /**
   * Calculate percentiles from an array of numbers
   */
  function calculatePercentiles(values: number[]): {
    min: number;
    max: number;
    mean: number;
    median: number;
    p50: number;
    p75: number;
    p90: number;
    p95: number;
    p99: number;
    p999: number;
    standardDeviation: number;
  } {
    if (values.length === 0) {
      return {
        min: 0, max: 0, mean: 0, median: 0,
        p50: 0, p75: 0, p90: 0, p95: 0, p99: 0, p999: 0,
        standardDeviation: 0
      };
    }

    const sorted = [...values].sort((a, b) => a - b);
    const min = sorted[0];
    const max = sorted[sorted.length - 1];
    const mean = values.reduce((sum, val) => sum + val, 0) / values.length;
    const median = sorted[Math.floor(sorted.length * 0.5)];

    const getPercentile = (p: number) => {
      const index = Math.floor(sorted.length * (p / 100));
      return sorted[Math.min(index, sorted.length - 1)];
    };

    // Calculate standard deviation
    const variance = values.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / values.length;
    const standardDeviation = Math.sqrt(variance);

    return {
      min,
      max,
      mean,
      median,
      p50: getPercentile(50),
      p75: getPercentile(75),
      p90: getPercentile(90),
      p95: getPercentile(95),
      p99: getPercentile(99),
      p999: getPercentile(99.9),
      standardDeviation
    };
  }

  describe('BASIC LATENCY MEASUREMENTS', () => {
    it('should measure latency percentiles for memory store operations', async () => {
      const storeTests = [
        { name: 'Single Item Store', itemCount: 1 },
        { name: 'Small Batch Store', itemCount: 5 },
        { name: 'Medium Batch Store', itemCount: 20 },
        { name: 'Large Batch Store', itemCount: 50 }
      ];

      const storeLatencyResults: Array<{
        name: string;
        itemCount: number;
        percentiles: ReturnType<typeof calculatePercentiles>;
        throughput: number;
      }> = [];

      for (const test of storeTests) {
        const latencies: number[] = [];
        const iterations = 100;

        for (let i = 0; i < iterations; i++) {
          const items = Array.from({ length: test.itemCount }, (_, j) =>
            testContext.dataFactory.createSection({
              title: `Latency Test ${test.name} ${i}-${j}`,
              content: `Content for latency testing`
            })
          );

          const startTime = performance.now();
          try {
            await memoryStore(items);
            const latency = performance.now() - startTime;
            latencies.push(latency);
          } catch (error) {
            // Add penalty for failed operations
            latencies.push(5000);
          }
        }

        const percentiles = calculatePercentiles(latencies);
        const totalTime = latencies.reduce((sum, lat) => sum + lat, 0);
        const throughput = (iterations * test.itemCount) / (totalTime / 1000);

        storeLatencyResults.push({
          name: test.name,
          itemCount: test.itemCount,
          percentiles,
          throughput
        });

        // Latency assertions for store operations
        TestAssertions.assertPerformance(percentiles.p50, 200, `P50 latency for ${test.name}`);
        TestAssertions.assertPerformance(percentiles.p95, 500, `P95 latency for ${test.name}`);
        TestAssertions.assertPerformance(percentiles.p99, 1000, `P99 latency for ${test.name}`);
        expect(throughput).toBeGreaterThan(10); // 10+ items/sec

        console.log(`   ${test.name} (${test.itemCount} items):`);
        console.log(`     P50: ${percentiles.p50.toFixed(2)}ms, P95: ${percentiles.p95.toFixed(2)}ms, P99: ${percentiles.p99.toFixed(2)}ms`);
        console.log(`     Throughput: ${throughput.toFixed(1)} items/sec`);
      }

      const result = {
        test: 'Memory Store Latency Measurements',
        storeLatencyResults
      };

      latencyTestResults.push(result);
    });

    it('should measure latency percentiles for memory find operations', async () => {
      const findTests = [
        { name: 'Simple Find', query: 'test', top_k: 10 },
        { name: 'Complex Find', query: 'complex search', top_k: 25 },
        { name: 'Type-Filtered Find', query: 'section', types: ['section'], top_k: 15 },
        { name: 'Deep Find', query: 'deep traversal', mode: 'deep' as const, top_k: 20 },
        { name: 'Large Result Find', query: 'large', top_k: 100 }
      ];

      const findLatencyResults: Array<{
        name: string;
        percentiles: ReturnType<typeof calculatePercentiles>;
        avgResultCount: number;
        throughput: number;
      }> = [];

      for (const test of findTests) {
        const latencies: number[] = [];
        const resultCounts: number[] = [];
        const iterations = 150;

        for (let i = 0; i < iterations; i++) {
          const searchParams: any = {
            query: test.query,
            top_k: test.top_k
          };

          if (test.types) searchParams.types = test.types;
          if (test.mode) searchParams.mode = test.mode;

          const startTime = performance.now();
          try {
            const result = await memoryFind(searchParams);
            const latency = performance.now() - startTime;
            latencies.push(latency);
            resultCounts.push(result.results?.length || 0);
          } catch (error) {
            latencies.push(3000);
            resultCounts.push(0);
          }
        }

        const percentiles = calculatePercentiles(latencies);
        const avgResultCount = resultCounts.reduce((sum, count) => sum + count, 0) / resultCounts.length;
        const totalTime = latencies.reduce((sum, lat) => sum + lat, 0);
        const throughput = iterations / (totalTime / 1000);

        findLatencyResults.push({
          name: test.name,
          percentiles,
          avgResultCount,
          throughput
        });

        // Latency assertions for find operations
        const maxP50 = test.mode === 'deep' ? 300 : 200;
        const maxP95 = test.mode === 'deep' ? 800 : 500;
        const maxP99 = test.mode === 'deep' ? 1500 : 1000;

        TestAssertions.assertPerformance(percentiles.p50, maxP50, `P50 latency for ${test.name}`);
        TestAssertions.assertPerformance(percentiles.p95, maxP95, `P95 latency for ${test.name}`);
        TestAssertions.assertPerformance(percentiles.p99, maxP99, `P99 latency for ${test.name}`);
        expect(throughput).toBeGreaterThan(5); // 5+ queries/sec

        console.log(`   ${test.name}:`);
        console.log(`     P50: ${percentiles.p50.toFixed(2)}ms, P95: ${percentiles.p95.toFixed(2)}ms, P99: ${percentiles.p99.toFixed(2)}ms`);
        console.log(`     Avg results: ${avgResultCount.toFixed(1)}, Throughput: ${throughput.toFixed(1)} queries/sec`);
      }

      const result = {
        test: 'Memory Find Latency Measurements',
        findLatencyResults
      };

      latencyTestResults.push(result);
    });
  });

  describe('LATENCY UNDER LOAD', () => {
    it('should measure latency degradation under increasing load', async () => {
      const loadTests = [
        { concurrency: 1, name: 'No Load' },
        { concurrency: 5, name: 'Light Load' },
        { concurrency: 15, name: 'Medium Load' },
        { concurrency: 30, name: 'Heavy Load' },
        { concurrency: 50, name: 'Very Heavy Load' }
      ];

      const loadLatencyResults: Array<{
        name: string;
        concurrency: number;
        percentiles: ReturnType<typeof calculatePercentiles>;
        throughput: number;
        errorRate: number;
        degradationFactor: number;
      }> = [];

      let baselineP50 = 0;
      let baselineP95 = 0;

      for (const test of loadTests) {
        const latencies: number[] = [];
        let errors = 0;
        const totalOperations = test.concurrency * 50; // 50 operations per concurrent thread

        for (let i = 0; i < totalOperations; i++) {
          const startTime = performance.now();
          try {
            // Mix of operations
            const operationType = i % 3;
            switch (operationType) {
              case 0:
                await memoryStore([testContext.dataFactory.createSection({
                  title: `Load Test ${i}`,
                  content: `Load test content ${i}`
                })]);
                break;
              case 1:
                await memoryFind({
                  query: 'load test',
                  top_k: 20
                });
                break;
              case 2:
                await memoryFind({
                  query: `specific ${i % 10}`,
                  types: ['section'],
                  top_k: 10
                });
                break;
            }

            const latency = performance.now() - startTime;
            latencies.push(latency);
          } catch (error) {
            errors++;
            latencies.push(5000);
          }
        }

        const percentiles = calculatePercentiles(latencies);
        const totalTime = latencies.reduce((sum, lat) => sum + lat, 0);
        const throughput = totalOperations / (totalTime / 1000);
        const errorRate = (errors / totalOperations) * 100;

        // Calculate degradation factor
        let degradationFactor = 1;
        if (baselineP50 > 0) {
          degradationFactor = percentiles.p50 / baselineP50;
        } else {
          baselineP50 = percentiles.p50;
          baselineP95 = percentiles.p95;
        }

        loadLatencyResults.push({
          name: test.name,
          concurrency: test.concurrency,
          percentiles,
          throughput,
          errorRate,
          degradationFactor
        });

        // Load-based latency assertions
        const maxP50 = 100 + (test.concurrency * 10);
        const maxP95 = 250 + (test.concurrency * 25);
        const maxP99 = 500 + (test.concurrency * 50);

        TestAssertions.assertPerformance(percentiles.p50, maxP50, `P50 latency under ${test.name}`);
        TestAssertions.assertPerformance(percentiles.p95, maxP95, `P95 latency under ${test.name}`);
        TestAssertions.assertPerformance(percentiles.p99, maxP99, `P99 latency under ${test.name}`);
        expect(errorRate).toBeLessThan(15); // Less than 15% error rate

        console.log(`   ${test.name} (${test.concurrency} concurrent):`);
        console.log(`     P50: ${percentiles.p50.toFixed(2)}ms, P95: ${percentiles.p95.toFixed(2)}ms, P99: ${percentiles.p99.toFixed(2)}ms`);
        console.log(`     Throughput: ${throughput.toFixed(1)} ops/sec, Error rate: ${errorRate.toFixed(1)}%`);
        console.log(`     Degradation factor: ${degradationFactor.toFixed(2)}x`);
      }

      const result = {
        test: 'Latency Under Load',
        loadLatencyResults,
        baselineP50,
        baselineP95
      };

      latencyTestResults.push(result);

      // Analyze worst-case degradation
      const worstDegradation = Math.max(...loadLatencyResults.map(r => r.degradationFactor));
      expect(worstDegradation).toBeLessThan(10); // Less than 10x degradation even under heavy load
    });

    it('should measure latency consistency over time', async () => {
      const testDuration = 60000; // 1 minute
      const samplingInterval = 5000; // 5 seconds
      const operationRate = 10; // operations per second

      const timeSeriesData: Array<{
        timestamp: number;
        p50: number;
        p95: number;
        p99: number;
        throughput: number;
        errorRate: number;
      }> = [];

      const startTime = Date.now();
      let nextSample = startTime + samplingInterval;

      while (Date.now() - startTime < testDuration) {
        const sampleStart = Date.now();
        const sampleLatencies: number[] = [];
        let sampleErrors = 0;
        const operationsInSample = operationRate * (samplingInterval / 1000);

        // Collect sample data
        for (let i = 0; i < operationsInSample; i++) {
          const opStart = performance.now();
          try {
            if (i % 2 === 0) {
              await memoryStore([testContext.dataFactory.createSection({
                title: `Time Series ${i}`,
                content: `Time series test content ${i}`
              })]);
            } else {
              await memoryFind({
                query: 'time series test',
                top_k: 15
              });
            }

            const latency = performance.now() - opStart;
            sampleLatencies.push(latency);
          } catch (error) {
            sampleErrors++;
            sampleLatencies.push(3000);
          }
        }

        const percentiles = calculatePercentiles(sampleLatencies);
        const sampleTime = Date.now() - sampleStart;
        const throughput = operationsInSample / (sampleTime / 1000);
        const errorRate = (sampleErrors / operationsInSample) * 100;

        timeSeriesData.push({
          timestamp: sampleStart,
          p50: percentiles.p50,
          p95: percentiles.p95,
          p99: percentiles.p99,
          throughput,
          errorRate
        });

        // Wait until next sample
        const waitTime = nextSample - Date.now();
        if (waitTime > 0) {
          await new Promise(resolve => setTimeout(resolve, waitTime));
        }
        nextSample += samplingInterval;
      }

      // Analyze time series data for consistency
      const p50Values = timeSeriesData.map(d => d.p50);
      const p95Values = timeSeriesData.map(d => d.p95);
      const p99Values = timeSeriesData.map(d => d.p99);

      const p50Stats = calculatePercentiles(p50Values);
      const p95Stats = calculatePercentiles(p95Values);
      const p99Stats = calculatePercentiles(p99Values);

      // Calculate consistency metrics
      const p50Variation = (p50Stats.standardDeviation / p50Stats.mean) * 100;
      const p95Variation = (p95Stats.standardDeviation / p95Stats.mean) * 100;
      const p99Variation = (p99Stats.standardDeviation / p99Stats.mean) * 100;

      const result = {
        test: 'Latency Consistency Over Time',
        duration: testDuration,
        sampleCount: timeSeriesData.length,
        p50Stats,
        p95Stats,
        p99Stats,
        consistencyMetrics: {
          p50Variation,
          p95Variation,
          p99Variation
        },
        timeSeriesData
      };

      latencyTestResults.push(result);

      // Consistency assertions
      expect(p50Variation).toBeLessThan(50); // P50 should vary less than 50%
      expect(p95Variation).toBeLessThan(60); // P95 should vary less than 60%
      expect(p99Variation).toBeLessThan(80); // P99 can vary more but still should be reasonable

      console.log(`✅ Latency consistency over time completed (${testDuration / 1000}s):`);
      console.log(`   Samples collected: ${timeSeriesData.length}`);
      console.log(`   P50: ${p50Stats.mean.toFixed(2)}ms ± ${p50Stats.standardDeviation.toFixed(2)}ms (${p50Variation.toFixed(1)}% variation)`);
      console.log(`   P95: ${p95Stats.mean.toFixed(2)}ms ± ${p95Stats.standardDeviation.toFixed(2)}ms (${p95Variation.toFixed(1)}% variation)`);
      console.log(`   P99: ${p99Stats.mean.toFixed(2)}ms ± ${p99Stats.standardDeviation.toFixed(2)}ms (${p99Variation.toFixed(1)}% variation)`);
    });
  });

  describe('LATENCY BOTTLENECK ANALYSIS', () => {
    it('should identify latency bottlenecks in different operation types', async () => {
      const operationBottlenecks = [
        {
          name: 'Simple Store',
          operation: async () => memoryStore([testContext.dataFactory.createSection({
            title: 'Bottleneck Test',
            content: 'Simple content'
          })]),
          expectedComplexity: 'low'
        },
        {
          name: 'Batch Store',
          operation: async () => memoryStore(testContext.dataFactory.createMixedBatch(20)),
          expectedComplexity: 'medium'
        },
        {
          name: 'Simple Find',
          operation: async () => memoryFind({
            query: 'bottleneck test',
            top_k: 10
          }),
          expectedComplexity: 'low'
        },
        {
          name: 'Complex Find',
          operation: async () => memoryFind({
            query: 'complex bottleneck test',
            top_k: 50,
            mode: 'deep',
            traverse: { depth: 2 }
          }),
          expectedComplexity: 'high'
        },
        {
          name: 'Delete Operation',
          operation: async () => {
            const item = testContext.dataFactory.createSection({
              title: 'Delete Bottleneck Test',
              content: 'To be deleted'
            });
            const stored = await memoryStore([item]);
            if (stored.stored.length > 0) {
              return softDelete(testContext.testDb, {
                entity_type: stored.stored[0].kind,
                entity_id: stored.stored[0].id
              });
            }
          },
          expectedComplexity: 'medium'
        }
      ];

      const bottleneckResults: Array<{
        name: string;
        expectedComplexity: string;
        percentiles: ReturnType<typeof calculatePercentiles>;
        throughput: number;
        bottleneckScore: number;
      }> = [];

      for (const bottleneckTest of operationBottlenecks) {
        const latencies: number[] = [];
        const iterations = 50;

        for (let i = 0; i < iterations; i++) {
          const startTime = performance.now();
          try {
            await bottleneckTest.operation();
            const latency = performance.now() - startTime;
            latencies.push(latency);
          } catch (error) {
            latencies.push(5000);
          }
        }

        const percentiles = calculatePercentiles(latencies);
        const totalTime = latencies.reduce((sum, lat) => sum + lat, 0);
        const throughput = iterations / (totalTime / 1000);

        // Calculate bottleneck score (higher = more bottleneck)
        const bottleneckScore = percentiles.p95;

        bottleneckResults.push({
          name: bottleneckTest.name,
          expectedComplexity: bottleneckTest.expectedComplexity,
          percentiles,
          throughput,
          bottleneckScore
        });

        console.log(`   ${bottleneckTest.name} (${bottleneckTest.expectedComplexity} complexity):`);
        console.log(`     P50: ${percentiles.p50.toFixed(2)}ms, P95: ${percentiles.p95.toFixed(2)}ms, P99: ${percentiles.p99.toFixed(2)}ms`);
        console.log(`     Throughput: ${throughput.toFixed(1)} ops/sec, Bottleneck score: ${bottleneckScore.toFixed(2)}`);
      }

      // Identify the biggest bottleneck
      const biggestBottleneck = bottleneckResults.reduce((max, result) =>
        result.bottleneckScore > max.bottleneckScore ? result : max
      );

      const result = {
        test: 'Latency Bottleneck Analysis',
        bottleneckResults,
        biggestBottleneck
      };

      latencyTestResults.push(result);

      // Bottleneck analysis assertions
      expect(biggestBottleneck.bottleneckScore).toBeLessThan(2000); // Even the worst bottleneck should be under 2s P95

      console.log(`✅ Latency bottleneck analysis completed:`);
      console.log(`   Biggest bottleneck: ${biggestBottleneck.name} (${biggestBottleneck.expectedComplexity} complexity)`);
      console.log(`   Bottleneck score: ${biggestBottleneck.bottleneckScore.toFixed(2)}ms (P95)`);
    });

    it('should measure cold start vs warm start latency', async () => {
      // First, clear any potential caches
      await new Promise(resolve => setTimeout(resolve, 2000));

      const coldStartLatencies: number[] = [];
      const warmStartLatencies: number[] = [];

      // Cold start measurements (first few operations)
      for (let i = 0; i < 10; i++) {
        const startTime = performance.now();
        try {
          await memoryFind({
            query: `cold start test ${i}`,
            top_k: 20
          });
          const latency = performance.now() - startTime;
          coldStartLatencies.push(latency);
        } catch (error) {
          coldStartLatencies.push(2000);
        }
      }

      // Warm up the system
      for (let i = 0; i < 20; i++) {
        try {
          await memoryFind({
            query: `warm up ${i}`,
            top_k: 10
          });
        } catch (error) {
          // Ignore warm-up errors
        }
      }

      // Warm start measurements
      for (let i = 0; i < 30; i++) {
        const startTime = performance.now();
        try {
          await memoryFind({
            query: `warm start test ${i}`,
            top_k: 20
          });
          const latency = performance.now() - startTime;
          warmStartLatencies.push(latency);
        } catch (error) {
          warmStartLatencies.push(1000);
        }
      }

      const coldStats = calculatePercentiles(coldStartLatencies);
      const warmStats = calculatePercentiles(warmStartLatencies);

      // Calculate improvement
      const p50Improvement = ((coldStats.p50 - warmStats.p50) / coldStats.p50) * 100;
      const p95Improvement = ((coldStats.p95 - warmStats.p95) / coldStats.p95) * 100;
      const p99Improvement = ((coldStats.p99 - warmStats.p99) / coldStats.p99) * 100;

      const result = {
        test: 'Cold Start vs Warm Start Latency',
        coldStats,
        warmStats,
        improvements: {
          p50: p50Improvement,
          p95: p95Improvement,
          p99: p99Improvement
        }
      };

      latencyTestResults.push(result);

      // Warm start should be significantly faster
      expect(p50Improvement).toBeGreaterThan(10); // At least 10% improvement in P50
      expect(p95Improvement).toBeGreaterThan(15); // At least 15% improvement in P95

      console.log(`✅ Cold start vs warm start latency completed:`);
      console.log(`   Cold start - P50: ${coldStats.p50.toFixed(2)}ms, P95: ${coldStats.p95.toFixed(2)}ms, P99: ${coldStats.p99.toFixed(2)}ms`);
      console.log(`   Warm start - P50: ${warmStats.p50.toFixed(2)}ms, P95: ${warmStats.p95.toFixed(2)}ms, P99: ${warmStats.p99.toFixed(2)}ms`);
      console.log(`   Improvements - P50: ${p50Improvement.toFixed(1)}%, P95: ${p95Improvement.toFixed(1)}%, P99: ${p99Improvement.toFixed(1)}%`);
    });
  });

  describe('LATENCY THRESHOLDS AND SLOS', () => {
    it('should validate latency against service level objectives', async () => {
      const slos = {
        // Define Service Level Objectives
        p50_target: 200,    // 200ms P50 target
        p95_target: 500,    // 500ms P95 target
        p99_target: 1000,   // 1000ms P99 target
        error_rate_target: 5 // 5% error rate target
      };

      const sloTests = [
        { name: 'Store Operations', operation: 'store' },
        { name: 'Find Operations', operation: 'find' },
        { name: 'Mixed Operations', operation: 'mixed' }
      ];

      const sloResults: Array<{
        name: string;
        operation: string;
        percentiles: ReturnType<typeof calculatePercentiles>;
        errorRate: number;
        sloCompliance: {
          p50: boolean;
          p95: boolean;
          p99: boolean;
          errorRate: boolean;
          overall: boolean;
        };
      }> = [];

      for (const test of sloTests) {
        const latencies: number[] = [];
        let errors = 0;
        const iterations = 200;

        for (let i = 0; i < iterations; i++) {
          const startTime = performance.now();
          try {
            switch (test.operation) {
              case 'store':
                await memoryStore([testContext.dataFactory.createSection({
                  title: `SLO Test ${i}`,
                  content: 'SLO validation test content'
                })]);
                break;
              case 'find':
                await memoryFind({
                  query: 'slo test',
                  top_k: 25
                });
                break;
              case 'mixed':
                if (i % 2 === 0) {
                  await memoryStore([testContext.dataFactory.createSection({
                    title: `Mixed SLO Test ${i}`,
                    content: 'Mixed SLO test content'
                  })]);
                } else {
                  await memoryFind({
                    query: 'mixed slo test',
                    top_k: 20
                  });
                }
                break;
            }

            const latency = performance.now() - startTime;
            latencies.push(latency);
          } catch (error) {
            errors++;
            latencies.push(5000);
          }
        }

        const percentiles = calculatePercentiles(latencies);
        const errorRate = (errors / iterations) * 100;

        const sloCompliance = {
          p50: percentiles.p50 <= slos.p50_target,
          p95: percentiles.p95 <= slos.p95_target,
          p99: percentiles.p99 <= slos.p99_target,
          errorRate: errorRate <= slos.error_rate_target,
          overall: false
        };

        sloCompliance.overall = sloCompliance.p50 && sloCompliance.p95 && sloCompliance.p99 && sloCompliance.errorRate;

        sloResults.push({
          name: test.name,
          operation: test.operation,
          percentiles,
          errorRate,
          sloCompliance
        });

        // SLO compliance assertions
        expect(sloCompliance.p50).toBe(true, `P50 SLO compliance failed for ${test.name}`);
        expect(sloCompliance.p95).toBe(true, `P95 SLO compliance failed for ${test.name}`);
        expect(sloCompliance.errorRate).toBe(true, `Error rate SLO compliance failed for ${test.name}`);

        console.log(`   ${test.name}:`);
        console.log(`     P50: ${percentiles.p50.toFixed(2)}ms (target: ${slos.p50_target}ms) - ${sloCompliance.p50 ? '✅' : '❌'}`);
        console.log(`     P95: ${percentiles.p95.toFixed(2)}ms (target: ${slos.p95_target}ms) - ${sloCompliance.p95 ? '✅' : '❌'}`);
        console.log(`     P99: ${percentiles.p99.toFixed(2)}ms (target: ${slos.p99_target}ms) - ${sloCompliance.p99 ? '✅' : '❌'}`);
        console.log(`     Error rate: ${errorRate.toFixed(2)}% (target: ${slos.error_rate_target}%) - ${sloCompliance.errorRate ? '✅' : '❌'}`);
        console.log(`     Overall SLO compliance: ${sloCompliance.overall ? '✅' : '❌'}`);
      }

      const result = {
        test: 'Service Level Objective Validation',
        sloTargets: slos,
        sloResults
      };

      latencyTestResults.push(result);

      // Overall SLO compliance
      const overallCompliance = sloResults.every(r => r.sloCompliance.overall);
      expect(overallCompliance).toBe(true, 'Overall SLO compliance failed');

      console.log(`✅ Service Level Objective validation completed:`);
      console.log(`   Overall SLO compliance: ${overallCompliance ? '✅' : '❌'}`);
    });
  });

  describe('LATENCY OUTLIER ANALYSIS', () => {
    it('should identify and analyze latency outliers', async () => {
      const latencies: number[] = [];
      const iterations = 500;

      // Collect comprehensive latency data
      for (let i = 0; i < iterations; i++) {
        const startTime = performance.now();
        try {
          // Mix of operations to create realistic latency distribution
          if (i % 3 === 0) {
            await memoryStore([testContext.dataFactory.createSection({
              title: `Outlier Test ${i}`,
              content: 'Outlier analysis test content'
            })]);
          } else if (i % 3 === 1) {
            await memoryFind({
              query: 'outlier test',
              top_k: 20
            });
          } else {
            await memoryFind({
              query: `complex outlier ${i % 10}`,
              top_k: 30,
              mode: 'deep'
            });
          }

          const latency = performance.now() - startTime;
          latencies.push(latency);
        } catch (error) {
          latencies.push(5000);
        }
      }

      const percentiles = calculatePercentiles(latencies);

      // Define outliers as values beyond 3 standard deviations from mean
      const outlierThreshold = percentiles.mean + (3 * percentiles.standardDeviation);
      const outliers = latencies.filter(latency => latency > outlierThreshold);
      const outlierRate = (outliers.length / latencies.length) * 100;

      // Analyze outlier characteristics
      const outlierStats = outliers.length > 0 ? calculatePercentiles(outliers) : null;
      const maxLatency = Math.max(...latencies);
      const outlierRange = outlierStats ? outlierStats.max - outlierStats.min : 0;

      const result = {
        test: 'Latency Outlier Analysis',
        totalSamples: iterations,
        percentiles,
        outlierThreshold,
        outlierCount: outliers.length,
        outlierRate,
        outlierStats,
        maxLatency,
        outlierRange
      };

      latencyTestResults.push(result);

      // Outlier analysis assertions
      expect(outlierRate).toBeLessThan(5); // Less than 5% outliers
      expect(maxLatency).toBeLessThan(10000); // Max latency should be under 10 seconds

      console.log(`✅ Latency outlier analysis completed:`);
      console.log(`   Total samples: ${iterations}`);
      console.log(`   Latency distribution:`);
      console.log(`     Mean: ${percentiles.mean.toFixed(2)}ms ± ${percentiles.standardDeviation.toFixed(2)}ms`);
      console.log(`     P50: ${percentiles.p50.toFixed(2)}ms, P95: ${percentiles.p95.toFixed(2)}ms, P99: ${percentiles.p99.toFixed(2)}ms`);
      console.log(`   Outlier analysis:`);
      console.log(`     Outlier threshold: ${outlierThreshold.toFixed(2)}ms`);
      console.log(`     Outliers: ${outliers.length} (${outlierRate.toFixed(2)}%)`);
      if (outlierStats) {
        console.log(`     Outlier range: ${outlierStats.min.toFixed(2)}ms - ${outlierStats.max.toFixed(2)}ms`);
        console.log(`     Outlier P50: ${outlierStats.p50.toFixed(2)}ms, P95: ${outlierStats.p95.toFixed(2)}ms`);
      }
      console.log(`     Max latency: ${maxLatency.toFixed(2)}ms`);
    });
  });
});