/**
 * HIGH-VOLUME LOAD TESTING
 *
 * Comprehensive load testing for the mcp-cortex system to validate performance
 * under various load levels (light, medium, heavy) and ensure system stability.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { TestRunner, TestAssertions } from '../framework/test-setup.js';
import { memoryStore } from '../../src/services/memory-store.js';
import { memoryFind } from '../../src/services/memory-find.js';
import { softDelete } from '../../src/services/delete-operations.js';
import type { TestContext } from '../framework/test-setup.js';

describe('HIGH-VOLUME LOAD TESTING', () => {
  let testRunner: TestRunner;
  let testContext: TestContext;
  let loadTestResults: any[] = [];

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
  });

  afterEach(async () => {
    await testRunner.cleanup();

    // Print load test summary
    if (loadTestResults.length > 0) {
      console.log('\n📊 Load Test Results Summary:');
      console.log('='.repeat(80));
      loadTestResults.forEach(result => {
        console.log(`${result.test.padEnd(50)} | ${result.throughput.toFixed(1)} ops/sec | ${result.successRate.toFixed(1)}% success | ${result.avgLatency.toFixed(2)}ms avg`);
      });
      console.log('='.repeat(80));
    }
  });

  describe('LIGHT LOAD TESTING', () => {
    it('should handle 10 concurrent operations efficiently', async () => {
      const concurrentOperations = 10;
      const testDuration = 5000; // 5 seconds
      const operations: Array<() => Promise<any>> = [];

      // Prepare test data
      for (let i = 0; i < concurrentOperations; i++) {
        operations.push(async () => {
          const item = testContext.dataFactory.createSection({
            title: `Load Test Section ${i}`,
          });
          return memoryStore([item]);
        });
      }

      const startTime = Date.now();
      const results: Array<{ success: boolean; duration: number; error?: string }> = [];
      let operationsCompleted = 0;

      // Run load test for specified duration
      while (Date.now() - startTime < testDuration) {
        const operationPromises = operations.map(async (op, index) => {
          const opStart = Date.now();
          try {
            await op();
            const duration = Date.now() - opStart;
            results.push({ success: true, duration });
            return true;
          } catch (error) {
            const duration = Date.now() - opStart;
            results.push({
              success: false,
              duration,
              error: error instanceof Error ? error.message : String(error)
            });
            return false;
          }
        });

        const batchResults = await Promise.all(operationPromises);
        operationsCompleted += batchResults.length;
      }

      const actualDuration = Date.now() - startTime;
      const successCount = results.filter(r => r.success).length;
      const successRate = (successCount / results.length) * 100;
      const throughput = (successCount / actualDuration) * 1000;
      const latencies = results.map(r => r.duration);
      const avgLatency = latencies.reduce((sum, lat) => sum + lat, 0) / latencies.length;
      const p95Latency = latencies.sort((a, b) => a - b)[Math.floor(latencies.length * 0.95)];
      const p99Latency = latencies.sort((a, b) => a - b)[Math.floor(latencies.length * 0.99)];

      loadTestResults.push({
        test: 'Light Load (10 concurrent ops)',
        operationsCompleted,
        successRate,
        throughput,
        avgLatency,
        p95Latency,
        p99Latency,
        duration: actualDuration
      });

      // Light load performance assertions
      TestAssertions.assertPerformance(avgLatency, 200, 'Average latency under light load');
      TestAssertions.assertPerformance(p95Latency, 500, '95th percentile latency under light load');
      TestAssertions.assertPerformance(p99Latency, 1000, '99th percentile latency under light load');
      expect(successRate).toBeGreaterThan(95); // 95%+ success rate
      expect(throughput).toBeGreaterThan(5); // 5+ ops/sec

      console.log(`✅ Light load test completed:`);
      console.log(`   Operations: ${operationsCompleted} in ${actualDuration}ms`);
      console.log(`   Success rate: ${successRate.toFixed(1)}%`);
      console.log(`   Throughput: ${throughput.toFixed(1)} ops/sec`);
      console.log(`   Latency - Avg: ${avgLatency.toFixed(2)}ms, P95: ${p95Latency.toFixed(2)}ms, P99: ${p99Latency.toFixed(2)}ms`);
    });

    it('should maintain performance with mixed operations', async () => {
      const operationMix = {
        store: 0.6,  // 60% store operations
        find: 0.3,   // 30% find operations
        delete: 0.1  // 10% delete operations
      };

      const testDuration = 8000; // 8 seconds
      const preparedItems: any[] = [];

      // Prepare some test data for find/delete operations
      const setupBatch = testContext.dataFactory.createMixedBatch(50);
      const setupResult = await memoryStore(setupBatch);
      preparedItems.push(...setupResult.stored);

      const startTime = Date.now();
      const results: Array<{ success: boolean; duration: number; operation: string }> = [];
      let operationsCompleted = 0;

      while (Date.now() - startTime < testDuration) {
        const rand = Math.random();
        let operationPromise: Promise<any>;

        if (rand < operationMix.store) {
          // Store operation
          operationPromise = memoryStore([testContext.dataFactory.createSection()]);
        } else if (rand < operationMix.store + operationMix.find) {
          // Find operation
          operationPromise = memoryFind({ query: 'test', top_k: 10 });
        } else {
          // Delete operation (if we have items to delete)
          if (preparedItems.length > 0) {
            const itemToDelete = preparedItems.pop();
            operationPromise = softDelete(testContext.testDb, {
              entity_type: itemToDelete.kind,
              entity_id: itemToDelete.id,
            });
          } else {
            operationPromise = memoryFind({ query: 'fallback', top_k: 5 });
          }
        }

        const opStart = Date.now();
        try {
          await operationPromise;
          const duration = Date.now() - opStart;
          const operationType = rand < operationMix.store ? 'store' :
                               rand < operationMix.store + operationMix.find ? 'find' : 'delete';
          results.push({ success: true, duration, operation: operationType });
        } catch (error) {
          const duration = Date.now() - opStart;
          results.push({ success: false, duration, operation: 'error' });
        }
        operationsCompleted++;
      }

      const actualDuration = Date.now() - startTime;
      const successCount = results.filter(r => r.success).length;
      const successRate = (successCount / results.length) * 100;
      const throughput = (successCount / actualDuration) * 1000;
      const avgLatency = results.reduce((sum, r) => sum + r.duration, 0) / results.length;

      // Analyze performance by operation type
      const opsByType = {
        store: results.filter(r => r.operation === 'store'),
        find: results.filter(r => r.operation === 'find'),
        delete: results.filter(r => r.operation === 'delete')
      };

      loadTestResults.push({
        test: 'Mixed Operations (Light Load)',
        operationsCompleted,
        successRate,
        throughput,
        avgLatency,
        opsByType
      });

      // Mixed operations performance assertions
      TestAssertions.assertPerformance(avgLatency, 300, 'Average latency for mixed operations');
      expect(successRate).toBeGreaterThan(90);
      expect(throughput).toBeGreaterThan(4);

      console.log(`✅ Mixed operations load test completed:`);
      console.log(`   Total operations: ${operationsCompleted}`);
      console.log(`   Success rate: ${successRate.toFixed(1)}%`);
      console.log(`   Throughput: ${throughput.toFixed(1)} ops/sec`);
      console.log(`   Average latency: ${avgLatency.toFixed(2)}ms`);
      console.log(`   Operations - Store: ${opsByType.store.length}, Find: ${opsByType.find.length}, Delete: ${opsByType.delete.length}`);
    });
  });

  describe('MEDIUM LOAD TESTING', () => {
    it('should handle 50 concurrent operations', async () => {
      const concurrentOperations = 50;
      const testDuration = 10000; // 10 seconds

      // Prepare batch operations
      const batchOperations: Array<() => Promise<any>> = [];
      for (let i = 0; i < concurrentOperations; i++) {
        batchOperations.push(async () => {
          const batch = testContext.dataFactory.createMixedBatch(5); // Small batches
          return memoryStore(batch);
        });
      }

      const startTime = Date.now();
      const results: Array<{ success: boolean; duration: number; batchSize: number }> = [];
      let operationsCompleted = 0;

      while (Date.now() - startTime < testDuration) {
        const operationPromises = batchOperations.map(async (op, index) => {
          const opStart = Date.now();
          try {
            const result = await op();
            const duration = Date.now() - opStart;
            results.push({
              success: true,
              duration,
              batchSize: 5
            });
            return { success: true, result };
          } catch (error) {
            const duration = Date.now() - opStart;
            results.push({
              success: false,
              duration,
              batchSize: 5,
              error: error instanceof Error ? error.message : String(error)
            });
            return { success: false, error };
          }
        });

        await Promise.allSettled(operationPromises);
        operationsCompleted += concurrentOperations;
      }

      const actualDuration = Date.now() - startTime;
      const successCount = results.filter(r => r.success).length;
      const successRate = (successCount / results.length) * 100;
      const throughput = (successCount / actualDuration) * 1000;
      const latencies = results.map(r => r.duration);
      const avgLatency = latencies.reduce((sum, lat) => sum + lat, 0) / latencies.length;
      const p95Latency = latencies.sort((a, b) => a - b)[Math.floor(latencies.length * 0.95)];
      const p99Latency = latencies.sort((a, b) => a - b)[Math.floor(latencies.length * 0.99)];

      loadTestResults.push({
        test: 'Medium Load (50 concurrent ops)',
        operationsCompleted,
        successRate,
        throughput,
        avgLatency,
        p95Latency,
        p99Latency,
        duration: actualDuration
      });

      // Medium load performance assertions (more lenient than light load)
      TestAssertions.assertPerformance(avgLatency, 500, 'Average latency under medium load');
      TestAssertions.assertPerformance(p95Latency, 1500, '95th percentile latency under medium load');
      TestAssertions.assertPerformance(p99Latency, 3000, '99th percentile latency under medium load');
      expect(successRate).toBeGreaterThan(85); // 85%+ success rate
      expect(throughput).toBeGreaterThan(20); // 20+ ops/sec (considering batch size)

      console.log(`✅ Medium load test completed:`);
      console.log(`   Operations: ${operationsCompleted} in ${actualDuration}ms`);
      console.log(`   Success rate: ${successRate.toFixed(1)}%`);
      console.log(`   Throughput: ${throughput.toFixed(1)} ops/sec`);
      console.log(`   Latency - Avg: ${avgLatency.toFixed(2)}ms, P95: ${p95Latency.toFixed(2)}ms, P99: ${p99Latency.toFixed(2)}ms`);
    });

    it('should sustain performance over extended duration', async () => {
      const testDuration = 30000; // 30 seconds sustained load
      const samplingInterval = 5000; // Sample every 5 seconds
      const concurrentOperations = 25;

      const samples: Array<{
        timestamp: number;
        throughput: number;
        avgLatency: number;
        successRate: number;
      }> = [];

      const startTime = Date.now();
      let nextSample = startTime + samplingInterval;

      while (Date.now() - startTime < testDuration) {
        const sampleStart = Date.now();
        const sampleResults: Array<{ success: boolean; duration: number }> = [];

        // Run operations until next sample
        while (Date.now() < nextSample) {
          const operations = Array.from({ length: concurrentOperations }, async (_, i) => {
            const opStart = Date.now();
            try {
              await memoryStore([testContext.dataFactory.createSection()]);
              const duration = Date.now() - opStart;
              sampleResults.push({ success: true, duration });
            } catch (error) {
              const duration = Date.now() - opStart;
              sampleResults.push({ success: false, duration });
            }
          });

          await Promise.allSettled(operations);
        }

        const sampleDuration = Date.now() - sampleStart;
        const successCount = sampleResults.filter(r => r.success).length;
        const successRate = (successCount / sampleResults.length) * 100;
        const throughput = (successCount / sampleDuration) * 1000;
        const avgLatency = sampleResults.reduce((sum, r) => sum + r.duration, 0) / sampleResults.length;

        samples.push({
          timestamp: sampleStart,
          throughput,
          avgLatency,
          successRate
        });

        nextSample += samplingInterval;
      }

      const actualDuration = Date.now() - startTime;
      const avgThroughput = samples.reduce((sum, s) => sum + s.throughput, 0) / samples.length;
      const avgLatency = samples.reduce((sum, s) => sum + s.avgLatency, 0) / samples.length;
      const minSuccessRate = Math.min(...samples.map(s => s.successRate));

      // Check for performance degradation
      const throughputs = samples.map(s => s.throughput);
      const maxThroughput = Math.max(...throughputs);
      const minThroughput = Math.min(...throughputs);
      const degradation = ((maxThroughput - minThroughput) / maxThroughput) * 100;

      loadTestResults.push({
        test: 'Sustained Medium Load (30s)',
        actualDuration,
        avgThroughput,
        avgLatency,
        minSuccessRate,
        degradation,
        sampleCount: samples.length
      });

      // Sustained load performance assertions
      TestAssertions.assertPerformance(avgLatency, 800, 'Average latency over sustained load');
      expect(minSuccessRate).toBeGreaterThan(80);
      expect(avgThroughput).toBeGreaterThan(15);
      expect(degradation).toBeLessThan(50); // Less than 50% degradation

      console.log(`✅ Sustained load test completed (${actualDuration}ms):`);
      console.log(`   Average throughput: ${avgThroughput.toFixed(1)} ops/sec`);
      console.log(`   Average latency: ${avgLatency.toFixed(2)}ms`);
      console.log(`   Minimum success rate: ${minSuccessRate.toFixed(1)}%`);
      console.log(`   Performance degradation: ${degradation.toFixed(1)}%`);
      console.log(`   Samples collected: ${samples.length}`);
    });
  });

  describe('HEAVY LOAD TESTING', () => {
    it('should handle 100 concurrent operations under stress', async () => {
      const concurrentOperations = 100;
      const testDuration = 15000; // 15 seconds

      // Prepare diverse operations for heavy load
      const operations: Array<() => Promise<any>> = [];

      // Mix of different operation types
      for (let i = 0; i < concurrentOperations; i++) {
        if (i % 3 === 0) {
          // Store operations
          operations.push(async () => {
            const batch = testContext.dataFactory.createMixedBatch(3);
            return memoryStore(batch);
          });
        } else if (i % 3 === 1) {
          // Find operations
          operations.push(async () => {
            return memoryFind({
              query: `test query ${i % 10}`,
              top_k: 20,
              types: ['section', 'decision', 'issue']
            });
          });
        } else {
          // Complex operations
          operations.push(async () => {
            return memoryFind({
              query: 'complex search',
              top_k: 50,
              mode: 'deep',
              traverse: { depth: 2 }
            });
          });
        }
      }

      const startTime = Date.now();
      const results: Array<{ success: boolean; duration: number; operationType: string }> = [];
      let operationsCompleted = 0;
      let totalItemsStored = 0;

      while (Date.now() - startTime < testDuration) {
        const operationPromises = operations.map(async (op, index) => {
          const opStart = Date.now();
          const operationType = index % 3 === 0 ? 'store' :
                               index % 3 === 1 ? 'find' : 'complex_find';
          try {
            const result = await op();
            const duration = Date.now() - opStart;
            results.push({ success: true, duration, operationType });
            if (operationType === 'store' && result.stored) {
              totalItemsStored += result.stored.length;
            }
            return { success: true, result };
          } catch (error) {
            const duration = Date.now() - opStart;
            results.push({
              success: false,
              duration,
              operationType,
              error: error instanceof Error ? error.message : String(error)
            });
            return { success: false, error };
          }
        });

        await Promise.allSettled(operationPromises);
        operationsCompleted += concurrentOperations;
      }

      const actualDuration = Date.now() - startTime;
      const successCount = results.filter(r => r.success).length;
      const successRate = (successCount / results.length) * 100;
      const throughput = (successCount / actualDuration) * 1000;
      const latencies = results.map(r => r.duration);
      const avgLatency = latencies.reduce((sum, lat) => sum + lat, 0) / latencies.length;
      const p95Latency = latencies.sort((a, b) => a - b)[Math.floor(latencies.length * 0.95)];
      const p99Latency = latencies.sort((a, b) => a - b)[Math.floor(latencies.length * 0.99)];

      // Analyze by operation type
      const storeResults = results.filter(r => r.operationType === 'store');
      const findResults = results.filter(r => r.operationType === 'find');
      const complexResults = results.filter(r => r.operationType === 'complex_find');

      loadTestResults.push({
        test: 'Heavy Load (100 concurrent ops)',
        operationsCompleted,
        successRate,
        throughput,
        avgLatency,
        p95Latency,
        p99Latency,
        totalItemsStored,
        operationBreakdown: {
          store: { count: storeResults.length, successRate: (storeResults.filter(r => r.success).length / storeResults.length) * 100 },
          find: { count: findResults.length, successRate: (findResults.filter(r => r.success).length / findResults.length) * 100 },
          complex_find: { count: complexResults.length, successRate: (complexResults.filter(r => r.success).length / complexResults.length) * 100 }
        }
      });

      // Heavy load performance assertions (most lenient)
      TestAssertions.assertPerformance(avgLatency, 2000, 'Average latency under heavy load');
      TestAssertions.assertPerformance(p95Latency, 5000, '95th percentile latency under heavy load');
      expect(successRate).toBeGreaterThan(70); // 70%+ success rate under heavy load
      expect(throughput).toBeGreaterThan(30); // 30+ ops/sec total

      console.log(`✅ Heavy load test completed:`);
      console.log(`   Operations: ${operationsCompleted} in ${actualDuration}ms`);
      console.log(`   Success rate: ${successRate.toFixed(1)}%`);
      console.log(`   Throughput: ${throughput.toFixed(1)} ops/sec`);
      console.log(`   Items stored: ${totalItemsStored}`);
      console.log(`   Latency - Avg: ${avgLatency.toFixed(2)}ms, P95: ${p95Latency.toFixed(2)}ms, P99: ${p99Latency.toFixed(2)}ms`);
      console.log(`   Operation success rates - Store: ${(storeResults.filter(r => r.success).length / storeResults.length * 100).toFixed(1)}%, Find: ${(findResults.filter(r => r.success).length / findResults.length * 100).toFixed(1)}%, Complex: ${(complexResults.filter(r => r.success).length / complexResults.length * 100).toFixed(1)}%`);
    });

    it('should recover performance after load spike', async () => {
      const baselineDuration = 5000; // 5 seconds baseline
      const spikeDuration = 10000; // 10 seconds heavy spike
      const recoveryDuration = 8000; // 8 seconds recovery
      const spikeConcurrency = 150;
      const baselineConcurrency = 20;

      const results: Array<{
        phase: 'baseline' | 'spike' | 'recovery';
        throughput: number;
        avgLatency: number;
        successRate: number;
      }> = [];

      // Phase 1: Baseline
      console.log('   Phase 1: Establishing baseline performance...');
      const baselineMetrics = await runLoadPhase('baseline', baselineDuration, baselineConcurrency, testContext);
      results.push(baselineMetrics);

      // Phase 2: Load Spike
      console.log('   Phase 2: Applying heavy load spike...');
      const spikeMetrics = await runLoadPhase('spike', spikeDuration, spikeConcurrency, testContext);
      results.push(spikeMetrics);

      // Phase 3: Recovery
      console.log('   Phase 3: Measuring recovery performance...');
      const recoveryMetrics = await runLoadPhase('recovery', recoveryDuration, baselineConcurrency, testContext);
      results.push(recoveryMetrics);

      // Analyze recovery
      const baselineThroughput = baselineMetrics.throughput;
      const recoveryThroughput = recoveryMetrics.throughput;
      const recoveryRate = (recoveryThroughput / baselineThroughput) * 100;

      loadTestResults.push({
        test: 'Load Spike and Recovery',
        phases: results,
        baselineThroughput,
        spikeThroughput: spikeMetrics.throughput,
        recoveryThroughput,
        recoveryRate
      });

      // Recovery assertions
      expect(recoveryRate).toBeGreaterThan(60); // Should recover at least 60% of baseline performance
      expect(recoveryMetrics.successRate).toBeGreaterThan(75);
      expect(recoveryMetrics.avgLatency).toBeLessThan(baselineMetrics.avgLatency * 2);

      console.log(`✅ Load spike and recovery test completed:`);
      console.log(`   Baseline throughput: ${baselineThroughput.toFixed(1)} ops/sec`);
      console.log(`   Spike throughput: ${spikeMetrics.throughput.toFixed(1)} ops/sec`);
      console.log(`   Recovery throughput: ${recoveryThroughput.toFixed(1)} ops/sec`);
      console.log(`   Recovery rate: ${recoveryRate.toFixed(1)}% of baseline`);
      results.forEach(phase => {
        console.log(`   ${phase.phase.toUpperCase()} - ${phase.throughput.toFixed(1)} ops/sec, ${phase.avgLatency.toFixed(2)}ms avg, ${phase.successRate.toFixed(1)}% success`);
      });
    });
  });

  describe('PERFORMANCE DEGRADATION ANALYSIS', () => {
    it('should track performance degradation under increasing load', async () => {
      const loadLevels = [
        { name: 'Very Light', concurrency: 5, duration: 4000 },
        { name: 'Light', concurrency: 15, duration: 4000 },
        { name: 'Medium', concurrency: 35, duration: 4000 },
        { name: 'Heavy', concurrency: 75, duration: 4000 },
        { name: 'Very Heavy', concurrency: 125, duration: 4000 }
      ];

      const degradationResults: Array<{
        loadLevel: string;
        concurrency: number;
        throughput: number;
        avgLatency: number;
        p95Latency: number;
        successRate: number;
        degradationFromBaseline?: number;
      }> = [];

      for (const loadLevel of loadLevels) {
        console.log(`   Testing ${loadLevel.name} load (${loadLevel.concurrency} concurrent ops)...`);

        const metrics = await runLoadPhase(loadLevel.name.toLowerCase(), loadLevel.duration, loadLevel.concurrency, testContext);

        const result = {
          loadLevel: loadLevel.name,
          concurrency: loadLevel.concurrency,
          throughput: metrics.throughput,
          avgLatency: metrics.avgLatency,
          p95Latency: metrics.p95Latency || metrics.avgLatency * 1.5,
          successRate: metrics.successRate
        };

        if (degradationResults.length > 0) {
          const baseline = degradationResults[0];
          result.degradationFromBaseline = ((baseline.throughput - metrics.throughput) / baseline.throughput) * 100;
        }

        degradationResults.push(result);
      }

      loadTestResults.push({
        test: 'Performance Degradation Analysis',
        degradationResults
      });

      // Analyze degradation patterns
      const baseline = degradationResults[0];
      const heavyLoad = degradationResults[3];
      const veryHeavyLoad = degradationResults[4];

      const heavyDegradation = heavyLoad.degradationFromBaseline || 0;
      const veryHeavyDegradation = veryHeavyLoad.degradationFromBaseline || 0;

      // Performance degradation should be gradual, not catastrophic
      expect(heavyDegradation).toBeLessThan(80); // Less than 80% degradation at heavy load
      expect(veryHeavyDegradation).toBeLessThan(90); // Less than 90% degradation at very heavy load
      expect(veryHeavyLoad.successRate).toBeGreaterThan(50); // Still maintain 50%+ success rate

      console.log(`✅ Performance degradation analysis completed:`);
      degradationResults.forEach(result => {
        const degradationStr = result.degradationFromBaseline ?
          ` (${result.degradationFromBaseline.toFixed(1)}% degradation)` : '';
        console.log(`   ${result.loadLevel}: ${result.throughput.toFixed(1)} ops/sec, ${result.avgLatency.toFixed(2)}ms latency, ${result.successRate.toFixed(1)}% success${degradationStr}`);
      });
    });
  });
});

/**
 * Helper function to run a load test phase
 */
async function runLoadPhase(
  phaseName: string,
  duration: number,
  concurrency: number,
  testContext: TestContext
): Promise<{
  throughput: number;
  avgLatency: number;
  p95Latency?: number;
  successRate: number;
}> {
  const startTime = Date.now();
  const results: Array<{ success: boolean; duration: number }> = [];

  const operations = Array.from({ length: concurrency }, async (_, i) => {
    return async () => {
      const opStart = Date.now();
      try {
        if (i % 2 === 0) {
          await memoryStore([testContext.dataFactory.createSection()]);
        } else {
          await memoryFind({ query: `test ${i % 5}`, top_k: 10 });
        }
        const duration = Date.now() - opStart;
        results.push({ success: true, duration });
      } catch (error) {
        const duration = Date.now() - opStart;
        results.push({ success: false, duration });
      }
    };
  });

  while (Date.now() - startTime < duration) {
    await Promise.allSettled(operations.map(op => op()));
  }

  const actualDuration = Date.now() - startTime;
  const successCount = results.filter(r => r.success).length;
  const successRate = (successCount / results.length) * 100;
  const throughput = (successCount / actualDuration) * 1000;
  const latencies = results.map(r => r.duration);
  const avgLatency = latencies.reduce((sum, lat) => sum + lat, 0) / latencies.length;
  const p95Latency = latencies.sort((a, b) => a - b)[Math.floor(latencies.length * 0.95)];

  return {
    throughput,
    avgLatency,
    p95Latency,
    successRate
  };
}