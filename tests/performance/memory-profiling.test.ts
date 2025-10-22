/**
 * MEMORY PROFILING AND LEAK DETECTION
 *
 * Comprehensive memory usage testing for detecting leaks, monitoring memory patterns,
 * and ensuring efficient memory management under various load conditions.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { TestRunner, TestAssertions } from '../framework/test-setup.js';
import { memoryStore } from '../../src/services/memory-store.js';
import { memoryFind } from '../../src/services/memory-find.js';
import { softDelete } from '../../src/services/delete-operations.js';
import type { TestContext } from '../framework/test-setup.js';

describe('MEMORY PROFILING AND LEAK DETECTION', () => {
  let testRunner: TestRunner;
  let testContext: TestContext;
  let memoryTestResults: any[] = [];

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

    // Force garbage collection before each test if available
    if (global.gc) {
      global.gc();
    }
  });

  afterEach(async () => {
    await testRunner.cleanup();

    // Print memory test summary
    if (memoryTestResults.length > 0) {
      console.log('\n📊 Memory Profiling Results Summary:');
      console.log('='.repeat(80));
      memoryTestResults.forEach(result => {
        console.log(`${result.test.padEnd(50)} | ${result.memoryDelta.toFixed(1)}MB | ${result.leakSuspected ? '🚨 LEAK' : '✅ OK'}`);
      });
      console.log('='.repeat(80));
    }
  });

  describe('BASELINE MEMORY USAGE', () => {
    it('should establish baseline memory usage patterns', async () => {
      const baselineMeasurements = [];
      const sampleCount = 10;
      const sampleInterval = 1000; // 1 second

      // Collect baseline measurements
      for (let i = 0; i < sampleCount; i++) {
        if (global.gc) {
          global.gc();
        }

        const memoryUsage = process.memoryUsage();
        baselineMeasurements.push({
          timestamp: Date.now(),
          heapUsed: memoryUsage.heapUsed,
          heapTotal: memoryUsage.heapTotal,
          external: memoryUsage.external,
          rss: memoryUsage.rss
        });

        if (i < sampleCount - 1) {
          await new Promise(resolve => setTimeout(resolve, sampleInterval));
        }
      }

      // Calculate baseline statistics
      const heapUsages = baselineMeasurements.map(m => m.heapUsed);
      const avgHeapUsed = heapUsages.reduce((sum, val) => sum + val, 0) / heapUsages.length;
      const maxHeapUsed = Math.max(...heapUsages);
      const minHeapUsed = Math.min(...heapUsages);
      const heapVariance = maxHeapUsed - minHeapUsed;

      const baselineStats = {
        sampleCount,
        avgHeapUsed: avgHeapUsed / 1024 / 1024, // MB
        maxHeapUsed: maxHeapUsed / 1024 / 1024, // MB
        minHeapUsed: minHeapUsed / 1024 / 1024, // MB
        heapVariance: heapVariance / 1024 / 1024, // MB
        stabilityScore: (1 - heapVariance / avgHeapUsed) * 100
      };

      memoryTestResults.push({
        test: 'Baseline Memory Usage',
        baselineStats,
        leakSuspected: baselineStats.heapVariance > 10 * 1024 * 1024 // 10MB variance threshold
      });

      // Baseline memory should be relatively stable
      expect(baselineStats.heapVariance).toBeLessThan(10 * 1024 * 1024); // Less than 10MB variance
      expect(baselineStats.stabilityScore).toBeGreaterThan(90); // 90%+ stability

      console.log(`✅ Baseline memory usage established:`);
      console.log(`   Average heap used: ${baselineStats.avgHeapUsed.toFixed(2)}MB`);
      console.log(`   Heap variance: ${baselineStats.heapVariance.toFixed(2)}MB`);
      console.log(`   Stability score: ${baselineStats.stabilityScore.toFixed(1)}%`);
    });
  });

  describe('MEMORY LEAK DETECTION', () => {
    it('should detect memory leaks during sustained operations', async () => {
      const operationCount = 1000;
      const batchSize = 10;
      const memorySnapshots = [];
      const operationType = 'store';

      // Take initial memory snapshot
      if (global.gc) {
        global.gc();
      }
      const initialMemory = process.memoryUsage();
      memorySnapshots.push({ phase: 'initial', ...initialMemory });

      // Perform operations and take memory snapshots
      for (let i = 0; i < operationCount; i += batchSize) {
        // Perform batch of operations
        const operations = [];
        for (let j = 0; j < batchSize && (i + j) < operationCount; j++) {
          operations.push(memoryStore([testContext.dataFactory.createSection()]));
        }

        await Promise.allSettled(operations);

        // Take memory snapshot every 100 operations
        if ((i + batchSize) % 100 === 0) {
          if (global.gc) {
            global.gc();
          }
          const currentMemory = process.memoryUsage();
          memorySnapshots.push({
            phase: `batch_${Math.floor((i + batchSize) / 100)}`,
            operationsCompleted: i + batchSize,
            ...currentMemory
          });
        }
      }

      // Final memory snapshot
      if (global.gc) {
        global.gc();
      }
      const finalMemory = process.memoryUsage();
      memorySnapshots.push({ phase: 'final', operationsCompleted: operationCount, ...finalMemory });

      // Analyze memory growth
      const memoryGrowth = finalMemory.heapUsed - initialMemory.heapUsed;
      const memoryPerOperation = memoryGrowth / operationCount;
      const maxMemoryUsed = Math.max(...memorySnapshots.map(s => s.heapUsed));
      const memoryGrowthRate = (memoryGrowth / initialMemory.heapUsed) * 100;

      // Check for leak patterns (linear growth over time)
      const memoryTrend = analyzeMemoryTrend(memorySnapshots);

      const leakAnalysis = {
        operationCount,
        memoryGrowth: memoryGrowth / 1024 / 1024, // MB
        memoryPerOperation: memoryPerOperation / 1024, // KB
        memoryGrowthRate,
        maxMemoryUsed: maxMemoryUsed / 1024 / 1024, // MB
        memoryTrend,
        leakSuspected: memoryGrowth > 50 * 1024 * 1024 || memoryTrend.slope > 1000 // 50MB threshold or significant positive slope
      };

      memoryTestResults.push({
        test: 'Memory Leak Detection - Sustained Operations',
        leakAnalysis,
        leakSuspected: leakAnalysis.leakSuspected
      });

      // Memory leak assertions
      expect(leakAnalysis.memoryGrowth).toBeLessThan(50 * 1024 * 1024); // Less than 50MB growth
      expect(leakAnalysis.memoryPerOperation).toBeLessThan(50 * 1024); // Less than 50KB per operation
      expect(memoryTrend.slope).toBeLessThan(1000); // Memory growth slope should be minimal

      console.log(`✅ Memory leak detection completed (${operationCount} operations):`);
      console.log(`   Total memory growth: ${leakAnalysis.memoryGrowth.toFixed(2)}MB`);
      console.log(`   Memory per operation: ${leakAnalysis.memoryPerOperation.toFixed(2)}KB`);
      console.log(`   Memory growth rate: ${leakAnalysis.memoryGrowthRate.toFixed(1)}%`);
      console.log(`   Memory trend slope: ${memoryTrend.slope.toFixed(2)} bytes/op`);
      console.log(`   Leak suspected: ${leakAnalysis.leakSuspected ? 'YES' : 'NO'}`);
    });

    it('should detect memory leaks in find operations', async () => {
      // First, populate with test data
      const setupData = testContext.dataFactory.createMixedBatch(500);
      await memoryStore(setupData);

      const searchIterations = 2000;
      const memorySnapshots = [];

      // Initial snapshot
      if (global.gc) {
        global.gc();
      }
      const initialMemory = process.memoryUsage();
      memorySnapshots.push({ phase: 'initial', ...initialMemory });

      // Perform find operations with varying complexity
      for (let i = 0; i < searchIterations; i++) {
        const queries = [
          { query: 'test', top_k: 10 },
          { query: 'decision', types: ['decision'], top_k: 20 },
          { query: 'complex', mode: 'deep', top_k: 50, traverse: { depth: 2 } },
          { query: `specific ${i % 10}`, types: ['section', 'issue'] }
        ];

        const randomQuery = queries[i % queries.length];
        await memoryFind(randomQuery);

        // Take snapshot every 500 operations
        if ((i + 1) % 500 === 0) {
          if (global.gc) {
            global.gc();
          }
          const currentMemory = process.memoryUsage();
          memorySnapshots.push({
            phase: `search_batch_${Math.floor((i + 1) / 500)}`,
            operationsCompleted: i + 1,
            ...currentMemory
          });
        }
      }

      // Final snapshot
      if (global.gc) {
        global.gc();
      }
      const finalMemory = process.memoryUsage();
      memorySnapshots.push({ phase: 'final', operationsCompleted: searchIterations, ...finalMemory });

      // Analyze memory patterns
      const memoryGrowth = finalMemory.heapUsed - initialMemory.heapUsed;
      const memoryPerSearch = memoryGrowth / searchIterations;
      const memoryTrend = analyzeMemoryTrend(memorySnapshots);

      const leakAnalysis = {
        operationType: 'find',
        searchIterations,
        memoryGrowth: memoryGrowth / 1024 / 1024, // MB
        memoryPerSearch: memoryPerSearch / 1024, // KB
        memoryTrend,
        leakSuspected: memoryGrowth > 30 * 1024 * 1024 || memoryTrend.slope > 500
      };

      memoryTestResults.push({
        test: 'Memory Leak Detection - Find Operations',
        leakAnalysis,
        leakSuspected: leakAnalysis.leakSuspected
      });

      // Find operations should not leak significantly
      expect(leakAnalysis.memoryGrowth).toBeLessThan(30 * 1024 * 1024); // Less than 30MB growth
      expect(leakAnalysis.memoryPerSearch).toBeLessThan(15 * 1024); // Less than 15KB per search
      expect(memoryTrend.slope).toBeLessThan(500);

      console.log(`✅ Find operations memory leak detection completed:`);
      console.log(`   Total memory growth: ${leakAnalysis.memoryGrowth.toFixed(2)}MB`);
      console.log(`   Memory per search: ${leakAnalysis.memoryPerSearch.toFixed(2)}KB`);
      console.log(`   Memory trend slope: ${memoryTrend.slope.toFixed(2)} bytes/search`);
      console.log(`   Leak suspected: ${leakAnalysis.leakSuspected ? 'YES' : 'NO'}`);
    });

    it('should detect memory leaks in concurrent operations', async () => {
      const concurrency = 20;
      const operationsPerWorker = 100;
      const memorySnapshots = [];

      // Initial snapshot
      if (global.gc) {
        global.gc();
      }
      const initialMemory = process.memoryUsage();
      memorySnapshots.push({ phase: 'initial', ...initialMemory });

      // Run concurrent operations
      for (let batch = 0; batch < 5; batch++) {
        const concurrentOperations = Array.from({ length: concurrency }, async (_, workerId) => {
          const operations = [];
          for (let i = 0; i < operationsPerWorker; i++) {
            const operation = i % 3 === 0 ?
              memoryStore([testContext.dataFactory.createSection()]) :
              memoryFind({ query: `worker_${workerId}_op_${i}`, top_k: 10 });
            operations.push(operation);
          }
          return Promise.allSettled(operations);
        });

        await Promise.all(concurrentOperations);

        // Take snapshot after each batch
        if (global.gc) {
          global.gc();
        }
        const currentMemory = process.memoryUsage();
        memorySnapshots.push({
          phase: `batch_${batch + 1}`,
          operationsCompleted: (batch + 1) * concurrency * operationsPerWorker,
          ...currentMemory
        });
      }

      // Final snapshot
      if (global.gc) {
        global.gc();
      }
      const finalMemory = process.memoryUsage();
      memorySnapshots.push({ phase: 'final', operationsCompleted: 5 * concurrency * operationsPerWorker, ...finalMemory });

      // Analyze concurrent memory patterns
      const memoryGrowth = finalMemory.heapUsed - initialMemory.heapUsed;
      const totalOperations = 5 * concurrency * operationsPerWorker;
      const memoryPerOperation = memoryGrowth / totalOperations;
      const memoryTrend = analyzeMemoryTrend(memorySnapshots);

      const leakAnalysis = {
        operationType: 'concurrent',
        totalOperations,
        concurrency,
        memoryGrowth: memoryGrowth / 1024 / 1024, // MB
        memoryPerOperation: memoryPerOperation / 1024, // KB
        memoryTrend,
        leakSuspected: memoryGrowth > 100 * 1024 * 1024 || memoryTrend.slope > 2000
      };

      memoryTestResults.push({
        test: 'Memory Leak Detection - Concurrent Operations',
        leakAnalysis,
        leakSuspected: leakAnalysis.leakSuspected
      });

      // Concurrent operations should still not leak excessively
      expect(leakAnalysis.memoryGrowth).toBeLessThan(100 * 1024 * 1024); // Less than 100MB growth
      expect(leakAnalysis.memoryPerOperation).toBeLessThan(100 * 1024); // Less than 100KB per operation
      expect(memoryTrend.slope).toBeLessThan(2000);

      console.log(`✅ Concurrent operations memory leak detection completed:`);
      console.log(`   Total operations: ${totalOperations}`);
      console.log(`   Concurrency: ${concurrency}`);
      console.log(`   Memory growth: ${leakAnalysis.memoryGrowth.toFixed(2)}MB`);
      console.log(`   Memory per operation: ${leakAnalysis.memoryPerOperation.toFixed(2)}KB`);
      console.log(`   Leak suspected: ${leakAnalysis.leakSuspected ? 'YES' : 'NO'}`);
    });
  });

  describe('MEMORY USAGE PATTERNS', () => {
    it('should analyze memory usage for different operation types', async () => {
      const operationTypes = [
        { name: 'Single Store', fn: () => memoryStore([testContext.dataFactory.createSection()]) },
        { name: 'Batch Store', fn: () => memoryStore(testContext.dataFactory.createMixedBatch(10)) },
        { name: 'Simple Find', fn: () => memoryFind({ query: 'test', top_k: 10 }) },
        { name: 'Complex Find', fn: () => memoryFind({ query: 'complex', mode: 'deep', top_k: 50 }) },
        { name: 'Delete Operation', fn: async () => {
          const item = testContext.dataFactory.createSection();
          const stored = await memoryStore([item]);
          if (stored.stored.length > 0) {
            return softDelete(testContext.testDb, {
              entity_type: stored.stored[0].kind,
              entity_id: stored.stored[0].id
            });
          }
        }}
      ];

      const operationMemoryProfiles = [];

      for (const opType of operationTypes) {
        const iterations = 100;
        const memoryMeasurements = [];

        for (let i = 0; i < iterations; i++) {
          // Measure memory before operation
          if (global.gc) {
            global.gc();
          }
          const memoryBefore = process.memoryUsage().heapUsed;

          try {
            await opType.fn();
          } catch (error) {
            // Log error but continue measurement
          }

          // Measure memory after operation
          if (global.gc) {
            global.gc();
          }
          const memoryAfter = process.memoryUsage().heapUsed;
          const memoryDelta = memoryAfter - memoryBefore;

          memoryMeasurements.push({
            iteration: i,
            memoryBefore,
            memoryAfter,
            memoryDelta
          });
        }

        // Calculate statistics for this operation type
        const memoryDeltas = memoryMeasurements.map(m => m.memoryDelta);
        const avgMemoryDelta = memoryDeltas.reduce((sum, delta) => sum + delta, 0) / memoryDeltas.length;
        const maxMemoryDelta = Math.max(...memoryDeltas);
        const minMemoryDelta = Math.min(...memoryDeltas);
        const memoryVariance = maxMemoryDelta - minMemoryDelta;

        const profile = {
          operationName: opType.name,
          iterations,
          avgMemoryDelta: avgMemoryDelta / 1024, // KB
          maxMemoryDelta: maxMemoryDelta / 1024, // KB
          minMemoryDelta: minMemoryDelta / 1024, // KB
          memoryVariance: memoryVariance / 1024, // KB
          efficiency: avgMemoryDelta > 0 ? iterations / (avgMemoryDelta / 1024) : 0 // ops per KB
        };

        operationMemoryProfiles.push(profile);
      }

      memoryTestResults.push({
        test: 'Memory Usage Patterns by Operation Type',
        operationMemoryProfiles,
        leakSuspected: false
      });

      // Each operation type should have reasonable memory usage
      operationMemoryProfiles.forEach(profile => {
        expect(profile.avgMemoryDelta).toBeLessThan(500 * 1024); // Less than 500KB average per operation
        expect(profile.maxMemoryDelta).toBeLessThan(2 * 1024 * 1024); // Less than 2MB maximum per operation
      });

      console.log(`✅ Memory usage patterns analysis completed:`);
      operationMemoryProfiles.forEach(profile => {
        console.log(`   ${profile.operationName}:`);
        console.log(`     Average memory: ${profile.avgMemoryDelta.toFixed(2)}KB`);
        console.log(`     Max memory: ${profile.maxMemoryDelta.toFixed(2)}KB`);
        console.log(`     Variance: ${profile.memoryVariance.toFixed(2)}KB`);
        console.log(`     Efficiency: ${profile.efficiency.toFixed(1)} ops/KB`);
      });
    });

    it('should monitor memory cleanup effectiveness', async () => {
      const testPhases = [
        { name: 'Accumulation', operations: 200, expectGrowth: true },
        { name: 'Stabilization', operations: 0, expectGrowth: false },
        { name: 'Recovery', operations: 0, expectGrowth: false }
      ];

      const memoryHistory = [];

      // Phase 1: Memory accumulation
      for (let i = 0; i < testPhases[0].operations; i++) {
        await memoryStore([testContext.dataFactory.createSection()]);

        if (i % 50 === 0) {
          if (global.gc) {
            global.gc();
          }
          const memory = process.memoryUsage();
          memoryHistory.push({
            phase: testPhases[0].name,
            operation: i,
            heapUsed: memory.heapUsed,
            timestamp: Date.now()
          });
        }
      }

      // Phase 2: Stabilization (no new operations, just GC)
      const stabilizationStart = Date.now();
      while (Date.now() - stabilizationStart < 5000) { // 5 seconds
        if (global.gc) {
          global.gc();
        }
        const memory = process.memoryUsage();
        memoryHistory.push({
          phase: testPhases[1].name,
          operation: 0,
          heapUsed: memory.heapUsed,
          timestamp: Date.now()
        });
        await new Promise(resolve => setTimeout(resolve, 1000));
      }

      // Phase 3: Recovery (aggressive GC)
      for (let i = 0; i < 10; i++) {
        if (global.gc) {
          global.gc();
        }
        const memory = process.memoryUsage();
        memoryHistory.push({
          phase: testPhases[2].name,
          operation: i,
          heapUsed: memory.heapUsed,
          timestamp: Date.now()
        });
        await new Promise(resolve => setTimeout(resolve, 500));
      }

      // Analyze memory cleanup
      const accumulationMemory = memoryHistory.filter(h => h.phase === testPhases[0].name);
      const stabilizationMemory = memoryHistory.filter(h => h.phase === testPhases[1].name);
      const recoveryMemory = memoryHistory.filter(h => h.phase === testPhases[2].name);

      const memoryCleanupAnalysis = {
        accumulationStart: accumulationMemory[0]?.heapUsed || 0,
        accumulationEnd: accumulationMemory[accumulationMemory.length - 1]?.heapUsed || 0,
        stabilizationEnd: stabilizationMemory[stabilizationMemory.length - 1]?.heapUsed || 0,
        recoveryEnd: recoveryMemory[recoveryMemory.length - 1]?.heapUsed || 0,
        accumulationGrowth: 0,
        stabilizationReduction: 0,
        recoveryReduction: 0,
        cleanupEffectiveness: 0
      };

      memoryCleanupAnalysis.accumulationGrowth = memoryCleanupAnalysis.accumulationEnd - memoryCleanupAnalysis.accumulationStart;
      memoryCleanupAnalysis.stabilizationReduction = memoryCleanupAnalysis.accumulationEnd - memoryCleanupAnalysis.stabilizationEnd;
      memoryCleanupAnalysis.recoveryReduction = memoryCleanupAnalysis.accumulationEnd - memoryCleanupAnalysis.recoveryEnd;
      memoryCleanupAnalysis.cleanupEffectiveness = (memoryCleanupAnalysis.recoveryReduction / memoryCleanupAnalysis.accumulationGrowth) * 100;

      memoryTestResults.push({
        test: 'Memory Cleanup Effectiveness',
        memoryCleanupAnalysis,
        leakSuspected: memoryCleanupAnalysis.cleanupEffectiveness < 20 // Less than 20% cleanup indicates potential leak
      });

      // Memory cleanup should be effective
      expect(memoryCleanupAnalysis.cleanupEffectiveness).toBeGreaterThan(20); // At least 20% cleanup

      console.log(`✅ Memory cleanup effectiveness analysis completed:`);
      console.log(`   Accumulation growth: ${(memoryCleanupAnalysis.accumulationGrowth / 1024 / 1024).toFixed(2)}MB`);
      console.log(`   Stabilization reduction: ${(memoryCleanupAnalysis.stabilizationReduction / 1024 / 1024).toFixed(2)}MB`);
      console.log(`   Recovery reduction: ${(memoryCleanupAnalysis.recoveryReduction / 1024 / 1024).toFixed(2)}MB`);
      console.log(`   Cleanup effectiveness: ${memoryCleanupAnalysis.cleanupEffectiveness.toFixed(1)}%`);
    });
  });

  describe('MEMORY PRESSURE TESTING', () => {
    it('should handle high memory pressure gracefully', async () => {
      const pressureTestDuration = 20000; // 20 seconds
      const highMemoryOperations = [];
      const memorySnapshots = [];

      // Create operations that consume significant memory
      const createHighMemoryOperation = (size: 'small' | 'medium' | 'large') => {
        switch (size) {
          case 'small':
            return memoryStore([testContext.dataFactory.createSection()]);
          case 'medium':
            return memoryStore(testContext.dataFactory.createMixedBatch(20));
          case 'large':
            return memoryFind({
              query: 'large search',
              top_k: 100,
              mode: 'deep',
              traverse: { depth: 3 }
            });
        }
      };

      const startTime = Date.now();
      let operationCount = 0;

      while (Date.now() - startTime < pressureTestDuration) {
        const operationSize = ['small', 'medium', 'large'][operationCount % 3] as 'small' | 'medium' | 'large';
        highMemoryOperations.push(createHighMemoryOperation(operationSize));
        operationCount++;

        // Take memory snapshot every 50 operations
        if (operationCount % 50 === 0) {
          if (global.gc) {
            global.gc();
          }
          const memory = process.memoryUsage();
          memorySnapshots.push({
            operationCount,
            heapUsed: memory.heapUsed,
            heapTotal: memory.heapTotal,
            external: memory.external,
            rss: memory.rss,
            timestamp: Date.now()
          });

          // Check if we're approaching memory limits
          if (memory.heapUsed > 500 * 1024 * 1024) { // 500MB threshold
            console.warn(`High memory usage detected: ${(memory.heapUsed / 1024 / 1024).toFixed(2)}MB`);
          }
        }

        // Execute operations in batches to avoid overwhelming the system
        if (highMemoryOperations.length >= 20) {
          await Promise.allSettled(highMemoryOperations.splice(0, 20));
        }
      }

      // Execute remaining operations
      if (highMemoryOperations.length > 0) {
        await Promise.allSettled(highMemoryOperations);
      }

      // Final memory snapshot
      if (global.gc) {
        global.gc();
      }
      const finalMemory = process.memoryUsage();
      memorySnapshots.push({
        operationCount,
        heapUsed: finalMemory.heapUsed,
        heapTotal: finalMemory.heapTotal,
        external: finalMemory.external,
        rss: finalMemory.rss,
        timestamp: Date.now()
      });

      // Analyze memory pressure handling
      const maxMemoryUsed = Math.max(...memorySnapshots.map(s => s.heapUsed));
      const memoryGrowthRate = memorySnapshots.length > 1 ?
        (memorySnapshots[memorySnapshots.length - 1].heapUsed - memorySnapshots[0].heapUsed) /
        (memorySnapshots[memorySnapshots.length - 1].timestamp - memorySnapshots[0].timestamp) : 0;

      const pressureAnalysis = {
        totalOperations: operationCount,
        testDuration: Date.now() - startTime,
        maxMemoryUsed: maxMemoryUsed / 1024 / 1024, // MB
        finalMemoryUsed: finalMemory.heapUsed / 1024 / 1024, // MB
        memoryGrowthRate: memoryGrowthRate / 1024, // KB per second
        snapshotCount: memorySnapshots.length,
        handledGracefully: maxMemoryUsed < 1024 * 1024 * 1024 // Less than 1GB
      };

      memoryTestResults.push({
        test: 'Memory Pressure Testing',
        pressureAnalysis,
        leakSuspected: !pressureAnalysis.handledGracefully || memoryGrowthRate > 1024 * 1024 // Growth > 1MB/sec
      });

      // System should handle memory pressure gracefully
      expect(pressureAnalysis.handledGracefully).toBe(true);
      expect(pressureAnalysis.memoryGrowthRate).toBeLessThan(1024 * 1024); // Less than 1MB/sec growth rate

      console.log(`✅ Memory pressure testing completed:`);
      console.log(`   Total operations: ${pressureAnalysis.totalOperations}`);
      console.log(`   Test duration: ${pressureAnalysis.testDuration}ms`);
      console.log(`   Max memory used: ${pressureAnalysis.maxMemoryUsed.toFixed(2)}MB`);
      console.log(`   Final memory used: ${pressureAnalysis.finalMemoryUsed.toFixed(2)}MB`);
      console.log(`   Memory growth rate: ${pressureAnalysis.memoryGrowthRate.toFixed(2)}KB/sec`);
      console.log(`   Handled gracefully: ${pressureAnalysis.handledGracefully ? 'YES' : 'NO'}`);
    });
  });
});

/**
 * Helper function to analyze memory trend over time
 */
function analyzeMemoryTrend(memorySnapshots: any[]): { slope: number; correlation: number; trend: 'increasing' | 'stable' | 'decreasing' } {
  if (memorySnapshots.length < 3) {
    return { slope: 0, correlation: 0, trend: 'stable' };
  }

  // Extract x (operations) and y (memory) values
  const xValues = memorySnapshots.map((s, i) => s.operationsCompleted || i);
  const yValues = memorySnapshots.map(s => s.heapUsed);

  // Calculate linear regression
  const n = xValues.length;
  const sumX = xValues.reduce((sum, x) => sum + x, 0);
  const sumY = yValues.reduce((sum, y) => sum + y, 0);
  const sumXY = xValues.reduce((sum, x, i) => sum + x * yValues[i], 0);
  const sumXX = xValues.reduce((sum, x) => sum + x * x, 0);

  const slope = (n * sumXY - sumX * sumY) / (n * sumXX - sumX * sumX);

  // Calculate correlation coefficient
  const meanX = sumX / n;
  const meanY = sumY / n;
  const numerator = xValues.reduce((sum, x, i) => sum + (x - meanX) * (yValues[i] - meanY), 0);
  const denominatorX = Math.sqrt(xValues.reduce((sum, x) => sum + Math.pow(x - meanX, 2), 0));
  const denominatorY = Math.sqrt(yValues.reduce((sum, y) => sum + Math.pow(y - meanY, 2), 0));
  const correlation = denominatorX * denominatorY !== 0 ? numerator / (denominatorX * denominatorY) : 0;

  // Determine trend
  let trend: 'increasing' | 'stable' | 'decreasing';
  if (Math.abs(slope) < 100) { // Less than 100 bytes per operation
    trend = 'stable';
  } else if (slope > 0) {
    trend = 'increasing';
  } else {
    trend = 'decreasing';
  }

  return { slope, correlation, trend };
}