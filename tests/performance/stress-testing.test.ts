/**
 * SYSTEM STRESS TESTING
 *
 * Comprehensive stress testing to validate system behavior under extreme conditions,
 * including resource exhaustion, error recovery, and system resilience.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { TestRunner, TestAssertions } from '../framework/test-setup.ts';
import { memoryStore } from '../services/memory-store.ts';
import { memoryFind } from '../services/memory-find.ts';
import { softDelete } from '../services/delete-operations.ts';
import type { TestContext } from '../framework/test-setup.ts';

describe('SYSTEM STRESS TESTING', () => {
  let testRunner: TestRunner;
  let testContext: TestContext;
  let stressTestResults: any[] = [];

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

    // Print stress test summary
    if (stressTestResults.length > 0) {
      console.log('\n📊 Stress Test Results Summary:');
      console.log('='.repeat(80));
      stressTestResults.forEach(result => {
        console.log(`${result.test.padEnd(50)} | ${result.resilienceScore.toFixed(1)}% | ${result.recoveryTime.toFixed(0)}ms`);
      });
      console.log('='.repeat(80));
    }
  });

  interface StressTestMetrics {
    totalOperations: number;
    successfulOperations: number;
    failedOperations: number;
    errorRate: number;
    avgResponseTime: number;
    maxResponseTime: number;
    minResponseTime: number;
    throughput: number;
    memoryUsage: {
      initial: number;
      peak: number;
      final: number;
      growth: number;
    };
    resilienceScore: number;
    recoveryTime: number;
  }

  /**
   * Measure system health and resource usage
   */
  function measureSystemHealth(): {
    memory: NodeJS.MemoryUsage;
    timestamp: number;
    responseTime: number;
  } {
    const startTime = performance.now();
    const memory = process.memoryUsage();
    const responseTime = performance.now() - startTime;

    return {
      memory,
      timestamp: Date.now(),
      responseTime
    };
  }

  /**
   * Calculate resilience score based on system performance under stress
   */
  function calculateResilienceScore(metrics: StressTestMetrics): number {
    const errorRatePenalty = Math.min(metrics.errorRate * 2, 50); // Up to 50% penalty for errors
    const responseTimePenalty = Math.min((metrics.avgResponseTime / 1000) * 20, 30); // Up to 30% penalty for slow response
    const memoryPenalty = Math.min((metrics.memoryUsage.growth / (1024 * 1024 * 100)) * 10, 20); // Up to 20% penalty for memory growth

    return Math.max(0, 100 - errorRatePenalty - responseTimePenalty - memoryPenalty);
  }

  /**
   * Simulate extreme concurrent load
   */
  async function simulateExtremeLoad(
    concurrency: number,
    duration: number,
    operationsPerSecond: number,
    testContext: TestContext
  ): Promise<StressTestMetrics> {
    const startTime = Date.now();
    const initialHealth = measureSystemHealth();
    const operations: Array<{ success: boolean; latency: number; error?: string }> = [];
    let totalOperations = 0;

    // Calculate operation interval
    const operationInterval = 1000 / operationsPerSecond;

    while (Date.now() - startTime < duration) {
      const batchStart = Date.now();
      const concurrentOperations = Array.from({ length: concurrency }, async (_, i) => {
        const opStart = performance.now();
        try {
          // Mix of operations to stress different components
          const operationType = i % 4;
          switch (operationType) {
            case 0:
              await memoryStore([testContext.dataFactory.createSection({
                title: `Stress Test ${totalOperations}-${i}`,
                content: 'A'.repeat(1000) // Larger content to increase memory pressure
              })]);
              break;
            case 1:
              await memoryFind({
                query: `stress test query ${i % 20}`,
                top_k: 50,
                mode: 'deep'
              });
              break;
            case 2:
              await memoryFind({
                query: 'complex stress search',
                top_k: 100,
                traverse: { depth: 3 }
              });
              break;
            case 3:
              // Attempt a delete operation
              const findResult = await memoryFind({
                query: 'delete candidate',
                top_k: 1
              });
              if (findResult.results && findResult.results.length > 0) {
                const item = findResult.results[0];
                await softDelete(testContext.testDb, {
                  entity_type: item.kind,
                  entity_id: item.id,
                  cascade_relations: true
                });
              }
              break;
          }

          const latency = performance.now() - opStart;
          operations.push({ success: true, latency });
          totalOperations++;
        } catch (error) {
          const latency = performance.now() - opStart;
          operations.push({
            success: false,
            latency,
            error: error instanceof Error ? error.message : String(error)
          });
          totalOperations++;
        }
      });

      await Promise.allSettled(concurrentOperations);

      // Rate limiting to achieve target operations per second
      const batchTime = Date.now() - batchStart;
      const expectedBatchTime = (concurrency * operationInterval);
      if (batchTime < expectedBatchTime) {
        await new Promise(resolve => setTimeout(resolve, expectedBatchTime - batchTime));
      }

      // Monitor memory usage during stress test
      if (totalOperations % 100 === 0) {
        const currentHealth = measureSystemHealth();
        const memoryGrowth = currentHealth.memory.heapUsed - initialHealth.memory.heapUsed;

        // If memory usage is too high, trigger garbage collection
        if (memoryGrowth > 500 * 1024 * 1024) { // 500MB threshold
          if (global.gc) {
            global.gc();
          }
        }
      }
    }

    const finalHealth = measureSystemHealth();
    const actualDuration = Date.now() - startTime;

    // Calculate metrics
    const successfulOps = operations.filter(op => op.success);
    const failedOps = operations.filter(op => !op.success);
    const latencies = operations.map(op => op.latency);

    const metrics: StressTestMetrics = {
      totalOperations: operations.length,
      successfulOperations: successfulOps.length,
      failedOperations: failedOps.length,
      errorRate: (failedOps.length / operations.length) * 100,
      avgResponseTime: latencies.reduce((sum, lat) => sum + lat, 0) / latencies.length,
      maxResponseTime: Math.max(...latencies),
      minResponseTime: Math.min(...latencies),
      throughput: operations.length / (actualDuration / 1000),
      memoryUsage: {
        initial: initialHealth.memory.heapUsed,
        peak: Math.max(initialHealth.memory.heapUsed, finalHealth.memory.heapUsed),
        final: finalHealth.memory.heapUsed,
        growth: finalHealth.memory.heapUsed - initialHealth.memory.heapUsed
      },
      resilienceScore: 0, // Will be calculated
      recoveryTime: 0 // Will be measured
    };

    metrics.resilienceScore = calculateResilienceScore(metrics);

    return metrics;
  }

  describe('EXTREME CONCURRENCY STRESS', () => {
    it('should handle extreme concurrent load without system failure', async () => {
      console.log('   Running extreme concurrency stress test...');

      const stressMetrics = await simulateExtremeLoad(
        100,    // 100 concurrent operations
        60000,  // 60 seconds duration
        200,    // 200 operations per second target
        testContext
      );

      // Measure recovery time after stress
      const recoveryStart = Date.now();
      let systemStabilized = false;
      let recoveryAttempts = 0;
      const maxRecoveryAttempts = 10;

      while (!systemStabilized && recoveryAttempts < maxRecoveryAttempts) {
        await new Promise(resolve => setTimeout(resolve, 2000));
        recoveryAttempts++;

        // Test system with a simple operation
        const testStart = performance.now();
        try {
          await memoryFind({ query: 'recovery test', top_k: 5 });
          const testLatency = performance.now() - testStart;

          // System is stabilized if response time is reasonable
          if (testLatency < 1000) { // 1 second threshold
            systemStabilized = true;
          }
        } catch (error) {
          // System not yet stabilized
        }
      }

      stressMetrics.recoveryTime = systemStabilized ? Date.now() - recoveryStart : 30000; // 30s timeout

      const result = {
        test: 'Extreme Concurrency Stress',
        ...stressMetrics,
        stabilized: systemStabilized,
        recoveryAttempts
      };

      stressTestResults.push(result);

      // Extreme stress assertions
      expect(stressMetrics.resilienceScore).toBeGreaterThan(40); // At least 40% resilience under extreme load
      expect(stressMetrics.errorRate).toBeLessThan(30); // Less than 30% error rate under extreme stress
      expect(stressMetrics.memoryUsage.growth).toBeLessThan(1024 * 1024 * 1024); // Less than 1GB memory growth
      expect(systemStabilized).toBe(true); // System should recover
      expect(stressMetrics.recoveryTime).toBeLessThan(30000); // Recover within 30 seconds

      console.log(`✅ Extreme concurrency stress test completed:`);
      console.log(`   Operations: ${stressMetrics.totalOperations}, Success: ${stressMetrics.successfulOperations}, Errors: ${stressMetrics.failedOperations}`);
      console.log(`   Error rate: ${stressMetrics.errorRate.toFixed(2)}%, Throughput: ${stressMetrics.throughput.toFixed(1)} ops/sec`);
      console.log(`   Response time - Avg: ${stressMetrics.avgResponseTime.toFixed(2)}ms, Max: ${stressMetrics.maxResponseTime.toFixed(2)}ms`);
      console.log(`   Memory usage: ${(stressMetrics.memoryUsage.growth / 1024 / 1024).toFixed(2)}MB growth`);
      console.log(`   Resilience score: ${stressMetrics.resilienceScore.toFixed(1)}%`);
      console.log(`   Recovery: ${systemStabilized ? '✅' : '❌'} (${stressMetrics.recoveryTime}ms, ${recoveryAttempts} attempts)`);
    });

    it('should maintain data integrity under stress', async () => {
      console.log('   Running data integrity stress test...');

      const testData = Array.from({ length: 500 }, (_, i) => ({
        id: `stress-integrity-${i}`,
        title: `Stress Integrity Test ${i}`,
        content: `Data integrity test content ${i}`,
        timestamp: Date.now()
      }));

      // Store all test data
      const storePromises = testData.map(data =>
        testContext.dataFactory.createSection({
          title: data.title,
          content: data.content,
          metadata: {
            stress_test_id: data.id,
            timestamp: data.timestamp
          }
        })
      );

      const storeResults = await Promise.allSettled(storePromises);
      const storedItems = storeResults
        .filter(result => result.status === 'fulfilled')
        .map(result => (result as PromiseFulfilledResult<any>).value);

      // Apply stress while verifying data integrity
      const stressDuration = 30000; // 30 seconds
      const stressStart = Date.now();
      const integrityChecks: Array<{
        timestamp: number;
        found: number;
        expected: number;
        integrityScore: number;
      }> = [];

      while (Date.now() - stressStart < stressDuration) {
        // Apply concurrent load
        const stressPromises = Array.from({ length: 50 }, async (_, i) => {
          // Mixed operations during stress
          if (i % 3 === 0) {
            // Search operations
            await memoryFind({
              query: 'stress integrity',
              top_k: 20
            });
          } else if (i % 3 === 1) {
            // Complex searches
            await memoryFind({
              query: 'integrity test',
              top_k: 50,
              mode: 'deep'
            });
          } else {
            // Store additional data
            await memoryStore([testContext.dataFactory.createSection({
              title: `Additional Stress ${i}`,
              content: 'Additional content during integrity test'
            })]);
          }
        });

        await Promise.allSettled(stressPromises);

        // Perform integrity check
        const integrityCheckStart = Date.now();
        try {
          const searchResult = await memoryFind({
            query: 'Stress Integrity Test',
            top_k: 1000 // Try to find all items
          });

          const found = searchResult.results?.length || 0;
          const expected = testData.length;
          const integrityScore = (found / expected) * 100;

          integrityChecks.push({
            timestamp: integrityCheckStart,
            found,
            expected,
            integrityScore
          });
        } catch (error) {
          integrityChecks.push({
            timestamp: integrityCheckStart,
            found: 0,
            expected: testData.length,
            integrityScore: 0
          });
        }

        await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2 seconds between checks
      }

      // Final comprehensive integrity check
      const finalSearchResult = await memoryFind({
        query: 'Stress Integrity Test',
        top_k: 1000
      });

      const finalFound = finalSearchResult.results?.length || 0;
      const finalIntegrityScore = (finalFound / testData.length) * 100;

      // Analyze integrity degradation
      const integrityScores = integrityChecks.map(check => check.integrityScore);
      const minIntegrity = Math.min(...integrityScores);
      const avgIntegrity = integrityScores.reduce((sum, score) => sum + score, 0) / integrityScores.length;
      const integrityVariance = integrityScores.reduce((sum, score) => sum + Math.pow(score - avgIntegrity, 2), 0) / integrityScores.length;

      const result = {
        test: 'Data Integrity Under Stress',
        initialItems: testData.length,
        finalFound,
        finalIntegrityScore,
        minIntegrity,
        avgIntegrity,
        integrityVariance,
        integrityChecks: integrityChecks.length
      };

      stressTestResults.push(result);

      // Data integrity assertions
      expect(finalIntegrityScore).toBeGreaterThan(90); // At least 90% of data should be preserved
      expect(minIntegrity).toBeGreaterThan(80); // Integrity should never drop below 80%
      expect(integrityVariance).toBeLessThan(100); // Low variance in integrity scores

      console.log(`✅ Data integrity stress test completed:`);
      console.log(`   Initial items: ${testData.length}, Final found: ${finalFound}`);
      console.log(`   Final integrity: ${finalIntegrityScore.toFixed(1)}%`);
      console.log(`   Min integrity during stress: ${minIntegrity.toFixed(1)}%`);
      console.log(`   Avg integrity: ${avgIntegrity.toFixed(1)}%`);
      console.log(`   Integrity variance: ${integrityVariance.toFixed(2)}`);
      console.log(`   Integrity checks performed: ${integrityChecks.length}`);
    });
  });

  describe('RESOURCE EXHAUSTION TESTING', () => {
    it('should handle memory exhaustion gracefully', async () => {
      console.log('   Running memory exhaustion stress test...');

      const initialMemory = process.memoryUsage();
      const memorySnapshots: Array<{
        timestamp: number;
        heapUsed: number;
        heapTotal: number;
        external: number;
        rss: number;
      }> = [];

      let memoryStressOperations = 0;
      let memoryErrors = 0;
      let systemRecovered = false;

      // Gradually increase memory pressure
      try {
        while (memoryStressOperations < 1000) {
          // Create large data structures
          const largeItems = Array.from({ length: 10 }, (_, i) =>
            testContext.dataFactory.createSection({
              title: `Memory Stress ${memoryStressOperations}-${i}`,
              content: 'X'.repeat(10000), // 10KB per item
              metadata: {
                large_data: 'Y'.repeat(5000), // Additional 5KB
                stress_test: true
              }
            })
          );

          try {
            await memoryStore(largeItems);
            memoryStressOperations++;

            // Take memory snapshot every 50 operations
            if (memoryStressOperations % 50 === 0) {
              const memory = process.memoryUsage();
              memorySnapshots.push({
                timestamp: Date.now(),
                heapUsed: memory.heapUsed,
                heapTotal: memory.heapTotal,
                external: memory.external,
                rss: memory.rss
              });

              // Check if we're approaching memory limits
              const memoryGrowth = memory.heapUsed - initialMemory.heapUsed;
              if (memoryGrowth > 800 * 1024 * 1024) { // 800MB growth threshold
                console.warn(`Memory usage high: ${(memoryGrowth / 1024 / 1024).toFixed(2)}MB`);

                // Try to force garbage collection
                if (global.gc) {
                  global.gc();
                }
              }
            }
          } catch (error) {
            memoryErrors++;

            // If we're getting memory errors, try to recover
            if (memoryErrors > 5) {
              console.warn('Memory errors detected, attempting recovery...');
              if (global.gc) {
                global.gc();
              }
              await new Promise(resolve => setTimeout(resolve, 5000));
              break;
            }
          }
        }
      } catch (error) {
        console.error('Memory exhaustion test error:', error);
      }

      // Test system recovery after memory stress
      const recoveryStart = Date.now();
      try {
        // Try simple operations to test recovery
        for (let i = 0; i < 10; i++) {
          await memoryStore([testContext.dataFactory.createSection({
            title: `Recovery Test ${i}`,
            content: 'Testing system recovery after memory stress'
          })]);
        }
        systemRecovered = true;
      } catch (error) {
        console.error('System recovery failed:', error);
      }
      const recoveryTime = Date.now() - recoveryStart;

      const finalMemory = process.memoryUsage();
      const memoryGrowth = finalMemory.heapUsed - initialMemory.heapUsed;
      const peakMemory = memorySnapshots.length > 0 ?
        Math.max(...memorySnapshots.map(s => s.heapUsed)) : finalMemory.heapUsed;

      const result = {
        test: 'Memory Exhaustion Handling',
        operationsCompleted: memoryStressOperations,
        memoryErrors,
        memoryGrowth: memoryGrowth / 1024 / 1024, // MB
        peakMemory: peakMemory / 1024 / 1024, // MB
        memorySnapshots: memorySnapshots.length,
        systemRecovered,
        recoveryTime
      };

      stressTestResults.push(result);

      // Memory exhaustion assertions
      expect(memoryStressOperations).toBeGreaterThan(100); // Should complete at least some operations
      expect(memoryErrors).toBeLessThan(memoryStressOperations * 0.5); // Less than 50% error rate
      expect(systemRecovered).toBe(true); // System should recover
      expect(recoveryTime).toBeLessThan(30000); // Recover within 30 seconds

      console.log(`✅ Memory exhaustion stress test completed:`);
      console.log(`   Operations completed: ${memoryStressOperations}, Memory errors: ${memoryErrors}`);
      console.log(`   Memory growth: ${memoryGrowth.toFixed(2)}MB, Peak memory: ${peakMemory.toFixed(2)}MB`);
      console.log(`   System recovered: ${systemRecovered ? '✅' : '❌'} (${recoveryTime}ms)`);
    });

    it('should handle connection pool exhaustion', async () => {
      console.log('   Running connection pool exhaustion test...');

      const concurrentOperations = 200;
      const operationsPerWorker = 10;
      const connectionErrors = [];
      const successfulOperations = [];

      // Create massive concurrent load to exhaust connection pool
      const workers = Array.from({ length: concurrentOperations }, async (_, workerId) => {
        const workerResults = [];

        for (let i = 0; i < operationsPerWorker; i++) {
          const startTime = performance.now();
          try {
            // Mix of operations to stress database connections
            const operationType = i % 4;
            switch (operationType) {
              case 0:
                await memoryStore([testContext.dataFactory.createSection({
                  title: `Connection Test ${workerId}-${i}`,
                  content: 'Connection pool stress test'
                })]);
                break;
              case 1:
                await memoryFind({
                  query: `connection test ${workerId}`,
                  top_k: 25
                });
                break;
              case 2:
                await memoryFind({
                  query: 'complex connection search',
                  top_k: 50,
                  mode: 'deep'
                });
                break;
              case 3:
                await memoryFind({
                  query: 'pool stress',
                  top_k: 100,
                  traverse: { depth: 2 }
                });
                break;
            }

            const latency = performance.now() - startTime;
            workerResults.push({ success: true, latency, workerId, operationId: i });
          } catch (error) {
            const latency = performance.now() - startTime;
            workerResults.push({
              success: false,
              latency,
              workerId,
              operationId: i,
              error: error instanceof Error ? error.message : String(error)
            });
            connectionErrors.push({
              workerId,
              operationId: i,
              error: error instanceof Error ? error.message : String(error),
              timestamp: Date.now()
            });
          }
        }

        return workerResults;
      });

      const allWorkerResults = await Promise.allSettled(workers);
      const allResults = allWorkerResults
        .filter(result => result.status === 'fulfilled')
        .flatMap(result => (result as PromiseFulfilledResult<any>).value);

      successfulOperations.push(...allResults.filter(r => r.success));

      // Calculate connection pool metrics
      const totalOperations = concurrentOperations * operationsPerWorker;
      const successRate = (successfulOperations.length / totalOperations) * 100;
      const connectionErrorRate = (connectionErrors.length / totalOperations) * 100;

      // Analyze error patterns
      const errorByWorker = connectionErrors.reduce((acc, error) => {
        acc[error.workerId] = (acc[error.workerId] || 0) + 1;
        return acc;
      }, {} as Record<number, number>);

      const workersWithErrors = Object.keys(errorByWorker).length;
      const maxErrorsPerWorker = Math.max(...Object.values(errorByWorker), 0);

      const result = {
        test: 'Connection Pool Exhaustion',
        totalOperations,
        successfulOperations: successfulOperations.length,
        connectionErrors: connectionErrors.length,
        successRate,
        connectionErrorRate,
        workersWithErrors,
        maxErrorsPerWorker,
        totalWorkers: concurrentOperations
      };

      stressTestResults.push(result);

      // Connection pool assertions
      expect(successRate).toBeGreaterThan(70); // At least 70% success rate
      expect(connectionErrorRate).toBeLessThan(30); // Less than 30% connection errors
      expect(workersWithErrors).toBeLessThan(concurrentOperations * 0.8); // Not all workers should fail

      console.log(`✅ Connection pool exhaustion test completed:`);
      console.log(`   Total operations: ${totalOperations}, Successful: ${successfulOperations.length}, Errors: ${connectionErrors.length}`);
      console.log(`   Success rate: ${successRate.toFixed(1)}%, Connection error rate: ${connectionErrorRate.toFixed(1)}%`);
      console.log(`   Workers with errors: ${workersWithErrors}/${concurrentOperations}`);
      console.log(`   Max errors per worker: ${maxErrorsPerWorker}`);
    });
  });

  describe('SYSTEM RECOVERY TESTING', () => {
    it('should recover from cascading failures', async () => {
      console.log('   Running cascading failure recovery test...');

      // Simulate cascading failures
      const failureStages = [
        { name: 'Stage 1: High Load', concurrency: 50, duration: 10000, intensity: 'high' },
        { name: 'Stage 2: Error Injection', concurrency: 30, duration: 8000, intensity: 'critical' },
        { name: 'Stage 3: Recovery Test', concurrency: 10, duration: 15000, intensity: 'normal' }
      ];

      const stageResults: Array<{
        stageName: string;
        operations: number;
        errors: number;
        errorRate: number;
        avgResponseTime: number;
        recovered: boolean;
      }> = [];

      for (const stage of failureStages) {
        console.log(`   Executing ${stage.name}...`);

        const stageStart = Date.now();
        const operations: Array<{ success: boolean; latency: number }> = [];
        let stageOperations = 0;

        while (Date.now() - stageStart < stage.duration) {
          const concurrentOps = Array.from({ length: stage.concurrency }, async (_, i) => {
            const opStart = performance.now();
            try {
              // Adjust operation complexity based on intensity
              let operation;
              switch (stage.intensity) {
                case 'high':
                  // Complex operations
                  operation = memoryFind({
                    query: 'complex cascading failure test',
                    top_k: 100,
                    mode: 'deep',
                    traverse: { depth: 3 }
                  });
                  break;
                case 'critical':
                  // Simulate problematic operations
                  if (i % 5 === 0) {
                    // Intentionally problematic query
                    operation = memoryFind({
                      query: '',
                      top_k: 1000 // Very large result set
                    });
                  } else {
                    operation = memoryFind({
                      query: 'critical stage test',
                      top_k: 50
                    });
                  }
                  break;
                default:
                  // Normal operations
                  operation = memoryFind({
                    query: 'recovery test',
                    top_k: 20
                  });
              }

              await operation;
              const latency = performance.now() - opStart;
              operations.push({ success: true, latency });
              stageOperations++;
            } catch (error) {
              const latency = performance.now() - opStart;
              operations.push({ success: false, latency });
              stageOperations++;
            }
          });

          await Promise.allSettled(concurrentOps);

          // Brief pause between batches
          await new Promise(resolve => setTimeout(resolve, 100));
        }

        const successfulOps = operations.filter(op => op.success);
        const errorOps = operations.filter(op => !op.success);
        const latencies = operations.map(op => op.latency);
        const errorRate = (errorOps.length / operations.length) * 100;
        const avgResponseTime = latencies.reduce((sum, lat) => sum + lat, 0) / latencies.length;

        // Test if system has recovered (only for recovery stage)
        let recovered = false;
        if (stage.intensity === 'normal') {
          // Perform specific recovery test
          try {
            const recoveryTest = await memoryFind({ query: 'recovery validation', top_k: 10 });
            recovered = recoveryTest.results !== undefined;
          } catch (error) {
            recovered = false;
          }
        }

        stageResults.push({
          stageName: stage.name,
          operations: operations.length,
          errors: errorOps.length,
          errorRate,
          avgResponseTime,
          recovered
        });

        console.log(`     Operations: ${operations.length}, Errors: ${errorOps.length}, Error rate: ${errorRate.toFixed(1)}%`);
        console.log(`     Avg response time: ${avgResponseTime.toFixed(2)}ms, Recovered: ${recovered ? '✅' : '❌'}`);
      }

      // Overall recovery assessment
      const highLoadStage = stageResults[0];
      const criticalStage = stageResults[1];
      const recoveryStage = stageResults[2];

      const recoveryEfficiency = recoveryStage.errorRate < highLoadStage.errorRate * 1.5;
      const responseTimeRecovery = recoveryStage.avgResponseTime < highLoadStage.avgResponseTime * 2;

      const result = {
        test: 'Cascading Failure Recovery',
        stageResults,
        recoveryEfficiency,
        responseTimeRecovery,
        overallRecovery: recoveryStage.recovered && recoveryEfficiency && responseTimeRecovery
      };

      stressTestResults.push(result);

      // Recovery assertions
      expect(recoveryStage.recovered).toBe(true);
      expect(recoveryEfficiency).toBe(true);
      expect(responseTimeRecovery).toBe(true);
      expect(recoveryStage.errorRate).toBeLessThan(50); // Recovery stage should have reasonable error rate

      console.log(`✅ Cascading failure recovery test completed:`);
      console.log(`   Recovery efficiency: ${recoveryEfficiency ? '✅' : '❌'}`);
      console.log(`   Response time recovery: ${responseTimeRecovery ? '✅' : '❌'}`);
      console.log(`   Overall recovery: ${result.overallRecovery ? '✅' : '❌'}`);
    });

    it('should maintain service availability during partial system degradation', async () => {
      console.log('   Running service availability degradation test...');

      const testDuration = 45000; // 45 seconds
      const degradationIntervals = [
        { start: 0, end: 15000, level: 'normal' },
        { start: 15000, end: 30000, level: 'degraded' },
        { start: 30000, end: 45000, level: 'recovery' }
      ];

      const availabilityMetrics: Array<{
        timestamp: number;
        level: string;
        available: boolean;
        responseTime: number;
        errorRate: number;
      }> = [];

      const testStart = Date.now();

      while (Date.now() - testStart < testDuration) {
        const currentTime = Date.now() - testStart;
        const currentInterval = degradationIntervals.find(interval =>
          currentTime >= interval.start && currentTime < interval.end
        );

        if (!currentInterval) break;

        // Test service availability with current degradation level
        const availabilityTests = Array.from({ length: 20 }, async (_, i) => {
          const testStart = performance.now();
          try {
            // Adjust test complexity based on degradation level
            let query;
            switch (currentInterval.level) {
              case 'degraded':
                // More challenging queries during degradation
                query = memoryFind({
                  query: 'availability degradation test',
                  top_k: 75,
                  mode: 'deep'
                });
                break;
              case 'recovery':
                // Moderate complexity during recovery
                query = memoryFind({
                  query: 'availability recovery test',
                  top_k: 40
                });
                break;
              default:
                // Normal queries
                query = memoryFind({
                  query: 'availability normal test',
                  top_k: 25
                });
            }

            await query;
            const responseTime = performance.now() - testStart;
            return { success: true, responseTime };
          } catch (error) {
            const responseTime = performance.now() - testStart;
            return { success: false, responseTime };
          }
        });

        const testResults = await Promise.allSettled(availabilityTests);
        const results = testResults
          .filter(result => result.status === 'fulfilled')
          .map(result => (result as PromiseFulfilledResult<any>).value);

        const successfulTests = results.filter(r => r.success);
        const available = successfulTests.length > results.length * 0.5; // 50% success threshold
        const avgResponseTime = results.reduce((sum, r) => sum + r.responseTime, 0) / results.length;
        const errorRate = ((results.length - successfulTests.length) / results.length) * 100;

        availabilityMetrics.push({
          timestamp: Date.now(),
          level: currentInterval.level,
          available,
          responseTime: avgResponseTime,
          errorRate
        });

        // Wait before next availability check
        await new Promise(resolve => setTimeout(resolve, 3000));
      }

      // Analyze availability across different degradation levels
      const normalMetrics = availabilityMetrics.filter(m => m.level === 'normal');
      const degradedMetrics = availabilityMetrics.filter(m => m.level === 'degraded');
      const recoveryMetrics = availabilityMetrics.filter(m => m.level === 'recovery');

      const calculateAvailabilityScore = (metrics: typeof availabilityMetrics) => {
        if (metrics.length === 0) return 0;
        const availableChecks = metrics.filter(m => m.available).length;
        return (availableChecks / metrics.length) * 100;
      };

      const normalAvailability = calculateAvailabilityScore(normalMetrics);
      const degradedAvailability = calculateAvailabilityScore(degradedMetrics);
      const recoveryAvailability = calculateAvailabilityScore(recoveryMetrics);

      const availabilityDegradation = normalAvailability - degradedAvailability;
      const recoveryEfficiency = recoveryAvailability > normalAvailability * 0.8;

      const result = {
        test: 'Service Availability During Degradation',
        availabilityMetrics: availabilityMetrics.length,
        normalAvailability,
        degradedAvailability,
        recoveryAvailability,
        availabilityDegradation,
        recoveryEfficiency,
        maintainedService: degradedAvailability > 60 // Service should be available at least 60% during degradation
      };

      stressTestResults.push(result);

      // Availability assertions
      expect(normalAvailability).toBeGreaterThan(80); // Normal availability should be high
      expect(degradedAvailability).toBeGreaterThan(60); // Even during degradation, service should be mostly available
      expect(recoveryAvailability).toBeGreaterThan(70); // Recovery should restore good availability
      expect(availabilityDegradation).toBeLessThan(40); // Availability degradation should be limited

      console.log(`✅ Service availability degradation test completed:`);
      console.log(`   Normal availability: ${normalAvailability.toFixed(1)}%`);
      console.log(`   Degraded availability: ${degradedAvailability.toFixed(1)}%`);
      console.log(`   Recovery availability: ${recoveryAvailability.toFixed(1)}%`);
      console.log(`   Availability degradation: ${availabilityDegradation.toFixed(1)}%`);
      console.log(`   Recovery efficiency: ${recoveryEfficiency ? '✅' : '❌'}`);
      console.log(`   Service maintained: ${result.maintainedService ? '✅' : '❌'}`);
    });
  });

  describe('STRESS TEST REPORTING', () => {
    it('should generate comprehensive stress test report', async () => {
      // This test summarizes all previous stress test results
      const overallMetrics = {
        totalTests: stressTestResults.length,
        averageResilienceScore: stressTestResults.reduce((sum, result) => sum + (result.resilienceScore || 0), 0) / stressTestResults.length,
        averageRecoveryTime: stressTestResults.reduce((sum, result) => sum + (result.recoveryTime || 0), 0) / stressTestResults.length,
        passedTests: stressTestResults.filter(result => {
          if (result.resilienceScore !== undefined) return result.resilienceScore > 50;
          if (result.finalIntegrityScore !== undefined) return result.finalIntegrityScore > 90;
          if (result.successRate !== undefined) return result.successRate > 70;
          return true;
        }).length
      });

      const stressTestSummary = {
        testSuite: 'System Stress Testing',
        timestamp: new Date().toISOString(),
        overallMetrics,
        individualResults: stressTestResults,
        recommendations: generateStressTestRecommendations(stressTestResults)
      };

      // Add this summary to results
      const result = {
        test: 'Stress Test Report Summary',
        ...stressTestSummary
      };

      stressTestResults.push(result);

      // Overall stress test assertions
      expect(overallMetrics.averageResilienceScore).toBeGreaterThan(50); // Average resilience should be good
      expect(overallMetrics.averageRecoveryTime).toBeLessThan(25000); // Average recovery should be under 25 seconds
      expect(overallMetrics.passedTests).toBeGreaterThan(overallMetrics.totalTests * 0.7); // 70% of tests should pass

      console.log(`✅ Comprehensive stress test report generated:`);
      console.log(`   Total tests: ${overallMetrics.totalTests}`);
      console.log(`   Passed tests: ${overallMetrics.passedTests}/${overallMetrics.totalTests}`);
      console.log(`   Average resilience score: ${overallMetrics.averageResilienceScore.toFixed(1)}%`);
      console.log(`   Average recovery time: ${overallMetrics.averageRecoveryTime.toFixed(0)}ms`);
      console.log(`   Recommendations: ${stressTestSummary.recommendations.length}`);
    });
  });
});

/**
 * Generate recommendations based on stress test results
 */
function generateStressTestRecommendations(results: any[]): string[] {
  const recommendations: string[] = [];

  // Analyze common issues and generate recommendations
  const lowResilienceTests = results.filter(r => r.resilienceScore < 60);
  if (lowResilienceTests.length > 0) {
    recommendations.push('Consider implementing circuit breakers and retry mechanisms for improved resilience');
  }

  const slowRecoveryTests = results.filter(r => r.recoveryTime > 20000);
  if (slowRecoveryTests.length > 0) {
    recommendations.push('Optimize system recovery procedures to reduce downtime');
  }

  const highErrorRateTests = results.filter(r => r.errorRate > 20);
  if (highErrorRateTests.length > 0) {
    recommendations.push('Improve error handling and implement graceful degradation strategies');
  }

  const memoryGrowthIssues = results.filter(r => r.memoryGrowth > 500);
  if (memoryGrowthIssues.length > 0) {
    recommendations.push('Implement memory management and garbage collection optimization');
  }

  if (recommendations.length === 0) {
    recommendations.push('System demonstrates excellent stress tolerance and recovery capabilities');
  }

  return recommendations;
}