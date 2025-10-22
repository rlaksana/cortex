/**
 * CONCURRENT USER SIMULATION
 *
 * Simulates multiple concurrent users performing realistic operations
 * to test system behavior under multi-user load conditions.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { TestRunner, TestAssertions } from '../framework/test-setup.js';
import { memoryStore } from '../../src/services/memory-store.js';
import { memoryFind } from '../../src/services/memory-find.js';
import { softDelete } from '../../src/services/delete-operations.js';
import type { TestContext } from '../framework/test-setup.js';

describe('CONCURRENT USER SIMULATION', () => {
  let testRunner: TestRunner;
  let testContext: TestContext;
  let concurrentUserResults: any[] = [];

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

    // Print concurrent user test summary
    if (concurrentUserResults.length > 0) {
      console.log('\n📊 Concurrent User Simulation Results Summary:');
      console.log('='.repeat(80));
      concurrentUserResults.forEach(result => {
        console.log(`${result.test.padEnd(50)} | ${result.avgResponseTime.toFixed(2)}ms | ${result.throughput.toFixed(1)} ops/sec | ${result.errorRate.toFixed(1)}% errors`);
      });
      console.log('='.repeat(80));
    }
  });

  interface SimulatedUser {
    id: string;
    sessionStartTime: number;
    operationsCompleted: number;
    errorsEncountered: number;
    totalLatency: number;
    operationHistory: Array<{
      operation: string;
      latency: number;
      success: boolean;
      timestamp: number;
    }>;
  }

  interface UserBehavior {
    readOperations: number;      // percentage
    writeOperations: number;     // percentage
    searchOperations: number;    // percentage
    deleteOperations: number;    // percentage
    operationFrequency: number;  // operations per minute
    sessionDuration: number;     // milliseconds
  }

  /**
   * Create a simulated user with specific behavior patterns
   */
  function createSimulatedUser(userId: string, behavior: UserBehavior): SimulatedUser {
    return {
      id: userId,
      sessionStartTime: Date.now(),
      operationsCompleted: 0,
      errorsEncountered: 0,
      totalLatency: 0,
      operationHistory: []
    };
  }

  /**
   * Execute a user operation based on behavior probabilities
   */
  async function executeUserOperation(
    user: SimulatedUser,
    behavior: UserBehavior,
    testContext: TestContext
  ): Promise<{ success: boolean; latency: number; operationType: string }> {
    const rand = Math.random() * 100;
    let operationType: string;
    let operation: Promise<any>;

    if (rand < behavior.readOperations) {
      // Read operation
      operationType = 'read';
      operation = memoryFind({
        query: `user-${user.id} query ${user.operationsCompleted}`,
        top_k: 10
      });
    } else if (rand < behavior.readOperations + behavior.writeOperations) {
      // Write operation
      operationType = 'write';
      operation = memoryStore([testContext.dataFactory.createSection({
        title: `User ${user.id} operation ${user.operationsCompleted}`,
        content: `Generated content from user session ${user.id}`
      })]);
    } else if (rand < behavior.readOperations + behavior.writeOperations + behavior.searchOperations) {
      // Search operation
      operationType = 'search';
      operation = memoryFind({
        query: 'test search',
        types: ['section', 'decision'],
        top_k: 20,
        mode: 'deep'
      });
    } else {
      // Delete operation (occasional cleanup)
      operationType = 'delete';
      operation = memoryFind({ query: `user-${user.id}`, top_k: 1 })
        .then(results => {
          if (results.results && results.results.length > 0) {
            return softDelete(testContext.testDb, {
              entity_type: results.results[0].kind,
              entity_id: results.results[0].id
            });
          }
          return Promise.resolve();
        });
    }

    const startTime = performance.now();
    try {
      await operation;
      const latency = performance.now() - startTime;

      user.operationsCompleted++;
      user.totalLatency += latency;
      user.operationHistory.push({
        operation: operationType,
        latency,
        success: true,
        timestamp: Date.now()
      });

      return { success: true, latency, operationType };
    } catch (error) {
      const latency = performance.now() - startTime;

      user.errorsEncountered++;
      user.operationHistory.push({
        operation: operationType,
        latency,
        success: false,
        timestamp: Date.now()
      });

      return { success: false, latency, operationType };
    }
  }

  /**
   * Simulate a user session with specific behavior
   */
  async function simulateUserSession(
    userId: string,
    behavior: UserBehavior,
    testContext: TestContext
  ): Promise<SimulatedUser> {
    const user = createSimulatedUser(userId, behavior);
    const endTime = Date.now() + behavior.sessionDuration;
    const operationInterval = 60000 / behavior.operationFrequency; // milliseconds between operations

    while (Date.now() < endTime) {
      await executeUserOperation(user, behavior, testContext);

      // Wait until next operation time
      const nextOperationTime = user.sessionStartTime + (user.operationsCompleted * operationInterval);
      const waitTime = Math.max(0, nextOperationTime - Date.now());

      if (waitTime > 0) {
        await new Promise(resolve => setTimeout(resolve, waitTime));
      }
    }

    return user;
  }

  describe('LIGHT USER LOAD SIMULATION', () => {
    it('should handle 10 concurrent users with light activity', async () => {
      const userCount = 10;
      const lightUserBehavior: UserBehavior = {
        readOperations: 70,    // 70% reads
        writeOperations: 20,   // 20% writes
        searchOperations: 8,   // 8% searches
        deleteOperations: 2,   // 2% deletes
        operationFrequency: 30, // 30 operations per minute
        sessionDuration: 30000  // 30 seconds
      };

      console.log(`   Simulating ${userCount} light users for ${lightUserBehavior.sessionDuration / 1000} seconds...`);

      const userPromises = Array.from({ length: userCount }, (_, i) =>
        simulateUserSession(`light-user-${i}`, lightUserBehavior, testContext)
      );

      const users = await Promise.all(userPromises);

      // Analyze results
      const totalOperations = users.reduce((sum, user) => sum + user.operationsCompleted, 0);
      const totalErrors = users.reduce((sum, user) => sum + user.errorsEncountered, 0);
      const totalLatency = users.reduce((sum, user) => sum + user.totalLatency, 0);
      const errorRate = (totalErrors / totalOperations) * 100;
      const avgResponseTime = totalLatency / totalOperations;
      const throughput = totalOperations / (lightUserBehavior.sessionDuration / 1000);

      // Analyze by operation type
      const operationStats = {
        read: { count: 0, totalLatency: 0 },
        write: { count: 0, totalLatency: 0 },
        search: { count: 0, totalLatency: 0 },
        delete: { count: 0, totalLatency: 0 }
      };

      users.forEach(user => {
        user.operationHistory.forEach(op => {
          if (operationStats[op.operation as keyof typeof operationStats]) {
            operationStats[op.operation as keyof typeof operationStats].count++;
            operationStats[op.operation as keyof typeof operationStats].totalLatency += op.latency;
          }
        });
      });

      const result = {
        test: 'Light User Load (10 users)',
        userCount,
        totalOperations,
        totalErrors,
        errorRate,
        avgResponseTime,
        throughput,
        sessionDuration: lightUserBehavior.sessionDuration,
        operationBreakdown: Object.fromEntries(
          Object.entries(operationStats).map(([op, stats]) => [
            op,
            {
              count: stats.count,
              avgLatency: stats.count > 0 ? stats.totalLatency / stats.count : 0,
              percentage: (stats.count / totalOperations) * 100
            }
          ])
        )
      };

      concurrentUserResults.push(result);

      // Light load assertions
      TestAssertions.assertPerformance(avgResponseTime, 300, 'Average response time under light load');
      expect(errorRate).toBeLessThan(5); // Less than 5% error rate
      expect(throughput).toBeGreaterThan(50); // 50+ ops/sec
      expect(totalOperations).toBeGreaterThan(userCount * 10); // At least 10 ops per user

      console.log(`✅ Light user load simulation completed:`);
      console.log(`   Users: ${userCount}, Operations: ${totalOperations}, Errors: ${totalErrors}`);
      console.log(`   Error rate: ${errorRate.toFixed(2)}%, Avg response: ${avgResponseTime.toFixed(2)}ms`);
      console.log(`   Throughput: ${throughput.toFixed(1)} ops/sec`);
      console.log(`   Operation breakdown:`);
      Object.entries(result.operationBreakdown).forEach(([op, stats]) => {
        console.log(`     ${op}: ${stats.count} ops (${stats.percentage.toFixed(1)}%), ${stats.avgLatency.toFixed(2)}ms avg`);
      });
    });

    it('should handle mixed user behavior patterns', async () => {
      const userBehaviors = [
        {
          name: 'Read-heavy User',
          behavior: {
            readOperations: 85,
            writeOperations: 10,
            searchOperations: 4,
            deleteOperations: 1,
            operationFrequency: 45,
            sessionDuration: 25000
          } as UserBehavior
        },
        {
          name: 'Write-heavy User',
          behavior: {
            readOperations: 30,
            writeOperations: 60,
            searchOperations: 8,
            deleteOperations: 2,
            operationFrequency: 25,
            sessionDuration: 25000
          } as UserBehavior
        },
        {
          name: 'Search-heavy User',
          behavior: {
            readOperations: 40,
            writeOperations: 15,
            searchOperations: 42,
            deleteOperations: 3,
            operationFrequency: 35,
            sessionDuration: 25000
          } as UserBehavior
        },
        {
          name: 'Balanced User',
          behavior: {
            readOperations: 50,
            writeOperations: 25,
            searchOperations: 20,
            deleteOperations: 5,
            operationFrequency: 30,
            sessionDuration: 25000
          } as UserBehavior
        }
      ];

      const userCounts = [3, 2, 2, 3]; // Distribution of user types
      const allUsers: SimulatedUser[] = [];

      console.log(`   Simulating mixed user behaviors...`);

      const userPromises: Promise<SimulatedUser>[] = [];
      userBehaviors.forEach((userType, typeIndex) => {
        for (let i = 0; i < userCounts[typeIndex]; i++) {
          const userId = `${userType.name.toLowerCase().replace(' ', '-')}-${i}`;
          userPromises.push(
            simulateUserSession(userId, userType.behavior, testContext)
          );
        }
      });

      const users = await Promise.all(userPromises);

      // Analyze results by user type
      const userAnalysis = userBehaviors.map((userType, typeIndex) => {
        const typeUsers = users.slice(
          userCounts.slice(0, typeIndex).reduce((sum, count) => sum + count, 0),
          userCounts.slice(0, typeIndex + 1).reduce((sum, count) => sum + count, 0)
        );

        const typeOperations = typeUsers.reduce((sum, user) => sum + user.operationsCompleted, 0);
        const typeErrors = typeUsers.reduce((sum, user) => sum + user.errorsEncountered, 0);
        const typeLatency = typeUsers.reduce((sum, user) => sum + user.totalLatency, 0);
        const typeErrorRate = typeOperations > 0 ? (typeErrors / typeOperations) * 100 : 0;
        const typeAvgLatency = typeOperations > 0 ? typeLatency / typeOperations : 0;

        return {
          userType: userType.name,
          userCount: typeUsers.length,
          operations: typeOperations,
          errors: typeErrors,
          errorRate: typeErrorRate,
          avgLatency: typeAvgLatency,
          throughput: typeOperations / (userType.behavior.sessionDuration / 1000)
        };
      });

      // Overall statistics
      const totalOperations = users.reduce((sum, user) => sum + user.operationsCompleted, 0);
      const totalErrors = users.reduce((sum, user) => sum + user.errorsEncountered, 0);
      const totalLatency = users.reduce((sum, user) => sum + user.totalLatency, 0);
      const overallErrorRate = (totalErrors / totalOperations) * 100;
      const overallAvgLatency = totalLatency / totalOperations;
      const overallThroughput = totalOperations / (25000 / 1000); // 25 seconds

      const result = {
        test: 'Mixed User Behavior Patterns',
        totalUsers: users.length,
        totalOperations,
        totalErrors,
        overallErrorRate,
        overallAvgLatency,
        overallThroughput,
        userAnalysis
      };

      concurrentUserResults.push(result);

      // Mixed behavior assertions
      TestAssertions.assertPerformance(overallAvgLatency, 400, 'Average response time for mixed behaviors');
      expect(overallErrorRate).toBeLessThan(8); // Less than 8% error rate for mixed patterns
      expect(overallThroughput).toBeGreaterThan(40); // 40+ ops/sec

      console.log(`✅ Mixed user behavior simulation completed:`);
      console.log(`   Total users: ${result.totalUsers}, Operations: ${totalOperations}, Errors: ${totalErrors}`);
      console.log(`   Overall error rate: ${overallErrorRate.toFixed(2)}%, Avg response: ${overallAvgLatency.toFixed(2)}ms`);
      console.log(`   Overall throughput: ${overallThroughput.toFixed(1)} ops/sec`);
      console.log(`   User type analysis:`);
      userAnalysis.forEach(analysis => {
        console.log(`     ${analysis.userType}: ${analysis.userCount} users, ${analysis.operations} ops, ${analysis.errorRate.toFixed(2)}% errors, ${analysis.avgLatency.toFixed(2)}ms avg, ${analysis.throughput.toFixed(1)} ops/sec`);
      });
    });
  });

  describe('MEDIUM USER LOAD SIMULATION', () => {
    it('should handle 25 concurrent users with moderate activity', async () => {
      const userCount = 25;
      const mediumUserBehavior: UserBehavior = {
        readOperations: 60,    // 60% reads
        writeOperations: 25,   // 25% writes
        searchOperations: 12,  // 12% searches
        deleteOperations: 3,   // 3% deletes
        operationFrequency: 40, // 40 operations per minute
        sessionDuration: 40000  // 40 seconds
      };

      console.log(`   Simulating ${userCount} medium users for ${mediumUserBehavior.sessionDuration / 1000} seconds...`);

      // Stagger user start times to simulate realistic load
      const staggerDelay = 2000; // 2 seconds between user groups
      const batchSize = 5;
      const userPromises: Promise<SimulatedUser>[] = [];

      for (let i = 0; i < userCount; i += batchSize) {
        const batchUsers = Array.from({ length: Math.min(batchSize, userCount - i) }, (_, j) => {
          const userId = `medium-user-${i + j}`;
          return simulateUserSession(userId, mediumUserBehavior, testContext);
        });

        userPromises.push(...batchUsers);

        // Stagger batches
        if (i + batchSize < userCount) {
          await new Promise(resolve => setTimeout(resolve, staggerDelay));
        }
      }

      const users = await Promise.all(userPromises);

      // Analyze results with percentiles
      const userStats = users.map(user => ({
        id: user.id,
        operations: user.operationsCompleted,
        errors: user.errorsEncountered,
        errorRate: user.operationsCompleted > 0 ? (user.errorsEncountered / user.operationsCompleted) * 100 : 0,
        avgLatency: user.operationsCompleted > 0 ? user.totalLatency / user.operationsCompleted : 0
      }));

      const totalOperations = users.reduce((sum, user) => sum + user.operationsCompleted, 0);
      const totalErrors = users.reduce((sum, user) => sum + user.errorsEncountered, 0);
      const totalLatency = users.reduce((sum, user) => sum + user.totalLatency, 0);
      const overallErrorRate = (totalErrors / totalOperations) * 100;
      const overallAvgLatency = totalLatency / totalOperations;
      const throughput = totalOperations / (mediumUserBehavior.sessionDuration / 1000);

      // Calculate percentiles
      const errorRates = userStats.map(u => u.errorRate).sort((a, b) => a - b);
      const avgLatencies = userStats.map(u => u.avgLatency).sort((a, b) => a - b);
      const operationCounts = userStats.map(u => u.operations).sort((a, b) => a - b);

      const percentiles = {
        errorRate: {
          p50: errorRates[Math.floor(errorRates.length * 0.5)],
          p90: errorRates[Math.floor(errorRates.length * 0.9)],
          p95: errorRates[Math.floor(errorRates.length * 0.95)],
          p99: errorRates[Math.floor(errorRates.length * 0.99)]
        },
        avgLatency: {
          p50: avgLatencies[Math.floor(avgLatencies.length * 0.5)],
          p90: avgLatencies[Math.floor(avgLatencies.length * 0.9)],
          p95: avgLatencies[Math.floor(avgLatencies.length * 0.95)],
          p99: avgLatencies[Math.floor(avgLatencies.length * 0.99)]
        },
        operations: {
          p50: operationCounts[Math.floor(operationCounts.length * 0.5)],
          p90: operationCounts[Math.floor(operationCounts.length * 0.9)],
          p95: operationCounts[Math.floor(operationCounts.length * 0.95)],
          p99: operationCounts[Math.floor(operationCounts.length * 0.99)]
        }
      };

      const result = {
        test: 'Medium User Load (25 users)',
        userCount,
        totalOperations,
        totalErrors,
        overallErrorRate,
        overallAvgLatency,
        throughput,
        sessionDuration: mediumUserBehavior.sessionDuration,
        percentiles
      };

      concurrentUserResults.push(result);

      // Medium load assertions
      TestAssertions.assertPerformance(overallAvgLatency, 500, 'Average response time under medium load');
      TestAssertions.assertPerformance(percentiles.avgLatency.p95, 1000, '95th percentile latency under medium load');
      expect(overallErrorRate).toBeLessThan(10); // Less than 10% error rate
      expect(throughput).toBeGreaterThan(80); // 80+ ops/sec
      expect(percentiles.errorRate.p95).toBeLessThan(15); // 95% of users have <15% error rate

      console.log(`✅ Medium user load simulation completed:`);
      console.log(`   Users: ${userCount}, Operations: ${totalOperations}, Errors: ${totalErrors}`);
      console.log(`   Overall error rate: ${overallErrorRate.toFixed(2)}%, Avg response: ${overallAvgLatency.toFixed(2)}ms`);
      console.log(`   Throughput: ${throughput.toFixed(1)} ops/sec`);
      console.log(`   Percentiles:`);
      console.log(`     Error Rate - P50: ${percentiles.errorRate.p50.toFixed(2)}%, P90: ${percentiles.errorRate.p90.toFixed(2)}%, P95: ${percentiles.errorRate.p95.toFixed(2)}%`);
      console.log(`     Latency - P50: ${percentiles.avgLatency.p50.toFixed(2)}ms, P90: ${percentiles.avgLatency.p90.toFixed(2)}ms, P95: ${percentiles.avgLatency.p95.toFixed(2)}ms`);
      console.log(`     Operations - P50: ${percentiles.operations.p50}, P90: ${percentiles.operations.p90}, P95: ${percentiles.operations.p95}`);
    });
  });

  describe('HEAVY USER LOAD SIMULATION', () => {
    it('should handle 50 concurrent users with high activity', async () => {
      const userCount = 50;
      const heavyUserBehavior: UserBehavior = {
        readOperations: 55,    // 55% reads
        writeOperations: 30,   // 30% writes
        searchOperations: 12,  // 12% searches
        deleteOperations: 3,   // 3% deletes
        operationFrequency: 60, // 60 operations per minute
        sessionDuration: 45000  // 45 seconds
      };

      console.log(`   Simulating ${userCount} heavy users for ${heavyUserBehavior.sessionDuration / 1000} seconds...`);

      // Simulate realistic burst patterns
      const simulateBurstyUser = async (userId: string, behavior: UserBehavior): Promise<SimulatedUser> => {
        const user = createSimulatedUser(userId, behavior);
        const endTime = Date.now() + behavior.sessionDuration;
        const burstCycle = 10000; // 10-second burst cycles
        let inBurst = true;

        while (Date.now() < endTime) {
          // Toggle burst mode every cycle
          if (Math.floor((Date.now() - user.sessionStartTime) / burstCycle) % 2 === 0) {
            inBurst = true;
          } else {
            inBurst = false;
          }

          if (inBurst) {
            // High frequency during burst
            await executeUserOperation(user, behavior, testContext);
            await new Promise(resolve => setTimeout(resolve, 200)); // 5 ops/sec during burst
          } else {
            // Low frequency during rest
            await executeUserOperation(user, behavior, testContext);
            await new Promise(resolve => setTimeout(resolve, 2000)); // 0.5 ops/sec during rest
          }
        }

        return user;
      };

      // Start users in waves to simulate ramp-up
      const waveSize = 10;
      const waveDelay = 3000; // 3 seconds between waves
      const userPromises: Promise<SimulatedUser>[] = [];

      for (let wave = 0; wave < userCount; wave += waveSize) {
        const currentWaveSize = Math.min(waveSize, userCount - wave);

        for (let i = 0; i < currentWaveSize; i++) {
          const userId = `heavy-user-${wave + i}`;
          userPromises.push(simulateBurstyUser(userId, heavyUserBehavior));
        }

        if (wave + waveSize < userCount) {
          await new Promise(resolve => setTimeout(resolve, waveDelay));
        }
      }

      const users = await Promise.all(userPromises);

      // Analyze burst pattern performance
      const totalOperations = users.reduce((sum, user) => sum + user.operationsCompleted, 0);
      const totalErrors = users.reduce((sum, user) => sum + user.errorsEncountered, 0);
      const totalLatency = users.reduce((sum, user) => sum + user.totalLatency, 0);
      const overallErrorRate = (totalErrors / totalOperations) * 100;
      const overallAvgLatency = totalLatency / totalOperations;
      const throughput = totalOperations / (heavyUserBehavior.sessionDuration / 1000);

      // Analyze performance degradation over time
      const timeWindows = 5; // Divide session into 5 time windows
      const windowSize = heavyUserBehavior.sessionDuration / timeWindows;
      const windowStats = Array.from({ length: timeWindows }, (_, i) => ({
        window: i + 1,
        operations: 0,
        errors: 0,
        totalLatency: 0,
        startTime: Date.now() - (timeWindows - i) * windowSize,
        endTime: Date.now() - (timeWindows - i - 1) * windowSize
      }));

      users.forEach(user => {
        user.operationHistory.forEach(op => {
          const relativeTime = op.timestamp - user.sessionStartTime;
          const windowIndex = Math.min(Math.floor(relativeTime / windowSize), timeWindows - 1);
          if (windowIndex >= 0 && windowIndex < timeWindows) {
            windowStats[windowIndex].operations++;
            if (!op.success) windowStats[windowIndex].errors++;
            windowStats[windowIndex].totalLatency += op.latency;
          }
        });
      });

      // Calculate window performance metrics
      const windowPerformance = windowStats.map(window => ({
        window: window.window,
        operations: window.operations,
        errors: window.errors,
        errorRate: window.operations > 0 ? (window.errors / window.operations) * 100 : 0,
        avgLatency: window.operations > 0 ? window.totalLatency / window.operations : 0,
        throughput: window.operations / (windowSize / 1000)
      }));

      // Check for performance degradation
      const firstWindow = windowPerformance[0];
      const lastWindow = windowPerformance[windowPerformance.length - 1];
      const degradationRate = firstWindow.avgLatency > 0 ?
        ((lastWindow.avgLatency - firstWindow.avgLatency) / firstWindow.avgLatency) * 100 : 0;

      const result = {
        test: 'Heavy User Load (50 users)',
        userCount,
        totalOperations,
        totalErrors,
        overallErrorRate,
        overallAvgLatency,
        throughput,
        sessionDuration: heavyUserBehavior.sessionDuration,
        windowPerformance,
        degradationRate
      };

      concurrentUserResults.push(result);

      // Heavy load assertions (more lenient)
      TestAssertions.assertPerformance(overallAvgLatency, 800, 'Average response time under heavy load');
      expect(overallErrorRate).toBeLessThan(15); // Less than 15% error rate under heavy load
      expect(throughput).toBeGreaterThan(150); // 150+ ops/sec
      expect(degradationRate).toBeLessThan(100); // Less than 100% degradation over time

      console.log(`✅ Heavy user load simulation completed:`);
      console.log(`   Users: ${userCount}, Operations: ${totalOperations}, Errors: ${totalErrors}`);
      console.log(`   Overall error rate: ${overallErrorRate.toFixed(2)}%, Avg response: ${overallAvgLatency.toFixed(2)}ms`);
      console.log(`   Throughput: ${throughput.toFixed(1)} ops/sec`);
      console.log(`   Performance degradation: ${degradationRate.toFixed(1)}%`);
      console.log(`   Window performance:`);
      windowPerformance.forEach(window => {
        console.log(`     Window ${window.window}: ${window.operations} ops, ${window.errorRate.toFixed(2)}% errors, ${window.avgLatency.toFixed(2)}ms avg, ${window.throughput.toFixed(1)} ops/sec`);
      });
    });
  });

  describe('USER SESSION ISOLATION', () => {
    it('should maintain data isolation between concurrent users', async () => {
      const userCount = 15;
      const isolationTestDuration = 20000; // 20 seconds

      // Create users with unique scopes
      const userScopes = Array.from({ length: userCount }, (_, i) => ({
        userId: `isolation-user-${i}`,
        scope: { project: `user-project-${i}` },
        sessionId: `session-${i}-${Date.now()}`
      }));

      console.log(`   Testing data isolation for ${userCount} concurrent users...`);

      const isolationPromises = userScopes.map(async (userScope) => {
        const userResults = {
          userId: userScope.userId,
          scope: userScope.scope,
          itemsStored: 0,
          itemsFound: 0,
          itemsFoundInOwnScope: 0,
          itemsFoundInOtherScope: 0,
          errors: 0
        };

        try {
          // Phase 1: Store items in user's own scope
          const itemsToStore = Array.from({ length: 5 }, (_, i) =>
            testContext.dataFactory.createSection({
              title: `${userScope.userId} item ${i}`,
              content: `Content specific to ${userScope.userId}`,
              metadata: { user_id: userScope.userId, session_id: userScope.sessionId }
            })
          );

          const storeResult = await memoryStore(itemsToStore);
          userResults.itemsStored = storeResult.stored.length;

          if (storeResult.errors.length > 0) {
            userResults.errors += storeResult.errors.length;
          }

          // Phase 2: Search in own scope
          const ownScopeResult = await memoryFind({
            query: userScope.userId,
            scope: userScope.scope,
            top_k: 20
          });
          userResults.itemsFoundInOwnScope = ownScopeResult.results?.length || 0;

          // Phase 3: Search without scope (should find items from all users)
          const globalResult = await memoryFind({
            query: 'item',
            top_k: 50
          });
          userResults.itemsFound = globalResult.results?.length || 0;

          // Phase 4: Search in another user's scope (should find none)
          const otherScopeIndex = (userScopes.indexOf(userScope) + 1) % userScopes.length;
          const otherScope = userScopes[otherScopeIndex].scope;

          const otherScopeResult = await memoryFind({
            query: userScope.userId,
            scope: otherScope,
            top_k: 20
          });
          userResults.itemsFoundInOtherScope = otherScopeResult.results?.length || 0;

        } catch (error) {
          userResults.errors++;
        }

        return userResults;
      });

      const userResults = await Promise.all(isolationPromises);

      // Analyze isolation results
      const totalItemsStored = userResults.reduce((sum, user) => sum + user.itemsStored, 0);
      const totalItemsFoundInOwnScope = userResults.reduce((sum, user) => sum + user.itemsFoundInOwnScope, 0);
      const totalItemsFoundInOtherScope = userResults.reduce((sum, user) => sum + user.itemsFoundInOtherScope, 0);
      const totalErrors = userResults.reduce((sum, user) => sum + user.errors, 0);

      const isolationScore = totalItemsStored > 0 ?
        ((totalItemsFoundInOwnScope - totalItemsFoundInOtherScope) / totalItemsStored) * 100 : 0;

      const result = {
        test: 'User Session Isolation',
        userCount,
        totalItemsStored,
        totalItemsFoundInOwnScope,
        totalItemsFoundInOtherScope,
        totalErrors,
        isolationScore,
        userResults
      };

      concurrentUserResults.push(result);

      // Isolation assertions
      expect(isolationScore).toBeGreaterThan(80); // 80%+ isolation effectiveness
      expect(totalItemsFoundInOwnScope).toBeGreaterThan(totalItemsStored * 0.8); // Should find most of own items
      expect(totalItemsFoundInOtherScope).toBeLessThan(totalItemsStored * 0.1); // Should find very few items from other scopes
      expect(totalErrors).toBeLessThan(userCount * 0.1); // Less than 10% of users should have errors

      console.log(`✅ User session isolation test completed:`);
      console.log(`   Users: ${userCount}, Items stored: ${totalItemsStored}`);
      console.log(`   Items found in own scope: ${totalItemsFoundInOwnScope}`);
      console.log(`   Items found in other scopes: ${totalItemsFoundInOtherScope}`);
      console.log(`   Isolation score: ${isolationScore.toFixed(1)}%`);
      console.log(`   Total errors: ${totalErrors}`);
    });
  });

  describe('USER SCALABILITY ANALYSIS', () => {
    it('should analyze performance scaling with user count', async () => {
      const scalabilityTests = [
        { userCount: 5, name: 'Very Small Scale' },
        { userCount: 15, name: 'Small Scale' },
        { userCount: 30, name: 'Medium Scale' },
        { userCount: 45, name: 'Large Scale' }
      ];

      const scalabilityResults: Array<{
        name: string;
        userCount: number;
        totalOperations: number;
        avgResponseTime: number;
        errorRate: number;
        throughput: number;
        efficiency: number;
      }> = [];

      const baseBehavior: UserBehavior = {
        readOperations: 65,
        writeOperations: 25,
        searchOperations: 8,
        deleteOperations: 2,
        operationFrequency: 30,
        sessionDuration: 20000 // 20 seconds for quicker testing
      };

      for (const test of scalabilityTests) {
        console.log(`   Running ${test.name} with ${test.userCount} users...`);

        const userPromises = Array.from({ length: test.userCount }, (_, i) =>
          simulateUserSession(`scale-user-${test.name.toLowerCase().replace(' ', '-')}-${i}`, baseBehavior, testContext)
        );

        const users = await Promise.all(userPromises);

        const totalOperations = users.reduce((sum, user) => sum + user.operationsCompleted, 0);
        const totalErrors = users.reduce((sum, user) => sum + user.errorsEncountered, 0);
        const totalLatency = users.reduce((sum, user) => sum + user.totalLatency, 0);
        const errorRate = (totalErrors / totalOperations) * 100;
        const avgResponseTime = totalLatency / totalOperations;
        const throughput = totalOperations / (baseBehavior.sessionDuration / 1000);

        // Calculate efficiency (throughput per user)
        const efficiency = throughput / test.userCount;

        scalabilityResults.push({
          name: test.name,
          userCount: test.userCount,
          totalOperations,
          avgResponseTime,
          errorRate,
          throughput,
          efficiency
        });
      }

      // Analyze scaling efficiency
      const baseline = scalabilityResults[0];
      const largestTest = scalabilityResults[scalabilityResults.length - 1];
      const scalingFactor = largestTest.userCount / baseline.userCount;
      const throughputScaling = largestTest.throughput / baseline.throughput;
      const efficiencyRetention = (largestTest.efficiency / baseline.efficiency) * 100;
      const latencyDegradation = ((largestTest.avgResponseTime - baseline.avgResponseTime) / baseline.avgResponseTime) * 100;

      const result = {
        test: 'User Scalability Analysis',
        scalabilityResults,
        scalingFactor,
        throughputScaling,
        efficiencyRetention,
        latencyDegradation
      };

      concurrentUserResults.push(result);

      // Scaling assertions
      expect(throughputScaling).toBeGreaterThan(scalingFactor * 0.6); // At least 60% of linear scaling
      expect(efficiencyRetention).toBeGreaterThan(40); // At least 40% efficiency retention
      expect(latencyDegradation).toBeLessThan(200); // Less than 200% latency degradation

      console.log(`✅ User scalability analysis completed:`);
      scalabilityResults.forEach(result => {
        console.log(`   ${result.name}: ${result.userCount} users, ${result.totalOperations} ops, ${result.avgResponseTime.toFixed(2)}ms avg, ${result.throughput.toFixed(1)} ops/sec, ${result.efficiency.toFixed(1)} ops/sec per user`);
      });
      console.log(`   Scaling factor: ${scalingFactor.toFixed(1)}x`);
      console.log(`   Throughput scaling: ${throughputScaling.toFixed(2)}x (${((throughputScaling / scalingFactor) * 100).toFixed(1)}% efficiency)`);
      console.log(`   Efficiency retention: ${efficiencyRetention.toFixed(1)}%`);
      console.log(`   Latency degradation: ${latencyDegradation.toFixed(1)}%`);
    });
  });
});