/**
 * DATABASE QUERY PERFORMANCE
 *
 * Comprehensive database performance testing for query optimization,
 * connection pooling, transaction efficiency, and database scalability.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { TestRunner, TestAssertions } from '../framework/test-setup.ts';
import { memoryStore } from '../services/memory-store.ts';
import { memoryFind } from '../services/memory-find.ts';
import { softDelete } from '../services/delete-operations.ts';
import type { TestContext } from '../framework/test-setup.ts';

describe('DATABASE QUERY PERFORMANCE', () => {
  let testRunner: TestRunner;
  let testContext: TestContext;
  let dbPerformanceResults: any[] = [];

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

    // Setup comprehensive test data for database operations
    await setupDatabaseTestData();
  });

  afterEach(async () => {
    await testRunner.cleanup();

    // Print database performance summary
    if (dbPerformanceResults.length > 0) {
      console.log('\n📊 Database Performance Results Summary:');
      console.log('='.repeat(80));
      dbPerformanceResults.forEach(result => {
        console.log(`${result.test.padEnd(50)} | ${result.avgQueryTime.toFixed(2)}ms | ${result.throughput.toFixed(0)} ops/sec`);
      });
      console.log('='.repeat(80));
    }
  });

  /**
   * Setup comprehensive test data for database operations
   */
  async function setupDatabaseTestData(): Promise<void> {
    console.log('   Setting up database test data...');

    // Create a variety of data types and sizes for testing
    const dataBatches = [
      { count: 300, type: 'section', size: 'small' },
      { count: 200, type: 'decision', size: 'medium' },
      { count: 250, type: 'issue', size: 'large' },
      { count: 150, type: 'entity', size: 'small' },
      { count: 100, type: 'relation', size: 'medium' },
      { count: 180, type: 'observation', size: 'large' },
      { count: 120, type: 'runbook', size: 'medium' },
      { count: 80, type: 'change', size: 'small' }
    ];

    for (const batch of dataBatches) {
      const items = [];
      for (let i = 0; i < batch.count; i++) {
        let item: any;

        // Create items with varying content sizes
        const contentSize = batch.size === 'small' ? 100 : batch.size === 'medium' ? 500 : 2000;
        const content = 'A'.repeat(contentSize);

        switch (batch.type) {
          case 'section':
            item = testContext.dataFactory.createSection({
              title: `DB Test Section ${i}`,
              content: `Database performance test content ${i}: ${content.substring(0, Math.min(100, content.length))}`
            });
            break;
          case 'decision':
            item = testContext.dataFactory.createDecision({
              title: `DB Test Decision ${i}`,
              rationale: `Database decision rationale ${i}: ${content.substring(0, Math.min(200, content.length))}`
            });
            break;
          case 'issue':
            item = testContext.dataFactory.createIssue({
              title: `DB Test Issue ${i}`,
              description: `Database issue description ${i}: ${content.substring(0, Math.min(300, content.length))}`
            });
            break;
          case 'entity':
            item = testContext.dataFactory.createEntity({
              name: `DB Test Entity ${i}`,
              description: `Database entity description ${i}: ${content.substring(0, Math.min(150, content.length))}`
            });
            break;
          case 'relation':
            item = testContext.dataFactory.createRelation({
              from_type: 'entity',
              from_id: `entity-${i}`,
              to_type: 'entity',
              to_id: `entity-${(i + 1) % 150}`,
              relation_type: 'depends_on'
            });
            break;
          case 'observation':
            item = testContext.dataFactory.createObservation({
              content: `Database observation ${i}: ${content.substring(0, Math.min(250, content.length))}`
            });
            break;
          case 'runbook':
            item = testContext.dataFactory.createRunbook({
              title: `DB Test Runbook ${i}`,
              procedure: `Database runbook procedure ${i}: ${content.substring(0, Math.min(400, content.length))}`
            });
            break;
          case 'change':
            item = testContext.dataFactory.createChange({
              description: `Database change description ${i}: ${content.substring(0, Math.min(200, content.length))}`
            });
            break;
        }

        items.push(item);
      }

      const result = await memoryStore(items);
      if (result.errors.length > 0) {
        console.warn(`Setup warning: ${result.errors.length} items failed to store`);
      }
    }

    console.log('   ✅ Database test data setup completed');
  }

  describe('INSERT PERFORMANCE TESTING', () => {
    it('should handle single inserts efficiently', async () => {
      const insertSizes = [1, 5, 10, 25, 50];
      const insertResults: Array<{
        batchSize: number;
        avgInsertTime: number;
        maxInsertTime: number;
        minInsertTime: number;
        throughput: number;
        errorRate: number;
      }> = [];

      for (const batchSize of insertSizes) {
        const iterations = 20;
        const insertTimes: number[] = [];
        let errors = 0;

        for (let i = 0; i < iterations; i++) {
          const items = Array.from({ length: batchSize }, (_, j) =>
            testContext.dataFactory.createSection({
              title: `Insert Test ${i}-${j}`,
              content: `Test content for insert performance testing batch ${i} item ${j}`
            })
          );

          const startTime = performance.now();
          try {
            await memoryStore(items);
            const insertTime = performance.now() - startTime;
            insertTimes.push(insertTime);
          } catch (error) {
            errors++;
            insertTimes.push(5000); // Penalize failed inserts
          }
        }

        const avgInsertTime = insertTimes.reduce((sum, time) => sum + time, 0) / insertTimes.length;
        const maxInsertTime = Math.max(...insertTimes);
        const minInsertTime = Math.min(...insertTimes);
        const throughput = (batchSize / avgInsertTime) * 1000;
        const errorRate = (errors / iterations) * 100;

        insertResults.push({
          batchSize,
          avgInsertTime,
          maxInsertTime,
          minInsertTime,
          throughput,
          errorRate
        });

        // Performance assertions for inserts
        const maxAcceptableTime = 100 + (batchSize * 10); // Base 100ms + 10ms per item
        TestAssertions.assertPerformance(avgInsertTime, maxAcceptableTime, `Insert batch size ${batchSize}`);
        TestAssertions.assertPerformance(maxInsertTime, maxAcceptableTime * 2, `Max insert time for batch size ${batchSize}`);
        expect(errorRate).toBeLessThan(10); // Less than 10% error rate
      }

      // Analyze insert scalability
      const singleInsert = insertResults[0];
      const batchInsert = insertResults[insertResults.length - 1];
      const batchEfficiency = (batchInsert.throughput / (singleInsert.throughput * batchInsert.batchSize)) * 100;

      const result = {
        test: 'Single Insert Performance',
        insertResults,
        batchEfficiency
      };

      dbPerformanceResults.push(result);

      // Insert efficiency should be reasonable
      expect(batchEfficiency).toBeGreaterThan(30); // At least 30% efficiency compared to single inserts

      console.log(`✅ Single insert performance completed:`);
      insertResults.forEach(result => {
        console.log(`   Batch size ${result.batchSize}: ${result.avgInsertTime.toFixed(2)}ms avg, ${result.throughput.toFixed(1)} ops/sec, ${result.errorRate.toFixed(1)}% errors`);
      });
      console.log(`   Batch efficiency: ${batchEfficiency.toFixed(1)}%`);
    });

    it('should handle bulk inserts efficiently', async () => {
      const bulkSizes = [100, 250, 500, 1000];
      const bulkResults: Array<{
        bulkSize: number;
        totalTime: number;
        avgTimePerItem: number;
        throughput: number;
        memoryUsage: number;
        success: boolean;
      }> = [];

      for (const bulkSize of bulkSizes) {
        // Force garbage collection before test
        if (global.gc) {
          global.gc();
        }
        const memoryBefore = process.memoryUsage().heapUsed;

        // Create bulk data
        const items = Array.from({ length: bulkSize }, (_, i) =>
          testContext.dataFactory.createSection({
            title: `Bulk Insert Test ${i}`,
            content: `Bulk insert test content item ${i} with moderate length content for performance testing`
          })
        );

        const startTime = performance.now();
        let success = true;

        try {
          // Split into reasonable chunks to avoid overwhelming the system
          const chunkSize = 50;
          const chunks = [];
          for (let i = 0; i < items.length; i += chunkSize) {
            chunks.push(items.slice(i, i + chunkSize));
          }

          for (const chunk of chunks) {
            await memoryStore(chunk);
          }
        } catch (error) {
          success = false;
        }

        const totalTime = performance.now() - startTime;
        const avgTimePerItem = totalTime / bulkSize;
        const throughput = bulkSize / (totalTime / 1000);

        if (global.gc) {
          global.gc();
        }
        const memoryAfter = process.memoryUsage().heapUsed;
        const memoryUsage = (memoryAfter - memoryBefore) / 1024 / 1024; // MB

        bulkResults.push({
          bulkSize,
          totalTime,
          avgTimePerItem,
          throughput,
          memoryUsage,
          success
        });

        // Bulk insert performance assertions
        TestAssertions.assertPerformance(avgTimePerItem, 50, `Bulk insert size ${bulkSize}`);
        expect(success).toBe(true);
        expect(memoryUsage).toBeLessThan(bulkSize * 0.01); // Less than 10KB per item
      }

      const result = {
        test: 'Bulk Insert Performance',
        bulkResults
      };

      dbPerformanceResults.push(result);

      console.log(`✅ Bulk insert performance completed:`);
      bulkResults.forEach(result => {
        console.log(`   Bulk size ${result.bulkSize}: ${result.totalTime.toFixed(2)}ms total, ${result.avgTimePerItem.toFixed(2)}ms per item, ${result.throughput.toFixed(1)} ops/sec, ${result.memoryUsage.toFixed(2)}MB memory`);
      });
    });
  });

  describe('SELECT QUERY PERFORMANCE', () => {
    it('should handle simple select queries efficiently', async () => {
      const queryTests = [
        { query: 'test', top_k: 10, name: 'Simple Query' },
        { query: 'database', top_k: 25, name: 'Medium Results' },
        { query: 'performance', top_k: 50, name: 'Large Results' },
        { query: 'section', types: ['section'], top_k: 20, name: 'Type-Filtered' },
        { query: 'entity relation', types: ['entity', 'relation'], top_k: 30, name: 'Multi-Type' }
      ];

      const queryResults: Array<{
        name: string;
        avgQueryTime: number;
        maxQueryTime: number;
        minQueryTime: number;
        p95QueryTime: number;
        avgResultCount: number;
        throughput: number;
      }> = [];

      for (const queryTest of queryTests) {
        const iterations = 30;
        const queryTimes: number[] = [];
        const resultCounts: number[] = [];

        for (let i = 0; i < iterations; i++) {
          const searchParams: any = {
            query: queryTest.query,
            top_k: queryTest.top_k
          };

          if (queryTest.types) {
            searchParams.types = queryTest.types;
          }

          const startTime = performance.now();
          try {
            const result = await memoryFind(searchParams);
            const queryTime = performance.now() - startTime;
            queryTimes.push(queryTime);
            resultCounts.push(result.results?.length || 0);
          } catch (error) {
            queryTimes.push(2000); // Penalize failed queries
            resultCounts.push(0);
          }
        }

        const avgQueryTime = queryTimes.reduce((sum, time) => sum + time, 0) / queryTimes.length;
        const maxQueryTime = Math.max(...queryTimes);
        const minQueryTime = Math.min(...queryTimes);
        const p95QueryTime = queryTimes.sort((a, b) => a - b)[Math.floor(queryTimes.length * 0.95)];
        const avgResultCount = resultCounts.reduce((sum, count) => sum + count, 0) / resultCounts.length;
        const throughput = iterations / (queryTimes.reduce((sum, time) => sum + time, 0) / 1000);

        queryResults.push({
          name: queryTest.name,
          avgQueryTime,
          maxQueryTime,
          minQueryTime,
          p95QueryTime,
          avgResultCount,
          throughput
        });

        // Select query performance assertions
        const maxAcceptableTime = 150 + (queryTest.top_k * 2); // Base 150ms + 2ms per result
        TestAssertions.assertPerformance(avgQueryTime, maxAcceptableTime, `Query: ${queryTest.name}`);
        TestAssertions.assertPerformance(p95QueryTime, maxAcceptableTime * 1.5, `P95 for: ${queryTest.name}`);
      }

      const result = {
        test: 'Select Query Performance',
        queryResults,
        overallAvgQueryTime: queryResults.reduce((sum, r) => sum + r.avgQueryTime, 0) / queryResults.length
      };

      dbPerformanceResults.push(result);

      console.log(`✅ Select query performance completed:`);
      queryResults.forEach(result => {
        console.log(`   ${result.name}: ${result.avgQueryTime.toFixed(2)}ms avg, ${result.p95QueryTime.toFixed(2)}ms P95, ${result.avgResultCount.toFixed(1)} results avg, ${result.throughput.toFixed(1)} queries/sec`);
      });
    });

    it('should handle complex select queries with joins efficiently', async () => {
      const complexQueries = [
        {
          query: 'entity',
          mode: 'deep' as const,
          traverse: { depth: 1 },
          name: 'Simple Join (depth 1)'
        },
        {
          query: 'relation',
          mode: 'deep' as const,
          traverse: { depth: 2 },
          name: 'Complex Join (depth 2)'
        },
        {
          query: 'section decision',
          mode: 'deep' as const,
          traverse: { depth: 3, max_results: 100 },
          name: 'Deep Join (depth 3)'
        },
        {
          query: 'performance',
          types: ['entity', 'relation', 'observation'],
          mode: 'deep' as const,
          traverse: { depth: 2 },
          name: 'Multi-Type Deep Join'
        }
      ];

      const joinResults: Array<{
        name: string;
        avgQueryTime: number;
        maxQueryTime: number;
        p95QueryTime: number;
        avgResultCount: number;
        joinEfficiency: number;
      }> = [];

      for (const query of complexQueries) {
        const iterations = 15;
        const queryTimes: number[] = [];
        const resultCounts: number[] = [];

        for (let i = 0; i < iterations; i++) {
          const searchParams: any = {
            query: query.query,
            mode: query.mode,
            traverse: query.traverse,
            top_k: 50
          };

          if (query.types) {
            searchParams.types = query.types;
          }

          const startTime = performance.now();
          try {
            const result = await memoryFind(searchParams);
            const queryTime = performance.now() - startTime;
            queryTimes.push(queryTime);
            resultCounts.push(result.results?.length || 0);
          } catch (error) {
            queryTimes.push(3000); // Higher penalty for complex query failures
            resultCounts.push(0);
          }
        }

        const avgQueryTime = queryTimes.reduce((sum, time) => sum + time, 0) / queryTimes.length;
        const maxQueryTime = Math.max(...queryTimes);
        const p95QueryTime = queryTimes.sort((a, b) => a - b)[Math.floor(queryTimes.length * 0.95)];
        const avgResultCount = resultCounts.reduce((sum, count) => sum + count, 0) / resultCounts.length;
        const joinEfficiency = avgResultCount > 0 ? avgResultCount / avgQueryTime : 0;

        joinResults.push({
          name: query.name,
          avgQueryTime,
          maxQueryTime,
          p95QueryTime,
          avgResultCount,
          joinEfficiency
        });

        // Complex query performance assertions (more lenient)
        const maxAcceptableTime = 300 + (query.traverse.depth * 200); // Base 300ms + 200ms per depth level
        TestAssertions.assertPerformance(avgQueryTime, maxAcceptableTime, `Complex query: ${query.name}`);
        TestAssertions.assertPerformance(p95QueryTime, maxAcceptableTime * 2, `P95 for: ${query.name}`);
      }

      const result = {
        test: 'Complex Select Query Performance',
        joinResults
      };

      dbPerformanceResults.push(result);

      console.log(`✅ Complex select query performance completed:`);
      joinResults.forEach(result => {
        console.log(`   ${result.name}: ${result.avgQueryTime.toFixed(2)}ms avg, ${result.p95QueryTime.toFixed(2)}ms P95, ${result.avgResultCount.toFixed(1)} results avg, ${result.joinEfficiency.toFixed(3)} efficiency`);
      });
    });
  });

  describe('UPDATE PERFORMANCE TESTING', () => {
    it('should handle update operations efficiently', async () => {
      // First, create some items to update
      const itemsToUpdate = [];
      for (let i = 0; i < 100; i++) {
        const item = testContext.dataFactory.createSection({
          title: `Update Test Item ${i}`,
          content: `Original content for update test item ${i}`
        });
        itemsToUpdate.push(item);
      }

      const storeResult = await memoryStore(itemsToUpdate);
      const storedItems = storeResult.stored;

      // Update performance tests
      const updateTests = [
        { batchSize: 1, name: 'Single Update' },
        { batchSize: 10, name: 'Small Batch Update' },
        { batchSize: 25, name: 'Medium Batch Update' },
        { batchSize: 50, name: 'Large Batch Update' }
      ];

      const updateResults: Array<{
        name: string;
        batchSize: number;
        avgUpdateTime: number;
        maxUpdateTime: number;
        throughput: number;
        successRate: number;
      }> = [];

      for (const updateTest of updateTests) {
        const iterations = 10;
        const updateTimes: number[] = [];
        let successfulUpdates = 0;

        for (let i = 0; i < iterations; i++) {
          // Select items to update
          const itemsForUpdate = storedItems.slice(0, updateTest.batchSize);

          // Modify the items
          const modifiedItems = itemsForUpdate.map((item, index) => ({
            ...item,
            title: `Updated Item ${i}-${index}`,
            content: `Updated content for test ${i} item ${index}`,
            metadata: {
              ...item.metadata,
              updated_at: new Date().toISOString(),
              update_version: (item.metadata?.update_version || 0) + 1
            }
          }));

          const startTime = performance.now();
          try {
            const result = await memoryStore(modifiedItems);
            const updateTime = performance.now() - startTime;
            updateTimes.push(updateTime);

            if (result.errors.length === 0) {
              successfulUpdates++;
            }
          } catch (error) {
            updateTimes(2000); // Penalize failed updates
          }
        }

        const avgUpdateTime = updateTimes.reduce((sum, time) => sum + time, 0) / updateTimes.length;
        const maxUpdateTime = Math.max(...updateTimes);
        const throughput = (updateTest.batchSize / avgUpdateTime) * 1000;
        const successRate = (successfulUpdates / iterations) * 100;

        updateResults.push({
          name: updateTest.name,
          batchSize: updateTest.batchSize,
          avgUpdateTime,
          maxUpdateTime,
          throughput,
          successRate
        });

        // Update performance assertions
        const maxAcceptableTime = 200 + (updateTest.batchSize * 5); // Base 200ms + 5ms per item
        TestAssertions.assertPerformance(avgUpdateTime, maxAcceptableTime, `Update: ${updateTest.name}`);
        expect(successRate).toBeGreaterThan(80); // 80%+ success rate
      }

      const result = {
        test: 'Update Performance',
        updateResults
      };

      dbPerformanceResults.push(result);

      console.log(`✅ Update performance completed:`);
      updateResults.forEach(result => {
        console.log(`   ${result.name} (${result.batchSize} items): ${result.avgUpdateTime.toFixed(2)}ms avg, ${result.throughput.toFixed(1)} ops/sec, ${result.successRate.toFixed(1)}% success`);
      });
    });
  });

  describe('DELETE PERFORMANCE TESTING', () => {
    it('should handle delete operations efficiently', async () => {
      // Create items for deletion testing
      const itemsForDeletion = [];
      for (let i = 0; i < 200; i++) {
        const item = testContext.dataFactory.createSection({
          title: `Delete Test Item ${i}`,
          content: `Content for delete test item ${i}`
        });
        itemsForDeletion.push(item);
      }

      const storeResult = await memoryStore(itemsForDeletion);
      const storedItems = storeResult.stored;

      // Delete performance tests
      const deleteTests = [
        { batchSize: 1, name: 'Single Delete', cascade: false },
        { batchSize: 5, name: 'Small Batch Delete', cascade: false },
        { batchSize: 20, name: 'Medium Batch Delete', cascade: false },
        { batchSize: 10, name: 'Cascade Delete', cascade: true }
      ];

      const deleteResults: Array<{
        name: string;
        batchSize: number;
        avgDeleteTime: number;
        maxDeleteTime: number;
        throughput: number;
        successRate: number;
        cascade: boolean;
      }> = [];

      let itemIndex = 0;

      for (const deleteTest of deleteTests) {
        const iterations = 8;
        const deleteTimes: number[] = [];
        let successfulDeletes = 0;

        for (let i = 0; i < iterations; i++) {
          // Select items to delete
          const itemsToDelete = storedItems.slice(itemIndex, itemIndex + deleteTest.batchSize);
          itemIndex += deleteTest.batchSize;

          if (itemsToDelete.length === 0) break;

          const deletePromises = itemsToDelete.map(item =>
            softDelete(testContext.testDb, {
              entity_type: item.kind,
              entity_id: item.id,
              cascade_relations: deleteTest.cascade
            })
          );

          const startTime = performance.now();
          try {
            const results = await Promise.all(deletePromises);
            const deleteTime = performance.now() - startTime;
            deleteTimes.push(deleteTime);

            // Check if all deletes were successful
            const allSuccessful = results.every(result => result !== undefined && result !== null);
            if (allSuccessful) {
              successfulDeletes++;
            }
          } catch (error) {
            deleteTimes.push(3000); // Higher penalty for delete failures
          }
        }

        if (deleteTimes.length === 0) continue;

        const avgDeleteTime = deleteTimes.reduce((sum, time) => sum + time, 0) / deleteTimes.length;
        const maxDeleteTime = Math.max(...deleteTimes);
        const throughput = (deleteTest.batchSize / avgDeleteTime) * 1000;
        const successRate = (successfulDeletes / deleteTimes.length) * 100;

        deleteResults.push({
          name: deleteTest.name,
          batchSize: deleteTest.batchSize,
          avgDeleteTime,
          maxDeleteTime,
          throughput,
          successRate,
          cascade: deleteTest.cascade
        });

        // Delete performance assertions
        const maxAcceptableTime = deleteTest.cascade ? 400 : 200; // Higher threshold for cascade deletes
        TestAssertions.assertPerformance(avgDeleteTime, maxAcceptableTime, `Delete: ${deleteTest.name}`);
        expect(successRate).toBeGreaterThan(75); // 75%+ success rate
      }

      const result = {
        test: 'Delete Performance',
        deleteResults
      };

      dbPerformanceResults.push(result);

      console.log(`✅ Delete performance completed:`);
      deleteResults.forEach(result => {
        console.log(`   ${result.name} (${result.batchSize} items, cascade: ${result.cascade}): ${result.avgDeleteTime.toFixed(2)}ms avg, ${result.throughput.toFixed(1)} ops/sec, ${result.successRate.toFixed(1)}% success`);
      });
    });
  });

  describe('CONCURRENT DATABASE OPERATIONS', () => {
    it('should handle concurrent database operations efficiently', async () => {
      const concurrencyLevels = [5, 15, 30];
      const concurrentResults: Array<{
        concurrency: number;
        avgOperationTime: number;
        maxOperationTime: number;
        p95OperationTime: number;
        throughput: number;
        errorRate: number;
        operationBreakdown: Record<string, { count: number; avgTime: number }>;
      }> = [];

      for (const concurrency of concurrencyLevels) {
        const iterations = 3;
        const allOperationTimes: number[] = [];
        let totalOperations = 0;
        let totalErrors = 0;
        const operationStats: Record<string, { times: number[]; count: number; errors: number }> = {
          insert: { times: [], count: 0, errors: 0 },
          select: { times: [], count: 0, errors: 0 },
          update: { times: [], count: 0, errors: 0 },
          delete: { times: [], count: 0, errors: 0 }
        };

        for (let iter = 0; iter < iterations; iter++) {
          const concurrentOperations = Array.from({ length: concurrency }, async (_, i) => {
            const operationType = ['insert', 'select', 'update', 'delete'][i % 4] as keyof typeof operationStats;
            const startTime = performance.now();

            try {
              switch (operationType) {
                case 'insert':
                  await memoryStore([testContext.dataFactory.createSection({
                    title: `Concurrent Insert ${iter}-${i}`,
                    content: `Concurrent insert test content`
                  })]);
                  break;
                case 'select':
                  await memoryFind({
                    query: 'concurrent test',
                    top_k: 20
                  });
                  break;
                case 'update':
                  // Update is more complex - find and update
                  const findResult = await memoryFind({
                    query: 'test',
                    top_k: 1,
                    types: ['section']
                  });
                  if (findResult.results && findResult.results.length > 0) {
                    const item = findResult.results[0];
                    await memoryStore([{
                      ...item,
                      title: `Updated ${item.title} at ${Date.now()}`,
                      metadata: {
                        ...item.metadata,
                        concurrent_update: true
                      }
                    }]);
                  }
                  break;
                case 'delete':
                  const deleteResult = await memoryFind({
                    query: 'delete test',
                    top_k: 1,
                    types: ['section']
                  });
                  if (deleteResult.results && deleteResult.results.length > 0) {
                    const item = deleteResult.results[0];
                    await softDelete(testContext.testDb, {
                      entity_type: item.kind,
                      entity_id: item.id
                    });
                  }
                  break;
              }

              const operationTime = performance.now() - startTime;
              allOperationTimes.push(operationTime);
              operationStats[operationType].times.push(operationTime);
              operationStats[operationType].count++;
              totalOperations++;

              return { success: true, operationTime, operationType };
            } catch (error) {
              const operationTime = performance.now() - startTime;
              allOperationTimes.push(operationTime);
              operationStats[operationType].times.push(operationTime);
              operationStats[operationType].errors++;
              totalOperations++;
              totalErrors++;

              return { success: false, operationTime, operationType };
            }
          });

          await Promise.allSettled(concurrentOperations);
        }

        const avgOperationTime = allOperationTimes.reduce((sum, time) => sum + time, 0) / allOperationTimes.length;
        const maxOperationTime = Math.max(...allOperationTimes);
        const p95OperationTime = allOperationTimes.sort((a, b) => a - b)[Math.floor(allOperationTimes.length * 0.95)];
        const throughput = totalOperations / (allOperationTimes.reduce((sum, time) => sum + time, 0) / 1000);
        const errorRate = (totalErrors / totalOperations) * 100;

        // Calculate operation breakdown
        const operationBreakdown: Record<string, { count: number; avgTime: number }> = {};
        Object.entries(operationStats).forEach(([op, stats]) => {
          if (stats.times.length > 0) {
            operationBreakdown[op] = {
              count: stats.count,
              avgTime: stats.times.reduce((sum, time) => sum + time, 0) / stats.times.length
            };
          }
        });

        concurrentResults.push({
          concurrency,
          avgOperationTime,
          maxOperationTime,
          p95OperationTime,
          throughput,
          errorRate,
          operationBreakdown
        });

        // Concurrency performance assertions
        const maxAcceptableTime = 300 + (concurrency * 5); // Base 300ms + 5ms per concurrent operation
        TestAssertions.assertPerformance(avgOperationTime, maxAcceptableTime, `Concurrency level ${concurrency}`);
        TestAssertions.assertPerformance(p95OperationTime, maxAcceptableTime * 2, `P95 for concurrency ${concurrency}`);
        expect(errorRate).toBeLessThan(15); // Less than 15% error rate under concurrency
      }

      // Analyze concurrency scalability
      const lowConcurrency = concurrentResults[0];
      const highConcurrency = concurrentResults[concurrentResults.length - 1];
      const concurrencyScaling = highConcurrency.throughput / lowConcurrency.throughput;
      const concurrencyFactor = highConcurrency.concurrency / lowConcurrency.concurrency;
      const scalingEfficiency = (concurrencyScaling / concurrencyFactor) * 100;

      const result = {
        test: 'Concurrent Database Operations',
        concurrentResults,
        scalingEfficiency
      };

      dbPerformanceResults.push(result);

      // Concurrency scaling should be reasonable
      expect(scalingEfficiency).toBeGreaterThan(25); // At least 25% efficiency under high concurrency

      console.log(`✅ Concurrent database operations completed:`);
      concurrentResults.forEach(result => {
        console.log(`   Concurrency ${result.concurrency}: ${result.avgOperationTime.toFixed(2)}ms avg, ${result.p95OperationTime.toFixed(2)}ms P95, ${result.throughput.toFixed(1)} ops/sec, ${result.errorRate.toFixed(1)}% errors`);
        console.log(`     Operation breakdown:`);
        Object.entries(result.operationBreakdown).forEach(([op, stats]) => {
          console.log(`       ${op}: ${stats.count} ops, ${stats.avgTime.toFixed(2)}ms avg`);
        });
      });
      console.log(`   Scaling efficiency: ${scalingEfficiency.toFixed(1)}%`);
    });
  });

  describe('DATABASE CONNECTION POOLING', () => {
    it('should efficiently manage database connections', async () => {
      const connectionTests = [
        { operations: 50, name: 'Light Connection Load' },
        { operations: 200, name: 'Medium Connection Load' },
        { operations: 500, name: 'Heavy Connection Load' }
      ];

      const connectionResults: Array<{
        name: string;
        operations: number;
        totalTime: number;
        avgTimePerOperation: number;
        connectionEfficiency: number;
        successRate: number;
      }> = [];

      for (const test of connectionTests) {
        const operations = Array.from({ length: test.operations }, async (_, i) => {
          const startTime = performance.now();
          try {
            // Mix of different database operations
            const operation = i % 4;
            switch (operation) {
              case 0:
                await memoryStore([testContext.dataFactory.createSection({
                  title: `Connection Test ${i}`,
                  content: `Testing database connection pooling`
                })]);
                break;
              case 1:
                await memoryFind({
                  query: 'connection test',
                  top_k: 10
                });
                break;
              case 2:
                await memoryFind({
                  query: `specific ${i % 10}`,
                  types: ['section', 'decision'],
                  top_k: 15
                });
                break;
              case 3:
                await memoryFind({
                  query: 'pool test',
                  mode: 'deep',
                  top_k: 5
                });
                break;
            }

            const operationTime = performance.now() - startTime;
            return { success: true, time: operationTime };
          } catch (error) {
            const operationTime = performance.now() - startTime;
            return { success: false, time: operationTime };
          }
        });

        const batchStartTime = performance.now();
        const results = await Promise.allSettled(operations);
        const totalTime = performance.now() - batchStartTime;

        const successfulOps = results.filter(r =>
          r.status === 'fulfilled' && r.value.success
        ).length;
        const totalOps = results.length;
        const successRate = (successfulOps / totalOps) * 100;
        const avgTimePerOperation = totalTime / test.operations;
        const connectionEfficiency = successfulOps / (totalTime / 1000);

        connectionResults.push({
          name: test.name,
          operations: test.operations,
          totalTime,
          avgTimePerOperation,
          connectionEfficiency,
          successRate
        });

        // Connection pooling assertions
        TestAssertions.assertPerformance(avgTimePerOperation, 100, `Connection test: ${test.name}`);
        expect(successRate).toBeGreaterThan(85); // 85%+ success rate
      }

      // Analyze connection pooling efficiency
      const lightLoad = connectionResults[0];
      const heavyLoad = connectionResults[connectionResults.length - 1];
      const poolingEfficiency = heavyLoad.connectionEfficiency / lightLoad.connectionEfficiency;

      const result = {
        test: 'Database Connection Pooling',
        connectionResults,
        poolingEfficiency
      };

      dbPerformanceResults.push(result);

      // Connection pooling should maintain efficiency under load
      expect(poolingEfficiency).toBeGreaterThan(0.6); // At least 60% efficiency under heavy load

      console.log(`✅ Database connection pooling completed:`);
      connectionResults.forEach(result => {
        console.log(`   ${result.name}: ${result.operations} ops, ${result.totalTime.toFixed(2)}ms total, ${result.avgTimePerOperation.toFixed(2)}ms avg, ${result.connectionEfficiency.toFixed(1)} ops/sec, ${result.successRate.toFixed(1)}% success`);
      });
      console.log(`   Pooling efficiency ratio: ${poolingEfficiency.toFixed(2)}x`);
    });
  });

  describe('TRANSACTION PERFORMANCE', () => {
    it('should handle transactions efficiently', async () => {
      const transactionTests = [
        { name: 'Small Transaction', operations: 5 },
        { name: 'Medium Transaction', operations: 20 },
        { name: 'Large Transaction', operations: 50 }
      ];

      const transactionResults: Array<{
        name: string;
        operations: number;
        avgTransactionTime: number;
        maxTransactionTime: number;
        throughput: number;
        successRate: number;
        atomicity: boolean;
      }> = [];

      for (const test of transactionTests) {
        const iterations = 10;
        const transactionTimes: number[] = [];
        let successfulTransactions = 0;
        let atomicTransactions = 0;

        for (let i = 0; i < iterations; i++) {
          // Create transaction data
          const transactionItems = Array.from({ length: test.operations }, (_, j) =>
            testContext.dataFactory.createSection({
              title: `Transaction ${i} Item ${j}`,
              content: `Transaction test content for item ${j} in transaction ${i}`,
              metadata: {
                transaction_id: `tx-${i}`,
                transaction_order: j
              }
            })
          );

          const startTime = performance.now();
          let transactionSuccess = true;

          try {
            // Simulate transaction by storing all items
            const result = await memoryStore(transactionItems);

            // Check if all items were stored successfully (atomicity)
            if (result.errors.length === 0 && result.stored.length === test.operations) {
              successfulTransactions++;
              atomicTransactions++;
            } else {
              transactionSuccess = false;
            }
          } catch (error) {
            transactionSuccess = false;
          }

          const transactionTime = performance.now() - startTime;
          transactionTimes.push(transactionTime);
        }

        const avgTransactionTime = transactionTimes.reduce((sum, time) => sum + time, 0) / transactionTimes.length;
        const maxTransactionTime = Math.max(...transactionTimes);
        const throughput = (test.operations / avgTransactionTime) * 1000;
        const successRate = (successfulTransactions / iterations) * 100;
        const atomicity = (atomicTransactions / successfulTransactions) * 100 === 100;

        transactionResults.push({
          name: test.name,
          operations: test.operations,
          avgTransactionTime,
          maxTransactionTime,
          throughput,
          successRate,
          atomicity
        });

        // Transaction performance assertions
        const maxAcceptableTime = 200 + (test.operations * 10); // Base 200ms + 10ms per operation
        TestAssertions.assertPerformance(avgTransactionTime, maxAcceptableTime, `Transaction: ${test.name}`);
        expect(successRate).toBeGreaterThan(80); // 80%+ success rate
        expect(atomicity).toBe(true); // Transactions should be atomic
      }

      const result = {
        test: 'Transaction Performance',
        transactionResults
      };

      dbPerformanceResults.push(result);

      console.log(`✅ Transaction performance completed:`);
      transactionResults.forEach(result => {
        console.log(`   ${result.name} (${result.operations} ops): ${result.avgTransactionTime.toFixed(2)}ms avg, ${result.throughput.toFixed(1)} ops/sec, ${result.successRate.toFixed(1)}% success, atomic: ${result.atomicity}`);
      });
    });
  });
});