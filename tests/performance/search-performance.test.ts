/**
 * SEARCH PERFORMANCE BENCHMARKS
 *
 * Comprehensive search performance testing for memory find operations,
 * including query optimization, indexing efficiency, and search scalability.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { TestRunner, TestAssertions } from '../framework/test-setup.js';
import { memoryStore } from '../../src/services/memory-store.js';
import { memoryFind } from '../../src/services/memory-find.js';
import type { TestContext } from '../framework/test-setup.js';

describe('SEARCH PERFORMANCE BENCHMARKS', () => {
  let testRunner: TestRunner;
  let testContext: TestContext;
  let searchTestResults: any[] = [];

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

    // Setup test data for search operations
    await setupSearchTestData();
  });

  afterEach(async () => {
    await testRunner.cleanup();

    // Print search test summary
    if (searchTestResults.length > 0) {
      console.log('\n📊 Search Performance Results Summary:');
      console.log('='.repeat(80));
      searchTestResults.forEach(result => {
        console.log(`${result.test.padEnd(50)} | ${result.avgLatency.toFixed(2)}ms | ${result.throughput.toFixed(0)} ops/sec`);
      });
      console.log('='.repeat(80));
    }
  });

  /**
   * Setup comprehensive test data for search operations
   */
  async function setupSearchTestData(): Promise<void> {
    console.log('   Setting up search test data...');

    const testDataBatches = [
      { count: 200, types: ['section'], prefix: 'api' },
      { count: 150, types: ['decision'], prefix: 'auth' },
      { count: 180, types: ['issue'], prefix: 'performance' },
      { count: 120, types: ['entity'], prefix: 'database' },
      { count: 100, types: ['relation'], prefix: 'security' },
      { count: 80, types: ['observation'], prefix: 'frontend' },
      { count: 90, types: ['runbook'], prefix: 'backend' },
      { count: 70, types: ['change'], prefix: 'deployment' }
    ];

    for (const batch of testDataBatches) {
      const items = [];
      for (let i = 0; i < batch.count; i++) {
        const kind = batch.types[i % batch.types.length];
        let item: any;

        switch (kind) {
          case 'section':
            item = testContext.dataFactory.createSection({
              title: `${batch.prefix} section ${i}: comprehensive testing guide`,
              content: `This section covers ${batch.prefix} testing methodologies and performance optimization techniques.`
            });
            break;
          case 'decision':
            item = testContext.dataFactory.createDecision({
              title: `${batch.prefix} decision ${i}: architectural choice`,
              rationale: `Decision to implement ${batch.prefix} using specific patterns for optimal performance.`
            });
            break;
          case 'issue':
            item = testContext.dataFactory.createIssue({
              title: `${batch.prefix} issue ${i}: performance bottleneck`,
              description: `Issue identified in ${batch.prefix} layer requiring immediate attention and optimization.`
            });
            break;
          case 'entity':
            item = testContext.dataFactory.createEntity({
              name: `${batch.prefix} entity ${i}`,
              description: `Core entity representing ${batch.prefix} component in the system architecture.`
            });
            break;
          case 'relation':
            item = testContext.dataFactory.createRelation({
              from_type: 'entity',
              from_id: `entity-${i}`,
              to_type: 'entity',
              to_id: `entity-${i + 1}`,
              relation_type: 'depends_on'
            });
            break;
          case 'observation':
            item = testContext.dataFactory.createObservation({
              content: `Observation about ${batch.prefix} behavior and performance characteristics under various conditions.`
            });
            break;
          case 'runbook':
            item = testContext.dataFactory.createRunbook({
              title: `${batch.prefix} runbook ${i}`,
              procedure: `Step-by-step procedure for handling ${batch.prefix} operations and troubleshooting.`
            });
            break;
          case 'change':
            item = testContext.dataFactory.createChange({
              description: `Change affecting ${batch.prefix} subsystem with performance improvements and bug fixes.`
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

    console.log('   ✅ Search test data setup completed');
  }

  describe('BASIC SEARCH PERFORMANCE', () => {
    it('should perform simple text searches efficiently', async () => {
      const searchQueries = [
        'api',
        'authentication',
        'performance',
        'database',
        'security',
        'testing'
      ];

      const results: Array<{
        query: string;
        latency: number;
        resultCount: number;
        success: boolean;
      }> = [];

      for (const query of searchQueries) {
        const iterations = 20;
        const latencies: number[] = [];

        for (let i = 0; i < iterations; i++) {
          const startTime = performance.now();
          try {
            const searchResult = await memoryFind({
              query,
              top_k: 20
            });
            const latency = performance.now() - startTime;
            latencies.push(latency);
            results.push({
              query,
              latency,
              resultCount: searchResult.results?.length || 0,
              success: true
            });
          } catch (error) {
            const latency = performance.now() - startTime;
            results.push({
              query,
              latency,
              resultCount: 0,
              success: false
            });
          }
        }

        const avgLatency = latencies.reduce((sum, lat) => sum + lat, 0) / latencies.length;
        const maxLatency = Math.max(...latencies);
        const p95Latency = latencies.sort((a, b) => a - b)[Math.floor(latencies.length * 0.95)];

        // Performance assertions for this query
        TestAssertions.assertPerformance(avgLatency, 200, `Average search latency for query "${query}"`);
        TestAssertions.assertPerformance(maxLatency, 500, `Max search latency for query "${query}"`);
        TestAssertions.assertPerformance(p95Latency, 300, `95th percentile latency for query "${query}"`);

        console.log(`   Query "${query}": ${avgLatency.toFixed(2)}ms avg, ${maxLatency.toFixed(2)}ms max, ${p95Latency.toFixed(2)}ms P95`);
      }

      const overallStats = {
        totalQueries: results.length,
        successfulQueries: results.filter(r => r.success).length,
        avgLatency: results.reduce((sum, r) => sum + r.latency, 0) / results.length,
        avgResultCount: results.reduce((sum, r) => sum + r.resultCount, 0) / results.length,
        throughput: results.length / (results.reduce((sum, r) => sum + r.latency, 0) / 1000)
      };

      searchTestResults.push({
        test: 'Basic Text Search Performance',
        ...overallStats
      });

      // Overall performance assertions
      expect(overallStats.successfulQueries).toBeGreaterThan(overallStats.totalQueries * 0.95); // 95% success rate
      expect(overallStats.avgLatency).toBeLessThan(200); // Under 200ms average
      expect(overallStats.throughput).toBeGreaterThan(5); // 5+ queries per second

      console.log(`✅ Basic search performance completed:`);
      console.log(`   Total queries: ${overallStats.totalQueries}`);
      console.log(`   Success rate: ${(overallStats.successfulQueries / overallStats.totalQueries * 100).toFixed(1)}%`);
      console.log(`   Average latency: ${overallStats.avgLatency.toFixed(2)}ms`);
      console.log(`   Average result count: ${overallStats.avgResultCount.toFixed(1)}`);
      console.log(`   Throughput: ${overallStats.throughput.toFixed(1)} queries/sec`);
    });

    it('should handle type-filtered searches efficiently', async () => {
      const typeFilters = [
        { types: ['section'], name: 'Sections Only' },
        { types: ['decision'], name: 'Decisions Only' },
        { types: ['issue'], name: 'Issues Only' },
        { types: ['section', 'decision'], name: 'Sections + Decisions' },
        { types: ['entity', 'relation'], name: 'Entities + Relations' },
        { types: ['section', 'decision', 'issue'], name: 'Sections + Decisions + Issues' }
      ];

      const filterResults: Array<{
        filterName: string;
        types: string[];
        avgLatency: number;
        maxLatency: number;
        avgResultCount: number;
        throughput: number;
      }> = [];

      for (const filter of typeFilters) {
        const iterations = 15;
        const latencies: number[] = [];
        const resultCounts: number[] = [];

        for (let i = 0; i < iterations; i++) {
          const startTime = performance.now();
          try {
            const searchResult = await memoryFind({
              query: 'test',
              types: filter.types,
              top_k: 25
            });
            const latency = performance.now() - startTime;
            latencies.push(latency);
            resultCounts.push(searchResult.results?.length || 0);
          } catch (error) {
            latencies.push(1000); // Penalize failed searches
            resultCounts.push(0);
          }
        }

        const avgLatency = latencies.reduce((sum, lat) => sum + lat, 0) / latencies.length;
        const maxLatency = Math.max(...latencies);
        const avgResultCount = resultCounts.reduce((sum, count) => sum + count, 0) / resultCounts.length;
        const throughput = iterations / (latencies.reduce((sum, lat) => sum + lat, 0) / 1000);

        filterResults.push({
          filterName: filter.name,
          types: filter.types,
          avgLatency,
          maxLatency,
          avgResultCount,
          throughput
        });

        // Type-filtered search should be efficient
        TestAssertions.assertPerformance(avgLatency, 250, `Type-filtered search: ${filter.name}`);
        TestAssertions.assertPerformance(maxLatency, 600, `Max latency for: ${filter.name}`);
      }

      searchTestResults.push({
        test: 'Type-Filtered Search Performance',
        filterResults,
        overallAvgLatency: filterResults.reduce((sum, r) => sum + r.avgLatency, 0) / filterResults.length
      });

      console.log(`✅ Type-filtered search performance completed:`);
      filterResults.forEach(result => {
        console.log(`   ${result.filterName}: ${result.avgLatency.toFixed(2)}ms avg, ${result.avgResultCount.toFixed(1)} results avg, ${result.throughput.toFixed(1)} ops/sec`);
      });
    });
  });

  describe('COMPLEX SEARCH PERFORMANCE', () => {
    it('should handle deep search with traversal efficiently', async () => {
      const complexQueries = [
        {
          query: 'api architecture',
          mode: 'deep' as const,
          traverse: { depth: 1 },
          name: 'Deep Search - Depth 1'
        },
        {
          query: 'authentication performance',
          mode: 'deep' as const,
          traverse: { depth: 2 },
          name: 'Deep Search - Depth 2'
        },
        {
          query: 'database security',
          mode: 'deep' as const,
          traverse: { depth: 3 },
          name: 'Deep Search - Depth 3'
        },
        {
          query: 'testing deployment',
          mode: 'deep' as const,
          traverse: { depth: 2, max_results: 50 },
          name: 'Deep Search - Limited Results'
        }
      ];

      const deepSearchResults: Array<{
        name: string;
        query: string;
        avgLatency: number;
        maxLatency: number;
        p95Latency: number;
        avgResultCount: number;
        throughput: number;
        traversalDepth: number;
      }> = [];

      for (const queryConfig of complexQueries) {
        const iterations = 10;
        const latencies: number[] = [];
        const resultCounts: number[] = [];

        for (let i = 0; i < iterations; i++) {
          const startTime = performance.now();
          try {
            const searchResult = await memoryFind({
              query: queryConfig.query,
              mode: queryConfig.mode,
              traverse: queryConfig.traverse,
              top_k: 30
            });
            const latency = performance.now() - startTime;
            latencies.push(latency);
            resultCounts.push(searchResult.results?.length || 0);
          } catch (error) {
            latencies.push(2000); // Penalize failed searches more heavily
            resultCounts.push(0);
          }
        }

        const avgLatency = latencies.reduce((sum, lat) => sum + lat, 0) / latencies.length;
        const maxLatency = Math.max(...latencies);
        const p95Latency = latencies.sort((a, b) => a - b)[Math.floor(latencies.length * 0.95)];
        const avgResultCount = resultCounts.reduce((sum, count) => sum + count, 0) / resultCounts.length;
        const throughput = iterations / (latencies.reduce((sum, lat) => sum + lat, 0) / 1000);

        deepSearchResults.push({
          name: queryConfig.name,
          query: queryConfig.query,
          avgLatency,
          maxLatency,
          p95Latency,
          avgResultCount,
          throughput,
          traversalDepth: queryConfig.traverse.depth
        });

        // Deep search performance assertions (more lenient due to complexity)
        const maxAcceptableLatency = 500 + (queryConfig.traverse.depth * 200); // Base 500ms + 200ms per depth level
        TestAssertions.assertPerformance(avgLatency, maxAcceptableLatency, `Deep search: ${queryConfig.name}`);
        TestAssertions.assertPerformance(maxLatency, maxAcceptableLatency * 2, `Max latency for: ${queryConfig.name}`);
      }

      searchTestResults.push({
        test: 'Deep Search Performance',
        deepSearchResults,
        overallAvgLatency: deepSearchResults.reduce((sum, r) => sum + r.avgLatency, 0) / deepSearchResults.length
      });

      console.log(`✅ Deep search performance completed:`);
      deepSearchResults.forEach(result => {
        console.log(`   ${result.name}: ${result.avgLatency.toFixed(2)}ms avg, ${result.maxLatency.toFixed(2)}ms max, ${result.p95Latency.toFixed(2)}ms P95, ${result.avgResultCount.toFixed(1)} results avg`);
      });
    });

    it('should handle fuzzy search and auto-correction efficiently', async () => {
      const fuzzyQueries = [
        { query: 'authntication', expected: 'authentication', name: 'Typo Correction' },
        { query: 'perfrmance', expected: 'performance', name: 'Performance Typo' },
        { query: 'data_base', expected: 'database', name: 'Underscore Separation' },
        { query: 'secrity', expected: 'security', name: 'Missing Letter' },
        { query: 'apinterface', expected: 'api interface', name: 'Concatenated Words' }
      ];

      const fuzzySearchResults: Array<{
        name: string;
        originalQuery: string;
        avgLatency: number;
        maxLatency: number;
        successRate: number;
        correctionDetected: boolean;
      }> = [];

      for (const queryConfig of fuzzyQueries) {
        const iterations = 12;
        const latencies: number[] = [];
        let successCount = 0;
        let correctionsDetected = 0;

        for (let i = 0; i < iterations; i++) {
          const startTime = performance.now();
          try {
            const searchResult = await memoryFind({
              query: queryConfig.query,
              enableAutoFix: true,
              enableSuggestions: true,
              top_k: 15
            });
            const latency = performance.now() - startTime;
            latencies.push(latency);

            if (searchResult.results && searchResult.results.length > 0) {
              successCount++;
              // Check if correction was applied (simple heuristic)
              if (searchResult.metadata?.autocorrected ||
                  searchResult.query !== queryConfig.query) {
                correctionsDetected++;
              }
            }
          } catch (error) {
            latencies.push(1000);
          }
        }

        const avgLatency = latencies.reduce((sum, lat) => sum + lat, 0) / latencies.length;
        const maxLatency = Math.max(...latencies);
        const successRate = (successCount / iterations) * 100;
        const correctionDetected = correctionsDetected > 0;

        fuzzySearchResults.push({
          name: queryConfig.name,
          originalQuery: queryConfig.query,
          avgLatency,
          maxLatency,
          successRate,
          correctionDetected
        });

        // Fuzzy search should still be reasonably fast
        TestAssertions.assertPerformance(avgLatency, 400, `Fuzzy search: ${queryConfig.name}`);
        expect(successRate).toBeGreaterThan(50); // At least 50% success rate even with typos
      }

      searchTestResults.push({
        test: 'Fuzzy Search Performance',
        fuzzySearchResults,
        overallAvgLatency: fuzzySearchResults.reduce((sum, r) => sum + r.avgLatency, 0) / fuzzySearchResults.length
      });

      console.log(`✅ Fuzzy search performance completed:`);
      fuzzySearchResults.forEach(result => {
        console.log(`   ${result.name} ("${result.originalQuery}"): ${result.avgLatency.toFixed(2)}ms avg, ${result.successRate.toFixed(1)}% success, correction: ${result.correctionDetected ? 'YES' : 'NO'}`);
      });
    });
  });

  describe('SEARCH SCALABILITY TESTING', () => {
    it('should maintain performance with increasing result set sizes', async () => {
      const resultSizeTests = [
        { top_k: 10, name: 'Small Results' },
        { top_k: 25, name: 'Medium Results' },
        { top_k: 50, name: 'Large Results' },
        { top_k: 100, name: 'Very Large Results' },
        { top_k: 200, name: 'Extra Large Results' }
      ];

      const scalabilityResults: Array<{
        name: string;
        topK: number;
        avgLatency: number;
        maxLatency: number;
        avgResultCount: number;
        latencyPerResult: number;
        throughput: number;
      }> = [];

      for (const sizeTest of resultSizeTests) {
        const iterations = 8;
        const latencies: number[] = [];
        const resultCounts: number[] = [];

        for (let i = 0; i < iterations; i++) {
          const startTime = performance.now();
          try {
            const searchResult = await memoryFind({
              query: 'test',
              top_k: sizeTest.top_k
            });
            const latency = performance.now() - startTime;
            latencies.push(latency);
            resultCounts.push(searchResult.results?.length || 0);
          } catch (error) {
            latencies.push(1500);
            resultCounts.push(0);
          }
        }

        const avgLatency = latencies.reduce((sum, lat) => sum + lat, 0) / latencies.length;
        const maxLatency = Math.max(...latencies);
        const avgResultCount = resultCounts.reduce((sum, count) => sum + count, 0) / resultCounts.length;
        const latencyPerResult = avgResultCount > 0 ? avgLatency / avgResultCount : 0;
        const throughput = iterations / (latencies.reduce((sum, lat) => sum + lat, 0) / 1000);

        scalabilityResults.push({
          name: sizeTest.name,
          topK: sizeTest.top_k,
          avgLatency,
          maxLatency,
          avgResultCount,
          latencyPerResult,
          throughput
        });

        // Scalability assertions - latency should grow sub-linearly with result size
        const maxAcceptableLatency = 150 + (sizeTest.top_k * 0.5); // Base 150ms + 0.5ms per result
        TestAssertions.assertPerformance(avgLatency, maxAcceptableLatency, `Search scalability: ${sizeTest.name}`);
        TestAssertions.assertPerformance(latencyPerResult, 5, `Latency per result for: ${sizeTest.name}`); // 5ms per result max
      }

      // Check for linear vs sub-linear scaling
      const smallResultLatency = scalabilityResults.find(r => r.name === 'Small Results')?.avgLatency || 0;
      const largeResultLatency = scalabilityResults.find(r => r.name === 'Very Large Results')?.avgLatency || 0;
      const latencyGrowthRatio = largeResultLatency / smallResultLatency;
      const resultGrowthRatio = 100 / 10; // 10x growth in result size

      searchTestResults.push({
        test: 'Search Scalability Performance',
        scalabilityResults,
        latencyGrowthRatio,
        resultGrowthRatio,
        scalingEfficiency: (resultGrowthRatio / latencyGrowthRatio) * 100
      });

      // Performance should scale better than linear
      expect(latencyGrowthRatio).toBeLessThan(resultGrowthRatio * 0.8); // Less than 80% of linear growth

      console.log(`✅ Search scalability performance completed:`);
      scalabilityResults.forEach(result => {
        console.log(`   ${result.name} (${result.topK} max): ${result.avgLatency.toFixed(2)}ms avg, ${result.latencyPerResult.toFixed(2)}ms per result, ${result.throughput.toFixed(1)} ops/sec`);
      });
      console.log(`   Latency growth ratio: ${latencyGrowthRatio.toFixed(2)}x vs ${resultGrowthRatio}x result growth`);
      console.log(`   Scaling efficiency: ${((resultGrowthRatio / latencyGrowthRatio) * 100).toFixed(1)}%`);
    });

    it('should handle concurrent search operations efficiently', async () => {
      const concurrencyLevels = [
        { concurrency: 5, name: 'Low Concurrency' },
        { concurrency: 15, name: 'Medium Concurrency' },
        { concurrency: 30, name: 'High Concurrency' },
        { concurrency: 50, name: 'Very High Concurrency' }
      ];

      const concurrencyResults: Array<{
        name: string;
        concurrency: number;
        avgLatency: number;
        maxLatency: number;
        p95Latency: number;
        throughput: number;
        successRate: number;
      }> = [];

      for (const concurrencyTest of concurrencyLevels) {
        const iterations = 3;
        const allLatencies: number[] = [];
        let totalOperations = 0;
        let successfulOperations = 0;

        for (let iter = 0; iter < iterations; iter++) {
          const concurrentOperations = Array.from({ length: concurrencyTest.concurrency }, async (_, i) => {
            const queries = [
              { query: 'api testing', types: ['section'] },
              { query: 'auth decisions', types: ['decision'] },
              { query: 'performance issues', types: ['issue'] },
              { query: 'database entities', types: ['entity'] },
              { query: 'security observations', types: ['observation'] }
            ];

            const query = queries[i % queries.length];
            const startTime = performance.now();
            try {
              const result = await memoryFind({
                ...query,
                top_k: 20
              });
              const latency = performance.now() - startTime;
              allLatencies.push(latency);
              successfulOperations++;
              return { success: true, latency, resultCount: result.results?.length || 0 };
            } catch (error) {
              const latency = performance.now() - startTime;
              allLatencies.push(latency);
              return { success: false, latency, resultCount: 0 };
            }
          });

          const batchResults = await Promise.allSettled(concurrentOperations);
          totalOperations += batchResults.length;
        }

        const avgLatency = allLatencies.reduce((sum, lat) => sum + lat, 0) / allLatencies.length;
        const maxLatency = Math.max(...allLatencies);
        const p95Latency = allLatencies.sort((a, b) => a - b)[Math.floor(allLatencies.length * 0.95)];
        const successRate = (successfulOperations / totalOperations) * 100;
        const totalBatchTime = allLatencies.reduce((sum, lat) => sum + lat, 0);
        const throughput = successfulOperations / (totalBatchTime / 1000);

        concurrencyResults.push({
          name: concurrencyTest.name,
          concurrency: concurrencyTest.concurrency,
          avgLatency,
          maxLatency,
          p95Latency,
          throughput,
          successRate
        });

        // Concurrency performance assertions
        const maxAcceptableLatency = 200 + (concurrencyTest.concurrency * 2); // Base 200ms + 2ms per concurrent operation
        TestAssertions.assertPerformance(avgLatency, maxAcceptableLatency, `Concurrent search: ${concurrencyTest.name}`);
        TestAssertions.assertPerformance(p95Latency, maxAcceptableLatency * 1.5, `P95 latency for: ${concurrencyTest.name}`);
        expect(successRate).toBeGreaterThan(80); // 80%+ success rate under concurrency
      }

      // Check concurrency scalability
      const lowConcurrencyThroughput = concurrencyResults.find(r => r.name === 'Low Concurrency')?.throughput || 0;
      const highConcurrencyThroughput = concurrencyResults.find(r => r.name === 'Very High Concurrency')?.throughput || 0;
      const concurrencyScaling = highConcurrencyThroughput / lowConcurrencyThroughput;

      searchTestResults.push({
        test: 'Concurrent Search Performance',
        concurrencyResults,
        concurrencyScaling
      });

      // Concurrency should provide reasonable scaling
      expect(concurrencyScaling).toBeGreaterThan(0.5); // At least 50% efficiency scaling

      console.log(`✅ Concurrent search performance completed:`);
      concurrencyResults.forEach(result => {
        console.log(`   ${result.name} (${result.concurrency} concurrent): ${result.avgLatency.toFixed(2)}ms avg, ${result.p95Latency.toFixed(2)}ms P95, ${result.throughput.toFixed(1)} ops/sec, ${result.successRate.toFixed(1)}% success`);
      });
      console.log(`   Concurrency scaling factor: ${concurrencyScaling.toFixed(2)}x`);
    });
  });

  describe('SEARCH QUERY OPTIMIZATION', () => {
    it('should demonstrate query optimization benefits', async () => {
      const optimizationTests = [
        {
          name: 'Unoptimized Query',
          query: 'api authentication performance testing database security',
          useOptimization: false,
          top_k: 50
        },
        {
          name: 'Optimized Query - Specific Terms',
          query: 'api authentication',
          useOptimization: true,
          top_k: 20
        },
        {
          name: 'Optimized Query - Type Filtered',
          query: 'authentication',
          useOptimization: true,
          types: ['decision'],
          top_k: 15
        },
        {
          name: 'Optimized Query - Limited Scope',
          query: 'security',
          useOptimization: true,
          scope: { project: 'optimization-test' },
          top_k: 10
        }
      ];

      const optimizationResults: Array<{
        name: string;
        avgLatency: number;
        maxLatency: number;
        avgResultCount: number;
        relevanceScore: number;
        efficiency: number;
      }> = [];

      for (const test of optimizationTests) {
        const iterations = 10;
        const latencies: number[] = [];
        const resultCounts: number[] = [];

        for (let i = 0; i < iterations; i++) {
          const startTime = performance.now();
          try {
            const searchParams: any = {
              query: test.query,
              top_k: test.top_k
            };

            if (test.types) searchParams.types = test.types;
            if (test.scope) searchParams.scope = test.scope;

            const searchResult = await memoryFind(searchParams);
            const latency = performance.now() - startTime;
            latencies.push(latency);
            resultCounts.push(searchResult.results?.length || 0);
          } catch (error) {
            latencies.push(2000);
            resultCounts.push(0);
          }
        }

        const avgLatency = latencies.reduce((sum, lat) => sum + lat, 0) / latencies.length;
        const maxLatency = Math.max(...latencies);
        const avgResultCount = resultCounts.reduce((sum, count) => sum + count, 0) / resultCounts.length;

        // Calculate efficiency (results per millisecond)
        const efficiency = avgResultCount > 0 ? avgResultCount / avgLatency : 0;

        // Relevance score (higher for more specific, targeted queries)
        const relevanceScore = test.useOptimization ?
          (test.types ? 0.9 : 0.7) * (test.scope ? 1.1 : 1.0) : 0.5;

        optimizationResults.push({
          name: test.name,
          avgLatency,
          maxLatency,
          avgResultCount,
          relevanceScore,
          efficiency
        });

        // Optimization should improve performance
        const maxAcceptableLatency = test.useOptimization ? 300 : 600;
        TestAssertions.assertPerformance(avgLatency, maxAcceptableLatency, `Query optimization: ${test.name}`);
      }

      // Compare optimized vs unoptimized performance
      const unoptimized = optimizationResults.find(r => r.name === 'Unoptimized Query');
      const optimized = optimizationResults.filter(r => r.name.includes('Optimized'));
      const avgOptimizedLatency = optimized.reduce((sum, r) => sum + r.avgLatency, 0) / optimized.length;
      const optimizationImprovement = unoptimized ? ((unoptimized.avgLatency - avgOptimizedLatency) / unoptimized.avgLatency) * 100 : 0;

      searchTestResults.push({
        test: 'Search Query Optimization',
        optimizationResults,
        optimizationImprovement
      });

      // Optimization should provide meaningful improvement
      if (unoptimized) {
        expect(optimizationImprovement).toBeGreaterThan(20); // At least 20% improvement
      }

      console.log(`✅ Search query optimization completed:`);
      optimizationResults.forEach(result => {
        console.log(`   ${result.name}: ${result.avgLatency.toFixed(2)}ms avg, ${result.avgResultCount.toFixed(1)} results avg, ${result.efficiency.toFixed(3)} results/ms, relevance: ${result.relevanceScore.toFixed(2)}`);
      });
      if (unoptimized) {
        console.log(`   Optimization improvement: ${optimizationImprovement.toFixed(1)}%`);
      }
    });
  });

  describe('INDEXING EFFICIENCY TESTING', () => {
    it('should demonstrate effective indexing for different query patterns', async () => {
      const indexingTests = [
        {
          name: 'Title-based Search',
          query: 'architecture decision',
          searchField: 'title',
          expectedSpeed: 'fast'
        },
        {
          name: 'Content-based Search',
          query: 'implementation details',
          searchField: 'content',
          expectedSpeed: 'medium'
        },
        {
          name: 'Metadata-based Search',
          query: 'priority high',
          searchField: 'metadata',
          expectedSpeed: 'fast'
        },
        {
          name: 'Type-specific Search',
          query: 'entity relationship',
          searchField: 'type',
          expectedSpeed: 'very_fast'
        },
        {
          name: 'Cross-field Search',
          query: 'security authentication',
          searchField: 'cross_field',
          expectedSpeed: 'medium'
        }
      ];

      const indexingResults: Array<{
        name: string;
        searchField: string;
        avgLatency: number;
        maxLatency: number;
        avgResultCount: number;
        latencyVariance: number;
        efficiency: number;
      }> = [];

      for (const test of indexingTests) {
        const iterations = 15;
        const latencies: number[] = [];
        const resultCounts: number[] = [];

        for (let i = 0; i < iterations; i++) {
          const startTime = performance.now();
          try {
            // Simulate different search patterns based on field
            let searchParams: any = { query: test.query, top_k: 25 };

            switch (test.searchField) {
              case 'title':
                searchParams = { ...searchParams, types: ['section', 'decision'] };
                break;
              case 'content':
                searchParams = { ...searchParams, mode: 'deep' };
                break;
              case 'metadata':
                searchParams = { ...searchParams, types: ['issue', 'decision'] };
                break;
              case 'type':
                searchParams = { ...searchParams, types: ['entity'] };
                break;
              case 'cross_field':
                searchParams = { ...searchParams, types: ['section', 'decision', 'issue'], mode: 'auto' };
                break;
            }

            const searchResult = await memoryFind(searchParams);
            const latency = performance.now() - startTime;
            latencies.push(latency);
            resultCounts.push(searchResult.results?.length || 0);
          } catch (error) {
            latencies.push(1500);
            resultCounts.push(0);
          }
        }

        const avgLatency = latencies.reduce((sum, lat) => sum + lat, 0) / latencies.length;
        const maxLatency = Math.max(...latencies);
        const avgResultCount = resultCounts.reduce((sum, count) => sum + count, 0) / resultCounts.length;

        // Calculate variance to measure consistency
        const variance = latencies.reduce((sum, lat) => sum + Math.pow(lat - avgLatency, 2), 0) / latencies.length;
        const latencyVariance = Math.sqrt(variance);

        const efficiency = avgResultCount > 0 ? avgResultCount / avgLatency : 0;

        indexingResults.push({
          name: test.name,
          searchField: test.searchField,
          avgLatency,
          maxLatency,
          avgResultCount,
          latencyVariance,
          efficiency
        });

        // Set performance expectations based on expected speed
        let maxAcceptableLatency: number;
        switch (test.expectedSpeed) {
          case 'very_fast':
            maxAcceptableLatency = 100;
            break;
          case 'fast':
            maxAcceptableLatency = 200;
            break;
          case 'medium':
            maxAcceptableLatency = 350;
            break;
          default:
            maxAcceptableLatency = 500;
        }

        TestAssertions.assertPerformance(avgLatency, maxAcceptableLatency, `Indexing efficiency: ${test.name}`);
        TestAssertions.assertPerformance(latencyVariance, avgLatency * 0.5, `Latency variance for: ${test.name}`); // Variance should be < 50% of average
      }

      // Analyze indexing efficiency across different patterns
      const fastestField = indexingResults.reduce((min, r) => r.avgLatency < min.avgLatency ? r : min);
      const slowestField = indexingResults.reduce((max, r) => r.avgLatency > max.avgLatency ? r : max);
      const efficiencyRange = slowestField.avgLatency / fastestField.avgLatency;

      searchTestResults.push({
        test: 'Indexing Efficiency Performance',
        indexingResults,
        fastestField: fastestField.name,
        slowestField: slowestField.name,
        efficiencyRange
      });

      // Indexing should provide reasonable efficiency range
      expect(efficiencyRange).toBeLessThan(5); // Fastest should be less than 5x faster than slowest

      console.log(`✅ Indexing efficiency performance completed:`);
      indexingResults.forEach(result => {
        console.log(`   ${result.name} (${result.searchField}): ${result.avgLatency.toFixed(2)}ms avg ±${result.latencyVariance.toFixed(2)}ms variance, ${result.avgResultCount.toFixed(1)} results avg, ${result.efficiency.toFixed(3)} efficiency`);
      });
      console.log(`   Efficiency range: ${efficiencyRange.toFixed(2)}x (${fastestField.name} fastest, ${slowestField.name} slowest)`);
    });
  });
});