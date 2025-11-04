/**
 * Performance Smoke Tests - N=100 Items, <1s Target
 *
 * Lightweight performance tests that verify the system can handle typical workloads
 * within acceptable time limits. These tests focus on core operations with realistic
 * data sizes and patterns.
 */

import { describe, it, expect, beforeEach, afterEach, beforeAll, afterAll } from 'vitest';
import { DatabaseManager } from '../../src/db/database-manager.js';
import { ChunkingService } from '../../src/services/chunking/chunking-service.js';
import { MemoryStoreService } from '../../src/services/memory-store.service.js';
import { MemoryFindService } from '../../src/services/memory-find.service.js';
import { MockEmbeddingService } from '../utils/mock-embedding-service.js';
import { createMockSemanticAnalyzer } from '../utils/mock-semantic-analyzer.js';
import { mockQdrantClient } from '../mocks/database.js';
import { MemoryStoreInput, MemoryFindInput } from '../../src/types/core-interfaces.js';

describe('Performance Smoke Tests - N=100 Items, <1s Target', () => {
  let databaseManager: DatabaseManager;
  let chunkingService: ChunkingService;
  let memoryStoreService: MemoryStoreService;
  let memoryFindService: MemoryFindService;
  let embeddingService: MockEmbeddingService;

  // Performance constants
  const TARGET_ITEM_COUNT = 100;
  const TARGET_STORAGE_TIME = 1000; // 1 second
  const TARGET_SEARCH_TIME = 1000; // 1 second
  const TARGET_CONCURRENT_TIME = 2000; // 2 seconds for concurrent operations

  beforeAll(async () => {
    // Initialize services with performance-optimized configuration
    embeddingService = new MockEmbeddingService({
      shouldFail: false,
      latency: 10, // Very low latency for performance testing
    });

    databaseManager = new DatabaseManager({
      qdrant: {
        url: process.env.QDRANT_URL || 'http://localhost:6333',
        apiKey: process.env.QDRANT_API_KEY,
        timeout: 10000, // Shorter timeout for performance tests
      },
      enableVectorOperations: true,
      enableFallback: true,
      performance: {
        batchSize: 50,
        maxConcurrency: 10,
        cacheSize: 1000,
      },
    });

    chunkingService = new ChunkingService(
      databaseManager,
      embeddingService,
      undefined,
    );

    const mockSemanticAnalyzer = createMockSemanticAnalyzer(embeddingService as any, {
      shouldFail: false,
    });
    (chunkingService as any).semanticAnalyzer = mockSemanticAnalyzer;

    memoryStoreService = new MemoryStoreService(databaseManager, chunkingService);
    memoryFindService = new MemoryFindService(databaseManager);
  });

  beforeEach(async () => {
    try {
      await databaseManager.healthCheck();
      await databaseManager.createCollection('test-performance', {
        vectors: { size: 1536, distance: 'Cosine' },
      });
    } catch (error) {
      // Use mock database for testing if real database unavailable
      (databaseManager as any).qdrantClient = mockQdrantClient;
    }
  });

  afterEach(async () => {
    try {
      await databaseManager.deleteCollection('test-performance');
    } catch (error) {
      // Ignore cleanup errors
    }
  });

  afterAll(async () => {
    try {
      await databaseManager.disconnect();
    } catch (error) {
      // Ignore disconnect errors
    }
  });

  describe('Storage Performance Tests', () => {
    it(`should store ${TARGET_ITEM_COUNT} items in <${TARGET_STORAGE_TIME}ms`, async () => {
      // Generate 100 test items
      const testItems: MemoryStoreInput[] = Array.from({ length: TARGET_ITEM_COUNT }, (_, index) => {
        const categories = ['entity', 'decision', 'observation', 'risk', 'assumption'];
        const category = categories[index % categories.length];
        const projects = ['project-alpha', 'project-beta', 'project-gamma', 'project-delta'];
        const project = projects[index % projects.length];

        return {
          kind: category,
          content: `Performance test item ${index}: This is test content for category ${category} in project ${project}. The content is designed to be representative of real-world usage patterns with meaningful semantic content.`,
          scope: { project, branch: 'main' },
          metadata: {
            test_index: index,
            category,
            created_at: new Date().toISOString(),
            test_type: 'performance_smoke',
          },
        };
      });

      // Measure storage performance
      const startTime = Date.now();
      const storeResult = await memoryStoreService.store({
        items: testItems,
      });
      const storageTime = Date.now() - startTime;

      // Verify performance targets
      expect(storageTime).toBeLessThan(TARGET_STORAGE_TIME);
      expect(storeResult.success).toBe(true);
      expect(storeResult.stored_count).toBe(TARGET_ITEM_COUNT);

      // Log performance metrics for quality gate parsing
      const avgTimePerItem = storageTime / TARGET_ITEM_COUNT;
      const itemsPerSecond = TARGET_ITEM_COUNT / (storageTime / 1000);

      console.log(`\n📊 PERFORMANCE SMOKE TEST RESULTS:`);
      console.log(`${TARGET_ITEM_COUNT} items in ${storageTime}ms`);
      console.log(`${avgTimePerItem.toFixed(2)}ms per item`);
      console.log(`${itemsPerSecond.toFixed(0)} items/second`);
      console.log(`Storage Performance: ${TARGET_ITEM_COUNT} items in ${storageTime}ms (${avgTimePerItem.toFixed(2)}ms per item)`);
      console.log(`Storage Rate: ${itemsPerSecond.toFixed(0)} items/second`);
    });

    it('should handle batch storage efficiently', async () => {
      // Test different batch sizes
      const batchSizes = [10, 25, 50, 100];
      const performanceResults = [];

      for (const batchSize of batchSizes) {
        const batchItems: MemoryStoreInput[] = Array.from({ length: batchSize }, (_, index) => ({
          kind: 'entity',
          content: `Batch test item ${index}: Content optimized for batch processing performance testing`,
          scope: { project: 'batch-test' },
          metadata: { batch_size: batchSize, item_index: index },
        }));

        const startTime = Date.now();
        const result = await memoryStoreService.store({
          items: batchItems,
        });
        const batchTime = Date.now() - startTime;

        performanceResults.push({
          batchSize,
          time: batchTime,
          timePerItem: batchTime / batchSize,
          itemsPerSecond: batchSize / (batchTime / 1000),
        });

        expect(result.success).toBe(true);
        expect(result.stored_count).toBe(batchSize);
      }

      // Verify performance scales reasonably with batch size
      const lastResult = performanceResults[performanceResults.length - 1];
      const firstResult = performanceResults[0];

      console.log('Batch Storage Performance:');
      performanceResults.forEach(result => {
        console.log(`  Batch ${result.batchSize}: ${result.time}ms total, ${result.timePerItem.toFixed(2)}ms/item, ${result.itemsPerSecond.toFixed(0)} items/sec`);
      });

      // Larger batches should be more efficient (lower time per item)
      expect(lastResult.timePerItem).toBeLessThanOrEqual(firstResult.timePerItem * 1.5);
    });

    it('should handle large content storage within time limits', async () => {
      // Create items with varying content sizes
      const largeContentItems: MemoryStoreInput[] = Array.from({ length: 20 }, (_, index) => {
        const contentSizes = [500, 1000, 2000, 5000]; // characters
        const size = contentSizes[index % contentSizes.length];
        const baseContent = `Large content test item ${index} with ${size} characters. `;
        const repeatedContent = 'This is repeated content to increase size. '.repeat(Math.ceil(size / 50));
        const finalContent = (baseContent + repeatedContent).substring(0, size);

        return {
          kind: index % 2 === 0 ? 'section' : 'runbook',
          content: finalContent,
          scope: { project: 'large-content-test' },
          metadata: {
            content_size: finalContent.length,
            test_index: index,
            expected_chunks: Math.ceil(finalContent.length / 1000), // Rough estimate
          },
        };
      });

      const startTime = Date.now();
      const storeResult = await memoryStoreService.store({
        items: largeContentItems,
      });
      const storageTime = Date.now() - startTime;

      expect(storageTime).toBeLessThan(TARGET_STORAGE_TIME);
      expect(storeResult.success).toBe(true);

      // Should have more total items due to chunking of large content
      expect(storeResult.items.length).toBeGreaterThanOrEqual(20);

      console.log(`Large Content Storage: 20 items (${storeResult.items.length} total with chunks) in ${storageTime}ms`);
    });
  });

  describe('Search Performance Tests', () => {
    it(`should search across ${TARGET_ITEM_COUNT} items in <${TARGET_SEARCH_TIME}ms`, async () => {
      // First, populate with test data
      const searchData: MemoryStoreInput[] = Array.from({ length: TARGET_ITEM_COUNT }, (_, index) => {
        const topics = ['authentication', 'database', 'api', 'security', 'performance', 'deployment', 'monitoring', 'testing'];
        const topic = topics[index % topics.length];

        return {
          kind: 'entity',
          content: `${topic} system component ${index}: This content discusses ${topic} implementation details, best practices, and operational considerations for enterprise applications.`,
          scope: { project: 'search-performance-test' },
          metadata: {
            topic,
            test_index: index,
            category: 'system_component',
          },
        };
      });

      // Store the data
      await memoryStoreService.store({
        items: searchData,
      });

      // Test various search queries
      const searchQueries = [
        'authentication security implementation',
        'database performance optimization',
        'api deployment monitoring',
        'testing best practices',
        'system components operational',
      ];

      const searchResults = [];

      for (const query of searchQueries) {
        const startTime = Date.now();
        const result = await memoryFindService.find({
          query,
          scope: { project: 'search-performance-test' },
          limit: 10,
        });
        const searchTime = Date.now() - startTime;

        searchResults.push({
          query,
          time: searchTime,
          resultCount: result.results.length,
        });

        expect(searchTime).toBeLessThan(TARGET_SEARCH_TIME);
        expect(result.results.length).toBeGreaterThan(0);
      }

      console.log('Search Performance Results:');
      searchResults.forEach(result => {
        console.log(`  Query "${result.query}": ${result.time}ms, ${result.resultCount} results`);
      });

      // Average search time should be well under target
      const avgSearchTime = searchResults.reduce((sum, r) => sum + r.time, 0) / searchResults.length;
      expect(avgSearchTime).toBeLessThan(TARGET_SEARCH_TIME * 0.7);
      console.log(`Average search time: ${avgSearchTime.toFixed(2)}ms`);
    });

    it('should handle concurrent searches efficiently', async () => {
      // Populate test data
      const concurrentData: MemoryStoreInput[] = Array.from({ length: 50 }, (_, index) => ({
        kind: 'observation',
        content: `Concurrent search test observation ${index}: System performance metrics show efficient handling of multiple simultaneous search operations with consistent response times.`,
        scope: { project: 'concurrent-search-test' },
        metadata: { test_index: index, test_type: 'concurrent_search' },
      }));

      await memoryStoreService.store({
        items: concurrentData,
      });

      // Perform concurrent searches
      const concurrentQueries = Array.from({ length: 10 }, (_, index) => ({
        query: `concurrent search test observation ${index % 5}`,
        scope: { project: 'concurrent-search-test' },
        limit: 5,
      }));

      const startTime = Date.now();
      const searchPromises = concurrentQueries.map(query =>
        memoryFindService.find(query)
      );

      const results = await Promise.all(searchPromises);
      const concurrentTime = Date.now() - startTime;

      expect(concurrentTime).toBeLessThan(TARGET_CONCURRENT_TIME);

      // Verify all searches succeeded
      results.forEach((result, index) => {
        expect(result.results.length).toBeGreaterThan(0);
        console.log(`  Concurrent search ${index + 1}: ${result.results.length} results`);
      });

      console.log(`Concurrent Search Performance: 10 searches in ${concurrentTime}ms (${concurrentTime / 10}ms per search)`);
    });

    it('should maintain search quality with high performance', async () => {
      // Create high-quality test data with semantic relationships
      const qualityData: MemoryStoreInput[] = [
        {
          kind: 'entity',
          content: 'User authentication service with OAuth 2.0 and JWT token management',
          scope: { project: 'quality-test' },
        },
        {
          kind: 'process',
          content: 'Database connection pooling and query optimization for high performance',
          scope: { project: 'quality-test' },
        },
        {
          kind: 'observation',
          content: 'API response time measurements show 95th percentile under 200ms',
          scope: { project: 'quality-test' },
        },
        {
          kind: 'decision',
          content: 'Technical decision to migrate to microservices architecture for better scalability',
          scope: { project: 'quality-test' },
        },
        {
          kind: 'risk',
          content: 'Security vulnerability assessment identifies potential injection risks',
          scope: { project: 'quality-test' },
        },
      ];

      await memoryStoreService.store({
        items: qualityData,
      });

      // Test search quality with performance
      const qualitySearches = [
        { query: 'OAuth JWT authentication user', expectedType: 'entity' },
        { query: 'database performance connection pooling', expectedType: 'process' },
        { query: 'API response time metrics performance', expectedType: 'observation' },
        { query: 'microservices architecture scalability decision', expectedType: 'decision' },
        { query: 'security vulnerability assessment injection', expectedType: 'risk' },
      ];

      const qualityResults = [];

      for (const { query, expectedType } of qualitySearches) {
        const startTime = Date.now();
        const result = await memoryFindService.find({
          query,
          scope: { project: 'quality-test' },
          limit: 3,
        });
        const searchTime = Date.now() - startTime;

        qualityResults.push({
          query,
          time: searchTime,
          resultCount: result.results.length,
          foundExpectedType: result.results.some(r => r.kind === expectedType),
          avgConfidence: result.results.reduce((sum, r) => sum + r.confidence_score, 0) / result.results.length,
        });

        expect(searchTime).toBeLessThan(TARGET_SEARCH_TIME);
        expect(result.results.length).toBeGreaterThan(0);
      }

      console.log('Search Quality Performance:');
      qualityResults.forEach(result => {
        console.log(`  "${result.query}": ${result.time}ms, ${result.resultCount} results, avg confidence: ${result.avgConfidence.toFixed(3)}, found expected: ${result.foundExpectedType}`);
      });

      // Verify quality metrics
      const avgConfidence = qualityResults.reduce((sum, r) => sum + r.avgConfidence, 0) / qualityResults.length;
      expect(avgConfidence).toBeGreaterThan(0.5); // Minimum quality threshold
      const foundExpectedRate = qualityResults.filter(r => r.foundExpectedType).length / qualityResults.length;
      expect(foundExpectedRate).toBeGreaterThan(0.8); // 80% of searches should find expected type
    });
  });

  describe('Mixed Operation Performance Tests', () => {
    it('should handle mixed storage and search operations efficiently', async () => {
      const mixedOperations = [];
      const totalOperations = 100;

      // Generate mixed operations (70% storage, 30% search)
      for (let i = 0; i < totalOperations; i++) {
        if (i % 10 < 7) {
          // Storage operation
          mixedOperations.push({
            type: 'store',
            item: {
              kind: 'entity',
              content: `Mixed operation test item ${i}: Content for testing mixed storage and search performance`,
              scope: { project: 'mixed-operations-test' },
              metadata: { operation_index: i, operation_type: 'store' },
            },
          });
        } else {
          // Search operation
          mixedOperations.push({
            type: 'search',
            query: `mixed operation test ${Math.max(0, i - 10)}`,
            scope: { project: 'mixed-operations-test' },
          });
        }
      }

      // Execute mixed operations
      const startTime = Date.now();
      const results = [];

      for (const operation of mixedOperations) {
        if (operation.type === 'store') {
          const result = await memoryStoreService.store({
            items: [operation.item],
          });
          results.push({ type: 'store', success: result.success, time: Date.now() - startTime });
        } else {
          const result = await memoryFindService.find({
            query: operation.query,
            scope: operation.scope,
            limit: 5,
          });
          results.push({ type: 'search', resultCount: result.results.length, time: Date.now() - startTime });
        }
      }

      const totalTime = Date.now() - startTime;

      // Analyze results
      const storeOps = results.filter(r => r.type === 'store');
      const searchOps = results.filter(r => r.type === 'search');

      expect(storeOps.every(op => op.success)).toBe(true);
      expect(searchOps.every(op => op.resultCount >= 0)).toBe(true);
      expect(totalTime).toBeLessThan(TARGET_STORAGE_TIME * 2); // Should complete in <2s

      console.log('Mixed Operations Performance:');
      console.log(`  Total operations: ${totalOperations} in ${totalTime}ms`);
      console.log(`  Storage operations: ${storeOps.length}`);
      console.log(`  Search operations: ${searchOps.length}`);
      console.log(`  Average time per operation: ${(totalTime / totalOperations).toFixed(2)}ms`);
      console.log(`  Operations per second: ${(totalOperations / (totalTime / 1000)).toFixed(0)}`);
    });

    it('should handle scope-isolated operations efficiently', async () => {
      const scopes = ['scope-a', 'scope-b', 'scope-c', 'scope-d', 'scope-e'];
      const itemsPerScope = 20;

      // Store data across multiple scopes
      const scopeStorageStartTime = Date.now();
      const storagePromises = scopes.map(scope =>
        Array.from({ length: itemsPerScope }, (_, index) => ({
          kind: 'entity',
          content: `Scope ${scope} item ${index}: Content isolated to specific scope for performance testing`,
          scope: { project: scope, branch: 'main' },
          metadata: { scope, item_index: index },
        }))
      ).flat();

      await memoryStoreService.store({
        items: storagePromises,
      });
      const scopeStorageTime = Date.now() - scopeStorageStartTime;

      expect(scopeStorageTime).toBeLessThan(TARGET_STORAGE_TIME);

      // Perform searches across different scopes
      const scopeSearchStartTime = Date.now();
      const searchPromises = scopes.map(scope =>
        memoryFindService.find({
          query: `scope ${scope} content`,
          scope: { project: scope },
          limit: 5,
        })
      );

      const searchResults = await Promise.all(searchPromises);
      const scopeSearchTime = Date.now() - scopeSearchStartTime;

      expect(scopeSearchTime).toBeLessThan(TARGET_SEARCH_TIME);

      // Verify scope isolation
      searchResults.forEach((result, index) => {
        expect(result.results.length).toBeGreaterThan(0);
        expect(result.results.every(r => r.scope.project === scopes[index])).toBe(true);
      });

      console.log('Scope Isolation Performance:');
      console.log(`  Storage: ${scopes.length * itemsPerScope} items across ${scopes.length} scopes in ${scopeStorageTime}ms`);
      console.log(`  Search: ${scopes.length} concurrent scope searches in ${scopeSearchTime}ms`);
    });
  });

  describe('Memory and Resource Usage', () => {
    it('should maintain efficient memory usage during operations', async () => {
      // Get initial memory usage
      const initialMemory = process.memoryUsage();

      // Perform intensive operations
      const memoryTestData = Array.from({ length: 100 }, (_, index) => ({
        kind: 'observation',
        content: `Memory efficiency test ${index}: This content is designed to test memory usage patterns during storage and search operations with large datasets.`,
        scope: { project: 'memory-efficiency-test' },
        metadata: {
          test_index: index,
          large_metadata: {
            description: `This is a large metadata object for test item ${index}`,
            tags: Array.from({ length: 10 }, (_, i) => `tag-${index}-${i}`),
            properties: {
              prop1: `value1-${index}`,
              prop2: `value2-${index}`,
              prop3: `value3-${index}`,
            },
          },
        },
      }));

      // Store operations
      await memoryStoreService.store({
        items: memoryTestData,
      });

      // Search operations
      const searchPromises = Array.from({ length: 20 }, (_, index) =>
        memoryFindService.find({
          query: `memory efficiency test ${index % 10}`,
          scope: { project: 'memory-efficiency-test' },
          limit: 10,
        })
      );

      await Promise.all(searchPromises);

      // Check final memory usage
      const finalMemory = process.memoryUsage();
      const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;

      // Memory increase should be reasonable (less than 100MB for this test)
      expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024);

      console.log('Memory Usage Performance:');
      console.log(`  Initial memory: ${(initialMemory.heapUsed / 1024 / 1024).toFixed(2)}MB`);
      console.log(`  Final memory: ${(finalMemory.heapUsed / 1024 / 1024).toFixed(2)}MB`);
      console.log(`  Memory increase: ${(memoryIncrease / 1024 / 1024).toFixed(2)}MB`);
      console.log(`  Memory per item: ${(memoryIncrease / 100 / 1024).toFixed(2)}KB`);
    });

    it('should handle cleanup and garbage collection efficiently', async () => {
      // Create temporary data for cleanup testing
      const cleanupTestData = Array.from({ length: 50 }, (_, index) => ({
        kind: 'entity',
        content: `Cleanup test item ${index}: Temporary data for testing cleanup and garbage collection performance`,
        scope: { project: 'cleanup-test' },
        metadata: { temp_data: true, test_index: index },
      }));

      // Store temporary data
      await memoryStoreService.store({
        items: cleanupTestData,
      });

      // Perform some searches to populate caches
      for (let i = 0; i < 10; i++) {
        await memoryFindService.find({
          query: `cleanup test item ${i}`,
          scope: { project: 'cleanup-test' },
          limit: 5,
        });
      }

      // Measure cleanup performance
      const cleanupStartTime = Date.now();

      // Simulate cleanup operations (in a real system, this might involve cache clearing, temp file deletion, etc.)
      if ((databaseManager as any).clearCache) {
        await (databaseManager as any).clearCache();
      }

      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }

      const cleanupTime = Date.now() - cleanupStartTime;

      // Cleanup should be fast
      expect(cleanupTime).toBeLessThan(500); // < 500ms

      console.log(`Cleanup Performance: ${cleanupTime}ms`);
    });
  });

  describe('Performance Regression Detection', () => {
    it('should detect performance regressions in core operations', async () => {
      // Define performance baselines (these would be updated based on historical data)
      const performanceBaselines = {
        storage_100_items: 1000, // ms
        search_single_query: 200, // ms
        concurrent_10_searches: 1500, // ms
        mixed_50_operations: 2000, // ms
      };

      // Test storage performance against baseline
      const storageTestData = Array.from({ length: 100 }, (_, index) => ({
        kind: 'entity',
        content: `Regression test item ${index}: Content for performance regression detection`,
        scope: { project: 'regression-test' },
      }));

      const storageStartTime = Date.now();
      await memoryStoreService.store({
        items: storageTestData,
      });
      const storageTime = Date.now() - storageStartTime;

      // Verify storage performance is within acceptable range (150% of baseline)
      expect(storageTime).toBeLessThan(performanceBaselines.storage_100_items * 1.5);

      // Test search performance against baseline
      const searchStartTime = Date.now();
      await memoryFindService.find({
        query: 'regression test content',
        scope: { project: 'regression-test' },
        limit: 10,
      });
      const searchTime = Date.now() - searchStartTime;

      expect(searchTime).toBeLessThan(performanceBaselines.search_single_query * 1.5);

      // Test concurrent search performance
      const concurrentStartTime = Date.now();
      const concurrentPromises = Array.from({ length: 10 }, (_, index) =>
        memoryFindService.find({
          query: `regression test ${index}`,
          scope: { project: 'regression-test' },
          limit: 5,
        })
      );

      await Promise.all(concurrentPromises);
      const concurrentTime = Date.now() - concurrentStartTime;

      expect(concurrentTime).toBeLessThan(performanceBaselines.concurrent_10_searches * 1.5);

      console.log('Performance Regression Test Results:');
      console.log(`  Storage (100 items): ${storageTime}ms (baseline: ${performanceBaselines.storage_100_items}ms)`);
      console.log(`  Search (single query): ${searchTime}ms (baseline: ${performanceBaselines.search_single_query}ms)`);
      console.log(`  Concurrent (10 searches): ${concurrentTime}ms (baseline: ${performanceBaselines.concurrent_10_searches}ms)`);
      console.log(`  All tests within 150% of baseline targets ✓`);
    });
  });
});