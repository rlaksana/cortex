/**
 * Performance Tests for Graph Expansion with Large Relationship Graphs
 *
 * Validates performance characteristics of graph expansion functionality
 * under various load conditions and complexity scenarios.
 *
 * @file tests/performance/graph-expansion-performance.test.ts
 */

import { describe, test, expect, jest, beforeAll, afterAll } from '@jest/globals';
import { traverseGraphWithExpansion } from '../../src/services/graph-traversal.js';
import { coreMemoryFind, type CoreFindParams } from '../../src/services/core-memory-find.js';
import type { TraversalOptions } from '../../src/services/graph-traversal.js';

// Performance test configuration
const PERFORMANCE_THRESHOLDS = {
  MAX_TRAVERSAL_TIME_MS: 2000, // 2 seconds max for single traversal
  MAX_MEMORY_FIND_TIME_MS: 5000, // 5 seconds max for full memory find
  MAX_MEMORY_USAGE_MB: 100, // 100MB max memory usage
  MIN_THROUGHPUT_PER_SECOND: 10, // Minimum traversals per second
} as const;

describe('Graph Expansion Performance Tests', () => {
  let memoryBaseline: number;

  beforeAll(() => {
    // Get baseline memory usage
    if (typeof process !== 'undefined' && process.memoryUsage) {
      memoryBaseline = process.memoryUsage().heapUsed / 1024 / 1024; // MB
    }
  });

  afterAll(() => {
    // Check for memory leaks
    if (typeof process !== 'undefined' && process.memoryUsage) {
      const memoryUsage = process.memoryUsage().heapUsed / 1024 / 1024; // MB
      const memoryIncrease = memoryUsage - memoryBaseline;

      expect(memoryIncrease).toBeLessThan(PERFORMANCE_THRESHOLDS.MAX_MEMORY_USAGE_MB);
    }
  });

  describe('Single Traversal Performance', () => {
    test('should complete simple traversal within time limit', async () => {
      const startTime = Date.now();

      const options: TraversalOptions = {
        depth: 2,
        direction: 'outgoing',
        max_results: 10,
        sort_by: 'relevance',
      };

      await traverseGraphWithExpansion('entity', 'test-entity-simple', options);

      const executionTime = Date.now() - startTime;

      expect(executionTime).toBeLessThan(PERFORMANCE_THRESHOLDS.MAX_TRAVERSAL_TIME_MS);
    });

    test('should handle moderate depth traversal efficiently', async () => {
      const startTime = Date.now();

      const options: TraversalOptions = {
        depth: 4,
        direction: 'both',
        max_results: 50,
        sort_by: 'confidence',
      };

      await traverseGraphWithExpansion('entity', 'test-entity-moderate', options);

      const executionTime = Date.now() - startTime;

      expect(executionTime).toBeLessThan(PERFORMANCE_THRESHOLDS.MAX_TRAVERSAL_TIME_MS);
    });

    test('should handle maximum depth within acceptable time', async () => {
      const startTime = Date.now();

      const options: TraversalOptions = {
        depth: 8,
        direction: 'both',
        max_results: 100,
        sort_by: 'relevance',
      };

      await traverseGraphWithExpansion('entity', 'test-entity-complex', options);

      const executionTime = Date.now() - startTime;

      // Allow more time for complex traversals but still within reasonable bounds
      expect(executionTime).toBeLessThan(PERFORMANCE_THRESHOLDS.MAX_TRAVERSAL_TIME_MS * 2);
    });
  });

  describe('Memory Find Performance with Expansion', () => {
    test('should complete children expansion within time limit', async () => {
      const startTime = Date.now();

      const params: CoreFindParams = {
        query: 'performance test query',
        expand: 'children',
        limit: 20,
        mode: 'auto',
      };

      await coreMemoryFind(params);

      const executionTime = Date.now() - startTime;

      expect(executionTime).toBeLessThan(PERFORMANCE_THRESHOLDS.MAX_MEMORY_FIND_TIME_MS);
    });

    test('should complete parents expansion within time limit', async () => {
      const startTime = Date.now();

      const params: CoreFindParams = {
        query: 'performance test query',
        expand: 'parents',
        limit: 20,
        mode: 'auto',
      };

      await coreMemoryFind(params);

      const executionTime = Date.now() - startTime;

      expect(executionTime).toBeLessThan(PERFORMANCE_THRESHOLDS.MAX_MEMORY_FIND_TIME_MS);
    });

    test('should complete relations expansion within time limit', async () => {
      const startTime = Date.now();

      const params: CoreFindParams = {
        query: 'performance test query',
        expand: 'relations',
        limit: 20,
        mode: 'auto',
      };

      await coreMemoryFind(params);

      const executionTime = Date.now() - startTime;

      expect(executionTime).toBeLessThan(PERFORMANCE_THRESHOLDS.MAX_MEMORY_FIND_TIME_MS);
    });

    test('should handle complex queries with expansion efficiently', async () => {
      const startTime = Date.now();

      const params: CoreFindParams = {
        query: 'complex performance test with filters and scope',
        expand: 'relations',
        limit: 50,
        mode: 'deep',
        types: ['entity', 'decision', 'issue', 'todo'],
        scope: {
          project: 'performance-test-project',
          branch: 'main',
          org: 'test-org',
        },
      };

      const result = await coreMemoryFind(params);

      const executionTime = Date.now() - startTime;

      expect(executionTime).toBeLessThan(PERFORMANCE_THRESHOLDS.MAX_MEMORY_FIND_TIME_MS);
      expect(result.graph_expansion).toBeDefined();
      expect(result.graph_expansion!.traversal_metadata.execution_time_ms).toBeLessThan(
        PERFORMANCE_THRESHOLDS.MAX_TRAVERSAL_TIME_MS
      );
    });
  });

  describe('Throughput Tests', () => {
    test('should handle concurrent traversals efficiently', async () => {
      const concurrency = 10;
      const startTime = Date.now();

      const traversalPromises = Array.from({ length: concurrency }, (_, index) => {
        const options: TraversalOptions = {
          depth: 2,
          direction: 'outgoing',
          max_results: 10,
          sort_by: 'relevance',
        };

        return traverseGraphWithExpansion('entity', `test-entity-${index}`, options);
      });

      await Promise.all(traversalPromises);

      const executionTime = Date.now() - startTime;
      const throughput = (concurrency / executionTime) * 1000; // traversals per second

      expect(throughput).toBeGreaterThan(PERFORMANCE_THRESHOLDS.MIN_THROUGHPUT_PER_SECOND);
    });

    test('should handle batch memory find operations', async () => {
      const batchSize = 5;
      const startTime = Date.now();

      const findPromises = Array.from({ length: batchSize }, (_, index) => {
        const params: CoreFindParams = {
          query: `batch performance test query ${index}`,
          expand: 'children',
          limit: 15,
          mode: 'auto',
        };

        return coreMemoryFind(params);
      });

      const results = await Promise.all(findPromises);

      const executionTime = Date.now() - startTime;
      const throughput = (batchSize / executionTime) * 1000; // operations per second

      expect(throughput).toBeGreaterThan(PERFORMANCE_THRESHOLDS.MIN_THROUGHPUT_PER_SECOND);
      expect(results).toHaveLength(batchSize);

      // Verify all operations succeeded
      for (const result of results) {
        expect(result.results).toBeDefined();
        expect(result.graph_expansion).toBeDefined();
      }
    });
  });

  describe('Memory Usage Tests', () => {
    test('should not leak memory during repeated traversals', async () => {
      const iterations = 20;
      const memoryUsages: number[] = [];

      for (let i = 0; i < iterations; i++) {
        // Get memory usage before operation
        const beforeMemory = typeof process !== 'undefined' && process.memoryUsage
          ? process.memoryUsage().heapUsed
          : 0;

        // Perform traversal
        const options: TraversalOptions = {
          depth: 3,
          direction: 'both',
          max_results: 25,
        };

        await traverseGraphWithExpansion('entity', `memory-test-entity-${i}`, options);

        // Get memory usage after operation
        const afterMemory = typeof process !== 'undefined' && process.memoryUsage
          ? process.memoryUsage().heapUsed
          : 0;

        memoryUsages.push(afterMemory - beforeMemory);

        // Force garbage collection if available
        if (typeof global !== 'undefined' && global.gc) {
          global.gc();
        }
      }

      // Calculate average memory increase
      const avgMemoryIncrease = memoryUsages.reduce((sum, usage) => sum + usage, 0) / memoryUsages.length;
      const avgMemoryIncreaseMB = avgMemoryIncrease / 1024 / 1024;

      // Memory increase should be minimal per operation
      expect(avgMemoryIncreaseMB).toBeLessThan(5); // Less than 5MB per operation
    });

    test('should handle large result sets efficiently', async () => {
      const startTime = Date.now();

      const options: TraversalOptions = {
        depth: 5,
        direction: 'both',
        max_results: 200, // Large result set
        sort_by: 'relevance',
      };

      const result = await traverseGraphWithExpansion('entity', 'large-result-set-test', options);

      const executionTime = Date.now() - startTime;

      expect(executionTime).toBeLessThan(PERFORMANCE_THRESHOLDS.MAX_TRAVERSAL_TIME_MS * 2);
      expect(result.nodes.length).toBeLessThanOrEqual(201); // max_results + root node
      expect(result.total_entities_found).toBeLessThanOrEqual(201);
    });
  });

  describe('Scaling Tests', () => {
    test('should scale linearly with result size', async () => {
      const resultSizes = [10, 25, 50, 100];
      const executionTimes: number[] = [];

      for (const maxResults of resultSizes) {
        const startTime = Date.now();

        const options: TraversalOptions = {
          depth: 3,
          direction: 'outgoing',
          max_results,
        };

        await traverseGraphWithExpansion('entity', 'scaling-test-entity', options);

        executionTimes.push(Date.now() - startTime);
      }

      // Execution time should increase sub-linearly with result size
      // due to optimizations like batching
      const timeIncreaseRatio = executionTimes[3] / executionTimes[0];
      const resultSizeRatio = resultSizes[3] / resultSizes[0];

      // Time increase should be less than result size increase
      expect(timeIncreaseRatio).toBeLessThan(resultSizeRatio);
    });

    test('should handle different sorting algorithms efficiently', async () => {
      const sortingAlgorithms = ['created_at', 'updated_at', 'relevance', 'confidence'] as const;
      const executionTimes: number[] = [];

      for (const sortBy of sortingAlgorithms) {
        const startTime = Date.now();

        const options: TraversalOptions = {
          depth: 3,
          direction: 'both',
          max_results: 50,
          sort_by: sortBy,
        };

        await traverseGraphWithExpansion('entity', 'sorting-test-entity', options);

        executionTimes.push(Date.now() - startTime);
      }

      // All sorting algorithms should complete within reasonable time
      for (const executionTime of executionTimes) {
        expect(executionTime).toBeLessThan(PERFORMANCE_THRESHOLDS.MAX_TRAVERSAL_TIME_MS);
      }

      // Variance between sorting algorithms should be minimal
      const maxTime = Math.max(...executionTimes);
      const minTime = Math.min(...executionTimes);
      const timeVarianceRatio = maxTime / minTime;

      expect(timeVarianceRatio).toBeLessThan(2); // Less than 2x variance
    });
  });

  describe('Edge Case Performance', () => {
    test('should handle empty queries efficiently', async () => {
      const startTime = Date.now();

      const params: CoreFindParams = {
        query: '',
        expand: 'children',
        limit: 10,
      };

      await coreMemoryFind(params);

      const executionTime = Date.now() - startTime;

      // Even empty queries should complete quickly
      expect(executionTime).toBeLessThan(PERFORMANCE_THRESHOLDS.MAX_MEMORY_FIND_TIME_MS / 2);
    });

    test('should handle circular references without performance degradation', async () => {
      const startTime = Date.now();

      const options: TraversalOptions = {
        depth: 6,
        direction: 'both',
        include_circular_refs: true,
        max_results: 75,
      };

      const result = await traverseGraphWithExpansion('entity', 'circular-ref-test', options);

      const executionTime = Date.now() - startTime;

      expect(executionTime).toBeLessThan(PERFORMANCE_THRESHOLDS.MAX_TRAVERSAL_TIME_MS);
      expect(result.circular_refs_detected).toBeDefined();
    });
  });
});