/**
 * Memory Store Benchmark Scenarios
 *
 * Benchmark scenarios for testing memory store performance under various load conditions
 */

import type { BenchmarkScenario, LoadTestConfig } from '../framework/types.js';

/**
 * Single item store benchmark
 */
export const singleItemStoreBenchmark: BenchmarkScenario = {
  name: 'Single Item Store',
  description: 'Store individual knowledge items with minimal payload',
  config: {
    concurrency: 1,
    operations: 100,
    dataConfig: {
      itemCount: 100,
      averageItemSize: 1024,
      sizeVariance: 0.2,
    },
  },
  tags: ['store', 'single', 'baseline'],
  async execute(config: LoadTestConfig): Promise<any> {
    // Import dynamically to avoid circular dependencies
    const { memoryStore } = await import('../../src/index.js');

    const results = [];

    for (let i = 0; i < config.operations; i++) {
      const startTime = performance.now();

      try {
        const item = {
          kind: 'entity' as const,
          content: `Test entity ${i} with content for benchmarking`,
          scope: { project: 'benchmark-test' },
          metadata: { index: i, test: true },
        };

        const result = await memoryStore({ items: [item] });
        const endTime = performance.now();

        results.push({
          success: true,
          duration: endTime - startTime,
          itemId: result.items?.[0]?.id,
        });
      } catch (error) {
        const endTime = performance.now();
        results.push({
          success: false,
          duration: endTime - startTime,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    return {
      totalOperations: results.length,
      successfulOperations: results.filter((r) => r.success).length,
      failedOperations: results.filter((r) => !r.success).length,
      averageDuration: results.reduce((sum, r) => sum + r.duration, 0) / results.length,
      results,
    };
  },
};

/**
 * Batch store benchmark
 */
export const batchStoreBenchmark: BenchmarkScenario = {
  name: 'Batch Store',
  description: 'Store multiple knowledge items in a single operation',
  config: {
    concurrency: 1,
    operations: 10,
    dataConfig: {
      itemCount: 1000,
      averageItemSize: 2048,
      sizeVariance: 0.3,
    },
  },
  tags: ['store', 'batch', 'throughput'],
  async execute(config: LoadTestConfig): Promise<any> {
    const { memoryStore } = await import('../../src/index.js');

    const results = [];
    const batchSize = 100; // Store 100 items per batch

    for (let i = 0; i < config.operations; i++) {
      const startTime = performance.now();

      try {
        const items = [];
        for (let j = 0; j < batchSize; j++) {
          items.push({
            kind: 'observation' as const,
            content: `Batch observation ${i}-${j} with detailed content for performance testing`,
            scope: { project: 'benchmark-test' },
            metadata: { batch: i, index: j, test: true },
          });
        }

        const result = await memoryStore({ items });
        const endTime = performance.now();

        results.push({
          success: true,
          duration: endTime - startTime,
          itemsStored: result.items?.length || 0,
          batchSize,
        });
      } catch (error) {
        const endTime = performance.now();
        results.push({
          success: false,
          duration: endTime - startTime,
          error: error instanceof Error ? error.message : String(error),
          batchSize,
        });
      }
    }

    return {
      totalOperations: results.length,
      totalItems: results.reduce((sum, r) => sum + (r.itemsStored || 0), 0),
      successfulOperations: results.filter((r) => r.success).length,
      averageDuration: results.reduce((sum, r) => sum + r.duration, 0) / results.length,
      itemsPerSecond:
        results.reduce((sum, r) => sum + (r.itemsStored || 0), 0) /
        (results.reduce((sum, r) => sum + r.duration, 0) / 1000),
      results,
    };
  },
};

/**
 * Concurrent store benchmark
 */
export const concurrentStoreBenchmark: BenchmarkScenario = {
  name: 'Concurrent Store',
  description: 'Store items with multiple concurrent operations',
  config: {
    concurrency: 10,
    operations: 1000,
    rampUpTime: 1000,
    dataConfig: {
      itemCount: 1000,
      averageItemSize: 1536,
      sizeVariance: 0.25,
    },
  },
  tags: ['store', 'concurrent', 'load'],
  async execute(config: LoadTestConfig): Promise<any> {
    const { memoryStore } = await import('../../src/index.js');

    const results = [];
    const promises = [];

    // Create concurrent operations
    for (let i = 0; i < config.operations; i++) {
      const operation = async (index: number) => {
        // Ramp-up delay
        if (config.rampUpTime) {
          const delay = (config.rampUpTime / config.operations) * index;
          await new Promise((resolve) => setTimeout(resolve, delay));
        }

        const startTime = performance.now();

        try {
          const result = await memoryStore({
            items: [
              {
                kind: 'decision' as const,
                content: `Concurrent decision ${index} for load testing with concurrent operations`,
                scope: { project: 'benchmark-test' },
                metadata: { concurrent: true, index, test: true },
              },
            ],
          });

          const endTime = performance.now();

          return {
            success: true,
            duration: endTime - startTime,
            itemId: result.items?.[0]?.id,
            index,
          };
        } catch (error) {
          const endTime = performance.now();
          return {
            success: false,
            duration: endTime - startTime,
            error: error instanceof Error ? error.message : String(error),
            index,
          };
        }
      };

      promises.push(operation(i));
    }

    // Execute all operations concurrently
    const operationResults = await Promise.all(promises);
    results.push(...operationResults);

    // Calculate metrics
    const successful = results.filter((r) => r.success);
    const failed = results.filter((r) => !r.success);

    return {
      totalOperations: results.length,
      successfulOperations: successful.length,
      failedOperations: failed.length,
      averageDuration: successful.reduce((sum, r) => sum + r.duration, 0) / successful.length,
      minDuration: Math.min(...successful.map((r) => r.duration)),
      maxDuration: Math.max(...successful.map((r) => r.duration)),
      concurrency: config.concurrency,
      throughput: successful.length / (Math.max(...results.map((r) => r.duration)) / 1000),
      errorRate: (failed.length / results.length) * 100,
      results,
    };
  },
};

/**
 * Deduplication benchmark
 */
export const deduplicationBenchmark: BenchmarkScenario = {
  name: 'Deduplication Performance',
  description: 'Test deduplication performance with duplicate content',
  config: {
    concurrency: 1,
    operations: 200,
    dataConfig: {
      itemCount: 50, // Only 50 unique items
      averageItemSize: 1024,
      sizeVariance: 0.1,
    },
  },
  tags: ['store', 'deduplication', 'performance'],
  async execute(config: LoadTestConfig): Promise<any> {
    const { memoryStore } = await import('../../src/index.js');

    const results = [];
    const uniqueContents = [];

    // Generate unique content pool
    for (let i = 0; i < 50; i++) {
      uniqueContents.push(`Unique content ${i} for deduplication testing with some variations`);
    }

    // Store items (many will be duplicates)
    for (let i = 0; i < config.operations; i++) {
      const startTime = performance.now();

      try {
        // Select content (50% chance of duplicate)
        const contentIndex = i < 50 ? i : Math.floor(Math.random() * 50);
        const isDuplicate = i >= 50;

        const result = await memoryStore({
          items: [
            {
              kind: 'entity' as const,
              content: uniqueContents[contentIndex],
              scope: { project: 'benchmark-test' },
              metadata: {
                index: i,
                duplicate: isDuplicate,
                originalIndex: contentIndex,
                test: true,
              },
            },
          ],
          deduplication: {
            enabled: true,
            mergeStrategy: 'intelligent',
            similarityThreshold: 0.85,
          },
        });

        const endTime = performance.now();

        results.push({
          success: true,
          duration: endTime - startTime,
          isDuplicate,
          itemId: result.items?.[0]?.id,
          duplicateDetected: result.duplicateDetection?.detected || false,
        });
      } catch (error) {
        const endTime = performance.now();
        results.push({
          success: false,
          duration: endTime - startTime,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    const duplicates = results.filter((r) => r.duplicateDetected);
    const uniques = results.filter((r) => !r.duplicateDetected);

    return {
      totalOperations: results.length,
      duplicateOperations: duplicates.length,
      uniqueOperations: uniques.length,
      averageDuration: results.reduce((sum, r) => sum + r.duration, 0) / results.length,
      averageDuplicateDuration:
        duplicates.length > 0
          ? duplicates.reduce((sum, r) => sum + r.duration, 0) / duplicates.length
          : 0,
      averageUniqueDuration:
        uniques.length > 0 ? uniques.reduce((sum, r) => sum + r.duration, 0) / uniques.length : 0,
      duplicateDetectionRate: (duplicates.length / 150) * 100, // 150 expected duplicates
      results,
    };
  },
};

/**
 * Large item store benchmark
 */
export const largeItemStoreBenchmark: BenchmarkScenario = {
  name: 'Large Item Store',
  description: 'Store large knowledge items to test performance with big payloads',
  config: {
    concurrency: 1,
    operations: 50,
    dataConfig: {
      itemCount: 50,
      averageItemSize: 50000, // 50KB average
      sizeVariance: 0.2,
    },
  },
  tags: ['store', 'large-items', 'memory'],
  async execute(config: LoadTestConfig): Promise<any> {
    const { memoryStore } = await import('../../src/index.js');

    const results = [];

    // Generate large content
    const generateLargeContent = (size: number): string => {
      const base = 'Large content item for performance testing with substantial data payload. ';
      const repetitions = Math.ceil(size / base.length);
      return base.repeat(repetitions).substring(0, size);
    };

    for (let i = 0; i < config.operations; i++) {
      const startTime = performance.now();
      const startMemory = process.memoryUsage();

      try {
        const targetSize = 50000 + Math.floor(Math.random() * 20000); // 50KB ± 20KB
        const content = generateLargeContent(targetSize);

        const result = await memoryStore({
          items: [
            {
              kind: 'observation' as const,
              content,
              scope: { project: 'benchmark-test' },
              metadata: {
                large: true,
                size: content.length,
                index: i,
                test: true,
              },
            },
          ],
        });

        const endTime = performance.now();
        const endMemory = process.memoryUsage();

        results.push({
          success: true,
          duration: endTime - startTime,
          itemSize: content.length,
          memoryDelta: {
            rss: endMemory.rss - startMemory.rss,
            heapUsed: endMemory.heapUsed - startMemory.heapUsed,
          },
          itemId: result.items?.[0]?.id,
        });
      } catch (error) {
        const endTime = performance.now();
        results.push({
          success: false,
          duration: endTime - startTime,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    const successful = results.filter((r) => r.success);
    const totalDataSize = successful.reduce((sum, r) => sum + (r.itemSize || 0), 0);
    const avgMemoryDelta =
      successful.reduce((sum, r) => sum + r.memoryDelta.rss, 0) / successful.length;

    return {
      totalOperations: results.length,
      successfulOperations: successful.length,
      totalDataSize,
      averageItemSize: successful.length > 0 ? totalDataSize / successful.length : 0,
      averageDuration: successful.reduce((sum, r) => sum + r.duration, 0) / successful.length,
      throughputMBps:
        totalDataSize / 1024 / 1024 / (successful.reduce((sum, r) => sum + r.duration, 0) / 1000),
      averageMemoryDelta: avgMemoryDelta,
      results,
    };
  },
};

/**
 * TTL processing benchmark
 */
export const ttlProcessingBenchmark: BenchmarkScenario = {
  name: 'TTL Processing Performance',
  description: 'Test performance of TTL (Time To Live) processing during store operations',
  config: {
    concurrency: 1,
    operations: 100,
    dataConfig: {
      itemCount: 100,
      averageItemSize: 1024,
      sizeVariance: 0.1,
    },
  },
  tags: ['store', 'ttl', 'expiration'],
  async execute(config: LoadTestConfig): Promise<any> {
    const { memoryStore } = await import('../../src/index.js');

    const results = [];

    for (let i = 0; i < config.operations; i++) {
      const startTime = performance.now();

      try {
        // Vary TTL settings
        const ttlMinutes = Math.floor(Math.random() * 1440); // 0 to 24 hours
        const ttlPolicy = ttlMinutes < 60 ? 'short' : ttlMinutes < 720 ? 'default' : 'long';

        const result = await memoryStore({
          items: [
            {
              kind: 'todo' as const,
              content: `TTL test item ${i} with ${ttlPolicy} policy`,
              scope: { project: 'benchmark-test' },
              metadata: {
                ttl: ttlMinutes,
                policy: ttlPolicy,
                index: i,
                test: true,
              },
            },
          ],
          ttl_config: {
            policy: ttlPolicy as any,
            expires_at: new Date(Date.now() + ttlMinutes * 60 * 1000).toISOString(),
          },
        });

        const endTime = performance.now();

        results.push({
          success: true,
          duration: endTime - startTime,
          ttlMinutes,
          ttlPolicy,
          itemId: result.items?.[0]?.id,
        });
      } catch (error) {
        const endTime = performance.now();
        results.push({
          success: false,
          duration: endTime - startTime,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    const byPolicy = results.reduce(
      (acc, result) => {
        if (result.success && result.ttlPolicy) {
          if (!acc[result.ttlPolicy]) {
            acc[result.ttlPolicy] = [];
          }
          acc[result.ttlPolicy].push(result);
        }
        return acc;
      },
      {} as Record<string, any[]>
    );

    const policyStats = Object.entries(byPolicy).map(([policy, items]) => ({
      policy,
      count: items.length,
      averageDuration: items.reduce((sum, item) => sum + item.duration, 0) / items.length,
    }));

    return {
      totalOperations: results.length,
      successfulOperations: results.filter((r) => r.success).length,
      averageDuration:
        results.filter((r) => r.success).reduce((sum, r) => sum + r.duration, 0) /
        results.filter((r) => r.success).length,
      policyPerformance: policyStats,
      results,
    };
  },
};
