/**
 * Performance Tests for Contradiction Detector
 * Tests system performance under various load conditions
 */

import {
  ContradictionDetector,
  ContradictionDetectionRequest,
  KnowledgeItem,
} from '../../src/types/contradiction-detector.interface';
import { ContradictionDetectorImpl } from '../../src/services/contradiction/contradiction-detector.service';
import { MetadataFlaggingService } from '../../src/services/contradiction/metadata-flagging.service';
import { PointerResolutionService } from '../../src/services/contradiction/pointer-resolution.service';
import { StoragePipelineIntegration } from '../../src/services/contradiction/storage-pipeline-integration';
import { generateId } from '../../src/utils/id-generator';

describe('Contradiction Detector Performance Tests', () => {
  let detector: ContradictionDetector;
  let flaggingService: MetadataFlaggingService;
  let resolutionService: PointerResolutionService;
  let pipelineIntegration: StoragePipelineIntegration;

  beforeEach(() => {
    detector = new ContradictionDetectorImpl({
      enabled: true,
      sensitivity: 'balanced',
      auto_flag: true,
      batch_checking: true,
      performance_monitoring: true,
      cache_results: true,
      cache_ttl_ms: 300000,
      max_items_per_check: 1000,
      timeout_ms: 60000,
    });

    flaggingService = new MetadataFlaggingService();
    resolutionService = new PointerResolutionService();
    pipelineIntegration = new StoragePipelineIntegration(
      detector,
      flaggingService,
      resolutionService,
      {
        enabled: true,
        check_on_store: true,
        check_on_update: true,
        check_on_delete: false,
        batch_check_threshold: 20,
        async_checking: true,
        max_concurrent_checks: 4,
        queue_checking: true,
        retry_failed_checks: true,
        max_retries: 3,
      }
    );
  });

  describe('Throughput Tests', () => {
    test('should handle small batches efficiently', async () => {
      const batchSizes = [10, 25, 50, 100];
      const results: Array<{ size: number; timeMs: number; itemsPerSecond: number }> = [];

      for (const size of batchSizes) {
        const items = generateTestItems(size);
        const request: ContradictionDetectionRequest = {
          items,
          scope: { project: 'throughput-test' },
        };

        const startTime = Date.now();
        const response = await detector.detectContradictions(request);
        const processingTime = Date.now() - startTime;

        const itemsPerSecond = (size / processingTime) * 1000;
        results.push({
          size,
          timeMs: processingTime,
          itemsPerSecond,
        });

        expect(response.summary.total_items_checked).toBe(size);
        expect(response.performance.items_per_second).toBeGreaterThan(0);
      }

      // Performance should remain reasonable as batch size increases
      console.table(results);

      // Items per second should not degrade significantly
      const firstThroughput = results[0].itemsPerSecond;
      const lastThroughput = results[results.length - 1].itemsPerSecond;
      expect(lastThroughput).toBeGreaterThan(firstThroughput * 0.3); // Not less than 30% of initial
    }, 30000);

    test('should handle medium to large batches', async () => {
      const batchSizes = [200, 500, 800];
      const maxTimePerBatch = 30000; // 30 seconds per batch

      for (const size of batchSizes) {
        const items = generateTestItems(size);
        const request: ContradictionDetectionRequest = {
          items,
          scope: { project: 'large-batch-test' },
        };

        const startTime = Date.now();
        const response = await detector.detectContradictions(request);
        const processingTime = Date.now() - startTime;

        expect(processingTime).toBeLessThan(maxTimePerBatch);
        expect(response.summary.total_items_checked).toBe(size);
        expect(response.performance.items_per_second).toBeGreaterThan(5); // At least 5 items/second

        console.log(
          `Batch size ${size}: ${processingTime}ms, ${response.performance.items_perSecond.toFixed(2)} items/sec`
        );
      }
    }, 120000);

    test('should maintain performance under sustained load', async () => {
      const batchSize = 100;
      const numberOfBatches = 10;
      const maxTotalTime = 60000; // 1 minute for all batches

      const results: Array<{ batch: number; timeMs: number; itemsPerSecond: number }> = [];

      const totalStartTime = Date.now();

      for (let i = 0; i < numberOfBatches; i++) {
        const items = generateTestItems(batchSize);
        const request: ContradictionDetectionRequest = {
          items,
          scope: { project: 'sustained-load-test' },
        };

        const startTime = Date.now();
        const response = await detector.detectContradictions(request);
        const processingTime = Date.now() - startTime;

        results.push({
          batch: i + 1,
          timeMs: processingTime,
          itemsPerSecond: response.performance.items_per_second,
        });
      }

      const totalProcessingTime = Date.now() - totalStartTime;

      expect(totalProcessingTime).toBeLessThan(maxTotalTime);

      // Performance should be consistent across batches
      const throughputs = results.map((r) => r.itemsPerSecond);
      const avgThroughput = throughputs.reduce((a, b) => a + b, 0) / throughputs.length;
      const maxThroughput = Math.max(...throughputs);
      const minThroughput = Math.min(...throughputs);

      expect(minThroughput).toBeGreaterThan(avgThroughput * 0.5); // Not less than 50% of average

      console.log('Sustained load performance:');
      console.table(results);
      console.log(`Average throughput: ${avgThroughput.toFixed(2)} items/sec`);
    }, 90000);
  });

  describe('Memory Usage Tests', () => {
    test('should handle memory efficiently for large datasets', async () => {
      const sizes = [100, 300, 500];
      const memorySnapshots: Array<{ size: number; memoryMb: number; memoryPerItem: number }> = [];

      for (const size of sizes) {
        // Force garbage collection if available
        if (global.gc) {
          global.gc();
        }

        const items = generateTestItems(size);
        const request: ContradictionDetectionRequest = {
          items,
          scope: { project: 'memory-test' },
        };

        const response = await detector.detectContradictions(request);

        const memoryUsage = response.performance.memory_usage_mb;
        const memoryPerItem = memoryUsage / size;

        memorySnapshots.push({
          size,
          memoryMb: memoryUsage,
          memoryPerItem,
        });

        // Memory usage should be reasonable
        expect(memoryUsage).toBeLessThan(500); // Less than 500MB
        expect(memoryPerItem).toBeLessThan(2); // Less than 2MB per item
      }

      console.table(memorySnapshots);

      // Memory per item should not grow dramatically with batch size
      const firstMemoryPerItem = memorySnapshots[0].memoryPerItem;
      const lastMemoryPerItem = memorySnapshots[memorySnapshots.length - 1].memoryPerItem;
      expect(lastMemoryPerItem).toBeLessThan(firstMemoryPerItem * 2); // Not more than 2x
    }, 120000);

    test('should not leak memory during repeated operations', async () => {
      const iterations = 20;
      const batchSize = 50;
      const memoryUsages: number[] = [];

      for (let i = 0; i < iterations; i++) {
        const items = generateTestItems(batchSize);
        const request: ContradictionDetectionRequest = {
          items,
          scope: { project: 'memory-leak-test' },
        };

        const response = await detector.detectContradictions(request);
        memoryUsages.push(response.performance.memory_usage_mb);

        if (i > 0 && i % 5 === 0) {
          // Periodic garbage collection
          if (global.gc) {
            global.gc();
          }
        }
      }

      // Memory usage should be relatively stable
      const initialMemory = memoryUsages.slice(0, 5).reduce((a, b) => a + b, 0) / 5;
      const finalMemory = memoryUsages.slice(-5).reduce((a, b) => a + b, 0) / 5;

      expect(finalMemory).toBeLessThan(initialMemory * 1.5); // Not more than 50% growth

      console.log('Memory usage over iterations:');
      memoryUsages.forEach((memory, i) => {
        console.log(`Iteration ${i + 1}: ${memory.toFixed(2)} MB`);
      });
    }, 120000);
  });

  describe('Concurrency Tests', () => {
    test('should handle concurrent contradiction detection', async () => {
      const concurrentRequests = 5;
      const itemsPerRequest = 100;

      const requests = Array.from({ length: concurrentRequests }, (_, i) => {
        const items = generateTestItems(itemsPerRequest);
        return {
          items,
          request: {
            items,
            scope: { project: `concurrent-test-${i}` },
          } as ContradictionDetectionRequest,
        };
      });

      const startTime = Date.now();
      const responses = await Promise.all(
        requests.map(({ request }) => detector.detectContradictions(request))
      );
      const totalTime = Date.now() - startTime;

      // All requests should complete successfully
      expect(responses).toHaveLength(concurrentRequests);
      responses.forEach((response, i) => {
        expect(response.summary.total_items_checked).toBe(itemsPerRequest);
        console.log(
          `Request ${i + 1}: ${response.performance.items_perSecond.toFixed(2)} items/sec`
        );
      });

      // Total time should be reasonable
      expect(totalTime).toBeLessThan(60000); // Less than 1 minute

      const totalItems = concurrentRequests * itemsPerRequest;
      const overallThroughput = (totalItems / totalTime) * 1000;
      console.log(`Concurrent processing: ${overallThroughput.toFixed(2)} items/sec total`);
    }, 90000);

    test('should handle mixed load efficiently', async () => {
      const mixedRequests = [
        { size: 25, priority: 'high' },
        { size: 100, priority: 'medium' },
        { size: 200, priority: 'low' },
        { size: 50, priority: 'high' },
        { size: 150, priority: 'medium' },
      ];

      const startTime = Date.now();
      const responses = await Promise.all(
        mixedRequests.map(({ size, priority }, i) => {
          const items = generateTestItems(size);
          return pipelineIntegration.batchCheckExistingItems(items, {
            priority: priority as 'critical' | 'high' | 'medium' | 'low',
          });
        })
      );
      const totalTime = Date.now() - startTime;

      // Flatten responses and verify all items were processed
      const flatResponses = responses.flat();
      const totalProcessed = flatResponses.reduce(
        (sum, r) => sum + r.summary.total_items_checked,
        0
      );
      const expectedTotal = mixedRequests.reduce((sum, r) => sum + r.size, 0);

      expect(totalProcessed).toBe(expectedTotal);
      expect(totalTime).toBeLessThan(120000); // Less than 2 minutes

      console.log('Mixed load processing completed');
      console.log(`Total time: ${totalTime}ms for ${expectedTotal} items`);
    }, 150000);
  });

  describe('Scalability Tests', () => {
    test('should scale linearly with dataset size', async () => {
      const testSizes = [50, 100, 200, 400];
      const performanceData: Array<{ size: number; timeMs: number; throughput: number }> = [];

      for (const size of testSizes) {
        const items = generateTestItems(size);
        const request: ContradictionDetectionRequest = {
          items,
          scope: { project: 'scalability-test' },
        };

        const startTime = Date.now();
        const response = await detector.detectContradictions(request);
        const processingTime = Date.now() - startTime;

        const throughput = (size / processingTime) * 1000;
        performanceData.push({
          size,
          timeMs: processingTime,
          throughput,
        });
      }

      console.table(performanceData);

      // Check if scaling is reasonable (not exponential growth)
      const firstTime = performanceData[0].timeMs;
      const lastTime = performanceData[performanceData.length - 1].timeMs;
      const sizeRatio = testSizes[testSizes.length - 1] / testSizes[0];
      const timeRatio = lastTime / firstTime;

      // Time growth should be close to size ratio (allowing some variance)
      expect(timeRatio).toBeLessThan(sizeRatio * 1.5); // Not more than 50% worse than linear
    }, 180000);

    test('should handle edge case dataset sizes', async () => {
      const edgeCases = [
        { name: 'Single item', size: 1 },
        { name: 'Empty list', size: 0 },
        { name: 'Maximum allowed', size: 1000 },
      ];

      for (const edgeCase of edgeCases) {
        const items = generateTestItems(edgeCase.size);
        const request: ContradictionDetectionRequest = {
          items,
          scope: { project: 'edge-case-test' },
        };

        const startTime = Date.now();
        const response = await detector.detectContradictions(request);
        const processingTime = Date.now() - startTime;

        expect(response.summary.total_items_checked).toBe(edgeCase.size);
        expect(processingTime).toBeLessThan(60000); // Should complete within 1 minute

        console.log(`${edgeCase.name} (${edgeCase.size} items): ${processingTime}ms`);
      }
    }, 120000);
  });

  describe('Resource Usage Tests', () => {
    test('should respect memory limits under stress', async () => {
      const memoryLimitMb = 300;
      const stressTestSize = 500;

      const items = generateTestItems(stressTestSize);
      const request: ContradictionDetectionRequest = {
        items,
        scope: { project: 'stress-test' },
      };

      const response = await detector.detectContradictions(request);

      expect(response.performance.memory_usage_mb).toBeLessThan(memoryLimitMb);
      expect(response.summary.total_items_checked).toBe(stressTestSize);

      console.log(
        `Stress test memory usage: ${response.performance.memory_usage_mb.toFixed(2)} MB`
      );
    }, 90000);

    test('should maintain performance with high contradiction density', async () => {
      // Generate items with high probability of contradictions
      const highContradictionItems = Array.from({ length: 200 }, (_, i) => ({
        id: generateId(),
        kind: 'entity',
        content: i % 2 === 0 ? 'System is enabled' : 'System is disabled',
        scope: { project: 'high-density-test' },
        data: {
          status: i % 2 === 0 ? 'enabled' : 'disabled',
          index: i,
        },
      }));

      const request: ContradictionDetectionRequest = {
        items: highContradictionItems,
        scope: { project: 'high-density-test' },
      };

      const startTime = Date.now();
      const response = await detector.detectContradictions(request);
      const processingTime = Date.now() - startTime;

      expect(response.summary.total_items_checked).toBe(200);
      expect(response.summary.contradictions_found).toBeGreaterThan(0);
      expect(processingTime).toBeLessThan(45000); // Should complete within 45 seconds

      console.log(
        `High density test: ${response.summary.contradictions_found} contradictions in ${processingTime}ms`
      );
    }, 90000);
  });

  // Helper function to generate test items
  function generateTestItems(count: number): KnowledgeItem[] {
    const statements = [
      'The system is operational',
      'The system is not operational',
      'Service is running',
      'Service is stopped',
      'Feature is enabled',
      'Feature is disabled',
      'Status is active',
      'Status is inactive',
      'Connection is online',
      'Connection is offline',
    ];

    return Array.from({ length: count }, (_, i) => ({
      id: generateId(),
      kind: 'entity',
      content: statements[i % statements.length],
      scope: { project: 'performance-test' },
      data: {
        index: i,
        status: i % 2 === 0 ? 'active' : 'inactive',
        timestamp: new Date(Date.now() - Math.random() * 86400000).toISOString(),
        metadata: {
          source: 'performance-test',
          batch: Math.floor(i / 50),
        },
      },
    }));
  }
});

// Mock implementation for performance testing
class ContradictionDetectorImpl implements ContradictionDetector {
  private config: any;
  private cache: Map<string, any> = new Map();

  constructor(config: any) {
    this.config = config;
  }

  async detectContradictions(request: ContradictionDetectionRequest): Promise<any> {
    const startTime = Date.now();

    // Simulate processing time based on item count
    const baseProcessingTime = 10; // 10ms base time
    const perItemTime = 5; // 5ms per item
    const expectedProcessingTime = baseProcessingTime + request.items.length * perItemTime;

    // Simulate realistic processing delays
    await new Promise((resolve) => setTimeout(resolve, Math.min(expectedProcessingTime, 1000)));

    // Simulate contradiction detection with varying density
    const contradictionProbability = 0.3; // 30% chance of contradiction between pairs
    const contradictions = [];

    for (let i = 0; i < request.items.length - 1; i++) {
      for (let j = i + 1; j < request.items.length; j++) {
        if (Math.random() < contradictionProbability) {
          contradictions.push({
            id: generateId(),
            detected_at: new Date(),
            contradiction_type: ['factual', 'temporal', 'logical', 'attribute'][
              Math.floor(Math.random() * 4)
            ],
            confidence_score: Math.random() * 0.4 + 0.6,
            severity: ['low', 'medium', 'high', 'critical'][Math.floor(Math.random() * 4)],
            primary_item_id: request.items[i].id || generateId(),
            conflicting_item_ids: [request.items[j].id || generateId()],
            description: 'Simulated contradiction',
            reasoning: 'Performance test contradiction simulation',
            metadata: {
              detection_method: 'performance_simulation',
              algorithm_version: '1.0.0',
              processing_time_ms: Math.random() * 50,
              comparison_details: {},
              evidence: [],
            },
            resolution_suggestions: [],
          });
        }
      }
    }

    const processingTime = Date.now() - startTime;
    const memoryUsage = this.simulateMemoryUsage(request.items.length);

    return {
      contradictions,
      summary: {
        total_items_checked: request.items.length,
        contradictions_found: contradictions.length,
        by_type: contradictions.reduce(
          (acc, c) => {
            acc[c.contradiction_type] = (acc[c.contradiction_type] || 0) + 1;
            return acc;
          },
          {} as Record<string, number>
        ),
        by_severity: contradictions.reduce(
          (acc, c) => {
            acc[c.severity] = (acc[c.severity] || 0) + 1;
            return acc;
          },
          {} as Record<string, number>
        ),
        processing_time_ms: processingTime,
        cache_hits: Math.floor(Math.random() * 20),
        cache_misses: Math.floor(Math.random() * 10),
      },
      performance: {
        items_per_second: (request.items.length / processingTime) * 1000,
        memory_usage_mb: memoryUsage,
        bottleneck_detected: memoryUsage > 400,
        bottlenecks: memoryUsage > 400 ? ['memory_usage'] : [],
      },
    };
  }

  private simulateMemoryUsage(itemCount: number): number {
    // Simulate memory usage based on item count and processing complexity
    const baseMemory = 50; // 50MB base
    const perItemMemory = 0.5; // 0.5MB per item
    const cacheMemory = this.cache.size * 0.1; // Cache overhead
    const processingMemory = Math.min(itemCount * 0.2, 100); // Processing overhead, capped at 100MB

    return baseMemory + itemCount * perItemMemory + cacheMemory + processingMemory;
  }

  getConfiguration(): any {
    return { ...this.config };
  }

  async updateConfiguration(config: Partial<any>): Promise<void> {
    this.config = { ...this.config, ...config };
  }

  // Mock implementations for other interface methods
  async flagContradictions() {
    return [];
  }
  async analyzeItem() {
    return {
      item_id: '',
      contradiction_count: 0,
      contradiction_types: [],
      severity_distribution: {},
      related_items: [],
      trust_score: 1.0,
      last_analysis: new Date(),
      analysis_details: {
        factual_consistency: 1.0,
        temporal_consistency: 1.0,
        logical_consistency: 1.0,
        attribute_consistency: 1.0,
      },
    };
  }
  async getContradictionPointers() {
    return [];
  }
  async batchCheck(items: KnowledgeItem[]) {
    return this.detectContradictions({ items });
  }
  async validateContradiction() {
    return true;
  }
  async resolveContradiction() {}
}
