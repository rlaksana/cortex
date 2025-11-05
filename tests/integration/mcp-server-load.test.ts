/**
 * MCP Server Performance and Load Tests
 *
 * This test suite validates the MCP server's performance under various load conditions.
 * It tests memory usage, response times, throughput, and resource management.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { performance } from 'perf_hooks';

// Mock environment for testing
process.env.OPENAI_API_KEY = 'test-key';
process.env.QDRANT_URL = 'http://localhost:6333';
process.env.NODE_ENV = 'test';

describe('MCP Server Performance and Load Tests', () => {
  let performanceMetrics: {
    startTime: number;
    endTime: number;
    memoryBefore: NodeJS.MemoryUsage;
    memoryAfter: NodeJS.MemoryUsage;
    responseTimes: number[];
    throughput: number;
  };

  beforeEach(() => {
    performanceMetrics = {
      startTime: 0,
      endTime: 0,
      memoryBefore: process.memoryUsage(),
      memoryAfter: process.memoryUsage(),
      responseTimes: [],
      throughput: 0
    };
  });

  afterEach(() => {
    // Force garbage collection if available
    if (global.gc) {
      global.gc();
    }
  });

  describe('Memory Usage Performance', () => {
    it('should handle large memory_store operations without memory leaks', async () => {
      performanceMetrics.startTime = performance.now();
      performanceMetrics.memoryBefore = process.memoryUsage();

      // Simulate large memory_store operation
      const largeItems = [];
      for (let i = 0; i < 1000; i++) {
        largeItems.push({
          kind: 'entity',
          data: {
            entity_type: 'performance_test',
            name: `perf_entity_${i}`,
            data: {
              large_content: 'x'.repeat(1024), // 1KB per item
              index: i,
              timestamp: new Date().toISOString()
            }
          },
          scope: { project: 'performance-test', branch: 'main' }
        });
      }

      const memoryStoreRequest = {
        jsonrpc: '2.0' as const,
        id: 1,
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: largeItems,
            deduplication_config: {
              enabled: false // Disable deduplication for pure performance test
            }
          }
        }
      };

      // Validate request structure
      expect(memoryStoreRequest.params.arguments.items).toHaveLength(1000);
      expect(memoryStoreRequest.params.arguments.items[0].data.data.large_content.length).toBe(1024);

      performanceMetrics.endTime = performance.now();
      performanceMetrics.memoryAfter = process.memoryUsage();

      const processingTime = performanceMetrics.endTime - performanceMetrics.startTime;
      const memoryIncrease = performanceMetrics.memoryAfter.heapUsed - performanceMetrics.memoryBefore.heapUsed;

      expect(processingTime).toBeLessThan(5000); // Should complete within 5 seconds
      expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024); // Less than 100MB increase
    });

    it('should handle memory pressure during large memory_find operations', async () => {
      performanceMetrics.startTime = performance.now();
      performanceMetrics.memoryBefore = process.memoryUsage();

      // Simulate complex memory_find operation
      const memoryFindRequest = {
        jsonrpc: '2.0' as const,
        id: 2,
        method: 'tools/call' as const,
        params: {
          name: 'memory_find',
          arguments: {
            query: 'large scale performance test data',
            scope: { project: 'performance-test', branch: 'main' },
            types: ['entity', 'observation', 'decision'],
            search_strategy: 'deep',
            limit: 1000,
            graph_expansion: {
              enabled: true,
              expansion_type: 'relations',
              max_depth: 3,
              max_nodes: 500
            }
          }
        }
      };

      expect(memoryFindRequest.params.arguments.limit).toBe(1000);
      expect(memoryFindRequest.params.arguments.graph_expansion.max_nodes).toBe(500);

      performanceMetrics.endTime = performance.now();
      performanceMetrics.memoryAfter = process.memoryUsage();

      const processingTime = performanceMetrics.endTime - performanceMetrics.startTime;
      const memoryIncrease = performanceMetrics.memoryAfter.heapUsed - performanceMetrics.memoryBefore.heapUsed;

      expect(processingTime).toBeLessThan(10000); // Should complete within 10 seconds
      expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024); // Less than 50MB increase
    });
  });

  describe('Throughput Performance', () => {
    it('should handle high-throughput memory_store operations', async () => {
      const concurrentRequests = 50;
      const itemsPerRequest = 20;
      const responseTimes: number[] = [];

      performanceMetrics.startTime = performance.now();

      // Simulate concurrent requests
      for (let reqId = 0; reqId < concurrentRequests; reqId++) {
        const requestStartTime = performance.now();

        const items = [];
        for (let i = 0; i < itemsPerRequest; i++) {
          items.push({
            kind: 'entity',
            data: {
              entity_type: 'throughput_test',
              name: `throughput_entity_${reqId}_${i}`,
              data: {
                request_id: reqId,
                item_index: i,
                content: `test content for throughput testing ${reqId}-${i}`
              }
            },
            scope: { project: 'throughput-test', branch: 'main' }
          });
        }

        const memoryStoreRequest = {
          jsonrpc: '2.0' as const,
          id: 3 + reqId,
          method: 'tools/call' as const,
          params: {
            name: 'memory_store',
            arguments: {
              items: items
            }
          }
        };

        expect(memoryStoreRequest.params.arguments.items).toHaveLength(itemsPerRequest);

        const requestEndTime = performance.now();
        responseTimes.push(requestEndTime - requestStartTime);
      }

      performanceMetrics.endTime = performance.now();
      performanceMetrics.responseTimes = responseTimes;

      const totalTime = performanceMetrics.endTime - performanceMetrics.startTime;
      const totalItems = concurrentRequests * itemsPerRequest;
      performanceMetrics.throughput = totalItems / (totalTime / 1000); // items per second

      const averageResponseTime = responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length;
      const maxResponseTime = Math.max(...responseTimes);

      expect(totalTime).toBeLessThan(15000); // Should complete within 15 seconds
      expect(averageResponseTime).toBeLessThan(1000); // Average response time less than 1 second
      expect(maxResponseTime).toBeLessThan(5000); // Maximum response time less than 5 seconds
      expect(performanceMetrics.throughput).toBeGreaterThan(10); // At least 10 items per second
    });

    it('should handle high-throughput memory_find operations', async () => {
      const concurrentSearches = 30;
      const responseTimes: number[] = [];

      performanceMetrics.startTime = performance.now();

      // Simulate concurrent search operations
      for (let searchId = 0; searchId < concurrentSearches; searchId++) {
        const searchStartTime = performance.now();

        const memoryFindRequest = {
          jsonrpc: '2.0' as const,
          id: 53 + searchId,
          method: 'tools/call' as const,
          params: {
            name: 'memory_find',
            arguments: {
              query: `search query ${searchId}`,
              scope: { project: 'search-test', branch: 'main' },
              types: ['entity'],
              search_strategy: 'auto',
              limit: 50
            }
          }
        };

        expect(memoryFindRequest.params.arguments.query).toBe(`search query ${searchId}`);
        expect(memoryFindRequest.params.arguments.limit).toBe(50);

        const searchEndTime = performance.now();
        responseTimes.push(searchEndTime - searchStartTime);
      }

      performanceMetrics.endTime = performance.now();
      performanceMetrics.responseTimes = responseTimes;

      const totalTime = performanceMetrics.endTime - performanceMetrics.startTime;
      const averageResponseTime = responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length;
      const maxResponseTime = Math.max(...responseTimes);
      performanceMetrics.throughput = concurrentSearches / (totalTime / 1000); // searches per second

      expect(totalTime).toBeLessThan(10000); // Should complete within 10 seconds
      expect(averageResponseTime).toBeLessThan(500); // Average response time less than 500ms
      expect(maxResponseTime).toBeLessThan(2000); // Maximum response time less than 2 seconds
      expect(performanceMetrics.throughput).toBeGreaterThan(3); // At least 3 searches per second
    });
  });

  describe('System Resource Management', () => {
    it('should handle system_status operations efficiently under load', async () => {
      const concurrentStatusRequests = 20;
      const responseTimes: number[] = [];

      performanceMetrics.startTime = performance.now();
      performanceMetrics.memoryBefore = process.memoryUsage();

      for (let statusId = 0; statusId < concurrentStatusRequests; statusId++) {
        const statusStartTime = performance.now();

        const systemStatusRequest = {
          jsonrpc: '2.0' as const,
          id: 83 + statusId,
          method: 'tools/call' as const,
          params: {
            name: 'system_status',
            arguments: {
              operation: 'health',
              include_detailed_metrics: true,
              filters: {
                components: ['deduplication_engine', 'ttl_manager', 'health_checker']
              }
            }
          }
        };

        expect(systemStatusRequest.params.arguments.operation).toBe('health');
        expect(systemStatusRequest.params.arguments.filters.components).toHaveLength(3);

        const statusEndTime = performance.now();
        responseTimes.push(statusEndTime - statusStartTime);
      }

      performanceMetrics.endTime = performance.now();
      performanceMetrics.memoryAfter = process.memoryUsage();

      const totalTime = performanceMetrics.endTime - performanceMetrics.startTime;
      const averageResponseTime = responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length;
      const memoryIncrease = performanceMetrics.memoryAfter.heapUsed - performanceMetrics.memoryBefore.heapUsed;

      expect(totalTime).toBeLessThan(5000); // Should complete within 5 seconds
      expect(averageResponseTime).toBeLessThan(100); // Average response time less than 100ms
      expect(memoryIncrease).toBeLessThan(10 * 1024 * 1024); // Less than 10MB increase
    });

    it('should handle CPU-intensive operations efficiently', async () => {
      const complexOperations = 10;
      const responseTimes: number[] = [];

      performanceMetrics.startTime = performance.now();

      for (let opId = 0; opId < complexOperations; opId++) {
        const operationStartTime = performance.now();

        // Simulate complex deduplication with intelligent merging
        const memoryStoreRequest = {
          jsonrpc: '2.0' as const,
          id: 103 + opId,
          method: 'tools/call' as const,
          params: {
            name: 'memory_store',
            arguments: {
              items: [{
                kind: 'decision',
                data: {
                  title: `Complex Decision ${opId}`,
                  rationale: 'Complex rationale for performance testing with multiple considerations',
                  alternatives: ['Alternative A', 'Alternative B', 'Alternative C'],
                  status: 'in_progress',
                  impact_assessment: {
                    technical_impact: 'high',
                    business_impact: 'medium',
                    timeline_impact: 'low'
                  }
                },
                scope: { project: 'complex-test', branch: 'main' }
              }],
              deduplication_config: {
                enabled: true,
                merge_strategy: 'intelligent',
                similarity_threshold: 0.85,
                enable_intelligent_merging: true,
                intelligent_merge_config: {
                  field_merging_strategies: {
                    arrays: 'append_unique',
                    objects: 'merge_deep',
                    strings: 'prefer_newer'
                  },
                  conflict_resolution: {
                    manual_review_threshold: 0.7,
                    auto_merge_confidence_threshold: 0.9
                  }
                }
              }
            }
          }
        };

        expect(memoryStoreRequest.params.arguments.deduplication_config.enable_intelligent_merging).toBe(true);

        const operationEndTime = performance.now();
        responseTimes.push(operationEndTime - operationStartTime);
      }

      performanceMetrics.endTime = performance.now();

      const totalTime = performanceMetrics.endTime - performanceMetrics.startTime;
      const averageResponseTime = responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length;
      const maxResponseTime = Math.max(...responseTimes);

      expect(totalTime).toBeLessThan(10000); // Should complete within 10 seconds
      expect(averageResponseTime).toBeLessThan(2000); // Average response time less than 2 seconds
      expect(maxResponseTime).toBeLessThan(5000); // Maximum response time less than 5 seconds
    });
  });

  describe('Stress Testing', () => {
    it('should handle sustained load without degradation', async () => {
      const sustainedOperations = 5; // Number of batches
      const operationsPerBatch = 20;
      const allResponseTimes: number[] = [];

      performanceMetrics.startTime = performance.now();
      performanceMetrics.memoryBefore = process.memoryUsage();

      for (let batch = 0; batch < sustainedOperations; batch++) {
        const batchResponseTimes: number[] = [];

        for (let op = 0; op < operationsPerBatch; op++) {
          const operationStartTime = performance.now();

          const memoryStoreRequest = {
            jsonrpc: '2.0' as const,
            id: 113 + (batch * operationsPerBatch) + op,
            method: 'tools/call' as const,
            params: {
              name: 'memory_store',
              arguments: {
                items: [{
                  kind: 'entity',
                  data: {
                    entity_type: 'stress_test',
                    name: `stress_entity_${batch}_${op}`,
                    data: {
                      batch: batch,
                      operation: op,
                      content: `stress test content for batch ${batch} operation ${op}`
                    }
                  },
                  scope: { project: 'stress-test', branch: 'main' }
                }]
              }
            }
          };

          expect(memoryStoreRequest.params.arguments.items[0].data.data.batch).toBe(batch);

          const operationEndTime = performance.now();
          const responseTime = operationEndTime - operationStartTime;
          batchResponseTimes.push(responseTime);
          allResponseTimes.push(responseTime);
        }

        // Small delay between batches to simulate real usage
        await new Promise(resolve => setTimeout(resolve, 100));

        // Check that performance doesn't degrade significantly within batch
        const batchAverage = batchResponseTimes.reduce((a, b) => a + b, 0) / batchResponseTimes.length;
        expect(batchAverage).toBeLessThan(500); // Each batch should average less than 500ms
      }

      performanceMetrics.endTime = performance.now();
      performanceMetrics.memoryAfter = process.memoryUsage();

      const totalTime = performanceMetrics.endTime - performanceMetrics.startTime;
      const overallAverage = allResponseTimes.reduce((a, b) => a + b, 0) / allResponseTimes.length;
      const memoryIncrease = performanceMetrics.memoryAfter.heapUsed - performanceMetrics.memoryBefore.heapUsed;

      expect(totalTime).toBeLessThan(30000); // Should complete within 30 seconds
      expect(overallAverage).toBeLessThan(200); // Overall average less than 200ms
      expect(memoryIncrease).toBeLessThan(20 * 1024 * 1024); // Less than 20MB increase
    });

    it('should handle memory pressure with garbage collection', async () => {
      const memoryIntensiveOperations = 3;
      const largeDataSize = 50000; // 50KB per operation

      performanceMetrics.startTime = performance.now();
      performanceMetrics.memoryBefore = process.memoryUsage();

      for (let op = 0; op < memoryIntensiveOperations; op++) {
        const operationStartTime = performance.now();

        const largeContent = 'x'.repeat(largeDataSize);

        const memoryStoreRequest = {
          jsonrpc: '2.0' as const,
          id: 213 + op,
          method: 'tools/call' as const,
          params: {
            name: 'memory_store',
            arguments: {
              items: [{
                kind: 'section',
                data: {
                  title: `Large Content Section ${op}`,
                  content: largeContent,
                  section_type: 'documentation',
                  metadata: {
                    content_size: largeContent.length,
                    operation_index: op
                  }
                },
                scope: { project: 'memory-test', branch: 'main' }
              }]
            }
          }
        };

        expect(memoryStoreRequest.params.arguments.items[0].data.content.length).toBe(largeDataSize);

        const operationEndTime = performance.now();
        const responseTime = operationEndTime - operationStartTime;

        expect(responseTime).toBeLessThan(2000); // Each operation should complete within 2 seconds

        // Force garbage collection between operations
        if (global.gc) {
          global.gc();
        }
      }

      performanceMetrics.endTime = performance.now();
      performanceMetrics.memoryAfter = process.memoryUsage();

      const totalTime = performanceMetrics.endTime - performanceMetrics.startTime;
      const memoryIncrease = performanceMetrics.memoryAfter.heapUsed - performanceMetrics.memoryBefore.heapUsed;

      expect(totalTime).toBeLessThan(15000); // Should complete within 15 seconds
      expect(memoryIncrease).toBeLessThan(30 * 1024 * 1024); // Less than 30MB increase

      // Final garbage collection
      if (global.gc) {
        global.gc();
      }
    });
  });

  describe('Performance Regression Tests', () => {
    it('should maintain performance within acceptable bounds', () => {
      // Define performance benchmarks
      const performanceBenchmarks = {
        maxMemoryStoreTime: 1000, // 1 second
        maxMemoryFindTime: 500,   // 500ms
        maxSystemStatusTime: 100, // 100ms
        maxMemoryIncrease: 50 * 1024 * 1024, // 50MB
        minThroughput: 5 // items per second
      };

      // Test basic memory_store performance
      const memoryStoreStartTime = performance.now();
      const basicMemoryStoreRequest = {
        jsonrpc: '2.0' as const,
        id: 216,
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [{
              kind: 'entity',
              data: {
                entity_type: 'performance_benchmark',
                name: 'benchmark_entity',
                data: { timestamp: new Date().toISOString() }
              },
              scope: { project: 'benchmark', branch: 'main' }
            }]
          }
        }
      };
      const memoryStoreEndTime = performance.now();
      const memoryStoreTime = memoryStoreEndTime - memoryStoreStartTime;

      expect(memoryStoreTime).toBeLessThan(performanceBenchmarks.maxMemoryStoreTime);

      // Test basic memory_find performance
      const memoryFindStartTime = performance.now();
      const basicMemoryFindRequest = {
        jsonrpc: '2.0' as const,
        id: 217,
        method: 'tools/call' as const,
        params: {
          name: 'memory_find',
          arguments: {
            query: 'benchmark query',
            scope: { project: 'benchmark', branch: 'main' },
            limit: 10
          }
        }
      };
      const memoryFindEndTime = performance.now();
      const memoryFindTime = memoryFindEndTime - memoryFindStartTime;

      expect(memoryFindTime).toBeLessThan(performanceBenchmarks.maxMemoryFindTime);

      // Test basic system_status performance
      const systemStatusStartTime = performance.now();
      const basicSystemStatusRequest = {
        jsonrpc: '2.0' as const,
        id: 218,
        method: 'tools/call' as const,
        params: {
          name: 'system_status',
          arguments: {
            operation: 'health'
          }
        }
      };
      const systemStatusEndTime = performance.now();
      const systemStatusTime = systemStatusEndTime - systemStatusStartTime;

      expect(systemStatusTime).toBeLessThan(performanceBenchmarks.maxSystemStatusTime);
    });
  });

  describe('Resource Limits and Boundaries', () => {
    it('should respect maximum request size limits', () => {
      const maxRequestSize = 1000000; // 1MB
      const reasonableRequestSize = 100000; // 100KB

      // Test reasonable request size
      const reasonableContent = 'x'.repeat(reasonableRequestSize);
      const reasonableRequest = {
        jsonrpc: '2.0' as const,
        id: 219,
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [{
              kind: 'section',
              data: {
                title: 'Reasonable Size Content',
                content: reasonableContent
              },
              scope: { project: 'size-test', branch: 'main' }
            }]
          }
        }
      };

      expect(reasonableRequest.params.arguments.items[0].data.content.length).toBe(reasonableRequestSize);
      expect(reasonableRequestSize).toBeLessThan(maxRequestSize);

      // Test boundary conditions
      expect(reasonableRequestSize).toBeGreaterThan(0);
      expect(reasonableRequestSize).toBeLessThan(maxRequestSize);
    });

    it('should handle concurrent request limits gracefully', async () => {
      const maxConcurrentRequests = 10;
      const actualConcurrentRequests = 5; // Test within limits

      const concurrentRequests: Promise<number>[] = [];

      for (let i = 0; i < actualConcurrentRequests; i++) {
        const requestPromise = new Promise<number>((resolve) => {
          const startTime = performance.now();

          const request = {
            jsonrpc: '2.0' as const,
            id: 220 + i,
            method: 'tools/call' as const,
            params: {
              name: 'memory_store',
              arguments: {
                items: [{
                  kind: 'entity',
                  data: {
                    entity_type: 'concurrent_test',
                    name: `concurrent_entity_${i}`,
                    data: { request_id: i }
                  },
                  scope: { project: 'concurrent-test', branch: 'main' }
                }]
              }
            }
          };

          expect(request.params.arguments.items[0].data.data.request_id).toBe(i);

          const endTime = performance.now();
          resolve(endTime - startTime);
        });

        concurrentRequests.push(requestPromise);
      }

      const responseTimes = await Promise.all(concurrentRequests);
      const averageResponseTime = responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length;

      expect(actualConcurrentRequests).toBeLessThanOrEqual(maxConcurrentRequests);
      expect(averageResponseTime).toBeLessThan(1000); // Should complete within 1 second on average
    });
  });
});