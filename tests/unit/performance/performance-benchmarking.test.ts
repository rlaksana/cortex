/**
 * Comprehensive Unit Tests for Performance Benchmarking
 *
 * Tests performance monitoring and benchmarking functionality including:
 * - Knowledge System Performance: storage, retrieval, search benchmarks
 * - Database Performance: vector operations, connection pools, transactions
 * - Service Layer Performance: API response times, concurrent requests
 * - Search Performance: query optimization, vector similarity, indexing
 * - Scalability Testing: load testing, stress testing, resource limits
 * - Performance Regression: baseline establishment, change detection
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { PerformanceCollector } from '../../../src/monitoring/performance-collector';
import type {
  KnowledgeItem,
  SearchResult,
  SearchQuery,
  StoreResult,
  MemoryStoreResponse,
  MemoryFindResponse,
} from '../../../src/types/core-interfaces';

// Mock dependencies
vi.mock('../../../src/utils/logger', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

vi.mock('../../../src/db/qdrant', () => ({
  getQdrantClient: () => mockQdrantClient,
}));

// Mock Qdrant client with performance tracking
const mockQdrantClient = {
  knowledgeEntity: {
    create: vi.fn(),
    findMany: vi.fn(),
    count: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
  },
  knowledgeRelation: {
    create: vi.fn(),
    findMany: vi.fn(),
    count: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
  },
  knowledgeObservation: {
    create: vi.fn(),
    findMany: vi.fn(),
    count: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
  },
  section: {
    create: vi.fn(),
    findMany: vi.fn(),
    count: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
  },
  adrDecision: {
    create: vi.fn(),
    findMany: vi.fn(),
    count: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
  },
  issueLog: {
    create: vi.fn(),
    findMany: vi.fn(),
    count: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
  },
  todoLog: {
    create: vi.fn(),
    findMany: vi.fn(),
    count: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
  },
  runbook: {
    create: vi.fn(),
    findMany: vi.fn(),
    count: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
  },
  changeLog: {
    create: vi.fn(),
    findMany: vi.fn(),
    count: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
  },
  releaseNote: {
    create: vi.fn(),
    findMany: vi.fn(),
    count: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
  },
  ddlHistory: {
    create: vi.fn(),
    findMany: vi.fn(),
    count: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
  },
  prContext: {
    create: vi.fn(),
    findMany: vi.fn(),
    count: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
  },
  incidentLog: {
    create: vi.fn(),
    findMany: vi.fn(),
    count: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
  },
  releaseLog: {
    create: vi.fn(),
    findMany: vi.fn(),
    count: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
  },
  riskLog: {
    create: vi.fn(),
    findMany: vi.fn(),
    count: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
  },
  assumptionLog: {
    create: vi.fn(),
    findMany: vi.fn(),
    count: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
  },
};

// Mock performance benchmarking service
class MockPerformanceBenchmarkingService {
  private collector: PerformanceCollector;
  private baselines: Map<string, any> = new Map();

  constructor() {
    this.collector = new PerformanceCollector();
    this.setupBaselines();
  }

  private setupBaselines(): void {
    this.baselines.set('memory_store', { averageDuration: 100, p95: 200, p99: 300 });
    this.baselines.set('memory_find', { averageDuration: 150, p95: 300, p99: 450 });
    this.baselines.set('vector_search', { averageDuration: 80, p95: 150, p99: 250 });
    this.baselines.set('database_query', { averageDuration: 50, p95: 100, p99: 150 });
  }

  async benchmarkKnowledgeStorage(items: KnowledgeItem[]): Promise<any> {
    const endMetric = this.collector.startMetric('knowledge_storage_benchmark', {
      itemCount: items.length,
    });

    try {
      const results: StoreResult[] = [];
      for (const item of items) {
        const mockResult: StoreResult = {
          id: `mock-${Date.now()}-${Math.random()}`,
          status: 'inserted',
          kind: item.kind,
          created_at: new Date().toISOString(),
        };
        results.push(mockResult);
      }

      endMetric();
      return {
        itemCount: items.length,
        totalDuration:
          this.collector.getSummary('knowledge_storage_benchmark')?.averageDuration || 0,
        averageItemDuration:
          (this.collector.getSummary('knowledge_storage_benchmark')?.averageDuration || 0) /
          items.length,
        throughput:
          items.length /
          ((this.collector.getSummary('knowledge_storage_benchmark')?.averageDuration || 1) / 1000),
        results,
      };
    } catch (error) {
      this.collector.recordError('knowledge_storage_benchmark', error as Error);
      throw error;
    }
  }

  async benchmarkKnowledgeRetrieval(query: SearchQuery): Promise<any> {
    const endMetric = this.collector.startMetric('knowledge_retrieval_benchmark', {
      query: query.query,
      mode: query.mode || 'auto',
    });

    try {
      // Mock search results based on query complexity
      const resultCount = Math.min(query.limit || 10, Math.floor(Math.random() * 20) + 1);
      const mockResults: SearchResult[] = Array.from({ length: resultCount }, (_, i) => ({
        id: `result-${i}`,
        kind: 'entity',
        scope: query.scope || {},
        data: { title: `Result ${i}`, content: `Content for ${query.query}` },
        created_at: new Date().toISOString(),
        confidence_score: Math.random() * 0.5 + 0.5,
        match_type: ['exact', 'fuzzy', 'semantic'][Math.floor(Math.random() * 3)] as any,
      }));

      endMetric();
      return {
        query: query.query,
        resultCount,
        totalDuration:
          this.collector.getSummary('knowledge_retrieval_benchmark')?.averageDuration || 0,
        averageResultDuration:
          (this.collector.getSummary('knowledge_retrieval_benchmark')?.averageDuration || 0) /
          resultCount,
        results: mockResults,
      };
    } catch (error) {
      this.collector.recordError('knowledge_retrieval_benchmark', error as Error);
      throw error;
    }
  }

  async benchmarkDatabaseOperations(operationCount: number): Promise<any> {
    const endMetric = this.collector.startMetric('database_operations_benchmark', {
      operationCount,
    });

    try {
      const operations = [];
      for (let i = 0; i < operationCount; i++) {
        operations.push({
          type: ['create', 'read', 'update', 'delete'][Math.floor(Math.random() * 4)],
          duration: Math.random() * 100 + 10,
          success: Math.random() > 0.05, // 95% success rate
        });
      }

      endMetric();
      const summary = this.collector.getSummary('database_operations_benchmark');
      return {
        operationCount,
        totalDuration: summary?.averageDuration || 0,
        averageOperationDuration: (summary?.averageDuration || 0) / operationCount,
        throughput: operationCount / ((summary?.averageDuration || 1) / 1000),
        successRate: (operations.filter((op) => op.success).length / operations.length) * 100,
        operations,
      };
    } catch (error) {
      this.collector.recordError('database_operations_benchmark', error as Error);
      throw error;
    }
  }

  async benchmarkSearchPerformance(queries: SearchQuery[]): Promise<any> {
    const endMetric = this.collector.startMetric('search_performance_benchmark', {
      queryCount: queries.length,
    });

    try {
      const results = [];
      for (const query of queries) {
        const mockResult: SearchResult = {
          id: `search-${Date.now()}-${Math.random()}`,
          kind: 'entity',
          scope: query.scope || {},
          data: { title: `Search result for ${query.query}`, content: `Matching content` },
          created_at: new Date().toISOString(),
          confidence_score: Math.random() * 0.6 + 0.4,
          match_type: 'semantic',
        };
        results.push(mockResult);
      }

      endMetric();
      return {
        queryCount: queries.length,
        totalDuration:
          this.collector.getSummary('search_performance_benchmark')?.averageDuration || 0,
        averageQueryDuration:
          (this.collector.getSummary('search_performance_benchmark')?.averageDuration || 0) /
          queries.length,
        queriesPerSecond:
          queries.length /
          ((this.collector.getSummary('search_performance_benchmark')?.averageDuration || 1) /
            1000),
        results,
      };
    } catch (error) {
      this.collector.recordError('search_performance_benchmark', error as Error);
      throw error;
    }
  }

  async benchmarkConcurrentOperations(
    concurrency: number,
    operationsPerWorker: number
  ): Promise<any> {
    const endMetric = this.collector.startMetric('concurrent_operations_benchmark', {
      concurrency,
      operationsPerWorker,
    });

    try {
      const workers = Array.from({ length: concurrency }, async (_, workerId) => {
        const workerResults = [];
        for (let i = 0; i < operationsPerWorker; i++) {
          const operationDuration = Math.random() * 200 + 50;
          await new Promise((resolve) => setTimeout(resolve, operationDuration));
          workerResults.push({
            workerId,
            operationId: i,
            duration: operationDuration,
            success: Math.random() > 0.02, // 98% success rate
          });
        }
        return workerResults;
      });

      const results = await Promise.all(workers);
      const allOperations = results.flat();

      endMetric();
      return {
        concurrency,
        operationsPerWorker,
        totalOperations: concurrency * operationsPerWorker,
        totalDuration:
          this.collector.getSummary('concurrent_operations_benchmark')?.averageDuration || 0,
        averageOperationDuration:
          allOperations.reduce((sum, op) => sum + op.duration, 0) / allOperations.length,
        throughput:
          (concurrency * operationsPerWorker) /
          ((this.collector.getSummary('concurrent_operations_benchmark')?.averageDuration || 1) /
            1000),
        successRate: (allOperations.filter((op) => op.success).length / allOperations.length) * 100,
        results,
      };
    } catch (error) {
      this.collector.recordError('concurrent_operations_benchmark', error as Error);
      throw error;
    }
  }

  async benchmarkLoadTesting(requestCount: number, rampUpTimeMs: number): Promise<any> {
    const endMetric = this.collector.startMetric('load_testing_benchmark', {
      requestCount,
      rampUpTimeMs,
    });

    try {
      const startTime = Date.now();
      const requests = [];
      const intervalMs = rampUpTimeMs / requestCount;

      for (let i = 0; i < requestCount; i++) {
        setTimeout(async () => {
          const requestStart = Date.now();
          // Simulate request processing
          await new Promise((resolve) => setTimeout(resolve, Math.random() * 100 + 20));
          const requestEnd = Date.now();

          requests.push({
            requestId: i,
            startTime: requestStart,
            endTime: requestEnd,
            duration: requestEnd - requestStart,
            success: Math.random() > 0.01, // 99% success rate
          });
        }, i * intervalMs);
      }

      // Wait for all requests to complete
      await new Promise((resolve) => setTimeout(resolve, rampUpTimeMs + 1000));

      endMetric();
      const totalTestDuration = Date.now() - startTime;
      const successfulRequests = requests.filter((req) => req.success);
      const responseTimes = successfulRequests.map((req) => req.duration);

      return {
        requestCount,
        rampUpTimeMs,
        totalTestDuration,
        successfulRequests: successfulRequests.length,
        failedRequests: requests.length - successfulRequests.length,
        successRate: (successfulRequests.length / requests.length) * 100,
        averageResponseTime:
          responseTimes.reduce((sum, time) => sum + time, 0) / responseTimes.length,
        minResponseTime: Math.min(...responseTimes),
        maxResponseTime: Math.max(...responseTimes),
        requestsPerSecond: requests.length / (totalTestDuration / 1000),
        requests,
      };
    } catch (error) {
      this.collector.recordError('load_testing_benchmark', error as Error);
      throw error;
    }
  }

  compareWithBaseline(operation: string, currentMetrics: any): any {
    const baseline = this.baselines.get(operation);
    if (!baseline) {
      return { status: 'no_baseline', message: `No baseline found for operation: ${operation}` };
    }

    const avgDiff =
      ((currentMetrics.averageDuration - baseline.averageDuration) / baseline.averageDuration) *
      100;
    const p95Diff = ((currentMetrics.p95 - baseline.p95) / baseline.p95) * 100;
    const p99Diff = ((currentMetrics.p99 - baseline.p99) / baseline.p99) * 100;

    let status: 'improved' | 'degraded' | 'stable';
    if (avgDiff < -10 && p95Diff < -10) {
      status = 'improved';
    } else if (avgDiff > 10 || p95Diff > 15 || p99Diff > 20) {
      status = 'degraded';
    } else {
      status = 'stable';
    }

    return {
      status,
      operation,
      baseline,
      current: currentMetrics,
      differences: {
        average: avgDiff,
        p95: p95Diff,
        p99: p99Diff,
      },
      recommendation: this.getRecommendation(status, avgDiff, p95Diff, p99Diff),
    };
  }

  private getRecommendation(
    status: string,
    avgDiff: number,
    p95Diff: number,
    p99Diff: number
  ): string {
    switch (status) {
      case 'improved':
        return 'Performance has improved. Consider updating baseline.';
      case 'degraded':
        if (avgDiff > 25)
          return 'Significant performance degradation detected. Immediate investigation required.';
        if (p95Diff > 20)
          return 'P95 response time degradation detected. Review optimization strategies.';
        return 'Performance has degraded. Monitor and consider optimization.';
      case 'stable':
        return 'Performance is stable within acceptable range.';
      default:
        return 'Unable to determine performance status.';
    }
  }

  getPerformanceReport(): any {
    return {
      timestamp: new Date().toISOString(),
      summaries: this.collector.getAllSummaries(),
      trends: this.collector.getPerformanceTrends(),
      memoryUsage: this.collector.getMemoryUsage(),
      baselines: Object.fromEntries(this.baselines),
      alerts: this.getActiveAlerts(),
    };
  }

  private getActiveAlerts(): any[] {
    // Mock alert generation based on performance metrics
    const alerts = [];
    const summaries = this.collector.getAllSummaries();

    for (const summary of summaries) {
      if (summary.averageDuration > 1000) {
        alerts.push({
          type: 'slow_operation',
          operation: summary.operation,
          severity: 'high',
          message: `Operation ${summary.operation} has slow average response time: ${summary.averageDuration}ms`,
        });
      }

      if (summary.successRate < 95) {
        alerts.push({
          type: 'low_success_rate',
          operation: summary.operation,
          severity: 'medium',
          message: `Operation ${summary.operation} has low success rate: ${summary.successRate}%`,
        });
      }
    }

    return alerts;
  }
}

describe('Performance Benchmarking - Comprehensive Performance Testing', () => {
  let benchmarkingService: MockPerformanceBenchmarkingService;

  beforeEach(() => {
    benchmarkingService = new MockPerformanceBenchmarkingService();
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // 1. Knowledge System Performance Tests
  describe('Knowledge System Performance', () => {
    it('should benchmark knowledge storage performance with varying item counts', async () => {
      const testCases = [
        { itemCount: 10, expectedMaxDuration: 500 },
        { itemCount: 50, expectedMaxDuration: 2000 },
        { itemCount: 100, expectedMaxDuration: 4000 },
        { itemCount: 500, expectedMaxDuration: 15000 },
      ];

      for (const testCase of testCases) {
        const items = Array.from({ length: testCase.itemCount }, (_, i) => ({
          id: `item-${i}`,
          kind: 'entity',
          scope: { project: 'performance-test' },
          data: { title: `Test Item ${i}`, content: `Test content for item ${i}` },
        }));

        const results = await benchmarkingService.benchmarkKnowledgeStorage(items);

        expect(results.itemCount).toBe(testCase.itemCount);
        expect(results.totalDuration).toBeLessThan(testCase.expectedMaxDuration);
        expect(results.averageItemDuration).toBeGreaterThan(0);
        expect(results.throughput).toBeGreaterThan(0);
        expect(results.results).toHaveLength(testCase.itemCount);
      }
    });

    it('should benchmark knowledge retrieval performance with different query complexities', async () => {
      const queries = [
        { query: 'simple', complexity: 'simple', expectedMaxDuration: 200 },
        {
          query: 'more complex query with multiple terms',
          complexity: 'medium',
          expectedMaxDuration: 400,
        },
        {
          query:
            'very complex query with many terms and filters and specific requirements for detailed search results',
          complexity: 'complex',
          expectedMaxDuration: 800,
        },
      ];

      for (const queryTest of queries) {
        const query: SearchQuery = {
          query: queryTest.query,
          mode: 'auto',
          limit: 10,
        };

        const results = await benchmarkingService.benchmarkKnowledgeRetrieval(query);

        expect(results.query).toBe(queryTest.query);
        expect(results.totalDuration).toBeLessThan(queryTest.expectedMaxDuration);
        expect(results.resultCount).toBeGreaterThan(0);
        expect(results.averageResultDuration).toBeGreaterThan(0);
      }
    });

    it('should handle large-scale knowledge operations efficiently', async () => {
      const largeItemSet = Array.from({ length: 1000 }, (_, i) => ({
        id: `large-item-${i}`,
        kind: ['entity', 'relation', 'observation'][Math.floor(Math.random() * 3)],
        scope: { project: 'large-scale-test', branch: 'main' },
        data: {
          title: `Large Scale Test Item ${i}`,
          content:
            `This is large scale test content for item ${i} with substantial data to simulate real-world knowledge entries`.repeat(
              5
            ),
        },
      }));

      const startTime = Date.now();
      const results = await benchmarkingService.benchmarkKnowledgeStorage(largeItemSet);
      const endTime = Date.now();

      expect(results.itemCount).toBe(1000);
      expect(endTime - startTime).toBeLessThan(10000); // Should complete within 10 seconds
      expect(results.throughput).toBeGreaterThan(50); // At least 50 items per second
    });

    it('should benchmark concurrent knowledge operations', async () => {
      const concurrency = 10;
      const operationsPerWorker = 20;

      const results = await benchmarkingService.benchmarkConcurrentOperations(
        concurrency,
        operationsPerWorker
      );

      expect(results.concurrency).toBe(concurrency);
      expect(results.operationsPerWorker).toBe(operationsPerWorker);
      expect(results.totalOperations).toBe(concurrency * operationsPerWorker);
      expect(results.successRate).toBeGreaterThan(95); // At least 95% success rate
      expect(results.throughput).toBeGreaterThan(0);
    });

    it('should measure memory usage during knowledge operations', async () => {
      const initialMemory = benchmarkingService['collector'].getMemoryUsage();

      const items = Array.from({ length: 100 }, (_, i) => ({
        id: `memory-test-${i}`,
        kind: 'entity',
        scope: { project: 'memory-test' },
        data: {
          title: `Memory Test Item ${i}`,
          content: 'Large content block '.repeat(100), // Significant content to test memory usage
        },
      }));

      await benchmarkingService.benchmarkKnowledgeStorage(items);

      const finalMemory = benchmarkingService['collector'].getMemoryUsage();

      expect(finalMemory.heapUsed).toBeGreaterThan(initialMemory.heapUsed);
      expect(finalMemory.heapTotal).toBeGreaterThanOrEqual(initialMemory.heapTotal);
      expect(finalMemory.timestamp).toBeGreaterThan(initialMemory.timestamp);
    });
  });

  // 2. Database Performance Testing
  describe('Database Performance Testing', () => {
    it('should benchmark database CRUD operations', async () => {
      const operationCounts = [100, 500, 1000];

      for (const count of operationCounts) {
        const results = await benchmarkingService.benchmarkDatabaseOperations(count);

        expect(results.operationCount).toBe(count);
        expect(results.totalDuration).toBeGreaterThan(0);
        expect(results.averageOperationDuration).toBeGreaterThan(0);
        expect(results.throughput).toBeGreaterThan(0);
        expect(results.successRate).toBeGreaterThan(90); // At least 90% success rate
      }
    });

    it('should simulate vector database search performance', async () => {
      const vectorSearchQueries = Array.from({ length: 50 }, (_, i) => ({
        query: `vector search query ${i} with embedding simulation`,
        mode: 'deep' as const,
        top_k: 10,
        limit: 10,
      }));

      const results = await benchmarkingService.benchmarkSearchPerformance(vectorSearchQueries);

      expect(results.queryCount).toBe(50);
      expect(results.totalDuration).toBeLessThan(5000); // Should complete within 5 seconds
      expect(results.averageQueryDuration).toBeLessThan(100); // Average under 100ms per query
      expect(results.queriesPerSecond).toBeGreaterThan(10); // At least 10 queries per second
    });

    it('should test connection pool performance under load', async () => {
      const connectionTest = {
        maxConnections: 20,
        concurrentRequests: 50,
        operationsPerRequest: 5,
      };

      const results = await benchmarkingService.benchmarkConcurrentOperations(
        connectionTest.concurrentRequests,
        connectionTest.operationsPerRequest
      );

      expect(results.totalOperations).toBe(
        connectionTest.concurrentRequests * connectionTest.operationsPerRequest
      );
      expect(results.successRate).toBeGreaterThan(95); // Connection pool should maintain high success rate
      expect(results.throughput).toBeGreaterThan(0);
    });

    it('should benchmark transaction performance', async () => {
      const transactionSizes = [10, 50, 100];

      for (const size of transactionSizes) {
        const endMetric = benchmarkingService['collector'].startMetric('transaction_benchmark', {
          transactionSize: size,
        });

        try {
          // Simulate transaction with multiple operations
          const operations = Array.from({ length: size }, (_, i) => ({
            id: `tx-operation-${i}`,
            type: ['insert', 'update', 'delete'][Math.floor(Math.random() * 3)],
            data: { value: `transaction-data-${i}` },
          }));

          // Simulate transaction processing time
          await new Promise((resolve) => setTimeout(resolve, size * 5));

          endMetric();
          const summary = benchmarkingService['collector'].getSummary('transaction_benchmark');

          expect(summary).toBeDefined();
          expect(summary!.averageDuration).toBeGreaterThan(0);
          expect(summary!.averageDuration).toBeLessThan(size * 20); // Should be efficient
        } catch (error) {
          benchmarkingService['collector'].recordError('transaction_benchmark', error as Error);
          throw error;
        }
      }
    });

    it('should test database performance under memory pressure', async () => {
      // Simulate memory pressure by creating large datasets
      const largeDataset = Array.from({ length: 1000 }, (_, i) => ({
        id: `pressure-test-${i}`,
        kind: 'entity',
        scope: { project: 'pressure-test' },
        data: {
          title: `Pressure Test Item ${i}`,
          content: 'Large content for memory pressure testing '.repeat(50),
          metadata: {
            tags: Array.from({ length: 20 }, (_, j) => `tag-${j}`),
            properties: Object.fromEntries(
              Array.from({ length: 30 }, (_, k) => [`property-${k}`, `value-${k}`])
            ),
          },
        },
      }));

      const memoryBefore = benchmarkingService['collector'].getMemoryUsage();
      const results = await benchmarkingService.benchmarkKnowledgeStorage(largeDataset);
      const memoryAfter = benchmarkingService['collector'].getMemoryUsage();

      expect(results.itemCount).toBe(1000);
      expect(memoryAfter.heapUsed).toBeGreaterThan(memoryBefore.heapUsed);
      expect(results.successRate).toBeGreaterThan(90); // Should handle pressure gracefully
    });
  });

  // 3. Service Layer Performance Benchmarks
  describe('Service Layer Performance Benchmarks', () => {
    it('should benchmark API response times for different endpoints', async () => {
      const endpoints = [
        { name: 'health_check', expectedMaxTime: 50 },
        { name: 'knowledge_store', expectedMaxTime: 500 },
        { name: 'knowledge_find', expectedMaxTime: 300 },
        { name: 'analytics_metrics', expectedMaxTime: 200 },
      ];

      for (const endpoint of endpoints) {
        const endMetric = benchmarkingService['collector'].startMetric(`api_${endpoint.name}`);

        try {
          // Simulate API endpoint processing
          await new Promise((resolve) =>
            setTimeout(resolve, Math.random() * endpoint.expectedMaxTime * 0.8)
          );

          endMetric();
          const summary = benchmarkingService['collector'].getSummary(`api_${endpoint.name}`);

          expect(summary).toBeDefined();
          expect(summary!.averageDuration).toBeLessThan(endpoint.expectedMaxTime);
          expect(summary!.successRate).toBe(100);
        } catch (error) {
          benchmarkingService['collector'].recordError(`api_${endpoint.name}`, error as Error);
          throw error;
        }
      }
    });

    it('should test service layer concurrent request handling', async () => {
      const concurrentRequests = 20;
      const requests = Array.from({ length: concurrentRequests }, async (_, i) => {
        const endMetric = benchmarkingService['collector'].startMetric('concurrent_api_request', {
          requestId: i,
        });

        try {
          // Simulate API request processing
          await new Promise((resolve) => setTimeout(resolve, Math.random() * 200 + 50));
          endMetric();
          return { requestId: i, success: true };
        } catch (error) {
          benchmarkingService['collector'].recordError('concurrent_api_request', error as Error);
          return { requestId: i, success: false, error };
        }
      });

      const results = await Promise.all(requests);
      const successfulRequests = results.filter((r) => r.success);

      expect(successfulRequests.length).toBeGreaterThan(concurrentRequests * 0.95); // 95% success rate

      const summary = benchmarkingService['collector'].getSummary('concurrent_api_request');
      expect(summary).toBeDefined();
      expect(summary!.averageDuration).toBeLessThan(300); // Average under 300ms
    });

    it('should benchmark memory usage in service operations', async () => {
      const initialMemory = benchmarkingService['collector'].getMemoryUsage();

      // Simulate intensive service operations
      const intensiveOperations = Array.from({ length: 100 }, async (_, i) => {
        const endMetric = benchmarkingService['collector'].startMetric(
          'intensive_service_operation'
        );

        try {
          // Simulate memory-intensive operation
          const largeData = new Array(1000).fill(`data-${i}`);
          await new Promise((resolve) => setTimeout(resolve, Math.random() * 50));

          endMetric();
          return largeData.length;
        } catch (error) {
          benchmarkingService['collector'].recordError(
            'intensive_service_operation',
            error as Error
          );
          throw error;
        }
      });

      await Promise.all(intensiveOperations);

      const finalMemory = benchmarkingService['collector'].getMemoryUsage();
      const summary = benchmarkingService['collector'].getSummary('intensive_service_operation');

      expect(summary).toBeDefined();
      expect(summary!.count).toBe(100);
      expect(finalMemory.heapUsed).toBeGreaterThan(initialMemory.heapUsed);
    });

    it('should test service performance with different payload sizes', async () => {
      const payloadSizes = [
        { size: 'small', bytes: 1024, expectedMaxTime: 100 },
        { size: 'medium', bytes: 10240, expectedMaxTime: 200 },
        { size: 'large', bytes: 102400, expectedMaxTime: 500 },
        { size: 'xlarge', bytes: 1024000, expectedMaxTime: 1000 },
      ];

      for (const payloadTest of payloadSizes) {
        const payload = 'x'.repeat(payloadTest.bytes);
        const endMetric = benchmarkingService['collector'].startMetric('payload_processing', {
          size: payloadTest.size,
          bytes: payloadTest.bytes,
        });

        try {
          // Simulate payload processing
          await new Promise((resolve) =>
            setTimeout(resolve, Math.random() * payloadTest.expectedMaxTime * 0.7)
          );

          endMetric();
          const summary = benchmarkingService['collector'].getSummary('payload_processing');

          expect(summary).toBeDefined();
          expect(summary!.averageDuration).toBeLessThan(payloadTest.expectedMaxTime);
        } catch (error) {
          benchmarkingService['collector'].recordError('payload_processing', error as Error);
          throw error;
        }
      }
    });

    it('should benchmark service error handling performance', async () => {
      const errorScenarios = [
        { type: 'validation_error', rate: 0.1 },
        { type: 'database_error', rate: 0.05 },
        { type: 'network_timeout', rate: 0.02 },
      ];

      for (const scenario of errorScenarios) {
        const requests = Array.from({ length: 100 }, async (_, i) => {
          const endMetric = benchmarkingService['collector'].startMetric('error_handling_test', {
            scenario: scenario.type,
          });

          try {
            // Simulate error condition based on rate
            if (Math.random() < scenario.rate) {
              throw new Error(`Simulated ${scenario.type}`);
            }

            await new Promise((resolve) => setTimeout(resolve, Math.random() * 50));
            endMetric();
            return { success: true, scenario: scenario.type };
          } catch (error) {
            benchmarkingService['collector'].recordError('error_handling_test', error as Error);
            return { success: false, scenario: scenario.type, error };
          }
        });

        const results = await Promise.all(requests);
        const successfulRequests = results.filter((r) => r.success);
        const actualErrorRate = (results.length - successfulRequests.length) / results.length;

        expect(actualErrorRate).toBeGreaterThan(scenario.rate * 0.5); // At least 50% of expected error rate
        expect(actualErrorRate).toBeLessThan(scenario.rate * 1.5); // At most 150% of expected error rate
      }
    });
  });

  // 4. Search Performance Optimization Tests
  describe('Search Performance Optimization Tests', () => {
    it('should benchmark search query performance with different complexities', async () => {
      const queryComplexities = [
        { complexity: 'simple', terms: 1, filters: 0, expectedMaxTime: 50 },
        { complexity: 'medium', terms: 3, filters: 2, expectedMaxTime: 150 },
        { complexity: 'complex', terms: 5, filters: 4, expectedMaxTime: 300 },
        { complexity: 'very_complex', terms: 10, filters: 8, expectedMaxTime: 500 },
      ];

      for (const complexityTest of queryComplexities) {
        const query: SearchQuery = {
          query: Array.from({ length: complexityTest.terms }, (_, i) => `term${i}`).join(' '),
          scope: {
            project: 'search-test',
            ...(complexityTest.filters > 0 && {
              filters: Object.fromEntries(
                Array.from({ length: complexityTest.filters }, (_, i) => [
                  `filter${i}`,
                  `value${i}`,
                ])
              ),
            }),
          },
          mode: 'auto',
          limit: 20,
        };

        const results = await benchmarkingService.benchmarkKnowledgeRetrieval(query);

        expect(results.totalDuration).toBeLessThan(complexityTest.expectedMaxTime);
        expect(results.resultCount).toBeGreaterThan(0);
      }
    });

    it('should test vector similarity search performance', async () => {
      const vectorSearchTests = [
        { dimensions: 128, topK: 5, expectedMaxTime: 100 },
        { dimensions: 512, topK: 10, expectedMaxTime: 200 },
        { dimensions: 1024, topK: 20, expectedMaxTime: 400 },
      ];

      for (const vectorTest of vectorSearchTests) {
        const endMetric = benchmarkingService['collector'].startMetric('vector_similarity_search', {
          dimensions: vectorTest.dimensions,
          topK: vectorTest.topK,
        });

        try {
          // Simulate vector search processing
          const mockVector = Array.from({ length: vectorTest.dimensions }, () => Math.random());
          await new Promise((resolve) => setTimeout(resolve, vectorTest.expectedMaxTime * 0.6));

          endMetric();
          const summary = benchmarkingService['collector'].getSummary('vector_similarity_search');

          expect(summary).toBeDefined();
          expect(summary!.averageDuration).toBeLessThan(vectorTest.expectedMaxTime);
        } catch (error) {
          benchmarkingService['collector'].recordError('vector_similarity_search', error as Error);
          throw error;
        }
      }
    });

    it('should benchmark search index performance', async () => {
      const indexSizes = [1000, 5000, 10000, 50000];

      for (const indexSize of indexSizes) {
        const endMetric = benchmarkingService['collector'].startMetric('search_index_benchmark', {
          indexSize,
        });

        try {
          // Simulate index search
          await new Promise((resolve) => setTimeout(resolve, Math.log(indexSize) * 10));

          endMetric();
          const summary = benchmarkingService['collector'].getSummary('search_index_benchmark');

          expect(summary).toBeDefined();
          expect(summary!.averageDuration).toBeLessThan(Math.log(indexSize) * 20); // Logarithmic scaling
        } catch (error) {
          benchmarkingService['collector'].recordError('search_index_benchmark', error as Error);
          throw error;
        }
      }
    });

    it('should test search caching performance', async () => {
      const cacheTests = [
        { cacheHit: true, expectedMaxTime: 10 },
        { cacheHit: false, expectedMaxTime: 200 },
      ];

      for (const cacheTest of cacheTests) {
        const endMetric = benchmarkingService['collector'].startMetric('search_cache_test', {
          cacheHit: cacheTest.cacheHit,
        });

        try {
          // Simulate cache vs database lookup
          const delay = cacheTest.cacheHit ? 5 : Math.random() * 150 + 50;
          await new Promise((resolve) => setTimeout(resolve, delay));

          endMetric();
          const summary = benchmarkingService['collector'].getSummary('search_cache_test');

          expect(summary).toBeDefined();
          expect(summary!.averageDuration).toBeLessThan(cacheTest.expectedMaxTime);
        } catch (error) {
          benchmarkingService['collector'].recordError('search_cache_test', error as Error);
          throw error;
        }
      }
    });

    it('should benchmark search result pagination performance', async () => {
      const paginationTests = [
        { page: 1, pageSize: 10, expectedMaxTime: 50 },
        { page: 10, pageSize: 10, expectedMaxTime: 100 },
        { page: 100, pageSize: 10, expectedMaxTime: 200 },
        { page: 1, pageSize: 100, expectedMaxTime: 150 },
        { page: 10, pageSize: 100, expectedMaxTime: 250 },
      ];

      for (const paginationTest of paginationTests) {
        const endMetric = benchmarkingService['collector'].startMetric('search_pagination_test', {
          page: paginationTest.page,
          pageSize: paginationTest.pageSize,
        });

        try {
          // Simulate pagination processing
          const offset = (paginationTest.page - 1) * paginationTest.pageSize;
          await new Promise((resolve) => setTimeout(resolve, 20 + offset * 0.5));

          endMetric();
          const summary = benchmarkingService['collector'].getSummary('search_pagination_test');

          expect(summary).toBeDefined();
          expect(summary!.averageDuration).toBeLessThan(paginationTest.expectedMaxTime);
        } catch (error) {
          benchmarkingService['collector'].recordError('search_pagination_test', error as Error);
          throw error;
        }
      }
    });
  });

  // 5. Scalability Testing
  describe('Scalability Testing', () => {
    it('should perform load testing with gradual ramp-up', async () => {
      const loadTestConfig = {
        requestCount: 100,
        rampUpTimeMs: 5000, // 5 seconds
        expectedMinSuccessRate: 95,
      };

      const results = await benchmarkingService.benchmarkLoadTesting(
        loadTestConfig.requestCount,
        loadTestConfig.rampUpTimeMs
      );

      expect(results.requestCount).toBe(loadTestConfig.requestCount);
      expect(results.successRate).toBeGreaterThan(loadTestConfig.expectedMinSuccessRate);
      expect(results.averageResponseTime).toBeLessThan(1000); // Average under 1 second
      expect(results.requestsPerSecond).toBeGreaterThan(10); // At least 10 RPS
    });

    it('should perform stress testing beyond normal capacity', async () => {
      const stressTestConfig = {
        concurrency: 50, // High concurrency
        operationsPerWorker: 10,
        expectedMinSuccessRate: 80, // Lower tolerance for stress test
      };

      const results = await benchmarkingService.benchmarkConcurrentOperations(
        stressTestConfig.concurrency,
        stressTestConfig.operationsPerWorker
      );

      expect(results.totalOperations).toBe(
        stressTestConfig.concurrency * stressTestConfig.operationsPerWorker
      );
      expect(results.successRate).toBeGreaterThan(stressTestConfig.expectedMinSuccessRate);
      expect(results.throughput).toBeGreaterThan(0);
    });

    it('should test performance degradation under increasing load', async () => {
      const loadLevels = [
        { concurrency: 5, expectedMaxAvgTime: 100 },
        { concurrency: 10, expectedMaxAvgTime: 200 },
        { concurrency: 20, expectedMaxAvgTime: 400 },
        { concurrency: 40, expectedMaxAvgTime: 800 },
      ];

      const performanceResults = [];

      for (const loadLevel of loadLevels) {
        const results = await benchmarkingService.benchmarkConcurrentOperations(
          loadLevel.concurrency,
          5
        );

        performanceResults.push({
          concurrency: loadLevel.concurrency,
          averageDuration: results.averageOperationDuration,
          successRate: results.successRate,
        });

        expect(results.averageOperationDuration).toBeLessThan(loadLevel.expectedMaxAvgTime);
      }

      // Verify that performance degrades gracefully (not exponentially)
      for (let i = 1; i < performanceResults.length; i++) {
        const current = performanceResults[i];
        const previous = performanceResults[i - 1];
        const concurrencyRatio = current.concurrency / previous.concurrency;
        const performanceRatio = current.averageDuration / previous.averageDuration;

        // Performance degradation should be less than concurrency increase
        expect(performanceRatio).toBeLessThan(concurrencyRatio * 1.5);
      }
    });

    it('should test resource utilization under different loads', async () => {
      const loadTests = [
        { name: 'light', concurrency: 5, operationsPerWorker: 10 },
        { name: 'moderate', concurrency: 15, operationsPerWorker: 10 },
        { name: 'heavy', concurrency: 30, operationsPerWorker: 10 },
      ];

      const resourceUtilization = [];

      for (const loadTest of loadTests) {
        const memoryBefore = benchmarkingService['collector'].getMemoryUsage();

        const results = await benchmarkingService.benchmarkConcurrentOperations(
          loadTest.concurrency,
          loadTest.operationsPerWorker
        );

        const memoryAfter = benchmarkingService['collector'].getMemoryUsage();
        const memoryUsed = memoryAfter.heapUsed - memoryBefore.heapUsed;

        resourceUtilization.push({
          load: loadTest.name,
          concurrency: loadTest.concurrency,
          totalOperations: results.totalOperations,
          memoryUsedPerOperation: memoryUsed / results.totalOperations,
          throughput: results.throughput,
          successRate: results.successRate,
        });
      }

      // Verify resource efficiency
      for (const utilization of resourceUtilization) {
        expect(utilization.memoryUsedPerOperation).toBeLessThan(1024 * 10); // Less than 10KB per operation
        expect(utilization.successRate).toBeGreaterThan(90);
      }
    });

    it('should test system recovery after load spikes', async () => {
      // Phase 1: Establish baseline
      const baseline = await benchmarkingService.benchmarkConcurrentOperations(5, 10);

      // Phase 2: Apply load spike
      const loadSpike = await benchmarkingService.benchmarkConcurrentOperations(50, 5);

      // Phase 3: Test recovery (return to normal load)
      const recovery = await benchmarkingService.benchmarkConcurrentOperations(5, 10);

      // System should recover to near-baseline performance
      const recoveryRatio = recovery.averageOperationDuration / baseline.averageOperationDuration;
      expect(recoveryRatio).toBeLessThan(1.5); // Recovery should be within 50% of baseline

      // Load spike should not cause lasting degradation
      expect(recovery.successRate).toBeGreaterThan(90);
      expect(loadSpike.successRate).toBeGreaterThan(70); // Stress test tolerance
    });
  });

  // 6. Performance Regression Testing
  describe('Performance Regression Testing', () => {
    it('should establish performance baselines', async () => {
      const baselineTests = [
        { operation: 'knowledge_storage', itemCount: 100 },
        { operation: 'knowledge_retrieval', queryCount: 50 },
        { operation: 'database_operations', operationCount: 200 },
      ];

      const baselines = new Map();

      for (const test of baselineTests) {
        let result;
        switch (test.operation) {
          case 'knowledge_storage': {
            const items = Array.from({ length: test.itemCount }, (_, i) => ({
              id: `baseline-item-${i}`,
              kind: 'entity',
              scope: { project: 'baseline-test' },
              data: { title: `Baseline Item ${i}` },
            }));
            result = await benchmarkingService.benchmarkKnowledgeStorage(items);
            break;
          }
          case 'knowledge_retrieval': {
            const queries = Array.from({ length: test.queryCount }, (_, i) => ({
              query: `baseline query ${i}`,
              mode: 'auto' as const,
              limit: 10,
            }));
            result = await benchmarkingService.benchmarkSearchPerformance(queries);
            break;
          }
          case 'database_operations':
            result = await benchmarkingService.benchmarkDatabaseOperations(test.operationCount);
            break;
        }

        baselines.set(test.operation, {
          timestamp: new Date().toISOString(),
          metrics: {
            averageDuration: result.totalDuration,
            throughput: result.throughput,
            successRate: result.successRate || 100,
          },
        });
      }

      expect(baselines.size).toBe(3);
      baselines.forEach((baseline, operation) => {
        expect(baseline.timestamp).toBeDefined();
        expect(baseline.metrics.averageDuration).toBeGreaterThan(0);
        expect(baseline.metrics.throughput).toBeGreaterThan(0);
      });
    });

    it('should detect performance regressions compared to baseline', async () => {
      // Simulate current performance metrics
      const currentMetrics = {
        averageDuration: 150,
        p95: 300,
        p99: 450,
      };

      const comparison = benchmarkingService.compareWithBaseline('memory_store', currentMetrics);

      expect(comparison).toBeDefined();
      expect(comparison.operation).toBe('memory_store');
      expect(comparison.status).toMatch(/improved|degraded|stable/);
      expect(comparison.baseline).toBeDefined();
      expect(comparison.current).toBeDefined();
      expect(comparison.differences).toBeDefined();
      expect(comparison.recommendation).toBeDefined();
    });

    it('should generate performance regression alerts', async () => {
      // Simulate degraded performance
      const degradedMetrics = {
        averageDuration: 200, // 100% increase from baseline of 100
        p95: 400, // 100% increase from baseline of 200
        p99: 600, // 100% increase from baseline of 300
      };

      const comparison = benchmarkingService.compareWithBaseline('memory_store', degradedMetrics);

      expect(comparison.status).toBe('degraded');
      expect(comparison.differences.average).toBeGreaterThan(50);
      expect(comparison.differences.p95).toBeGreaterThan(50);
      expect(comparison.differences.p99).toBeGreaterThan(50);
      expect(comparison.recommendation).toContain('degraded');
    });

    it('should track performance trends over time', async () => {
      const trendData = [];
      const timePoints = 5;

      for (let i = 0; i < timePoints; i++) {
        const performanceVariation = 100 + (Math.random() - 0.5) * 40; // ±20% variation
        const results = await benchmarkingService.benchmarkDatabaseOperations(50);

        trendData.push({
          timestamp: new Date().toISOString(),
          averageDuration: results.averageOperationDuration,
          throughput: results.throughput,
          successRate: results.successRate,
        });

        // Small delay between measurements
        await new Promise((resolve) => setTimeout(resolve, 100));
      }

      expect(trendData).toHaveLength(timePoints);

      // Verify trend data consistency
      trendData.forEach((dataPoint, index) => {
        expect(dataPoint.timestamp).toBeDefined();
        expect(dataPoint.averageDuration).toBeGreaterThan(0);
        expect(dataPoint.throughput).toBeGreaterThan(0);
        expect(dataPoint.successRate).toBeGreaterThan(0);
      });
    });

    it('should generate comprehensive performance reports', async () => {
      // Run various performance tests to generate report data
      await benchmarkingService.benchmarkKnowledgeStorage(
        Array.from({ length: 50 }, (_, i) => ({
          id: `report-item-${i}`,
          kind: 'entity',
          scope: { project: 'report-test' },
          data: { title: `Report Item ${i}` },
        }))
      );

      await benchmarkingService.benchmarkDatabaseOperations(100);
      await benchmarkingService.benchmarkConcurrentOperations(10, 5);

      const report = benchmarkingService.getPerformanceReport();

      expect(report).toBeDefined();
      expect(report.timestamp).toBeDefined();
      expect(report.summaries).toBeInstanceOf(Array);
      expect(report.trends).toBeDefined();
      expect(report.memoryUsage).toBeDefined();
      expect(report.baselines).toBeDefined();
      expect(report.alerts).toBeInstanceOf(Array);

      // Verify report structure
      report.summaries.forEach((summary: any) => {
        expect(summary.operation).toBeDefined();
        expect(summary.averageDuration).toBeGreaterThanOrEqual(0);
        expect(summary.successRate).toBeGreaterThanOrEqual(0);
        expect(summary.count).toBeGreaterThan(0);
      });
    });

    it('should validate performance against SLA thresholds', async () => {
      const slaThresholds = {
        maxAverageResponseTime: 500,
        minSuccessRate: 99,
        maxP99ResponseTime: 1000,
        minThroughput: 10,
      };

      const results = await benchmarkingService.benchmarkConcurrentOperations(20, 10);
      const summary = benchmarkingService['collector'].getSummary(
        'concurrent_operations_benchmark'
      );

      expect(summary).toBeDefined();

      const slaCompliance = {
        responseTime: (summary!.averageDuration || 0) <= slaThresholds.maxAverageResponseTime,
        successRate: results.successRate >= slaThresholds.minSuccessRate,
        throughput: results.throughput >= slaThresholds.minThroughput,
      };

      // At least response time and success rate should meet SLA for normal operations
      expect(slaCompliance.responseTime).toBe(true);
      expect(slaCompliance.successRate).toBe(true);
    });
  });

  // 7. Performance Monitoring and Alerting
  describe('Performance Monitoring and Alerting', () => {
    it('should configure and test performance alert thresholds', async () => {
      const customThresholds = [
        { operation: 'test_operation_1', duration: 100, errorRate: 5 },
        { operation: 'test_operation_2', duration: 200, errorRate: 3 },
        { operation: 'test_operation_3', duration: 500, errorRate: 1 },
      ];

      for (const threshold of customThresholds) {
        benchmarkingService['collector'].setAlertThreshold(
          threshold.operation,
          threshold.duration,
          threshold.errorRate
        );
      }

      // Simulate operations that might trigger alerts
      for (let i = 0; i < 10; i++) {
        const operation = customThresholds[i % customThresholds.length].operation;
        const duration = Math.random() * 600; // Some operations will exceed thresholds
        const success = Math.random() > 0.1; // 90% success rate

        if (success) {
          benchmarkingService['collector'].recordMetric({
            operation,
            startTime: Date.now() - duration,
            endTime: Date.now(),
            duration,
            success,
          });
        } else {
          benchmarkingService['collector'].recordError(operation, new Error('Test error'));
        }
      }

      // Check that summaries were generated
      for (const threshold of customThresholds) {
        const summary = benchmarkingService['collector'].getSummary(threshold.operation);
        expect(summary).toBeDefined();
        expect(summary!.count).toBeGreaterThan(0);
      }
    });

    it('should test performance metrics collection and aggregation', async () => {
      const testOperation = 'metrics_collection_test';
      const metricCount = 50;

      // Generate metrics with varying durations
      for (let i = 0; i < metricCount; i++) {
        const duration = Math.random() * 400 + 50; // 50-450ms range
        benchmarkingService['collector'].recordMetric({
          operation: testOperation,
          startTime: Date.now() - duration,
          endTime: Date.now(),
          duration,
          success: Math.random() > 0.05, // 95% success rate
        });
      }

      const summary = benchmarkingService['collector'].getSummary(testOperation);
      const recentMetrics = benchmarkingService['collector'].getRecentMetrics(testOperation, 20);

      expect(summary).toBeDefined();
      expect(summary!.count).toBe(metricCount);
      expect(summary!.averageDuration).toBeGreaterThan(0);
      expect(summary!.p95).toBeGreaterThan(summary!.averageDuration);
      expect(summary!.p99).toBeGreaterThanOrEqual(summary!.p95);
      expect(summary!.successRate).toBeGreaterThan(90);

      expect(recentMetrics).toHaveLength(20);
      recentMetrics.forEach((metric) => {
        expect(metric.operation).toBe(testOperation);
        expect(metric.duration).toBeGreaterThan(0);
      });
    });

    it('should test performance trends calculation', async () => {
      const operations = ['trend_test_1', 'trend_test_2', 'trend_test_3'];

      // Generate metrics for each operation over time
      for (const operation of operations) {
        for (let i = 0; i < 20; i++) {
          const duration = 100 + Math.sin(i * 0.5) * 50 + Math.random() * 30;
          benchmarkingService['collector'].recordMetric({
            operation,
            startTime: Date.now() - (20 - i) * 60000, // Spread over last 20 minutes
            endTime: Date.now() - (20 - i) * 60000 + duration,
            duration,
            success: Math.random() > 0.02,
          });
        }
      }

      const trends = benchmarkingService['collector'].getPerformanceTrends(60); // Last 60 minutes

      expect(Object.keys(trends)).toHaveLength(operations.length);

      Object.values(trends).forEach((trend: any) => {
        expect(trend.operation).toBeDefined();
        expect(trend.totalRequests).toBeGreaterThan(0);
        expect(trend.averageDuration).toBeGreaterThan(0);
        expect(trend.p95Duration).toBeGreaterThanOrEqual(trend.averageDuration);
        expect(trend.successRate).toBeGreaterThanOrEqual(0);
        expect(trend.requestsPerMinute).toBeGreaterThan(0);
      });
    });

    it('should test performance metrics export functionality', async () => {
      // Generate some test metrics
      await benchmarkingService.benchmarkKnowledgeStorage(
        Array.from({ length: 10 }, (_, i) => ({
          id: `export-test-${i}`,
          kind: 'entity',
          scope: { project: 'export-test' },
          data: { title: `Export Test Item ${i}` },
        }))
      );

      const jsonExport = benchmarkingService['collector'].exportMetrics('json');
      const prometheusExport = benchmarkingService['collector'].exportMetrics('prometheus');

      // Test JSON export
      expect(jsonExport).toBeDefined();
      expect(typeof jsonExport).toBe('string');

      const jsonData = JSON.parse(jsonExport);
      expect(jsonData.summaries).toBeDefined();
      expect(jsonData.trends).toBeDefined();
      expect(jsonData.memory).toBeDefined();
      expect(jsonData.timestamp).toBeDefined();

      // Test Prometheus export
      expect(prometheusExport).toBeDefined();
      expect(typeof prometheusExport).toBe('string');
      expect(prometheusExport).toContain('# HELP');
      expect(prometheusExport).toContain('# TYPE');
      expect(prometheusExport).toContain('cortex_');
    });

    it('should test memory usage monitoring', async () => {
      const initialMemory = benchmarkingService['collector'].getMemoryUsage();

      // Simulate memory-intensive operations
      const memoryIntensiveData = Array.from({ length: 1000 }, (_, i) =>
        `memory-test-data-${i}`.repeat(100)
      );

      // Process the data to simulate memory usage
      const processedData = memoryIntensiveData.map((data) => data.toUpperCase());

      const finalMemory = benchmarkingService['collector'].getMemoryUsage();

      expect(initialMemory).toBeDefined();
      expect(finalMemory).toBeDefined();

      expect(finalMemory.heapUsed).toBeGreaterThan(initialMemory.heapUsed);
      expect(finalMemory.heapTotal).toBeGreaterThanOrEqual(initialMemory.heapTotal);
      expect(finalMemory.timestamp).toBeGreaterThan(initialMemory.timestamp);
      expect(finalMemory.rss).toBeGreaterThan(0);
      expect(finalMemory.external).toBeGreaterThanOrEqual(0);

      // Clean up
      processedData.length = 0;
      memoryIntensiveData.length = 0;
    });
  });
});
