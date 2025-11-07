/**
 * Memory Find Benchmark Scenarios
 *
 * Benchmark scenarios for testing memory find/search performance under various conditions
 */

import type { BenchmarkScenario, LoadTestConfig } from '../framework/types.js';

/**
 * Simple search benchmark
 */
export const simpleSearchBenchmark: BenchmarkScenario = {
  name: 'Simple Search',
  description: 'Basic semantic search with simple queries',
  config: {
    concurrency: 1,
    operations: 100,
    dataConfig: {
      itemCount: 1000,
      averageItemSize: 1024,
      sizeVariance: 0.2,
    },
  },
  tags: ['search', 'simple', 'baseline'],
  async execute(config: LoadTestConfig): Promise<any> {
    const { memoryFind } = await import('../../src/index.js');

    const results = [];
    const queries = [
      'user authentication',
      'database performance',
      'security vulnerabilities',
      'api documentation',
      'system monitoring',
      'error handling',
      'data backup',
      'user interface',
      'network connectivity',
      'memory optimization',
    ];

    for (let i = 0; i < config.operations; i++) {
      const startTime = performance.now();

      try {
        const query = queries[i % queries.length];

        const result = await memoryFind({
          query,
          limit: 10,
          search_strategy: 'auto',
        });

        const endTime = performance.now();

        results.push({
          success: true,
          duration: endTime - startTime,
          query,
          resultCount: result.results?.length || 0,
          hasMore: result.hasMore || false,
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

    return {
      totalOperations: results.length,
      successfulOperations: successful.length,
      averageDuration: successful.reduce((sum, r) => sum + r.duration, 0) / successful.length,
      averageResultCount:
        successful.reduce((sum, r) => sum + (r.resultCount || 0), 0) / successful.length,
      results,
    };
  },
};

/**
 * Complex search benchmark
 */
export const complexSearchBenchmark: BenchmarkScenario = {
  name: 'Complex Search',
  description: 'Advanced search with filters and complex queries',
  config: {
    concurrency: 1,
    operations: 50,
    dataConfig: {
      itemCount: 5000,
      averageItemSize: 2048,
      sizeVariance: 0.3,
    },
  },
  tags: ['search', 'complex', 'filters'],
  async execute(config: LoadTestConfig): Promise<any> {
    const { memoryFind } = await import('../../src/index.js');

    const results = [];

    const complexQueries = [
      {
        query: 'security vulnerabilities authentication system',
        types: ['issue', 'risk'],
        limit: 20,
        filters: { created_after: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString() },
      },
      {
        query: 'performance optimization database queries',
        types: ['observation', 'decision'],
        limit: 15,
        filters: { scope: { project: 'performance-analysis' } },
      },
      {
        query: 'user experience interface design',
        types: ['entity', 'observation'],
        limit: 25,
        filters: { tags: ['frontend', 'ui'] },
      },
      {
        query: 'deployment pipeline continuous integration',
        types: ['decision', 'release', 'runbook'],
        limit: 30,
        filters: { created_after: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString() },
      },
      {
        query: 'backup recovery disaster planning',
        types: ['runbook', 'incident', 'risk'],
        limit: 20,
        filters: { tags: ['backup', 'recovery'] },
      },
    ];

    for (let i = 0; i < config.operations; i++) {
      const startTime = performance.now();

      try {
        const queryConfig = complexQueries[i % complexQueries.length];

        const result = await memoryFind({
          query: queryConfig.query,
          types: queryConfig.types as any,
          limit: queryConfig.limit,
          filters: queryConfig.filters,
          search_strategy: 'deep',
        });

        const endTime = performance.now();

        results.push({
          success: true,
          duration: endTime - startTime,
          query: queryConfig.query,
          resultCount: result.results?.length || 0,
          hasMore: result.hasMore || false,
          complexity: 'high',
        });
      } catch (error) {
        const endTime = performance.now();
        results.push({
          success: false,
          duration: endTime - startTime,
          error: error instanceof Error ? error.message : String(error),
          complexity: 'high',
        });
      }
    }

    const successful = results.filter((r) => r.success);

    return {
      totalOperations: results.length,
      successfulOperations: successful.length,
      averageDuration: successful.reduce((sum, r) => sum + r.duration, 0) / successful.length,
      averageResultCount:
        successful.reduce((sum, r) => sum + (r.resultCount || 0), 0) / successful.length,
      results,
    };
  },
};

/**
 * Concurrent search benchmark
 */
export const concurrentSearchBenchmark: BenchmarkScenario = {
  name: 'Concurrent Search',
  description: 'Multiple concurrent search operations',
  config: {
    concurrency: 20,
    operations: 200,
    rampUpTime: 2000,
    dataConfig: {
      itemCount: 10000,
      averageItemSize: 1536,
      sizeVariance: 0.25,
    },
  },
  tags: ['search', 'concurrent', 'load'],
  async execute(config: LoadTestConfig): Promise<any> {
    const { memoryFind } = await import('../../src/index.js');

    const results = [];
    const promises = [];

    const queries = [
      'authentication security',
      'performance metrics',
      'database optimization',
      'user management',
      'error handling',
      'system monitoring',
      'api integration',
      'data analysis',
      'network configuration',
      'memory management',
    ];

    for (let i = 0; i < config.operations; i++) {
      const operation = async (index: number) => {
        // Ramp-up delay
        if (config.rampUpTime) {
          const delay = (config.rampUpTime / config.operations) * index;
          await new Promise((resolve) => setTimeout(resolve, delay));
        }

        const startTime = performance.now();

        try {
          const query = queries[index % queries.length];
          const limit = 10 + Math.floor(Math.random() * 20); // 10-30 results

          const result = await memoryFind({
            query,
            limit,
            search_strategy: 'auto',
          });

          const endTime = performance.now();

          return {
            success: true,
            duration: endTime - startTime,
            query,
            resultCount: result.results?.length || 0,
            limit,
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

    const operationResults = await Promise.all(promises);
    results.push(...operationResults);

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
      averageResultCount:
        successful.reduce((sum, r) => sum + (r.resultCount || 0), 0) / successful.length,
      results,
    };
  },
};

/**
 * Graph expansion benchmark
 */
export const graphExpansionBenchmark: BenchmarkScenario = {
  name: 'Graph Expansion Search',
  description: 'Search with graph expansion for related items',
  config: {
    concurrency: 1,
    operations: 30,
    dataConfig: {
      itemCount: 5000,
      averageItemSize: 1024,
      relationshipDensity: 0.3,
    },
  },
  tags: ['search', 'graph', 'expansion'],
  async execute(config: LoadTestConfig): Promise<any> {
    const { memoryFind } = await import('../../src/index.js');

    const results = [];

    for (let i = 0; i < config.operations; i++) {
      const startTime = performance.now();

      try {
        const depth = 1 + (i % 3); // Depth 1, 2, or 3
        const maxNodes = 20 + depth * 10;

        const result = await memoryFind({
          query: 'system architecture',
          limit: 5,
          graph_expansion: {
            enabled: true,
            expansion_type: 'relations',
            max_depth: depth,
            max_nodes: maxNodes,
          },
        });

        const endTime = performance.now();

        results.push({
          success: true,
          duration: endTime - startTime,
          depth,
          maxNodes,
          resultCount: result.results?.length || 0,
          expandedNodes: result.graph_expansion?.nodes?.length || 0,
          expansionCount: result.graph_expansion?.expansions?.length || 0,
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

    const byDepth = successful.reduce(
      (acc, result) => {
        if (!acc[result.depth]) {
          acc[result.depth] = [];
        }
        acc[result.depth].push(result);
        return acc;
      },
      {} as Record<number, any[]>
    );

    const depthStats = Object.entries(byDepth).map(([depth, items]) => ({
      depth: parseInt(depth),
      count: items.length,
      averageDuration: items.reduce((sum, item) => sum + item.duration, 0) / items.length,
      averageExpandedNodes:
        items.reduce((sum, item) => sum + (item.expandedNodes || 0), 0) / items.length,
    }));

    return {
      totalOperations: results.length,
      successfulOperations: successful.length,
      averageDuration: successful.reduce((sum, r) => sum + r.duration, 0) / successful.length,
      depthPerformance: depthStats,
      averageExpandedNodes:
        successful.reduce((sum, r) => sum + (r.expandedNodes || 0), 0) / successful.length,
      results,
    };
  },
};

/**
 * Fuzzy search benchmark
 */
export const fuzzySearchBenchmark: BenchmarkScenario = {
  name: 'Fuzzy Search',
  description: 'Search with typo tolerance and fuzzy matching',
  config: {
    concurrency: 1,
    operations: 80,
    dataConfig: {
      itemCount: 3000,
      averageItemSize: 1024,
      sizeVariance: 0.2,
    },
  },
  tags: ['search', 'fuzzy', 'tolerance'],
  async execute(config: LoadTestConfig): Promise<any> {
    const { memoryFind } = await import('../../src/index.js');

    const results = [];

    // Queries with intentional typos
    const fuzzyQueries = [
      'authentification', // authentication
      'preformance', // performance
      'dataabse', // database
      'secuirty', // security
      'vulnerablities', // vulnerabilities
      'backp', // backup
      'deploymnet', // deployment
      'monitaring', // monitoring
      'optimisation', // optimization
      'intergration', // integration
    ];

    for (let i = 0; i < config.operations; i++) {
      const startTime = performance.now();

      try {
        const query = fuzzyQueries[i % fuzzyQueries.length];
        const searchStrategy = i % 3 === 0 ? 'deep' : 'auto';

        const result = await memoryFind({
          query,
          limit: 15,
          search_strategy: searchStrategy,
          filters: { fuzzy_matching: true },
        });

        const endTime = performance.now();

        results.push({
          success: true,
          duration: endTime - startTime,
          query,
          resultCount: result.results?.length || 0,
          searchStrategy,
          hasCorrections: result.query_corrections?.length > 0,
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
    const withCorrections = successful.filter((r) => r.hasCorrections);

    return {
      totalOperations: results.length,
      successfulOperations: successful.length,
      averageDuration: successful.reduce((sum, r) => sum + r.duration, 0) / successful.length,
      averageResultCount:
        successful.reduce((sum, r) => sum + (r.resultCount || 0), 0) / successful.length,
      correctionRate: (withCorrections.length / successful.length) * 100,
      results,
    };
  },
};

/**
 * Large result set benchmark
 */
export const largeResultSetBenchmark: BenchmarkScenario = {
  name: 'Large Result Set Search',
  description: 'Search that returns large result sets',
  config: {
    concurrency: 1,
    operations: 20,
    dataConfig: {
      itemCount: 20000,
      averageItemSize: 1024,
      sizeVariance: 0.3,
    },
  },
  tags: ['search', 'large-results', 'pagination'],
  async execute(config: LoadTestConfig): Promise<any> {
    const { memoryFind } = await import('../../src/index.js');

    const results = [];

    for (let i = 0; i < config.operations; i++) {
      const startTime = performance.now();
      const startMemory = process.memoryUsage();

      try {
        const limit = 100 + i * 50; // 100 to 1050 results

        const result = await memoryFind({
          query: 'system', // Broad query
          limit,
          search_strategy: 'fast',
        });

        const endTime = performance.now();
        const endMemory = process.memoryUsage();

        results.push({
          success: true,
          duration: endTime - startTime,
          limit,
          resultCount: result.results?.length || 0,
          hasMore: result.hasMore || false,
          memoryDelta: {
            rss: endMemory.rss - startMemory.rss,
            heapUsed: endMemory.heapUsed - startMemory.heapUsed,
          },
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

    return {
      totalOperations: results.length,
      successfulOperations: successful.length,
      averageDuration: successful.reduce((sum, r) => sum + r.duration, 0) / successful.length,
      averageResultCount:
        successful.reduce((sum, r) => sum + (r.resultCount || 0), 0) / successful.length,
      maxResultCount: Math.max(...successful.map((r) => r.resultCount || 0)),
      averageMemoryDelta:
        successful.reduce((sum, r) => sum + r.memoryDelta.rss, 0) / successful.length,
      results,
    };
  },
};
