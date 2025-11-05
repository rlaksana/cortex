/**
 * Search and Retrieval Load Testing
 *
 * Comprehensive load testing for search operations including semantic search,
 * keyword search, and hybrid search with performance validation
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { PerformanceHarness } from '../../../src/performance/performance-harness.js';
import { PerformanceTestConfig } from '../../../src/performance/performance-targets.js';
import { randomUUID } from 'crypto';

describe('Search and Retrieval Load Tests', () => {
  let harness: PerformanceHarness;
  const TEST_DATASET_SIZE = 5000;

  beforeAll(async () => {
    harness = new PerformanceHarness('./artifacts/performance/search-retrieval');

    // Prepare test dataset
    await prepareSearchDataset();
  });

  afterAll(async () => {
    console.log('Search and retrieval load tests completed');
  });

  describe('Semantic Search Performance', () => {
    it('should meet performance targets for semantic search', async () => {
      const config: PerformanceTestConfig = {
        name: 'semantic_search_performance',
        description: 'Performance test for semantic search operations',
        operationCount: 200,
        concurrency: 20,
        timeout: 30000,
        warmupIterations: 5,
        targets: [
          {
            name: 'search_latency_p95',
            description: '95th percentile latency for semantic search',
            target: 500,
            max: 1000,
            unit: 'ms',
            type: 'latency',
            priority: 'critical',
            enabled: true
          },
          {
            name: 'search_latency_p99',
            description: '99th percentile latency for semantic search',
            target: 1000,
            max: 2000,
            unit: 'ms',
            type: 'latency',
            priority: 'critical',
            enabled: true
          },
          {
            name: 'search_throughput',
            description: 'Throughput for semantic search operations',
            target: 200,
            max: 100,
            unit: 'ops/s',
            type: 'throughput',
            priority: 'high',
            enabled: true
          },
          {
            name: 'search_error_rate',
            description: 'Error rate for semantic search operations',
            target: 0,
            max: 2,
            unit: '%',
            type: 'error_rate',
            priority: 'critical',
            enabled: true
          }
        ],
        categories: ['search', 'semantic', 'critical'],
        parameters: {
          queryType: 'semantic',
          resultSize: 50,
          searchComplexity: 'medium',
          embeddingDimensions: 1536,
          similarityThreshold: 0.7
        }
      };

      const result = await harness.runTest(config);

      expect(result.validation.passed).toBe(true);

      if (result.validation.failures.length > 0) {
        console.error('Performance target failures:', result.validation.failures);
      }

      // Store as baseline
      await harness.storeBaseline(result);

      // Verify specific metrics
      expect(result.results.metrics.latencies.p95).toBeLessThan(1000);
      expect(result.results.metrics.latencies.p99).toBeLessThan(2000);
      expect(result.results.metrics.throughput).toBeGreaterThan(100);
      expect(result.results.metrics.errorRate).toBeLessThan(2);
    }, 60000);

    it('should handle complex semantic queries efficiently', async () => {
      const config: PerformanceTestConfig = {
        name: 'complex_semantic_search',
        description: 'Complex semantic search performance test',
        operationCount: 100,
        concurrency: 10,
        timeout: 45000,
        warmupIterations: 5,
        targets: [
          {
            name: 'search_latency_p95',
            description: '95th percentile latency for complex semantic search',
            target: 800,
            max: 1500,
            unit: 'ms',
            type: 'latency',
            priority: 'critical',
            enabled: true
          },
          {
            name: 'search_throughput',
            description: 'Throughput for complex semantic search',
            target: 50,
            max: 25,
            unit: 'ops/s',
            type: 'throughput',
            priority: 'high',
            enabled: true
          }
        ],
        categories: ['search', 'semantic', 'complex'],
        parameters: {
          queryType: 'semantic',
          resultSize: 100,
          searchComplexity: 'high',
          embeddingDimensions: 1536,
          similarityThreshold: 0.8,
          filters: ['type', 'date_range', 'tags'],
          rankingAlgorithm: 'hybrid'
        }
      };

      const result = await harness.runTest(config);

      expect(result.validation.passed).toBe(true);
      expect(result.results.metrics.latencies.p95).toBeLessThan(1500);
      expect(result.results.metrics.throughput).toBeGreaterThan(25);
    }, 90000);
  });

  describe('Keyword Search Performance', () => {
    it('should meet performance targets for keyword search', async () => {
      const config: PerformanceTestConfig = {
        name: 'keyword_search_performance',
        description: 'Performance test for keyword search operations',
        operationCount: 300,
        concurrency: 30,
        timeout: 20000,
        warmupIterations: 5,
        targets: [
          {
            name: 'search_latency_p95',
            description: '95th percentile latency for keyword search',
            target: 200,
            max: 500,
            unit: 'ms',
            type: 'latency',
            priority: 'critical',
            enabled: true
          },
          {
            name: 'search_latency_p99',
            description: '99th percentile latency for keyword search',
            target: 400,
            max: 1000,
            unit: 'ms',
            type: 'latency',
            priority: 'critical',
            enabled: true
          },
          {
            name: 'search_throughput',
            description: 'Throughput for keyword search operations',
            target: 500,
            max: 250,
            unit: 'ops/s',
            type: 'throughput',
            priority: 'high',
            enabled: true
          }
        ],
        categories: ['search', 'keyword', 'critical'],
        parameters: {
          queryType: 'keyword',
          resultSize: 75,
          searchComplexity: 'low',
          indexingMethod: 'inverted_index',
          queryOperators: ['AND', 'OR', 'NOT']
        }
      };

      const result = await harness.runTest(config);

      expect(result.validation.passed).toBe(true);
      expect(result.results.metrics.latencies.p95).toBeLessThan(500);
      expect(result.results.metrics.latencies.p99).toBeLessThan(1000);
      expect(result.results.metrics.throughput).toBeGreaterThan(250);
    }, 60000);
  });

  describe('Hybrid Search Performance', () => {
    it('should meet performance targets for hybrid search', async () => {
      const config: PerformanceTestConfig = {
        name: 'hybrid_search_performance',
        description: 'Performance test for hybrid search operations',
        operationCount: 150,
        concurrency: 15,
        timeout: 30000,
        warmupIterations: 5,
        targets: [
          {
            name: 'search_latency_p95',
            description: '95th percentile latency for hybrid search',
            target: 600,
            max: 1200,
            unit: 'ms',
            type: 'latency',
            priority: 'critical',
            enabled: true
          },
          {
            name: 'search_throughput',
            description: 'Throughput for hybrid search operations',
            target: 150,
            max: 75,
            unit: 'ops/s',
            type: 'throughput',
            priority: 'high',
            enabled: true
          }
        ],
        categories: ['search', 'hybrid', 'critical'],
        parameters: {
          queryType: 'hybrid',
          resultSize: 60,
          searchComplexity: 'medium',
          weightingStrategy: 'adaptive',
          semanticWeight: 0.6,
          keywordWeight: 0.4,
          fusionMethod: 'rank_fusion'
        }
      };

      const result = await harness.runTest(config);

      expect(result.validation.passed).toBe(true);
      expect(result.results.metrics.latencies.p95).toBeLessThan(1200);
      expect(result.results.metrics.throughput).toBeGreaterThan(75);
    }, 60000);
  });

  describe('Search Under Load', () => {
    it('should maintain performance under concurrent search load', async () => {
      const config: PerformanceTestConfig = {
        name: 'concurrent_search_load',
        description: 'Concurrent search load performance test',
        operationCount: 500,
        concurrency: 50,
        timeout: 45000,
        warmupIterations: 10,
        targets: [
          {
            name: 'search_latency_p95',
            description: '95th percentile latency under concurrent load',
            target: 800,
            max: 1500,
            unit: 'ms',
            type: 'latency',
            priority: 'critical',
            enabled: true
          },
          {
            name: 'search_throughput',
            description: 'Throughput under concurrent load',
            target: 300,
            max: 150,
            unit: 'ops/s',
            type: 'throughput',
            priority: 'high',
            enabled: true
          }
        ],
        categories: ['search', 'concurrency', 'load'],
        parameters: {
          queryTypes: ['semantic', 'keyword', 'hybrid'],
          resultSize: 50,
          concurrencyLevel: 'high',
          queryDistribution: {
            semantic: 0.4,
            keyword: 0.4,
            hybrid: 0.2
          }
        }
      };

      const result = await harness.runTest(config);

      expect(result.validation.passed).toBe(true);
      expect(result.results.metrics.latencies.p95).toBeLessThan(1500);
      expect(result.results.metrics.throughput).toBeGreaterThan(150);
      expect(result.results.summary.successRate).toBeGreaterThan(95);
    }, 90000);
  });

  describe('Search Result Ranking Performance', () => {
    it('should efficiently rank large result sets', async () => {
      const config: PerformanceTestConfig = {
        name: 'search_ranking_performance',
        description: 'Search result ranking performance test',
        operationCount: 100,
        concurrency: 8,
        timeout: 30000,
        warmupIterations: 3,
        targets: [
          {
            name: 'search_latency_p95',
            description: '95th percentile latency for search with ranking',
            target: 700,
            max: 1400,
            unit: 'ms',
            type: 'latency',
            priority: 'critical',
            enabled: true
          },
          {
            name: 'search_throughput',
            description: 'Throughput for search with ranking',
            target: 80,
            max: 40,
            unit: 'ops/s',
            type: 'throughput',
            priority: 'high',
            enabled: true
          }
        ],
        categories: ['search', 'ranking', 'performance'],
        parameters: {
          queryType: 'hybrid',
          resultSize: 500,
          rankingComplexity: 'high',
          rankingFactors: ['relevance', 'recency', 'popularity', 'authority'],
          personalizationEnabled: true,
          diversityAlgorithm: 'maximal_marginal_relevance'
        }
      };

      const result = await harness.runTest(config);

      expect(result.validation.passed).toBe(true);
      expect(result.results.metrics.latencies.p95).toBeLessThan(1400);
      expect(result.results.metrics.throughput).toBeGreaterThan(40);
    }, 60000);
  });

  describe('Search Memory Efficiency', () => {
    it('should maintain memory efficiency during search operations', async () => {
      const config: PerformanceTestConfig = {
        name: 'search_memory_efficiency',
        description: 'Memory efficiency test for search operations',
        operationCount: 300,
        concurrency: 25,
        timeout: 60000,
        warmupIterations: 8,
        targets: [
          {
            name: 'search_latency_p95',
            description: '95th percentile latency with memory constraints',
            target: 600,
            max: 1200,
            unit: 'ms',
            type: 'latency',
            priority: 'critical',
            enabled: true
          },
          {
            name: 'memory_usage_peak',
            description: 'Peak memory usage during search',
            target: 256 * 1024 * 1024,
            max: 512 * 1024 * 1024,
            unit: 'bytes',
            type: 'memory',
            priority: 'high',
            enabled: true
          }
        ],
        categories: ['search', 'memory', 'efficiency'],
        parameters: {
          queryTypes: ['semantic', 'keyword'],
          resultSize: 100,
          memoryOptimization: true,
          streamingResults: true,
          cacheEnabled: true,
          cacheSize: 1000
        }
      };

      const result = await harness.runTest(config);

      expect(result.validation.passed).toBe(true);
      expect(result.results.metrics.latencies.p95).toBeLessThan(1200);
      expect(result.metadata.systemMetrics.peakMemoryUsage).toBeLessThan(512 * 1024 * 1024);
      expect(result.metadata.systemMetrics.memoryLeakDetected).toBe(false);
    }, 90000);
  });

  /**
   * Prepare search dataset for testing
   */
  async function prepareSearchDataset(): Promise<void> {
    console.log('Preparing search dataset for load testing...');

    const searchTerms = [
      'machine learning', 'artificial intelligence', 'software development',
      'database design', 'user experience', 'performance optimization',
      'cloud computing', 'microservices', 'security', 'devops',
      'data analysis', 'neural networks', 'natural language processing',
      'computer vision', 'deep learning', 'algorithms', 'data structures'
    ];

    const documentTypes = ['entity', 'observation', 'decision', 'task', 'documentation'];
    const domains = ['technology', 'business', 'research', 'development', 'operations'];

    // Generate realistic test documents
    const testDocuments = [];

    for (let i = 0; i < TEST_DATASET_SIZE; i++) {
      const type = documentTypes[i % documentTypes.length];
      const domain = domains[i % domains.length];
      const term = searchTerms[i % searchTerms.length];
      const complexity = Math.floor(Math.random() * 3) + 1; // 1-3 complexity levels

      testDocuments.push({
        id: randomUUID(),
        type,
        domain,
        title: `${term} - ${type} ${i}`,
        content: generateDocumentContent(term, type, complexity),
        metadata: {
          created: new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000).toISOString(),
          tags: generateTags(term, domain, complexity),
          size: Math.floor(Math.random() * 4096) + 512, // 512-4608 bytes
          author: `author-${Math.floor(Math.random() * 10)}`,
          priority: ['low', 'medium', 'high'][Math.floor(Math.random() * 3)]
        }
      });
    }

    console.log(`Generated ${testDocuments.length} test documents for search testing`);
  }

  /**
   * Generate realistic document content
   */
  function generateDocumentContent(term: string, type: string, complexity: number): string {
    const baseContent = `This document discusses ${term} in the context of ${type}. `;

    const complexityAdditions = {
      1: `${term} is an important concept in modern technology.`,
      2: `${term} involves multiple aspects including theoretical foundations, practical applications, and future developments. The implementation of ${term} requires careful consideration of various factors.`,
      3: `${term} represents a complex multidisciplinary field that encompasses theoretical frameworks, practical implementations, empirical evaluations, and future research directions. The sophisticated interplay between ${term} and related domains necessitates a comprehensive understanding of underlying principles, methodological approaches, and real-world implications. Advanced techniques in ${term} leverage cutting-edge methodologies and state-of-the-art technologies to address challenging problems and unlock new possibilities.`
    };

    let content = baseContent + (complexityAdditions[complexity] || complexityAdditions[1]);

    // Add some variation
    const variations = [
      'This analysis provides insights into current trends and future directions.',
      'Recent developments have significantly advanced our understanding.',
      'Practical applications demonstrate the value of these approaches.',
      'Theoretical foundations support the implementation strategies.',
      'Empirical evidence validates the effectiveness of these methods.'
    ];

    content += ' ' + variations[Math.floor(Math.random() * variations.length)];

    return content;
  }

  /**
   * Generate relevant tags for documents
   */
  function generateTags(term: string, domain: string, complexity: number): string[] {
    const baseTags = [term, domain];

    const complexityTags = {
      1: ['basic', 'introduction', 'overview'],
      2: ['intermediate', 'detailed', 'comprehensive'],
      3: ['advanced', 'expert', 'research', 'in-depth']
    };

    const additionalTags = [
      'technology', 'innovation', 'analysis', 'optimization',
      'implementation', 'strategy', 'methodology', 'framework'
    ];

    const tags = [...baseTags, ...(complexityTags[complexity] || [])];

    // Add 2-4 random additional tags
    const numAdditional = Math.floor(Math.random() * 3) + 2;
    for (let i = 0; i < numAdditional; i++) {
      const randomTag = additionalTags[Math.floor(Math.random() * additionalTags.length)];
      if (!tags.includes(randomTag)) {
        tags.push(randomTag);
      }
    }

    return tags;
  }
});