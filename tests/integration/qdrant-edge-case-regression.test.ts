/**
 * Qdrant Edge Case Regression Suite
 *
 * Comprehensive regression tests for Qdrant adapter edge cases and failure scenarios.
 * Ensures robust behavior under various conditions including network failures,
 * data inconsistencies, performance bottlenecks, and malformed inputs.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { QdrantAdapter } from '../../src/db/adapters/qdrant-adapter.js';
import { logger } from '../../src/utils/logger.js';
import { CircuitBreakerManager } from '../../src/services/circuit-breaker.service.js';
import type {
  KnowledgeItem,
  SearchQuery,
  StoreOptions,
  SearchOptions,
  HybridSearchOptions,
} from '../../src/types/core-interfaces.js';

describe('Qdrant Edge Case Regression Suite', () => {
  let qdrantAdapter: QdrantAdapter;
  let circuitBreakerManager: CircuitBreakerManager;
  const testTimeout = 30000; // 30 seconds for edge cases

  beforeEach(async () => {
    // Initialize Qdrant adapter with test configuration
    qdrantAdapter = new QdrantAdapter({
      host: 'localhost',
      port: 6333,
      timeout: 10000,
      retryAttempts: 3,
      retryDelay: 1000,
    });

    circuitBreakerManager = new CircuitBreakerManager();

    // Suppress logs during tests
    logger.level = 'error';
  }, testTimeout);

  afterEach(async () => {
    try {
      if (qdrantAdapter) {
        await qdrantAdapter.disconnect();
      }
    } catch (error) {
      // Ignore cleanup errors
    }
  });

  describe('Network Connection Edge Cases', () => {
    it(
      'should handle connection timeouts gracefully',
      async () => {
        // Create adapter with very short timeout
        const shortTimeoutAdapter = new QdrantAdapter({
          host: 'nonexistent-host',
          port: 6333,
          timeout: 1000, // 1 second
          retryAttempts: 2,
          retryDelay: 100,
        });

        try {
          await shortTimeoutAdapter.initialize();
          expect.fail('Should have thrown connection error');
        } catch (error) {
          expect(error.message).toContain('Failed to connect to Qdrant');
          expect(error.message).toContain('ECONNREFUSED');
        }
      },
      testTimeout
    );

    it(
      'should handle intermittent network failures',
      async () => {
        // Mock network failures during operations
        const originalSearch = qdrantAdapter.search;
        let callCount = 0;

        qdrantAdapter.search = async function (query: SearchQuery, options: SearchOptions = {}) {
          callCount++;
          if (callCount === 2) {
            throw new Error('Network timeout');
          }
          return originalSearch.call(this, query, options);
        };

        const query = {
          query: 'test query',
          scope: { project: 'test' },
        };

        // First call should succeed
        const result1 = await qdrantAdapter.search(query);
        expect(result1).toBeDefined();

        // Second call should fail
        try {
          await qdrantAdapter.search(query);
          expect.fail('Should have thrown network error');
        } catch (error) {
          expect(error.message).toContain('Network timeout');
        }

        // Third call should succeed again
        const result3 = await qdrantAdapter.search(query);
        expect(result3).toBeDefined();
      },
      testTimeout
    );

    it(
      'should handle connection pool exhaustion',
      async () => {
        // Simulate many concurrent requests
        const concurrentRequests = 50;
        const query = {
          query: 'concurrent test query',
          scope: { project: 'test' },
        };

        const promises = Array.from({ length: concurrentRequests }, () =>
          qdrantAdapter.search(query).catch((error) => ({ error: error.message }))
        );

        const results = await Promise.all(promises);

        // Should handle most requests successfully, some may fail due to pool exhaustion
        const successes = results.filter((r) => !r.error).length;
        const failures = results.filter((r) => r.error).length;

        expect(successes + failures).toBe(concurrentRequests);
        expect(successes).toBeGreaterThan(0); // At least some should succeed
      },
      testTimeout
    );
  });

  describe('Data Consistency Edge Cases', () => {
    it(
      'should handle malformed vector embeddings',
      async () => {
        const itemsWithInvalidVectors: KnowledgeItem[] = [
          {
            id: 'invalid-embedding-1',
            kind: 'entity',
            content: { name: 'Test Entity 1' },
            scope: { project: 'test' },
            metadata: {
              embedding: 'not-an-array', // Invalid embedding
            },
          },
          {
            id: 'invalid-embedding-2',
            kind: 'entity',
            content: { name: 'Test Entity 2' },
            scope: { project: 'test' },
            metadata: {
              embedding: [1, 2], // Too short embedding
            },
          },
          {
            id: 'invalid-embedding-3',
            kind: 'entity',
            content: { name: 'Test Entity 3' },
            scope: { project: 'test' },
            metadata: {
              embedding: Array.from({ length: 2000 }, () => Math.random()), // Too long embedding
            },
          },
        ];

        const result = await qdrantAdapter.store(itemsWithInvalidVectors);
        expect(result).toBeDefined();

        // Should handle invalid embeddings gracefully
        expect(result.failed).toBeGreaterThan(0);
        expect(result.errors).toHaveLength(itemsWithInvalidVectors.length);
      },
      testTimeout
    );

    it(
      'should handle duplicate item IDs with different content',
      async () => {
        const duplicateItems: KnowledgeItem[] = [
          {
            id: 'duplicate-test',
            kind: 'entity',
            content: { name: 'First Version' },
            scope: { project: 'test' },
            metadata: { version: 1 },
          },
          {
            id: 'duplicate-test',
            kind: 'entity',
            content: { name: 'Second Version' },
            scope: { project: 'test' },
            metadata: { version: 2 },
          },
        ];

        const result1 = await qdrantAdapter.store(duplicateItems.slice(0, 1));
        expect(result1.success).toBe(1);

        const result2 = await qdrantAdapter.store(duplicateItems.slice(1));
        expect(result2.success).toBe(1); // Should update existing item

        // Verify latest version is returned
        const searchResult = await qdrantAdapter.search({
          query: 'duplicate-test',
          scope: { project: 'test' },
        });

        const foundItem = searchResult.results.find((r) => r.id === 'duplicate-test');
        expect(foundItem).toBeDefined();
        expect(foundItem.content.name).toBe('Second Version');
      },
      testTimeout
    );

    it(
      'should handle extremely large payload data',
      async () => {
        const largePayload = 'x'.repeat(10 * 1024 * 1024); // 10MB payload
        const largeItem: KnowledgeItem = {
          id: 'large-payload-test',
          kind: 'entity',
          content: {
            name: 'Large Payload Test',
            data: largePayload,
          },
          scope: { project: 'test' },
        };

        const result = await qdrantAdapter.store([largeItem]);

        // Should either succeed or fail gracefully
        if (result.success === 1) {
          // If succeeded, should be retrievable
          const searchResult = await qdrantAdapter.search({
            query: 'large-payload-test',
            scope: { project: 'test' },
          });
          expect(searchResult.results.length).toBeGreaterThan(0);
        } else {
          // If failed, should have meaningful error
          expect(result.errors.length).toBeGreaterThan(0);
          expect(result.errors[0].message).toContain('too large');
        }
      },
      testTimeout
    );
  });

  describe('Search Performance Edge Cases', () => {
    it(
      'should handle empty and null queries gracefully',
      async () => {
        const testQueries = ['', '   ', null as any, undefined as any];

        for (const query of testQueries) {
          try {
            const result = await qdrantAdapter.search({
              query,
              scope: { project: 'test' },
            });
            expect(result).toBeDefined();
            expect(result.results).toBeInstanceOf(Array);
          } catch (error) {
            // Should fail gracefully with meaningful error
            expect(error.message).toMatch(/empty|null|undefined/i);
          }
        }
      },
      testTimeout
    );

    it(
      'should handle extremely long search queries',
      async () => {
        const longQuery = 'search term '.repeat(1000); // Very long query
        const veryLongQuery = 'a'.repeat(10000); // Extremely long query

        const results = await Promise.allSettled([
          qdrantAdapter.search({ query: longQuery, scope: { project: 'test' } }),
          qdrantAdapter.search({ query: veryLongQuery, scope: { project: 'test' } }),
        ]);

        results.forEach((result, index) => {
          if (result.status === 'fulfilled') {
            expect(result.value).toBeDefined();
          } else {
            // Should fail gracefully
            expect(result.reason.message).toMatch(/too long|exceeds.*limit/i);
          }
        });
      },
      testTimeout
    );

    it(
      'should handle special characters in search queries',
      async () => {
        const specialQueries = [
          'query with "quotes"',
          "query with 'apostrophes'",
          'query with \\backslashes\\',
          'query with \n newlines \t tabs',
          'query with emoji 🚀🎯',
          'query with unicode: 中文测试',
          'query with math: ∑∫∞√',
          'query with special chars: !@#$%^&*()[]{}|;:,.<>?',
        ];

        for (const query of specialQueries) {
          try {
            const result = await qdrantAdapter.search({
              query,
              scope: { project: 'test' },
            });
            expect(result).toBeDefined();
          } catch (error) {
            // Should handle gracefully
            expect(error.message).not.toContain('unhandled');
          }
        }
      },
      testTimeout
    );
  });

  describe('Hybrid Search Edge Cases', () => {
    it(
      'should handle hybrid search with partial failures',
      async () => {
        // Mock semantic search failure
        const originalHybridSearch = qdrantAdapter.hybridSearch;
        let callCount = 0;

        qdrantAdapter.hybridSearch = async function (
          query: string,
          options: HybridSearchOptions = {}
        ) {
          callCount++;
          if (callCount === 1) {
            // First call: mock semantic search failure
            throw new Error('Semantic search failed');
          }
          // Subsequent calls: use original implementation
          return originalHybridSearch.call(this, query, options);
        };

        // Should fallback gracefully
        try {
          await qdrantAdapter.hybridSearch('test query', {
            enableFallback: true,
            deterministic: true,
          });
          expect.fail('Should have thrown error on first call');
        } catch (error) {
          expect(error.message).toContain('Semantic search failed');
        }

        // Second call should work
        const result = await qdrantAdapter.hybridSearch('test query', {
          enableFallback: true,
          deterministic: true,
        });
        expect(result).toBeDefined();
        expect(result).toBeInstanceOf(Array);
      },
      testTimeout
    );

    it(
      'should maintain deterministic ordering across multiple calls',
      async () => {
        const query = 'deterministic test query';
        const options: HybridSearchOptions = {
          deterministic: true,
          limit: 10,
          semanticWeight: 0.7,
          keywordWeight: 0.3,
          searchStrategy: 'balanced',
        };

        // Run same query multiple times
        const results = await Promise.all([
          qdrantAdapter.hybridSearch(query, options),
          qdrantAdapter.hybridSearch(query, options),
          qdrantAdapter.hybridSearch(query, options),
        ]);

        // Should return consistent ordering
        const firstResultIds = results[0].map((r) => r.id);
        const secondResultIds = results[1].map((r) => r.id);
        const thirdResultIds = results[2].map((r) => r.id);

        expect(firstResultIds).toEqual(secondResultIds);
        expect(secondResultIds).toEqual(thirdResultIds);

        // Scores should be consistent
        const firstScores = results[0].map((r) => r.hybridScore);
        const secondScores = results[1].map((r) => r.hybridScore);

        firstScores.forEach((score, index) => {
          expect(Math.abs(score - secondScores[index])).toBeLessThan(0.001);
        });
      },
      testTimeout
    );

    it(
      'should handle concurrent hybrid search requests',
      async () => {
        const concurrentQueries = 20;
        const queries = Array.from(
          { length: concurrentQueries },
          (_, i) => `concurrent hybrid search query ${i}`
        );

        const promises = queries.map((query) =>
          qdrantAdapter
            .hybridSearch(query, {
              deterministic: true,
              limit: 5,
              enableFallback: true,
            })
            .catch((error) => ({ error: error.message, query }))
        );

        const results = await Promise.all(promises);

        // Should handle most requests successfully
        const successes = results.filter((r) => !r.error).length;
        const failures = results.filter((r) => r.error).length;

        expect(successes + failures).toBe(concurrentQueries);
        expect(successes).toBeGreaterThan(concurrentQueries * 0.8); // At least 80% success rate
      },
      testTimeout
    );
  });

  describe('Circuit Breaker Integration', () => {
    it(
      'should trip circuit breaker on repeated failures',
      async () => {
        const circuitBreaker = circuitBreakerManager.createCircuitBreaker('test-circuit', {
          failureThreshold: 3,
          recoveryTimeoutMs: 5000,
          monitoringWindowMs: 10000,
          minimumCalls: 3,
          failureRateThreshold: 0.6,
        });

        // Execute operations through circuit breaker
        for (let i = 0; i < 5; i++) {
          try {
            await circuitBreaker.execute(async () => {
              throw new Error(`Simulated failure ${i + 1}`);
            });
          } catch (error) {
            // Expected failures
          }
        }

        // Circuit should be open
        const stats = circuitBreaker.getStats();
        expect(stats.state).toBe('open');
        expect(stats.isOpen).toBe(true);
      },
      testTimeout
    );

    it(
      'should recover circuit breaker after timeout',
      async () => {
        const circuitBreaker = circuitBreakerManager.createCircuitBreaker('recovery-test', {
          failureThreshold: 2,
          recoveryTimeoutMs: 1000, // Short timeout for testing
          monitoringWindowMs: 5000,
          minimumCalls: 2,
          failureRateThreshold: 0.5,
        });

        // Trip the circuit
        try {
          await circuitBreaker.execute(async () => {
            throw new Error('Initial failure');
          });
        } catch (error) {
          // Expected
        }

        try {
          await circuitBreaker.execute(async () => {
            throw new Error('Second failure');
          });
        } catch (error) {
          // Expected
        }

        // Circuit should be open
        expect(circuitBreaker.getStats().state).toBe('open');

        // Wait for recovery timeout
        await new Promise((resolve) => setTimeout(resolve, 1200));

        // Next call should be half-open and succeed
        const result = await circuitBreaker.execute(async () => {
          return 'success';
        });

        expect(result).toBe('success');
        expect(circuitBreaker.getStats().state).toBe('closed');
      },
      testTimeout
    );

    it(
      'should log circuit breaker events appropriately',
      async () => {
        const logEvents: any[] = [];
        const originalInfo = logger.info;
        const originalWarn = logger.warn;
        const originalError = logger.error;

        // Capture log events
        logger.info = (data: any, message: string) => {
          if (message.includes('CIRCUIT')) {
            logEvents.push({ level: 'info', data, message });
          }
          originalInfo(data, message);
        };

        logger.warn = (data: any, message: string) => {
          if (message.includes('CIRCUIT')) {
            logEvents.push({ level: 'warn', data, message });
          }
          originalWarn(data, message);
        };

        logger.error = (data: any, message: string) => {
          if (message.includes('CIRCUIT')) {
            logEvents.push({ level: 'error', data, message });
          }
          originalError(data, message);
        };

        const circuitBreaker = circuitBreakerManager.createCircuitBreaker('logging-test', {
          failureThreshold: 2,
          recoveryTimeoutMs: 5000,
          enableSLOAnnotations: true,
          enablePerformanceLogging: true,
        });

        // Generate some activity
        for (let i = 0; i < 3; i++) {
          try {
            await circuitBreaker.execute(async () => {
              if (i < 2) {
                throw new Error(`Test failure ${i + 1}`);
              }
              return 'success';
            });
          } catch (error) {
            // Expected
          }
        }

        // Restore original logger
        logger.info = originalInfo;
        logger.warn = originalWarn;
        logger.error = originalError;

        // Should have logged circuit breaker events
        const circuitEvents = logEvents.filter((e) => e.message.includes('logging-test'));
        expect(circuitEvents.length).toBeGreaterThan(0);

        // Check for required log fields
        circuitEvents.forEach((event) => {
          expect(event.data).toHaveProperty('circuitBreaker', 'logging-test');
          expect(event.data).toHaveProperty('state');
          expect(event.data).toHaveProperty('failures');
        });
      },
      testTimeout
    );
  });

  describe('Memory and Performance Edge Cases', () => {
    it('should handle memory pressure scenarios', async () => {
      // Create large batch of items
      const largeBatch: KnowledgeItem[] = Array.from({ length: 1000 }, (_, i) => ({
        id: `memory-test-${i}`,
        kind: 'entity',
        content: {
          name: `Memory Test Entity ${i}`,
          description: 'x'.repeat(1000), // 1KB per item
          data: Array.from({ length: 100 }, (_, j) => `data-${j}`),
        },
        scope: { project: 'memory-test' },
      }));

      const startTime = Date.now();
      const result = await qdrantAdapter.store(largeBatch, {
        batchSize: 100,
        parallel: true,
      });
      const duration = Date.now() - startTime;

      // Should handle large batch without memory issues
      expect(result).toBeDefined();
      expect(result.success + result.failed).toBe(largeBatch.length);

      // Should complete in reasonable time
      expect(duration).toBeLessThan(30000); // 30 seconds max

      logger.info(
        {
          totalItems: largeBatch.length,
          success: result.success,
          failed: result.failed,
          duration,
          throughput: largeBatch.length / (duration / 1000),
        },
        'Memory pressure test completed'
      );
    }, 60000); // 60 second timeout for this test

    it('should handle concurrent operations without deadlocks', async () => {
      const concurrentOperations = 50;
      const operations = [];

      // Mix of different operations
      for (let i = 0; i < concurrentOperations; i++) {
        if (i % 3 === 0) {
          // Store operation
          operations.push(
            qdrantAdapter
              .store([
                {
                  id: `concurrent-store-${i}`,
                  kind: 'entity',
                  content: { name: `Concurrent Entity ${i}` },
                  scope: { project: 'concurrent-test' },
                },
              ])
              .catch((error) => ({ type: 'store', error: error.message, index: i }))
          );
        } else if (i % 3 === 1) {
          // Search operation
          operations.push(
            qdrantAdapter
              .search({
                query: `concurrent search query ${i}`,
                scope: { project: 'concurrent-test' },
              })
              .catch((error) => ({ type: 'search', error: error.message, index: i }))
          );
        } else {
          // Hybrid search operation
          operations.push(
            qdrantAdapter
              .hybridSearch(`concurrent hybrid search ${i}`, {
                limit: 5,
                deterministic: true,
              })
              .catch((error) => ({ type: 'hybrid', error: error.message, index: i }))
          );
        }
      }

      const startTime = Date.now();
      const results = await Promise.all(operations);
      const duration = Date.now() - startTime;

      // Should complete without hanging
      expect(results.length).toBe(concurrentOperations);

      const successes = results.filter((r) => !r.error).length;
      const failures = results.filter((r) => r.error).length;

      expect(successes + failures).toBe(concurrentOperations);
      expect(duration).toBeLessThan(45000); // 45 seconds max

      logger.info(
        {
          totalOperations: concurrentOperations,
          successes,
          failures,
          duration,
          operationsPerSecond: concurrentOperations / (duration / 1000),
        },
        'Concurrent operations test completed'
      );
    }, 60000); // 60 second timeout
  });

  describe('Error Recovery Edge Cases', () => {
    it(
      'should handle partial batch failures gracefully',
      async () => {
        const mixedBatch: KnowledgeItem[] = [
          // Valid items
          {
            id: 'valid-item-1',
            kind: 'entity',
            content: { name: 'Valid Item 1' },
            scope: { project: 'batch-test' },
          },
          {
            id: 'valid-item-2',
            kind: 'entity',
            content: { name: 'Valid Item 2' },
            scope: { project: 'batch-test' },
          },
          // Invalid items
          {
            id: 'invalid-item-1',
            kind: 'invalid-kind',
            content: { name: 'Invalid Item 1' },
            scope: { project: 'batch-test' },
          },
          {
            id: '', // Empty ID
            kind: 'entity',
            content: { name: 'Invalid Item 2' },
            scope: { project: 'batch-test' },
          },
        ];

        const result = await qdrantAdapter.store(mixedBatch);

        // Should handle mixed batch correctly
        expect(result.success).toBe(2); // Valid items
        expect(result.failed).toBe(2); // Invalid items
        expect(result.errors).toHaveLength(2);
      },
      testTimeout
    );

    it(
      'should recover from temporary database unavailability',
      async () => {
        // This test would require mocking Qdrant unavailability
        // For now, we'll test the retry mechanism
        const adapterWithRetry = new QdrantAdapter({
          host: 'localhost',
          port: 6333,
          retryAttempts: 5,
          retryDelay: 1000,
          backoffMultiplier: 2,
          maxRetryDelay: 10000,
        });

        let attemptCount = 0;
        const originalSearch = adapterWithRetry.search;

        adapterWithRetry.search = async function (query: SearchQuery, options: SearchOptions = {}) {
          attemptCount++;
          if (attemptCount <= 2) {
            throw new Error('Temporary database unavailable');
          }
          return originalSearch.call(this, query, options);
        };

        const result = await adapterWithRetry.search({
          query: 'recovery test',
          scope: { project: 'test' },
        });

        expect(result).toBeDefined();
        expect(attemptCount).toBe(3); // Should have retried twice before succeeding
      },
      testTimeout
    );
  });
});
