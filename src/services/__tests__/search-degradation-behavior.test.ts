/**
 * Search Degradation Behavior Test Suite
 *
 * Comprehensive tests for search system resilience and degrade behavior including:
 * - Vector database failure scenarios and graceful degradation
 * - High query load handling and performance degradation
 * - Memory pressure and network latency scenarios
 * - Automatic recovery mechanisms and manual recovery triggers
 * - Circuit breaker patterns and fallback strategies
 * - Error rate monitoring and system health tracking
 *
 * Tests verify that the search system maintains availability and provides
 * appropriate fallback behavior under various failure conditions.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { logger } from '../../utils/logger.js';
import { safeGetProperty, safeObjectAccess } from '../../utils/type-safe-access.js';

import type { SearchQuery } from '../../types/core-interfaces';
import {
  ErrorCategory,
  ErrorSeverity,
  RecoveryStrategy,
  searchErrorHandler,
} from '../search/search-error-handler';
import { SearchStrategyManager } from '../search/search-strategy-manager';

// Mock the logger to avoid noise in tests
vi.mock('../../utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

describe('Search Degradation Behavior Tests', () => {
  let searchManager: SearchStrategyManager;

  beforeEach(() => {
    searchManager = new SearchStrategyManager({
      maxResults: 20,
      timeoutMs: 10000,
      enableVectorSearch: true,
      enableGraphExpansion: true,
      fallbackEnabled: true,
      retryAttempts: 3,
      degradationThreshold: 0.7,
    });

    // Reset error handler and metrics before each test
    searchErrorHandler.resetMetrics();
    searchManager.resetMetrics();
    logger.clearLogs();
  });

  afterEach(() => {
    searchManager.resetMetrics();
    searchErrorHandler.resetAllCircuitBreakers();
    logger.clearLogs();
  });

  describe('Vector Database Failure Scenarios', () => {
    describe('Complete Vector Database Unavailability', () => {
      it('should degrade gracefully when vector database is completely unavailable', async () => {
        // Mock complete vector database failure
        vi.spyOn(searchManager as unknown, 'checkVectorBackendHealth').mockResolvedValue(false);

        const query: SearchQuery = {
          query: 'test semantic search query',
          mode: 'deep',
          expand: 'relations',
          limit: 10,
        };

        const result = await searchManager.executeSearch(query, 'deep');

        // Verify degradation behavior
        expect(result.strategy).toBe('deep');
        expect(result.degraded).toBe(true);
        expect(result.fallbackReason).toContain('unavailable');
        expect(result.vectorUsed).toBe(false);
        expect(result.metadata.backendHealthStatus).toBe('unavailable');

        // Verify results are still returned (fallback to keyword search)
        expect(result.results).toBeDefined();
        expect(Array.isArray(result.results)).toBe(true);

        // Verify audit logging
        const auditLogs = searchManager.getRecentAuditLogs(10);
        const degradationLogs = auditLogs.filter((log) => log.event_type === 'degradation');
        expect(degradationLogs.length).toBeGreaterThan(0);
      });

      it('should maintain functionality across all search strategies during vector outage', async () => {
        // Mock persistent vector database failure
        vi.spyOn(searchManager as unknown, 'checkVectorBackendHealth').mockResolvedValue(false);

        const strategies = ['fast', 'auto', 'deep'] as const;
        const results = [];

        for (const strategy of strategies) {
          const query: SearchQuery = {
            query: `test ${strategy} during vector outage`,
            mode: strategy,
            limit: 5,
          };

          const result = await searchManager.executeSearch(query, strategy);
          results.push(result);

          // All strategies should complete, even if degraded
          expect(result.strategy).toBe(strategy);
          expect(result.results).toBeDefined();
          expect(result.executionTime).toBeGreaterThan(0);
        }

        // Verify that auto and deep strategies are degraded, fast is not
        expect(results[0].degraded).toBe(false); // fast
        expect(results[1].degraded).toBe(true); // auto
        expect(results[2].degraded).toBe(true); // deep
      });

      it('should handle vector database recovery gracefully', async () => {
        // Mock initial vector database failure
        let vectorAvailable = false;
        jest
          .spyOn(searchManager as unknown, 'checkVectorBackendHealth')
          .mockImplementation(async () => {
            return vectorAvailable;
          });

        const query: SearchQuery = {
          query: 'test recovery behavior',
          mode: 'deep',
          limit: 10,
        };

        // First search during failure (should degrade)
        const degradedResult = await searchManager.executeSearch(query, 'deep');
        expect(degradedResult.degraded).toBe(true);
        expect(degradedResult.vectorUsed).toBe(false);

        // Simulate vector database recovery
        vectorAvailable = true;

        // Second search after recovery (should not degrade)
        const recoveredResult = await searchManager.executeSearch(query, 'deep');
        expect(recoveredResult.degraded).toBe(false);
        expect(recoveredResult.vectorUsed).toBe(true);

        // Verify recovery is logged
        const healthReport = searchManager.getSystemHealth();
        expect(healthReport.vector_backend.available).toBe(true);
        expect(healthReport.overall_status).toBe('healthy');
      });
    });

    describe('Partial Vector Database Degradation', () => {
      it('should handle intermittent vector database failures', async () => {
        let failureCount = 0;
        vi.spyOn(searchManager as unknown, 'performVectorSearch').mockImplementation(async () => {
          failureCount++;
          if (failureCount <= 2) {
            throw new Error('Vector database temporarily unavailable');
          }
          return [];
        });

        const query: SearchQuery = {
          query: 'test intermittent failures',
          mode: 'auto',
          limit: 10,
        };

        const result = await searchManager.executeSearch(query, 'auto');

        // Should recover and provide results
        expect(result.strategy).toBe('auto');
        expect(result.results).toBeDefined();
        expect(result.executionTime).toBeGreaterThan(0);

        // Should have attempted retries
        const errorMetrics = searchManager.getErrorMetrics();
        expect(errorMetrics.recoveryAttempts).toBeGreaterThan(0);
      });

      it('should handle vector database slow response times', async () => {
        // Mock slow vector responses
        vi.spyOn(searchManager as unknown, 'performVectorSearch').mockImplementation(async () => {
          // Simulate slow response
          await new Promise((resolve) => setTimeout(resolve, 2000));
          return [];
        });

        // Reduce timeout to trigger degradation
        const fastManager = new SearchStrategyManager({ timeoutMs: 1000 });

        const query: SearchQuery = {
          query: 'test slow vector response',
          mode: 'auto',
          limit: 10,
        };

        const result = await fastManager.executeSearch(query, 'auto');

        // Should degrade due to timeout
        expect(result.strategy).toBe('auto');
        expect(result.degraded).toBe(true);
        expect(result.fallbackReason).toContain('timeout');

        fastManager.resetMetrics();
      });

      it('should handle vector database high error rates', async () => {
        const errorRate = 0.8; // 80% error rate
        vi.spyOn(searchManager as unknown, 'performVectorSearch').mockImplementation(async () => {
          if (Math.random() < errorRate) {
            throw new Error('Vector database error');
          }
          return [];
        });

        const query: SearchQuery = {
          query: 'test high error rate',
          mode: 'deep',
          limit: 10,
        };

        // Execute multiple searches to trigger circuit breaker
        for (let i = 0; i < 10; i++) {
          try {
            await searchManager.executeSearch(query, 'deep');
          } catch (error) {
            // Some searches may fail completely
          }
        }

        // Circuit breaker should be activated
        const circuitBreakers = searchManager.getCircuitBreakerStates();
        expect(Array.from(circuitBreakers.values()).some((cb) => cb.isOpen)).toBe(true);

        // System should be marked as degraded
        const healthReport = searchManager.getSystemHealth();
        expect(['degraded', 'critical']).toContain(healthReport.overall_status);
      });
    });
  });

  describe('High Query Load Scenarios', () => {
    describe('Concurrent Search Load', () => {
      it('should handle high concurrent search load without system failure', async () => {
        const concurrentQueries = 50;
        const queries = Array.from({ length: concurrentQueries }, (_, i) => ({
          query: `concurrent search test ${i}`,
          mode: 'auto' as const,
          limit: 10,
        }));

        const startTime = Date.now();
        const results = await Promise.allSettled(
          queries.map((query) => searchManager.executeSearch(query, 'auto'))
        );
        const endTime = Date.now();

        // Analyze results
        const successful = results.filter((r) => r.status === 'fulfilled').length;
        const failed = results.filter((r) => r.status === 'rejected').length;

        // Most searches should succeed
        expect(successful).toBeGreaterThan(concurrentQueries * 0.8);
        expect(failed).toBeLessThan(concurrentQueries * 0.2);

        // Performance should remain reasonable
        const totalTime = endTime - startTime;
        const averageTime = totalTime / concurrentQueries;
        expect(averageTime).toBeLessThan(1000); // Less than 1 second per search

        // Verify system health
        const healthReport = searchManager.getSystemHealth();
        expect(['healthy', 'degraded']).toContain(healthReport.overall_status);

        // Performance metrics should be tracked
        const performanceMetrics = searchManager.getPerformanceMetrics();
        const autoMetrics = performanceMetrics.get('auto');
        expect(autoMetrics?.totalExecutions).toBe(concurrentQueries);
      });

      it('should maintain search quality under high load', async () => {
        const loadQueries = 30;
        const queries = Array.from({ length: loadQueries }, (_, i) => ({
          query: `quality test search ${i % 5} with repeated terms`,
          mode: 'deep' as const,
          limit: 15,
        }));

        const results = await Promise.allSettled(
          queries.map((query) => searchManager.executeSearch(query, 'deep'))
        );

        const successfulResults = results
          .filter((r) => r.status === 'fulfilled')
          .map((r) => (r as PromiseFulfilledResult<unknown>).value);

        // Verify search quality metrics
        const averageResults =
          successfulResults.reduce((sum, r) => sum + r.results.length, 0) /
          successfulResults.length;
        expect(averageResults).toBeGreaterThan(0);

        const averageConfidence =
          successfulResults.reduce((sum, r) => sum + r.confidence, 0) / successfulResults.length;
        expect(averageConfidence).toBeGreaterThan(0);

        // Check degradation rate
        const degradedCount = successfulResults.filter((r) => r.degraded).length;
        const degradationRate = degradedCount / successfulResults.length;
        expect(degradationRate).toBeLessThan(0.5); // Less than 50% degradation
      });

      it('should implement proper queuing and throttling under extreme load', async () => {
        // Create extremely high load
        const extremeLoad = 100;
        const queries = Array.from({ length: extremeLoad }, (_, i) => ({
          query: `extreme load test ${i}`,
          mode: 'fast' as const, // Use fastest strategy to test throughput
          limit: 5,
        }));

        const startTime = Date.now();
        const results = await Promise.allSettled(
          queries.map((query) => searchManager.executeSearch(query, 'fast'))
        );
        const endTime = Date.now();

        // System should handle extreme load gracefully
        const successful = results.filter((r) => r.status === 'fulfilled').length;
        expect(successful).toBeGreaterThan(extremeLoad * 0.7); // At least 70% success rate

        // Response times should increase but remain reasonable
        const totalTime = endTime - startTime;
        expect(totalTime).toBeLessThan(30000); // Less than 30 seconds total

        // Error rate should be controlled
        const errorMetrics = searchManager.getErrorMetrics();
        expect(errorMetrics.totalErrors).toBeLessThan(extremeLoad * 0.3);
      });
    });

    describe('Resource Exhaustion Scenarios', () => {
      it('should handle memory pressure gracefully', async () => {
        // Mock memory pressure detection
        jest
          .spyOn(searchManager as unknown, 'executeWithTimeout')
          .mockImplementation(async (operation, operationName) => {
            if (operationName.includes('vector') || operationName.includes('deep')) {
              // Simulate memory pressure on resource-intensive operations
              throw new Error('Out of memory');
            }
            return operation();
          });

        const query: SearchQuery = {
          query: 'test memory pressure',
          mode: 'deep',
          limit: 10,
        };

        const result = await searchManager.executeSearch(query, 'deep');

        // Should degrade to less memory-intensive strategy
        expect(result.strategy).toBe('deep');
        expect(result.degraded).toBe(true);
        expect(result.fallbackReason).toContain('memory');

        // Should still provide results
        expect(result.results).toBeDefined();
        expect(result.results.length).toBeGreaterThanOrEqual(0);
      });

      it('should handle database connection pool exhaustion', async () => {
        // Mock connection pool exhaustion
        let connectionCount = 0;
        const maxConnections = 5;

        vi.spyOn(searchManager as unknown, 'queryDatabase').mockImplementation(async () => {
          connectionCount++;
          if (connectionCount > maxConnections) {
            throw new Error('Connection pool exhausted');
          }
          return [];
        });

        const concurrentQueries = 10;
        const queries = Array.from({ length: concurrentQueries }, (_, i) => ({
          query: `connection test ${i}`,
          mode: 'auto',
          limit: 5,
        }));

        const results = await Promise.allSettled(
          queries.map((query) => searchManager.executeSearch(query, 'auto'))
        );

        // Some queries should succeed, others should be handled gracefully
        const successful = results.filter((r) => r.status === 'fulfilled').length;
        const failed = results.filter((r) => r.status === 'rejected').length;

        expect(successful).toBeGreaterThan(0);
        expect(failed).toBeGreaterThan(0);

        // Error handling should categorize as database errors
        const errorMetrics = searchManager.getErrorMetrics();
        expect(errorMetrics.errorsByCategory[ErrorCategory.DATABASE]).toBeGreaterThan(0);
      });

      it('should maintain system stability during CPU spikes', async () => {
        // Mock CPU-intensive operations causing timeouts
        vi.spyOn(searchManager as unknown, 'performVectorSearch').mockImplementation(async () => {
          // Simulate CPU-intensive operation
          const start = Date.now();
          while (Date.now() - start < 5000) {
            // Busy wait to simulate CPU load
          }
          throw new Error('Operation timed out');
        });

        const query: SearchQuery = {
          query: 'test cpu spike handling',
          mode: 'auto',
          limit: 10,
        };

        const startTime = Date.now();
        const result = await searchManager.executeSearch(query, 'auto');
        const endTime = Date.now();

        // Should timeout and degrade gracefully
        expect(result.strategy).toBe('auto');
        expect(result.degraded).toBe(true);
        expect(result.fallbackReason).toContain('timed out');

        // Should not take excessive time due to timeout handling
        expect(endTime - startTime).toBeLessThan(15000); // Less than 15 seconds
      });
    });
  });

  describe('Network Latency and Connectivity Issues', () => {
    describe('High Network Latency', () => {
      it('should handle high latency to vector database', async () => {
        // Mock high latency responses
        vi.spyOn(searchManager as unknown, 'performVectorSearch').mockImplementation(async () => {
          await new Promise((resolve) => setTimeout(resolve, 8000)); // 8 second delay
          return [];
        });

        // Set short timeout to trigger degradation
        const latencyManager = new SearchStrategyManager({ timeoutMs: 5000 });

        const query: SearchQuery = {
          query: 'test high latency',
          mode: 'auto',
          limit: 10,
        };

        const result = await latencyManager.executeSearch(query, 'auto');

        // Should degrade due to latency
        expect(result.strategy).toBe('auto');
        expect(result.degraded).toBe(true);
        expect(result.fallbackReason).toContain('timed out');

        latencyManager.resetMetrics();
      });

      it('should implement adaptive timeouts based on network conditions', async () => {
        let callCount = 0;
        vi.spyOn(searchManager as unknown, 'performVectorSearch').mockImplementation(async () => {
          callCount++;
          // First call is slow, subsequent calls are faster
          const delay = callCount === 1 ? 3000 : 500;
          await new Promise((resolve) => setTimeout(resolve, delay));
          return [];
        });

        const query: SearchQuery = {
          query: 'test adaptive timeout',
          mode: 'auto',
          limit: 10,
        };

        const firstResult = await searchManager.executeSearch(query, 'auto');
        expect(firstResult.degraded).toBe(true);

        // Subsequent calls should adapt
        const secondResult = await searchManager.executeSearch(query, 'auto');
        expect(secondResult.degraded).toBe(false);
      });

      it('should provide graceful fallback when network is unreliable', async () => {
        const reliabilityFactor = 0.5; // 50% network reliability
        vi.spyOn(searchManager as unknown, 'performVectorSearch').mockImplementation(async () => {
          if (Math.random() > reliabilityFactor) {
            throw new Error('Network timeout');
          }
          await new Promise((resolve) => setTimeout(resolve, 2000));
          return [];
        });

        const query: SearchQuery = {
          query: 'test unreliable network',
          mode: 'deep',
          limit: 10,
        };

        const results = [];
        for (let i = 0; i < 10; i++) {
          try {
            const result = await searchManager.executeSearch(query, 'deep');
            results.push(result);
          } catch (error) {
            // Some failures expected
          }
        }

        // Should have mixed success and degradation
        const degradedCount = results.filter((r) => r.degraded).length;
        const successCount = results.filter((r) => !r.degraded).length;

        expect(results.length).toBeGreaterThan(0);
        expect(degradedCount + successCount).toBe(results.length);
      });
    });

    describe('Network Connectivity Loss', () => {
      it('should handle complete network connectivity loss', async () => {
        // Mock complete network failure
        jest
          .spyOn(searchManager as unknown, 'performVectorSearch')
          .mockRejectedValue(new Error('Network unreachable'));
        jest
          .spyOn(searchManager as unknown, 'queryDatabase')
          .mockRejectedValue(new Error('Network unreachable'));

        const query: SearchQuery = {
          query: 'test network loss',
          mode: 'auto',
          limit: 10,
        };

        const result = await searchManager.executeSearch(query, 'auto');

        // Should handle gracefully with appropriate error
        expect(result.strategy).toBe('auto');
        expect(result.degraded).toBe(true);
        expect(result.fallbackReason).toMatch(/network|connection/);

        // Error should be properly categorized
        const errorMetrics = searchManager.getErrorMetrics();
        expect(errorMetrics.errorsByCategory[ErrorCategory.NETWORK]).toBeGreaterThan(0);
      });

      it('should handle intermittent network connectivity', async () => {
        let networkConnected = true;
        let flipCount = 0;

        vi.spyOn(searchManager as unknown, 'performVectorSearch').mockImplementation(async () => {
          flipCount++;
          if (flipCount % 3 === 0) {
            networkConnected = !networkConnected;
          }

          if (!networkConnected) {
            throw new Error('Connection reset by peer');
          }
          return [];
        });

        const query: SearchQuery = {
          query: 'test intermittent connectivity',
          mode: 'auto',
          limit: 10,
        };

        const results = [];
        for (let i = 0; i < 6; i++) {
          try {
            const result = await searchManager.executeSearch(query, 'auto');
            results.push(result);
          } catch (error) {
            // Some failures expected
          }
        }

        // Should have successful results despite intermittent failures
        expect(results.length).toBeGreaterThan(3);

        // Should show recovery attempts
        const errorMetrics = searchManager.getErrorMetrics();
        expect(errorMetrics.recoveryAttempts).toBeGreaterThan(0);
      });
    });
  });

  describe('Automatic Recovery Mechanisms', () => {
    describe('Health Check Recovery', () => {
      it('should automatically recover when vector database becomes available', async () => {
        let vectorHealthStatus = false;
        let healthCheckCount = 0;

        jest
          .spyOn(searchManager as unknown, 'checkVectorBackendHealth')
          .mockImplementation(async () => {
            healthCheckCount++;
            // Recover after 3 health checks
            if (healthCheckCount > 3) {
              vectorHealthStatus = true;
            }
            return vectorHealthStatus;
          });

        const query: SearchQuery = {
          query: 'test automatic recovery',
          mode: 'deep',
          limit: 10,
        };

        // First search should be degraded
        const firstResult = await searchManager.executeSearch(query, 'deep');
        expect(firstResult.degraded).toBe(true);

        // Wait for health check interval (simulated)
        await new Promise((resolve) => setTimeout(resolve, 100));

        // Second search should recover
        const secondResult = await searchManager.executeSearch(query, 'deep');
        expect(secondResult.degraded).toBe(false);
        expect(secondResult.vectorUsed).toBe(true);
      });

      it('should implement gradual recovery with health monitoring', async () => {
        let healthScore = 0.3; // Start with poor health
        let healthImprovementCount = 0;

        jest
          .spyOn(searchManager as unknown, 'checkVectorBackendHealth')
          .mockImplementation(async () => {
            healthImprovementCount++;
            // Gradually improve health
            healthScore = Math.min(1.0, healthScore + 0.2);
            return healthScore > 0.5; // Return true when health is sufficient
          });

        const query: SearchQuery = {
          query: 'test gradual recovery',
          mode: 'auto',
          limit: 10,
        };

        const results = [];
        for (let i = 0; i < 5; i++) {
          const result = await searchManager.executeSearch(query, 'auto');
          results.push(result);
          await new Promise((resolve) => setTimeout(resolve, 50));
        }

        // Should show gradual improvement
        const degradedResults = results.filter((r) => r.degraded).length;
        const recoveredResults = results.filter((r) => !r.degraded).length;

        expect(degradedResults).toBeGreaterThan(0);
        expect(recoveredResults).toBeGreaterThan(0);
        expect(recoveredResults).toBeGreaterThan(degradedResults); // More recovered than degraded
      });

      it('should handle recovery setbacks gracefully', async () => {
        let healthStatus = false;
        let recoveryAttempts = 0;
        let setbacks = 0;

        jest
          .spyOn(searchManager as unknown, 'checkVectorBackendHealth')
          .mockImplementation(async () => {
            recoveryAttempts++;

            // Simulate recovery with occasional setbacks
            if (recoveryAttempts % 4 === 0 && recoveryAttempts > 0) {
              setbacks++;
              healthStatus = false; // Setback
            } else if (recoveryAttempts > 2) {
              healthStatus = true; // Recovery
            }

            return healthStatus;
          });

        const query: SearchQuery = {
          query: 'test recovery setbacks',
          mode: 'deep',
          limit: 10,
        };

        const results = [];
        for (let i = 0; i < 8; i++) {
          const result = await searchManager.executeSearch(query, 'deep');
          results.push(result);
          await new Promise((resolve) => setTimeout(resolve, 50));
        }

        // Should handle setbacks and eventual recovery
        const finalResults = results.slice(-2);
        expect(finalResults.every((r) => r.degraded === false)).toBe(true);

        // Should track setbacks in metrics
        const healthReport = searchManager.getSystemHealth();
        expect(healthReport.vector_backend.consecutive_failures).toBeLessThanOrEqual(1);
      });
    });

    describe('Circuit Breaker Recovery', () => {
      it('should implement circuit breaker half-open state correctly', async () => {
        // Force circuit breaker to open
        const persistentError = new Error('Persistent failure');
        vi.spyOn(searchManager['deepVectorSearch'], 'search').mockRejectedValue(persistentError);

        const query: SearchQuery = {
          query: 'test circuit breaker',
          mode: 'deep',
          limit: 10,
        };

        // Trigger circuit breaker
        for (let i = 0; i < 6; i++) {
          try {
            await searchManager.executeSearch(query, 'deep');
          } catch (error) {
            // Expected failures
          }
        }

        // Circuit breaker should be open
        let circuitBreakers = searchManager.getCircuitBreakerStates();
        expect(circuitBreakers.get('search_deep')?.isOpen).toBe(true);

        // Mock successful recovery after timeout
        vi.spyOn(searchManager['deepVectorSearch'], 'search').mockResolvedValue([]);

        // Wait for circuit breaker timeout (simulated)
        await new Promise((resolve) => setTimeout(resolve, 100));

        // Next call should be in half-open state and succeed
        const recoveryResult = await searchManager.executeSearch(query, 'deep');
        expect(recoveryResult.degraded).toBe(false);

        // Circuit breaker should be closed after successful recovery
        circuitBreakers = searchManager.getCircuitBreakerStates();
        expect(circuitBreakers.get('search_deep')?.isOpen).toBe(false);
      });

      it('should handle circuit breaker re-opening on persistent failures', async () => {
        let failureCount = 0;
        const persistentError = new Error('Still failing');

        vi.spyOn(searchManager['deepVectorSearch'], 'search').mockImplementation(async () => {
          failureCount++;
          // Fail in half-open state to re-open circuit breaker
          if (failureCount === 7) {
            // After circuit breaker opens and goes half-open
            throw persistentError;
          }
          if (failureCount < 6) {
            throw persistentError;
          }
          return [];
        });

        const query: SearchQuery = {
          query: 'test circuit breaker reopening',
          mode: 'deep',
          limit: 10,
        };

        // Trigger initial circuit breaker opening
        for (let i = 0; i < 6; i++) {
          try {
            await searchManager.executeSearch(query, 'deep');
          } catch (error) {
            // Expected failures
          }
        }

        // Wait for half-open state
        await new Promise((resolve) => setTimeout(resolve, 100));

        // Try recovery (should fail and re-open)
        try {
          await searchManager.executeSearch(query, 'deep');
        } catch (error) {
          // Expected failure
        }

        // Circuit breaker should be open again
        const circuitBreakers = searchManager.getCircuitBreakerStates();
        expect(circuitBreakers.get('search_deep')?.isOpen).toBe(true);

        // Should track circuit breaker activations
        const errorMetrics = searchManager.getErrorMetrics();
        expect(errorMetrics.circuitBreakerActivations).toBeGreaterThan(0);
      });
    });

    describe('Performance-Based Recovery', () => {
      it('should auto-adjust based on performance metrics', async () => {
        let performanceTrend = 'degrading';
        let performanceValue = 5000; // Start with poor performance (5 seconds)

        vi.spyOn(searchManager as unknown, 'performVectorSearch').mockImplementation(async () => {
          // Simulate performance improvement
          if (performanceTrend === 'improving') {
            performanceValue = Math.max(1000, performanceValue - 1000);
          } else {
            performanceValue = Math.min(10000, performanceValue + 1000);
          }

          await new Promise((resolve) => setTimeout(resolve, performanceValue / 1000));

          if (performanceValue > 8000) {
            throw new Error('Performance too poor');
          }

          return [];
        });

        const query: SearchQuery = {
          query: 'test performance-based recovery',
          mode: 'auto',
          limit: 10,
        };

        // Initial searches should be degraded due to poor performance
        const initialResults = [];
        for (let i = 0; i < 3; i++) {
          const result = await searchManager.executeSearch(query, 'auto');
          initialResults.push(result);
        }

        expect(initialResults.every((r) => r.degraded)).toBe(true);

        // Simulate performance improvement
        performanceTrend = 'improving';

        // Later searches should recover
        const recoveredResults = [];
        for (let i = 0; i < 3; i++) {
          const result = await searchManager.executeSearch(query, 'auto');
          recoveredResults.push(result);
        }

        expect(recoveredResults.some((r) => !r.degraded)).toBe(true);
      });

      it('should implement intelligent retry backoff based on failure patterns', async () => {
        const failurePattern = [true, true, false, true, false, false, false]; // true = failure
        let patternIndex = 0;

        vi.spyOn(searchManager['autoHybridSearch'], 'search').mockImplementation(async () => {
          const shouldFail = failurePattern[patternIndex % failurePattern.length];
          patternIndex++;

          if (shouldFail) {
            throw new Error('Pattern-based failure');
          }

          return [];
        });

        const query: SearchQuery = {
          query: 'test intelligent retry',
          mode: 'auto',
          limit: 10,
        };

        const results = [];
        for (let i = 0; i < 7; i++) {
          try {
            const result = await searchManager.executeSearch(query, 'auto');
            results.push(result);
          } catch (error) {
            // Some failures expected based on pattern
          }
        }

        // Should have more successes than failures due to intelligent retry
        expect(results.length).toBeGreaterThan(3);

        // Should track recovery success rate
        const errorMetrics = searchManager.getErrorMetrics();
        const recoveryRate = errorMetrics.successfulRecoveries / errorMetrics.recoveryAttempts;
        expect(recoveryRate).toBeGreaterThan(0.5);
      });
    });
  });

  describe('Manual Recovery Triggers', () => {
    describe('Administrative Recovery', () => {
      it('should support manual circuit breaker reset', async () => {
        // Force circuit breaker to open
        const persistentError = new Error('Persistent failure');
        vi.spyOn(searchManager['fastKeywordSearch'], 'search').mockRejectedValue(persistentError);

        const query: SearchQuery = {
          query: 'test manual reset',
          mode: 'fast',
          limit: 10,
        };

        // Trigger circuit breaker
        for (let i = 0; i < 6; i++) {
          try {
            await searchManager.executeSearch(query, 'fast');
          } catch (error) {
            // Expected failures
          }
        }

        // Verify circuit breaker is open
        let circuitBreakers = searchManager.getCircuitBreakerStates();
        expect(circuitBreakers.get('search_fast')?.isOpen).toBe(true);

        // Manually reset circuit breaker
        searchManager.resetCircuitBreaker('search_fast');

        // Verify circuit breaker is reset
        circuitBreakers = searchManager.getCircuitBreakerStates();
        expect(circuitBreakers.get('search_fast')).toBeUndefined();

        // Mock successful operation after reset
        vi.spyOn(searchManager['fastKeywordSearch'], 'search').mockResolvedValue([]);

        // Should succeed after manual reset
        const result = await searchManager.executeSearch(query, 'fast');
        expect(result.strategy).toBe('fast');
        expect(result.degraded).toBe(false);
      });

      it('should support manual health status override', async () => {
        // Mock unhealthy status
        vi.spyOn(searchManager as unknown, 'checkVectorBackendHealth').mockResolvedValue(false);

        const query: SearchQuery = {
          query: 'test health override',
          mode: 'deep',
          limit: 10,
        };

        // Should be degraded initially
        const degradedResult = await searchManager.executeSearch(query, 'deep');
        expect(degradedResult.degraded).toBe(true);

        // Manually override vector health status
        (searchManager as unknown).vectorHealth = {
          available: true,
          responseTime: 100,
          lastChecked: new Date(),
          consecutiveFailures: 0,
          maxConsecutiveFailures: 3,
        };

        // Should recover after manual override
        const recoveredResult = await searchManager.executeSearch(query, 'deep');
        expect(recoveredResult.degraded).toBe(false);
        expect(recoveredResult.vectorUsed).toBe(true);
      });

      it('should support manual performance metrics reset', async () => {
        // Generate some poor performance metrics
        const query: SearchQuery = {
          query: 'test metrics reset',
          mode: 'auto',
          limit: 10,
        };

        // Execute searches to generate metrics
        for (let i = 0; i < 5; i++) {
          await searchManager.executeSearch(query, 'auto');
        }

        // Verify metrics exist
        let metrics = searchManager.getPerformanceMetrics();
        expect(metrics.get('auto')?.totalExecutions).toBeGreaterThan(0);

        // Reset metrics manually
        searchManager.resetMetrics();

        // Verify metrics are reset
        metrics = searchManager.getPerformanceMetrics();
        expect(metrics.get('auto')?.totalExecutions).toBe(0);

        // Should work normally after reset
        const result = await searchManager.executeSearch(query, 'auto');
        expect(result.strategy).toBe('auto');
        expect(result.executionTime).toBeGreaterThan(0);

        metrics = searchManager.getPerformanceMetrics();
        expect(metrics.get('auto')?.totalExecutions).toBe(1);
      });
    });

    describe('Configuration-Based Recovery', () => {
      it('should support runtime configuration updates for recovery', async () => {
        // Create manager with conservative settings
        const conservativeManager = new SearchStrategyManager({
          timeoutMs: 1000,
          retryAttempts: 1,
          degradationThreshold: 0.9,
        });

        // Mock slow responses
        jest
          .spyOn(conservativeManager as unknown, 'performVectorSearch')
          .mockImplementation(async () => {
            await new Promise((resolve) => setTimeout(resolve, 1500));
            throw new Error('Slow response');
          });

        const query: SearchQuery = {
          query: 'test config recovery',
          mode: 'auto',
          limit: 10,
        };

        // Should fail with conservative settings
        const conservativeResult = await conservativeManager.executeSearch(query, 'auto');
        expect(conservativeResult.degraded).toBe(true);

        // Create new manager with more lenient settings
        const lenientManager = new SearchStrategyManager({
          timeoutMs: 5000,
          retryAttempts: 3,
          degradationThreshold: 0.5,
        });

        // Apply same mocks to lenient manager
        jest
          .spyOn(lenientManager as unknown, 'performVectorSearch')
          .mockImplementation(async () => {
            await new Promise((resolve) => setTimeout(resolve, 1500));
            throw new Error('Slow response');
          });

        // Should handle better with lenient settings
        const lenientResult = await lenientManager.executeSearch(query, 'auto');
        expect(lenientResult.strategy).toBe('auto');
        // May still be degraded but should handle retries better

        conservativeManager.resetMetrics();
        lenientManager.resetMetrics();
      });

      it('should support adaptive threshold adjustments', async () => {
        let successRate = 0.3; // Start with poor success rate
        let adjustmentCount = 0;

        // Mock adaptive threshold logic
        vi.spyOn(searchManager as unknown, 'shouldDegrade').mockImplementation((performance) => {
          adjustmentCount++;

          // Simulate threshold adjustment based on recent performance
          if (adjustmentCount > 3) {
            successRate = Math.min(1.0, successRate + 0.2);
          }

          return performance < successRate;
        });

        const query: SearchQuery = {
          query: 'test adaptive thresholds',
          mode: 'auto',
          limit: 10,
        };

        const results = [];
        for (let i = 0; i < 6; i++) {
          const result = await searchManager.executeSearch(query, 'auto');
          results.push(result);
        }

        // Should show adaptation over time
        const earlyResults = results.slice(0, 3);
        const laterResults = results.slice(3);

        const earlyDegradationRate =
          earlyResults.filter((r) => r.degraded).length / earlyResults.length;
        const laterDegradationRate =
          laterResults.filter((r) => r.degraded).length / laterResults.length;

        expect(laterDegradationRate).toBeLessThanOrEqual(earlyDegradationRate);
      });
    });
  });

  describe('System Health Monitoring', () => {
    describe('Comprehensive Health Assessment', () => {
      it('should provide accurate overall system health status', async () => {
        // Generate mixed health conditions
        await searchManager.executeSearch({ query: 'healthy test', mode: 'fast' }, 'fast');

        // Mock some failures for degraded state
        vi.spyOn(searchManager as unknown, 'checkVectorBackendHealth').mockResolvedValue(false);
        await searchManager.executeSearch({ query: 'degraded test', mode: 'deep' }, 'deep');

        const healthReport = searchManager.getSystemHealth();

        // Verify comprehensive health reporting
        expect(healthReport.timestamp).toBeDefined();
        expect(healthReport.overall_status).toMatch(/^(healthy|degraded|critical)$/);
        expect(healthReport.vector_backend).toBeDefined();
        expect(healthReport.performance_metrics).toBeDefined();
        expect(healthReport.error_metrics).toBeDefined();
        expect(healthReport.circuit_breakers).toBeDefined();
        expect(healthReport.strategies).toBeDefined();

        // Verify vector backend status
        expect(healthReport.vector_backend.available).toBe(false);
        expect(healthReport.vector_backend.consecutive_failures).toBeGreaterThan(0);

        // Verify strategy status
        expect(healthReport.strategies).toHaveLength(3);
        const deepStrategy = healthReport.strategies.find((s: unknown) => s.name === 'deep');
        expect(['degraded', 'unavailable']).toContain(deepStrategy?.status);
      });

      it('should track health trends over time', async () => {
        const healthSnapshots = [];

        // Collect health snapshots over time
        for (let i = 0; i < 5; i++) {
          // Simulate changing conditions
          const isHealthy = i >= 2; // Become healthy after 2 iterations
          jest
            .spyOn(searchManager as unknown, 'checkVectorBackendHealth')
            .mockResolvedValue(isHealthy);

          await searchManager.executeSearch(
            {
              query: `health trend test ${i}`,
              mode: 'auto',
            },
            'auto'
          );

          const healthReport = searchManager.getSystemHealth();
          healthSnapshots.push(healthReport);
          await new Promise((resolve) => setTimeout(resolve, 50));
        }

        // Verify health trend tracking
        const earlySnapshots = healthSnapshots.slice(0, 2);
        const laterSnapshots = healthSnapshots.slice(2);

        const earlyHealthyCount = earlySnapshots.filter(
          (h) => h.overall_status === 'healthy'
        ).length;
        const laterHealthyCount = laterSnapshots.filter(
          (h) => h.overall_status === 'healthy'
        ).length;

        expect(laterHealthyCount).toBeGreaterThan(earlyHealthyCount);
      });

      it('should provide actionable health recommendations', async () => {
        // Create conditions that would trigger recommendations
        for (let i = 0; i < 10; i++) {
          try {
            await searchManager.executeSearch(
              {
                query: `recommendation test ${i}`,
                mode: 'deep',
              },
              'deep'
            );
          } catch (error) {
            // Generate failures for recommendations
          }
        }

        const analytics = searchManager.getSearchAnalytics();

        // Verify analytics include recommendations
        expect(analytics.timestamp).toBeDefined();
        expect(analytics.systemHealth).toBeDefined();
        expect(analytics.strategyMetrics).toBeDefined();
        expect(analytics.errorMetrics).toBeDefined();
        expect(analytics.recommendations).toBeDefined();
        expect(Array.isArray(analytics.recommendations)).toBe(true);

        // Verify recommendations have proper structure
        if (analytics.recommendations.length > 0) {
          const recommendation = analytics.recommendations[0];
          expect(recommendation.category).toMatch(
            /^(performance|reliability|usability|infrastructure)$/
          );
          expect(recommendation.priority).toMatch(/^(high|medium|low)$/);
          expect(recommendation.title).toBeDefined();
          expect(recommendation.description).toBeDefined();
          expect(Array.isArray(recommendation.actionItems)).toBe(true);
        }
      });
    });

    describe('Performance Metrics During Degradation', () => {
      it('should maintain accurate metrics during system degradation', async () => {
        // Mock degradation scenario
        vi.spyOn(searchManager as unknown, 'checkVectorBackendHealth').mockResolvedValue(false);

        const queries = Array.from({ length: 20 }, (_, i) => ({
          query: `degradation metrics test ${i}`,
          mode: 'auto' as const,
          limit: 10,
        }));

        // Execute searches during degradation
        const results = await Promise.allSettled(
          queries.map((query) => searchManager.executeSearch(query, 'auto'))
        );

        const successfulResults = results
          .filter((r) => r.status === 'fulfilled')
          .map((r) => (r as PromiseFulfilledResult<unknown>).value);

        // Verify metrics are tracked during degradation
        const performanceMetrics = searchManager.getPerformanceMetrics();
        const autoMetrics = performanceMetrics.get('auto');

        expect(autoMetrics?.totalExecutions).toBe(20);
        expect(autoMetrics?.degradationCount).toBeGreaterThan(0);
        expect(autoMetrics?.averageExecutionTime).toBeGreaterThan(0);

        // Verify error metrics
        const errorMetrics = searchManager.getErrorMetrics();
        expect(errorMetrics.totalErrors).toBeGreaterThanOrEqual(0);
        expect(errorMetrics.recoveryAttempts).toBeGreaterThan(0);
      });

      it('should measure performance impact of fallback strategies', async () => {
        // Mock fallback scenarios
        let useVector = false;
        jest
          .spyOn(searchManager as unknown, 'checkVectorBackendHealth')
          .mockImplementation(async () => {
            return useVector;
          });

        const query: SearchQuery = {
          query: 'fallback performance test',
          mode: 'auto',
          limit: 10,
        };

        // Test without vector (fallback mode)
        const fallbackResults = [];
        for (let i = 0; i < 5; i++) {
          const result = await searchManager.executeSearch(query, 'auto');
          fallbackResults.push(result);
        }

        // Test with vector (normal mode)
        useVector = true;
        const normalResults = [];
        for (let i = 0; i < 5; i++) {
          const result = await searchManager.executeSearch(query, 'auto');
          normalResults.push(result);
        }

        // Analyze performance differences
        const avgFallbackTime =
          fallbackResults.reduce((sum, r) => sum + r.executionTime, 0) / fallbackResults.length;
        const avgNormalTime =
          normalResults.reduce((sum, r) => sum + r.executionTime, 0) / normalResults.length;

        // Both should provide reasonable performance
        expect(avgFallbackTime).toBeGreaterThan(0);
        expect(avgNormalTime).toBeGreaterThan(0);

        // Fallback should maintain acceptable performance
        expect(avgFallbackTime).toBeLessThan(10000); // Less than 10 seconds

        // Verify all results are marked appropriately
        expect(fallbackResults.every((r) => r.degraded === true)).toBe(true);
        expect(normalResults.every((r) => r.degraded === false)).toBe(true);
      });
    });
  });

  describe('Error Rate and Threshold Management', () => {
    describe('Error Rate Monitoring', () => {
      it('should track error rates across different failure scenarios', async () => {
        // Mock different types of errors
        const errorScenarios = [
          () => Promise.reject(new Error('Network timeout')),
          () => Promise.reject(new Error('Database connection failed')),
          () => Promise.reject(new Error('Vector backend unavailable')),
          () => Promise.reject(new Error('Memory pressure')),
        ];

        const query: SearchQuery = {
          query: 'error rate test',
          mode: 'auto',
          limit: 10,
        };

        // Execute searches with different error types
        for (let i = 0; i < errorScenarios.length; i++) {
          jest
            .spyOn(searchManager['autoHybridSearch'], 'search')
            .mockImplementationOnce(errorScenarios[i]);

          try {
            await searchManager.executeSearch(query, 'auto');
          } catch (error) {
            // Expected failures
          }
        }

        // Verify error categorization
        const errorMetrics = searchManager.getErrorMetrics();
        expect(errorMetrics.totalErrors).toBe(4);
        expect(errorMetrics.errorsByCategory[ErrorCategory.NETWORK]).toBeGreaterThan(0);
        expect(errorMetrics.errorsByCategory[ErrorCategory.DATABASE]).toBeGreaterThan(0);
        expect(errorMetrics.errorsByCategory[ErrorCategory.VECTOR_BACKEND]).toBeGreaterThan(0);
        expect(errorMetrics.errorsByCategory[ErrorCategory.MEMORY]).toBeGreaterThan(0);
      });

      it('should implement error rate-based degradation thresholds', async () => {
        let errorRate = 0;
        let totalRequests = 0;

        vi.spyOn(searchManager['autoHybridSearch'], 'search').mockImplementation(async () => {
          totalRequests++;
          // Increase error rate over time
          if (totalRequests > 5) {
            errorRate = 0.8; // 80% error rate after 5 requests
          }

          if (Math.random() < errorRate) {
            throw new Error('High error rate condition');
          }

          return [];
        });

        const query: SearchQuery = {
          query: 'error threshold test',
          mode: 'auto',
          limit: 10,
        };

        const results = [];
        for (let i = 0; i < 10; i++) {
          try {
            const result = await searchManager.executeSearch(query, 'auto');
            results.push(result);
          } catch (error) {
            // Some failures expected
          }
        }

        // Should have mixed results due to error rate threshold
        expect(results.length).toBeGreaterThan(0);
        expect(results.length).toBeLessThan(10);

        // Should track error rate in metrics
        const errorMetrics = searchManager.getErrorMetrics();
        expect(errorMetrics.totalErrors).toBeGreaterThan(0);
        expect(errorMetrics.totalErrors).toBeLessThan(10);
      });

      it('should provide error rate recovery mechanisms', async () => {
        let errorRate = 0.9; // Start with high error rate
        let recoveryProgress = 0;

        vi.spyOn(searchManager['autoHybridSearch'], 'search').mockImplementation(async () => {
          recoveryProgress++;

          // Gradually reduce error rate (recovery)
          errorRate = Math.max(0.1, errorRate - 0.15);

          if (Math.random() < errorRate) {
            throw new Error('Recovering from high error rate');
          }

          return [];
        });

        const query: SearchQuery = {
          query: 'error recovery test',
          mode: 'auto',
          limit: 10,
        };

        const results = [];
        for (let i = 0; i < 8; i++) {
          try {
            const result = await searchManager.executeSearch(query, 'auto');
            results.push(result);
          } catch (error) {
            // Some failures expected during recovery
          }
        }

        // Should show improvement over time (more successes later)
        const earlyResults = results.slice(0, 4);
        const laterResults = results.slice(4);

        expect(laterResults.length).toBeGreaterThanOrEqual(earlyResults.length);

        // Recovery should be tracked
        const errorMetrics = searchManager.getErrorMetrics();
        expect(errorMetrics.successfulRecoveries).toBeGreaterThan(0);
      });
    });

    describe('Dynamic Threshold Adjustment', () => {
      it('should adjust degradation thresholds based on system performance', async () => {
        let systemLoad = 0.3; // Start with low load

        // Mock performance-based threshold adjustment
        vi.spyOn(searchManager as unknown, 'getDynamicThreshold').mockImplementation(() => {
          // Increase threshold as system load increases
          return 0.7 + systemLoad * 0.2;
        });

        vi.spyOn(searchManager as unknown, 'performVectorSearch').mockImplementation(async () => {
          systemLoad += 0.1; // Simulate increasing load

          if (systemLoad > 0.7) {
            throw new Error('System overloaded');
          }

          return [];
        });

        const query: SearchQuery = {
          query: 'dynamic threshold test',
          mode: 'auto',
          limit: 10,
        };

        const results = [];
        for (let i = 0; i < 6; i++) {
          try {
            const result = await searchManager.executeSearch(query, 'auto');
            results.push(result);
          } catch (error) {
            // Some failures expected as load increases
          }
        }

        // Should adapt to changing conditions
        expect(results.length).toBeGreaterThan(0);

        // Later searches should be more likely to be degraded
        const degradations = results.map((r) => r.degraded);
        const laterDegradations = degradations.slice(3);
        expect(laterDegradations.some((d) => d)).toBe(true);
      });

      it('should implement context-aware threshold adjustments', async () => {
        // Mock different contexts requiring different thresholds
        const contexts = [
          { query: 'critical search', priority: 'high', expectedThreshold: 0.9 },
          { query: 'background search', priority: 'low', expectedThreshold: 0.5 },
          { query: 'standard search', priority: 'medium', expectedThreshold: 0.7 },
        ];

        const results = [];

        for (const context of contexts) {
          jest
            .spyOn(searchManager as unknown, 'getContextualThreshold')
            .mockReturnValue(context.expectedThreshold);

          const query: SearchQuery = {
            query: context.query,
            mode: 'auto',
            limit: 10,
          };

          // Mock performance based on threshold
          jest
            .spyOn(searchManager as unknown, 'performVectorSearch')
            .mockImplementation(async () => {
              const performance = Math.random();
              if (performance < context.expectedThreshold) {
                throw new Error('Below contextual threshold');
              }
              return [];
            });

          try {
            const result = await searchManager.executeSearch(query, 'auto');
            results.push({ ...result, context: context.priority });
          } catch (error) {
            // Handle based on context
          }
        }

        // Should have applied different thresholds based on context
        expect(results.length).toBeGreaterThan(0);

        // Higher priority contexts should have better success rates
        const highPriorityResult = results.find((r) => r.context === 'high');
        expect(highPriorityResult?.degraded).toBe(false);
      });
    });
  });
});
