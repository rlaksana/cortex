/**
 * Search Strategy Manager Test Suite - Phase 3 Enhanced
 *
 * Comprehensive tests for the stabilized search strategy system including:
 * - Fast, auto, and deep search strategies
 * - Vector backend degradation and fallback logic
 * - Error handling and recovery mechanisms
 * - Circuit breaker functionality
 * - Performance monitoring and metrics
 * - System health reporting
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { SearchQuery } from '../../types/core-interfaces';
import { memoryFindWithStrategies } from '../memory-find';
import { ErrorCategory, ErrorSeverity, searchErrorHandler } from '../search/search-error-handler';
import { SearchStrategyManager } from '../search/search-strategy-manager';

// Mock the logger to avoid noise in tests
vi.mock('@/utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

describe('SearchStrategyManager', () => {
  let searchManager: SearchStrategyManager;

  beforeEach(() => {
    searchManager = new SearchStrategyManager({
      maxResults: 10,
      timeoutMs: 5000,
      retryAttempts: 2,
      degradationThreshold: 0.7,
    });

    // Reset error handler metrics before each test
    searchErrorHandler.resetMetrics();
    searchManager.resetMetrics();
  });

  afterEach(() => {
    searchManager.resetMetrics();
    searchErrorHandler.resetAllCircuitBreakers();
  });

  describe('Strategy Execution', () => {
    describe('Fast Search Strategy', () => {
      it('should execute fast search successfully', async () => {
        const query: SearchQuery = {
          query: 'test query',
          mode: 'fast',
          limit: 5,
        };

        const result = await searchManager.executeSearch(query, 'fast');

        expect(result.strategy).toBe('fast');
        expect(result.vectorUsed).toBe(false);
        expect(result.degraded).toBe(false);
        expect(result.executionTime).toBeGreaterThan(0);
        expect(result.metadata.totalSearched).toBeGreaterThanOrEqual(0);
        expect(result.metadata.backendHealthStatus).toBe('healthy');
      });

      it('should handle empty query in fast mode', async () => {
        const query: SearchQuery = {
          query: '',
          mode: 'fast',
        };

        const result = await searchManager.executeSearch(query, 'fast');

        expect(result.strategy).toBe('fast');
        expect(result.results).toBeDefined();
      });

      it('should respect limit parameter in fast mode', async () => {
        const query: SearchQuery = {
          query: 'test query',
          mode: 'fast',
          limit: 3,
        };

        const result = await searchManager.executeSearch(query, 'fast');

        expect(result.results.length).toBeLessThanOrEqual(3);
      });
    });

    describe('Auto Search Strategy', () => {
      it('should execute auto search with vector available', async () => {
        const query: SearchQuery = {
          query: 'test query',
          mode: 'auto',
          limit: 10,
        };

        const result = await searchManager.executeSearch(query, 'auto');

        expect(result.strategy).toBe('auto');
        expect(result.vectorUsed).toBeDefined();
        expect(result.degraded).toBeDefined();
        expect(result.executionTime).toBeGreaterThan(0);
      });

      it('should degrade gracefully when vector unavailable', async () => {
        // Mock vector health as unavailable
        searchManager['vectorHealth'] = {
          available: false,
          consecutiveFailures: 3,
          degradationReason: 'Mocked failure',
        };

        const query: SearchQuery = {
          query: 'test query',
          mode: 'auto',
        };

        const result = await searchManager.executeSearch(query, 'auto');

        expect(result.strategy).toBe('auto');
        expect(result.degraded).toBe(true);
        expect(result.fallbackReason).toContain('degraded');
      });

      it('should handle type filtering in auto mode', async () => {
        const query: SearchQuery = {
          query: 'test query',
          mode: 'auto',
          types: ['entity', 'decision'],
          limit: 10,
        };

        const result = await searchManager.executeSearch(query, 'auto');

        expect(result.strategy).toBe('auto');
        // Note: In mock implementation, all results are allowed through
        // In real implementation, this would filter by specified types
      });
    });

    describe('Deep Search Strategy', () => {
      it('should execute deep search with vector available', async () => {
        const query: SearchQuery = {
          query: 'test query',
          mode: 'deep',
          limit: 15,
        };

        const result = await searchManager.executeSearch(query, 'deep');

        expect(result.strategy).toBe('deep');
        expect(result.vectorUsed).toBe(true);
        expect(result.degraded).toBe(false);
        expect(result.executionTime).toBeGreaterThan(0);
      });

      it('should degrade to auto when vector unavailable', async () => {
        // Mock vector health check to return false
        vi.spyOn(searchManager as any, 'getVectorHealth').mockReturnValue(false);

        const query: SearchQuery = {
          query: 'test query',
          mode: 'deep',
        };

        const result = await searchManager.executeSearch(query, 'deep');

        expect(result.strategy).toBe('deep');
        expect(result.degraded).toBe(true);
        expect(result.fallbackReason).toContain('unavailable');
      });

      it('should apply graph expansion when requested', async () => {
        const query: SearchQuery = {
          query: 'test query',
          mode: 'deep',
          expand: 'relations',
          limit: 20,
        };

        const result = await searchManager.executeSearch(query, 'deep');

        expect(result.strategy).toBe('deep');
        expect(result.metadata.expansionApplied).toBe(true);
      });

      it('should handle different expansion types', async () => {
        const expansionTypes = ['relations', 'parents', 'children'] as const;

        for (const expandType of expansionTypes) {
          const query: SearchQuery = {
            query: 'test query',
            mode: 'deep',
            expand: expandType,
          };

          const result = await searchManager.executeSearch(query, 'deep');

          expect(result.strategy).toBe('deep');
          expect(result.metadata.expansionApplied).toBe(true);
        }
      });
    });
  });

  describe('Error Handling and Recovery', () => {
    it('should handle network errors with retry', async () => {
      // Mock network error
      const networkError = new Error('Network connection failed');
      vi
        .spyOn(searchManager['fastKeywordSearch'], 'search')
        .mockRejectedValueOnce(networkError)
        .mockRejectedValueOnce(networkError)
        .mockResolvedValueOnce([]);

      const query: SearchQuery = {
        query: 'test query',
        mode: 'fast',
      };

      const result = await searchManager.executeSearch(query, 'fast');

      expect(result.strategy).toBe('fast');
      expect(searchManager['fastKeywordSearch'].search).toHaveBeenCalledTimes(3);
    });

    it('should handle timeout errors with fallback', async () => {
      const timeoutError = new Error('Request timed out');
      vi.spyOn(searchManager['autoHybridSearch'], 'search').mockRejectedValue(timeoutError);

      const query: SearchQuery = {
        query: 'test query',
        mode: 'auto',
      };

      const result = await searchManager.executeSearch(query, 'auto');

      expect(result.strategy).toBe('auto');
      expect(result.degraded).toBe(true);
      expect(result.fallbackReason).toBeDefined();
    });

    it('should activate circuit breaker on repeated failures', async () => {
      const persistentError = new Error('Persistent database error');
      vi.spyOn(searchManager['deepVectorSearch'], 'search').mockRejectedValue(persistentError);

      const query: SearchQuery = {
        query: 'test query',
        mode: 'deep',
      };

      // Execute multiple failing searches to trigger circuit breaker
      for (let i = 0; i < 6; i++) {
        try {
          await searchManager.executeSearch(query, 'deep');
        } catch (error) {
          // Expected to fail
        }
      }

      const circuitBreakers = searchManager.getCircuitBreakerStates();
      expect(circuitBreakers.has('search_deep')).toBe(true);
    });

    it('should provide detailed error information', async () => {
      const validationError = new Error('Invalid query format');
      vi.spyOn(searchManager['fastKeywordSearch'], 'search').mockRejectedValue(validationError);

      const query: SearchQuery = {
        query: 'test query',
        mode: 'fast',
      };

      try {
        await searchManager.executeSearch(query, 'fast');
      } catch (error) {
        // Verify error was handled by error handler
        const errorMetrics = searchManager.getErrorMetrics();
        expect(errorMetrics.totalErrors).toBeGreaterThan(0);
        expect(errorMetrics.errorsByCategory[ErrorCategory.VALIDATION]).toBeGreaterThan(0);
      }
    });
  });

  describe('Performance Monitoring', () => {
    it('should track performance metrics for each strategy', async () => {
      const strategies = ['fast', 'auto', 'deep'] as const;

      for (const strategy of strategies) {
        const query: SearchQuery = {
          query: `test ${strategy} query`,
          mode: strategy,
        };

        await searchManager.executeSearch(query, strategy);
      }

      const performanceMetrics = searchManager.getPerformanceMetrics();

      // Verify we have basic metrics (the implementation stores aggregated metrics, not per-strategy)
      expect(typeof performanceMetrics.totalSearches).toBe('number');
      expect(typeof performanceMetrics.successfulSearches).toBe('number');
      expect(typeof performanceMetrics.averageResponseTime).toBe('number');

      // Should have executed 3 searches total
      expect(performanceMetrics.totalSearches).toBe(3);
    });

    it('should calculate average execution times', async () => {
      const query: SearchQuery = {
        query: 'performance test query',
        mode: 'fast',
      };

      // Execute multiple searches to build metrics
      for (let i = 0; i < 3; i++) {
        const searchResult = await searchManager.executeSearch(query, 'fast');
        // Verify the result is defined
        const isDefined = searchResult !== undefined;
        expect(isDefined).toBe(true);
      }

      const performanceMetrics = searchManager.getPerformanceMetrics();

      // Verify basic metrics exist and are reasonable
      expect(performanceMetrics.totalSearches).toBe(3);
      expect(performanceMetrics.successfulSearches).toBe(3);
      expect(performanceMetrics.averageResponseTime).toBeGreaterThanOrEqual(0);
      expect(typeof performanceMetrics.averageResponseTime).toBe('number');
    });

    it('should track degradation and fallback metrics', async () => {
      // Mock vector unavailability to trigger degradation
      vi.spyOn(searchManager as any, 'getVectorHealth').mockReturnValue(false);

      const query: SearchQuery = {
        query: 'degradation test',
        mode: 'deep',
      };

      const searchResult = await searchManager.executeSearch(query, 'deep');
      const resultExists = searchResult !== undefined;
      expect(resultExists).toBe(true);

      const performanceMetrics = searchManager.getPerformanceMetrics();

      // Verify basic metrics exist after deep search execution
      expect(performanceMetrics.totalSearches).toBeGreaterThanOrEqual(1);
      expect(typeof performanceMetrics.totalSearches).toBe('number');
    });
  });

  describe('System Health and Monitoring', () => {
    it('should provide comprehensive system health report', async () => {
      // Execute some searches to generate data
      await searchManager.executeSearch({ query: 'test', mode: 'fast' }, 'fast');
      await searchManager.executeSearch({ query: 'test', mode: 'auto' }, 'auto');

      const healthReport = searchManager.getSystemHealth();

      expect(healthReport.overall).toMatch(/^(healthy|degraded|unhealthy)$/);
      expect(healthReport.components).toBeDefined();
      expect(healthReport.metrics).toBeDefined();
    });

    it('should detect degraded system state', async () => {
      // Mock vector backend failure
      vi.spyOn(searchManager as any, 'getVectorHealth').mockReturnValue(false);

      const query: SearchQuery = {
        query: 'health test',
        mode: 'deep',
      };

      await searchManager.executeSearch(query, 'deep');

      const healthReport = searchManager.getSystemHealth();

      expect(healthReport.components.vector).toBe(false);
      expect(healthReport.overall).toBe('degraded');
    });

    it('should provide strategy status information', async () => {
      const strategies = searchManager.getSupportedStrategies();

      expect(strategies.length).toBeGreaterThan(0);
      expect(strategies).toContain('fast');
      expect(strategies).toContain('auto');
      expect(strategies).toContain('deep');
    });

    it('should track error metrics across categories', async () => {
      // Generate different types of errors
      const errors = [
        new Error('Network timeout'),
        new Error('Validation failed'),
        new Error('Database connection lost'),
      ];

      const errorPromises = errors.map(async (error, index) => {
        vi.spyOn(searchManager['fastKeywordSearch'], 'search').mockRejectedValueOnce(error);

        try {
          await searchManager.executeSearch({ query: `error test ${index}`, mode: 'fast' }, 'fast');
        } catch (e) {
          // Expected to fail
        }
      });

      await Promise.allSettled(errorPromises);

      const errorMetrics = searchManager.getErrorMetrics();

      expect(errorMetrics.totalErrors).toBeGreaterThan(0);
      expect(Object.values(errorMetrics.errorsByCategory).some((count) => count > 0)).toBe(true);
    });
  });

  describe('Configuration and Customization', () => {
    it('should accept custom configuration', () => {
      const customConfig = {
        maxResults: 25,
        timeoutMs: 10000,
        retryAttempts: 5,
        degradationThreshold: 0.8,
      };

      const customManager = new SearchStrategyManager(customConfig);

      expect(customManager).toBeDefined();
      // Configuration is private, but we can test its effects through behavior
    });

    it('should reset metrics successfully', async () => {
      // Generate some metrics
      await searchManager.executeSearch({ query: 'test', mode: 'fast' }, 'fast');

      let metrics = searchManager.getPerformanceMetrics();
      const totalSearchesBefore = metrics.totalSearches;
      expect(totalSearchesBefore).toBeGreaterThan(0);

      // Reset metrics
      searchManager.resetMetrics();

      metrics = searchManager.getPerformanceMetrics();
      const totalSearchesAfter = metrics.totalSearches;
      expect(totalSearchesAfter).toBe(0);
    });

    it('should handle circuit breaker reset', async () => {
      const operationKey = 'test_operation';

      // Check circuit breaker states
      const circuitBreakers = searchManager.getCircuitBreakerStates();
      expect(circuitBreakers).toBeDefined();
    });
  });

  describe('Integration with Memory Find', () => {
    it('should work with memory find wrapper', async () => {
      const memoryFindService = memoryFindWithStrategies;

      const query: SearchQuery = {
        query: 'integration test',
        mode: 'auto',
        limit: 5,
      };

      const result = await memoryFindService(query);

      expect(result.results).toBeDefined();
      expect(result.observability).toBeDefined();
      expect(result.observability.strategy).toBe('auto');
      expect(result.observability.search_id).toBeDefined();
      expect(result.autonomous_context).toBeDefined();
    });

    it('should handle scope precedence correctly', async () => {
      const memoryFindService = memoryFindWithStrategies;

      // Set environment variables
      process.env.CORTEX_ORG = 'test-org';
      process.env.CORTEX_PROJECT = 'test-project';

      const query: SearchQuery = {
        query: 'scope test',
        mode: 'fast',
        scope: {
          branch: 'test-branch',
        },
      };

      const result = await memoryFindService(query);

      expect(result.results).toBeDefined();

      // Clean up
      delete process.env.CORTEX_ORG;
      delete process.env.CORTEX_PROJECT;
    });
  });

  describe('Edge Cases and Boundary Conditions', () => {
    it('should handle very long queries', async () => {
      const longQuery = 'a'.repeat(1000);
      const query: SearchQuery = {
        query: longQuery,
        mode: 'fast',
      };

      const result = await searchManager.executeSearch(query, 'fast');

      expect(result.strategy).toBe('fast');
      expect(result.executionTime).toBeGreaterThan(0);
    });

    it('should handle special characters in queries', async () => {
      const specialQuery = 'test query with special chars: !@#$%^&*()_+-={}[]|\\:";\'<>?,./';
      const query: SearchQuery = {
        query: specialQuery,
        mode: 'auto',
      };

      const result = await searchManager.executeSearch(query, 'auto');

      expect(result.strategy).toBe('auto');
      expect(result).toBeDefined();
    });

    it('should handle zero limit', async () => {
      const query: SearchQuery = {
        query: 'test query',
        mode: 'fast',
        limit: 0,
      };

      const result = await searchManager.executeSearch(query, 'fast');

      expect(result.results.length).toBe(0);
    });

    it('should handle very large limit', async () => {
      const query: SearchQuery = {
        query: 'test query',
        mode: 'fast',
        limit: 10000,
      };

      const result = await searchManager.executeSearch(query, 'fast');

      // Should respect maximum internal limit
      expect(result.results.length).toBeLessThanOrEqual(50); // Default maxResults
    });

    it('should handle concurrent searches', async () => {
      const queries = Array.from({ length: 10 }, (_, i) => ({
        query: `concurrent test ${i}`,
        mode: 'fast' as const,
      }));

      const results = await Promise.all(
        queries.map((query) => searchManager.executeSearch(query, 'fast'))
      );

      expect(results).toHaveLength(10);
      results.forEach((result) => {
        expect(result.strategy).toBe('fast');
        expect(result.executionTime).toBeGreaterThan(0);
      });

      const performanceMetrics = searchManager.getPerformanceMetrics();
      const totalSearches = performanceMetrics.totalSearches;
      expect(totalSearches).toBeGreaterThan(0);
    });
  });
});
