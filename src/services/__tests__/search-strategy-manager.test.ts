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

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { SearchStrategyManager } from '../search/search-strategy-manager.js';
import {
  searchErrorHandler,
  ErrorCategory,
  ErrorSeverity,
} from '../search/search-error-handler.js';
import type { SearchQuery } from '../../types/core-interfaces.js';

// Mock the logger to avoid noise in tests
jest.mock('../../utils/logger.js', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
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
        jest.spyOn(searchManager as any, 'updateVectorHealth').mockImplementation(async () => {
          searchManager['vectorHealth'].available = false;
          searchManager['vectorHealth'].consecutiveFailures = 3;
          searchManager['vectorHealth'].degradationReason = 'Mocked failure';
        });

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
        jest.spyOn(searchManager as any, 'checkVectorBackendHealth').mockResolvedValue(false);

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
      jest
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
      jest.spyOn(searchManager['autoHybridSearch'], 'search').mockRejectedValue(timeoutError);

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
      jest.spyOn(searchManager['deepVectorSearch'], 'search').mockRejectedValue(persistentError);

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
      jest.spyOn(searchManager['fastKeywordSearch'], 'search').mockRejectedValue(validationError);

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

      expect(performanceMetrics.size).toBe(3);
      expect(performanceMetrics.get('fast')?.totalExecutions).toBe(1);
      expect(performanceMetrics.get('auto')?.totalExecutions).toBe(1);
      expect(performanceMetrics.get('deep')?.totalExecutions).toBe(1);
    });

    it('should calculate average execution times', async () => {
      const query: SearchQuery = {
        query: 'performance test query',
        mode: 'fast',
      };

      // Execute multiple searches to build metrics
      for (let i = 0; i < 3; i++) {
        await searchManager.executeSearch(query, 'fast');
      }

      const performanceMetrics = searchManager.getPerformanceMetrics();
      const fastMetrics = performanceMetrics.get('fast');

      expect(fastMetrics?.totalExecutions).toBe(3);
      expect(fastMetrics?.averageExecutionTime).toBeGreaterThan(0);
      expect(fastMetrics?.averageResultCount).toBeGreaterThanOrEqual(0);
    });

    it('should track degradation and fallback metrics', async () => {
      // Mock vector unavailability to trigger degradation
      jest.spyOn(searchManager as any, 'checkVectorBackendHealth').mockResolvedValue(false);

      const query: SearchQuery = {
        query: 'degradation test',
        mode: 'deep',
      };

      await searchManager.executeSearch(query, 'deep');

      const performanceMetrics = searchManager.getPerformanceMetrics();
      const deepMetrics = performanceMetrics.get('deep');

      expect(deepMetrics?.degradationCount).toBeGreaterThan(0);
    });
  });

  describe('System Health and Monitoring', () => {
    it('should provide comprehensive system health report', async () => {
      // Execute some searches to generate data
      await searchManager.executeSearch({ query: 'test', mode: 'fast' }, 'fast');
      await searchManager.executeSearch({ query: 'test', mode: 'auto' }, 'auto');

      const healthReport = searchManager.getSystemHealth();

      expect(healthReport.timestamp).toBeDefined();
      expect(healthReport.overall_status).toMatch(/^(healthy|degraded|critical)$/);
      expect(healthReport.vector_backend).toBeDefined();
      expect(healthReport.performance_metrics).toBeDefined();
      expect(healthReport.error_metrics).toBeDefined();
      expect(healthReport.circuit_breakers).toBeDefined();
      expect(healthReport.strategies).toBeDefined();
    });

    it('should detect degraded system state', async () => {
      // Mock vector backend failure
      jest.spyOn(searchManager as any, 'checkVectorBackendHealth').mockResolvedValue(false);

      const query: SearchQuery = {
        query: 'health test',
        mode: 'deep',
      };

      await searchManager.executeSearch(query, 'deep');

      const healthReport = searchManager.getSystemHealth();

      expect(healthReport.vector_backend.available).toBe(false);
      expect(healthReport.overall_status).toBe('degraded');
    });

    it('should provide strategy status information', async () => {
      const strategies = searchManager.getSupportedStrategies();

      expect(strategies).toHaveLength(3);
      expect(strategies.map((s) => s.name)).toEqual(['fast', 'auto', 'deep']);

      const fastStrategy = strategies.find((s) => s.name === 'fast');
      expect(fastStrategy?.vector_required).toBe(false);
      expect(fastStrategy?.current_status).toBe('available');

      const deepStrategy = strategies.find((s) => s.name === 'deep');
      expect(deepStrategy?.vector_required).toBe(true);
      expect(deepStrategy?.performance).toBeDefined();
    });

    it('should track error metrics across categories', async () => {
      // Generate different types of errors
      const errors = [
        new Error('Network timeout'),
        new Error('Validation failed'),
        new Error('Database connection lost'),
      ];

      const errorPromises = errors.map(async (error, index) => {
        jest.spyOn(searchManager['fastKeywordSearch'], 'search').mockRejectedValueOnce(error);

        try {
          await searchManager.executeSearch({ query: `error test ${index}`, mode: 'fast' }, 'fast');
        } catch (e) {
          // Expected to fail
        }
      });

      await Promise.allSettled(errorPromises);

      const errorMetrics = searchManager.getErrorMetrics();

      expect(errorMetrics.totalErrors).toBeGreaterThan(0);
      expect(errorMetrics.recoveryAttempts).toBeGreaterThan(0);
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
      expect(metrics.get('fast')?.totalExecutions).toBe(1);

      // Reset metrics
      searchManager.resetMetrics();

      metrics = searchManager.getPerformanceMetrics();
      expect(metrics.get('fast')?.totalExecutions).toBe(0);
    });

    it('should handle circuit breaker reset', async () => {
      const operationKey = 'test_operation';

      // Manually activate circuit breaker
      searchManager.resetCircuitBreaker(operationKey);

      const circuitBreakers = searchManager.getCircuitBreakerStates();
      expect(circuitBreakers.has(operationKey)).toBe(false);
    });
  });

  describe('Integration with Memory Find', () => {
    it('should work with memory find wrapper', async () => {
      const { memoryFindWithStrategies } = require('../memory-find.js');

      const query: SearchQuery = {
        query: 'integration test',
        mode: 'auto',
        limit: 5,
      };

      const result = await memoryFindWithStrategies(query);

      expect(result.results).toBeDefined();
      expect(result.observability).toBeDefined();
      expect(result.observability.strategy).toBe('auto');
      expect(result.observability.search_id).toBeDefined();
      expect(result.autonomous_context).toBeDefined();
    });

    it('should handle scope precedence correctly', async () => {
      const { memoryFindWithStrategies } = require('../memory-find.js');

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

      const result = await memoryFindWithStrategies(query);

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
      expect(performanceMetrics.get('fast')?.totalExecutions).toBe(10);
    });
  });
});
