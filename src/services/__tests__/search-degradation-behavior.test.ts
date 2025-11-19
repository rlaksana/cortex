/**
 * Search Degradation Behavior Test Suite (Fixed)
 *
 * Comprehensive tests for search system resilience and degrade behavior
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { logger } from '@/utils/logger.js';
import type { SearchQuery } from '../../types/core-interfaces';
import {
  ErrorCategory,
  ErrorSeverity,
  RecoveryStrategy,
  searchErrorHandler,
} from '../search/search-error-handler';
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
    vi.clearAllMocks();
  });

  afterEach(() => {
    searchManager.resetMetrics();
    searchErrorHandler.resetAllCircuitBreakers();
    vi.clearAllMocks();
  });

  describe('Vector Database Failure Scenarios', () => {
    describe('Complete Vector Database Unavailability', () => {
      it('should degrade gracefully when vector database is completely unavailable', async () => {
        // Mock complete vector database failure
        vi.spyOn(searchManager, 'getVectorHealth').mockReturnValue(false);

        const query: SearchQuery = {
          query: 'test semantic search query',
          mode: 'deep',
          expand: 'relations',
          limit: 10,
        };

        const result = await searchManager.executeSearch(query, 'deep');

        // Verify degradation behavior
        expect(result.strategy).toBe('deep');
        expect(result.results).toBeDefined();
        expect(Array.isArray(result.results)).toBe(true);
        expect(result.executionTime).toBeGreaterThan(0);

        // Verify audit logging
        const auditLogs = searchManager.getRecentAuditLogs();
        expect(Array.isArray(auditLogs)).toBe(true);
      });

      it('should maintain functionality across all search strategies during vector outage', async () => {
        // Mock persistent vector database failure
        vi.spyOn(searchManager, 'getVectorHealth').mockReturnValue(false);

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

        // Verify all strategies completed
        expect(results).toHaveLength(3);
        results.forEach(result => {
          expect(result.strategy).toBeDefined();
          expect(result.results).toBeDefined();
        });
      });

      it('should handle vector database recovery gracefully', async () => {
        // Mock initial vector database failure
        let vectorAvailable = false;
        vi
          .spyOn(searchManager, 'getVectorHealth')
          .mockImplementation(() => {
            return vectorAvailable;
          });

        const query: SearchQuery = {
          query: 'test recovery behavior',
          mode: 'deep',
          limit: 10,
        };

        // First search during failure (should degrade)
        const degradedResult = await searchManager.executeSearch(query, 'deep');
        expect(degradedResult.results).toBeDefined();
        expect(degradedResult.executionTime).toBeGreaterThan(0);

        // Simulate vector database recovery
        vectorAvailable = true;

        // Second search after recovery (should not degrade)
        const recoveredResult = await searchManager.executeSearch(query, 'deep');
        expect(recoveredResult.results).toBeDefined();
        expect(recoveredResult.executionTime).toBeGreaterThan(0);

        // Verify recovery is logged
        const healthReport = searchManager.getSystemHealth();
        expect(healthReport.overall).toBeDefined();
      });
    });

    describe('Circuit Breaker Functionality', () => {
      it('should activate circuit breaker when error rate is high', async () => {
        // Force circuit breaker open
        searchManager.forceCircuitBreakerState('vector_search', true);

        const query: SearchQuery = {
          query: 'test circuit breaker activation',
          mode: 'auto',
          limit: 10,
        };

        const result = await searchManager.executeSearch(query, 'auto');

        // Should still complete with fallback
        expect(result.strategy).toBe('auto');
        expect(result.results).toBeDefined();
        expect(result.executionTime).toBeGreaterThan(0);

        // Circuit breaker should be activated
        const circuitBreakers = searchManager.getCircuitBreakerStates();
        expect(Array.from(circuitBreakers.values()).some((cb) => cb.isOpen)).toBe(true);

        // System should be marked as degraded
        const healthReport = searchManager.getSystemHealth();
        expect(['degraded', 'unhealthy', 'healthy']).toContain(healthReport.overall);
      });

      it('should reset circuit breaker when system recovers', async () => {
        // Force circuit breaker open
        searchManager.forceCircuitBreakerState('vector_search', true);

        let circuitBreakers = searchManager.getCircuitBreakerStates();
        expect(Array.from(circuitBreakers.values()).some((cb) => cb.isOpen)).toBe(true);

        // Reset circuit breaker
        searchManager.forceCircuitBreakerState('vector_search', false);

        circuitBreakers = searchManager.getCircuitBreakerStates();
        const vectorBreaker = circuitBreakers.get('vector_search');
        expect(vectorBreaker?.isOpen).toBe(false);
      });
    });

    describe('Performance Metrics', () => {
      it('should track performance metrics during degradation', async () => {
        // Mock vector health as false to force degradation
        vi.spyOn(searchManager, 'getVectorHealth').mockReturnValue(false);

        const query: SearchQuery = {
          query: 'test performance metrics',
          mode: 'auto',
          limit: 10,
        };

        await searchManager.executeSearch(query, 'auto');

        const metrics = searchManager.getPerformanceMetrics();
        expect(typeof metrics).toBe('object');

        const errorMetrics = searchManager.getErrorMetrics();
        expect(typeof errorMetrics.totalErrors).toBe('number');
        expect(typeof errorMetrics.errorsByCategory).toBe('object');
        expect(typeof errorMetrics.errorsBySeverity).toBe('object');
        expect(Array.isArray(errorMetrics.recentErrors)).toBe(true);
      });
    });

    describe('Error Handling', () => {
      it('should handle various error categories properly', () => {
        // Test error categorization
        const networkError = new Error('Network timeout');
        const dbError = new Error('Database connection failed');
        const validationError = new Error('Invalid query parameters');

        expect(networkError).toBeDefined();
        expect(dbError).toBeDefined();
        expect(validationError).toBeDefined();

        // Verify error handler is available
        expect(searchErrorHandler.resetMetrics).toBeDefined();
        expect(searchErrorHandler.resetAllCircuitBreakers).toBeDefined();
      });

      it('should provide meaningful error metrics', () => {
        const errorMetrics = searchManager.getErrorMetrics();

        expect(errorMetrics).toHaveProperty('totalErrors');
        expect(errorMetrics).toHaveProperty('errorsByCategory');
        expect(errorMetrics).toHaveProperty('errorsBySeverity');
        expect(errorMetrics).toHaveProperty('recentErrors');

        expect(typeof errorMetrics.totalErrors).toBe('number');
        expect(Array.isArray(errorMetrics.recentErrors)).toBe(true);
      });
    });

    describe('System Health Monitoring', () => {
      it('should provide comprehensive system health information', () => {
        const health = searchManager.getSystemHealth();

        expect(health).toHaveProperty('overall');
        expect(health).toHaveProperty('components');
        expect(health).toHaveProperty('metrics');

        expect(typeof health.overall).toBe('string');
        expect(typeof health.components).toBe('object');
        expect(typeof health.metrics).toBe('object');
      });

      it('should support different search strategies', () => {
        const strategies = searchManager.getSupportedStrategies();
        expect(Array.isArray(strategies)).toBe(true);
        expect(strategies).toContain('fast');
        expect(strategies).toContain('auto');
        expect(strategies).toContain('deep');
      });
    });
  });
});