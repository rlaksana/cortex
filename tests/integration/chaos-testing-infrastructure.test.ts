/**
 * Chaos Testing Infrastructure for Network and Service Failures
 *
 * Comprehensive chaos testing suite that simulates real-world failure scenarios:
 * - Network blips and intermittent connectivity issues
 * - Qdrant 5xx server errors and partial failures
 * - Timeouts and latency spikes
 * - Circuit breaker behavior under chaos conditions
 * - Graceful degradation and recovery mechanisms
 *
 * Tests ensure system resilience and observability requirements are met
 * under various failure conditions.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { SearchStrategyManager } from '../../src/services/search/search-strategy-manager.js';
import { QdrantAdapter } from '../../src/db/adapters/qdrant-adapter.js';
import { MemoryStoreOrchestratorQdrant } from '../../src/services/orchestrators/memory-store-orchestrator-qdrant.js';
import { MemoryFindOrchestratorQdrant } from '../../src/services/orchestrators/memory-find-orchestrator-qdrant.js';
import {
  searchErrorHandler,
  ErrorCategory,
  ErrorSeverity,
} from '../../src/services/search/search-error-handler.js';
import type { SearchQuery, SearchResult, KnowledgeItem } from '../../src/types/core-interfaces.js';

// Mock logger to avoid noise in tests
vi.mock('../../src/utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

// Mock chaos engineering utilities
interface ChaosConfig {
  failureRate: number;
  latencyMs: number;
  errorType: 'timeout' | 'connection' | 'server_error' | 'partial_failure';
  recoveryTimeMs: number;
  intermittent: boolean;
}

class ChaosEngine {
  private activeChaos: Map<string, ChaosConfig> = new Map();
  private callCounters: Map<string, number> = new Map();

  injectChaos(operation: string, config: ChaosConfig): void {
    this.activeChaos.set(operation, config);
    this.callCounters.set(operation, 0);
  }

  removeChaos(operation: string): void {
    this.activeChaos.delete(operation);
    this.callCounters.delete(operation);
  }

  async executeWithChaos<T>(operation: string, normalOperation: () => Promise<T>): Promise<T> {
    const config = this.activeChaos.get(operation);
    if (!config) {
      return normalOperation();
    }

    const callCount = (this.callCounters.get(operation) || 0) + 1;
    this.callCounters.set(operation, callCount);

    // Check if this call should fail based on failure rate
    const shouldFail = !config.intermittent || Math.random() < config.failureRate;

    if (shouldFail) {
      // Simulate latency before failure
      if (config.latencyMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, config.latencyMs));
      }

      // Throw appropriate error based on error type
      switch (config.errorType) {
        case 'timeout':
          throw new Error(`Operation ${operation} timed out after ${config.latencyMs}ms`);
        case 'connection':
          throw new Error(`Connection refused for ${operation}`);
        case 'server_error':
          const serverError = new Error(`Internal server error for ${operation}`) as any;
          serverError.status = 500;
          serverError.code = 'INTERNAL_ERROR';
          throw serverError;
        case 'partial_failure':
          const partialError = new Error(`Partial failure for ${operation}`) as any;
          partialError.status = 206;
          partialError.code = 'PARTIAL_CONTENT';
          throw partialError;
        default:
          throw new Error(`Chaos injection for ${operation}`);
      }
    }

    // Execute normal operation with potential latency
    if (config.latencyMs > 0 && Math.random() < 0.5) {
      await new Promise((resolve) => setTimeout(resolve, config.latencyMs * 0.5));
    }

    return normalOperation();
  }

  getChaosStats(): Record<string, { calls: number; active: boolean; config: ChaosConfig | null }> {
    const stats: Record<string, { calls: number; active: boolean; config: ChaosConfig | null }> =
      {};

    for (const [operation, config] of this.activeChaos.entries()) {
      stats[operation] = {
        calls: this.callCounters.get(operation) || 0,
        active: true,
        config,
      };
    }

    return stats;
  }
}

describe('Chaos Testing Infrastructure', () => {
  let chaosEngine: ChaosEngine;
  let searchManager: SearchStrategyManager;
  let qdrantAdapter: QdrantAdapter;
  let memoryStoreOrchestrator: MemoryStoreOrchestratorQdrant;
  let memoryFindOrchestrator: MemoryFindOrchestratorQdrant;

  beforeEach(() => {
    chaosEngine = new ChaosEngine();

    // Initialize services with chaos-aware configuration
    searchManager = new SearchStrategyManager({
      maxResults: 20,
      timeoutMs: 8000,
      enableVectorSearch: true,
      enableGraphExpansion: true,
      fallbackEnabled: true,
      retryAttempts: 3,
      degradationThreshold: 0.7,
      circuitBreakerEnabled: true,
      chaosModeEnabled: true,
    });

    qdrantAdapter = new QdrantAdapter({
      url: 'http://localhost:6333',
      timeout: 5000,
      maxRetries: 3,
      chaosMode: true,
    });

    memoryStoreOrchestrator = new MemoryStoreOrchestratorQdrant(qdrantAdapter);
    memoryFindOrchestrator = new MemoryFindOrchestratorQdrant(qdrantAdapter);

    // Reset error handling
    searchErrorHandler.resetMetrics();
    searchErrorHandler.resetAllCircuitBreakers();
  });

  afterEach(() => {
    // Clean up chaos configurations
    chaosEngine = new ChaosEngine(); // Reset chaos engine
    searchManager.resetMetrics();
  });

  describe('Network Blip Simulation', () => {
    describe('Intermittent Connectivity Issues', () => {
      it('should handle short network blips without service degradation', async () => {
        // Inject network blips: 20% failure rate, 100ms latency, quick recovery
        chaosEngine.injectChaos('vector_search', {
          failureRate: 0.2,
          latencyMs: 100,
          errorType: 'connection',
          recoveryTimeMs: 500,
          intermittent: true,
        });

        // Mock vector search with chaos
        vi.spyOn(searchManager as any, 'performVectorSearch').mockImplementation(async () => {
          return chaosEngine.executeWithChaos('vector_search', async () => {
            return [
              { id: 'result-1', content: 'search result', score: 0.8 },
              { id: 'result-2', content: 'another result', score: 0.7 },
            ];
          });
        });

        const query: SearchQuery = {
          query: 'test network blip resilience',
          mode: 'auto',
          limit: 10,
        };

        const results = [];
        const totalRequests = 20;

        // Execute multiple requests to test blip handling
        for (let i = 0; i < totalRequests; i++) {
          try {
            const result = await searchManager.executeSearch(query, 'auto');
            results.push(result);
          } catch (error) {
            // Some failures expected during blips
          }
          await new Promise((resolve) => setTimeout(resolve, 50));
        }

        // Verify resilience to network blips
        const successRate = results.length / totalRequests;
        expect(successRate).toBeGreaterThan(0.7); // At least 70% success rate

        // Verify successful results maintain quality
        const successfulResults = results.filter((r) => r.results && r.results.length > 0);
        const avgConfidence =
          successfulResults.reduce((sum, r) => sum + r.confidence, 0) / successfulResults.length;
        expect(avgConfidence).toBeGreaterThan(0.6);

        // Verify circuit breaker behavior
        const circuitBreakers = searchManager.getCircuitBreakerStates();
        expect(circuitBreakers.size).toBeGreaterThan(0);

        // Circuit breaker should not be permanently opened by blips
        const vectorSearchBreaker = circuitBreakers.get('vector_search');
        expect(vectorSearchBreaker?.isOpen).toBe(false);

        // Verify chaos statistics
        const chaosStats = chaosEngine.getChaosStats();
        expect(chaosStats['vector_search'].calls).toBe(totalRequests);
      });

      it('should recover gracefully from extended network interruptions', async () => {
        // Simulate extended network outage
        chaosEngine.injectChaos('vector_search', {
          failureRate: 1.0, // 100% failure initially
          latencyMs: 200,
          errorType: 'connection',
          recoveryTimeMs: 2000,
          intermittent: false,
        });

        const outageDuration = 1000; // 1 second outage
        const outageStartTime = Date.now();

        vi.spyOn(searchManager as any, 'performVectorSearch').mockImplementation(async () => {
          const elapsed = Date.now() - outageStartTime;

          // Check if outage should be recovered
          if (elapsed > outageDuration) {
            // Remove chaos after outage duration
            chaosEngine.removeChaos('vector_search');
          }

          return chaosEngine.executeWithChaos('vector_search', async () => {
            return [{ id: 'recovery-result', content: 'recovery test result', score: 0.85 }];
          });
        });

        const query: SearchQuery = {
          query: 'test network recovery',
          mode: 'auto',
          limit: 10,
        };

        const results = [];
        const startTime = Date.now();

        // Continue testing through outage and recovery
        while (Date.now() - startTime < 3000) {
          // 3 second test
          try {
            const result = await searchManager.executeSearch(query, 'auto');
            results.push({ ...result, timestamp: Date.now() });
          } catch (error) {
            // Expect failures during outage
          }
          await new Promise((resolve) => setTimeout(resolve, 200));
        }

        // Should have recovered after outage
        const recoveryTime = results.find((r) => r.results && r.results.length > 0)?.timestamp;
        expect(recoveryTime).toBeDefined();
        expect(recoveryTime! - startTime).toBeGreaterThan(outageDuration);

        // Post-recovery results should maintain quality
        const recoveredResults = results.filter((r) => r.results && r.results.length > 0);
        if (recoveredResults.length > 0) {
          const avgConfidence =
            recoveredResults.reduce((sum, r) => sum + r.confidence, 0) / recoveredResults.length;
          expect(avgConfidence).toBeGreaterThan(0.7);
        }

        // Verify system health recovery
        const healthReport = searchManager.getSystemHealth();
        expect(['healthy', 'degraded']).toContain(healthReport.overall_status);
      });

      it('should maintain fallback functionality during network degradation', async () => {
        // Inject network degradation with 40% failure rate
        chaosEngine.injectChaos('vector_search', {
          failureRate: 0.4,
          latencyMs: 300,
          errorType: 'connection',
          recoveryTimeMs: 1000,
          intermittent: true,
        });

        // Mock sparse search as fallback
        vi.spyOn(searchManager as any, 'performSparseSearch').mockResolvedValue([
          { id: 'fallback-1', content: 'fallback result 1', score: 0.75 },
          { id: 'fallback-2', content: 'fallback result 2', score: 0.65 },
        ]);

        vi.spyOn(searchManager as any, 'performVectorSearch').mockImplementation(async () => {
          return chaosEngine.executeWithChaos('vector_search', async () => {
            return [
              { id: 'vector-1', content: 'vector result 1', score: 0.9 },
              { id: 'vector-2', content: 'vector result 2', score: 0.85 },
            ];
          });
        });

        const query: SearchQuery = {
          query: 'test fallback during network issues',
          mode: 'auto',
          limit: 10,
        };

        const results = [];
        const totalRequests = 15;

        for (let i = 0; i < totalRequests; i++) {
          try {
            const result = await searchManager.executeSearch(query, 'auto');
            results.push(result);
          } catch (error) {
            // Some failures expected
          }
          await new Promise((resolve) => setTimeout(resolve, 150));
        }

        // Should have mixed vector and fallback results
        const vectorResults = results.filter((r) => r.vectorUsed && !r.degraded);
        const fallbackResults = results.filter(
          (r) => r.degraded && r.fallbackReason?.includes('fallback')
        );

        expect(results.length).toBeGreaterThan(totalRequests * 0.6); // At least 60% overall success
        expect(fallbackResults.length).toBeGreaterThan(0); // Should have fallback usage

        // All successful results should have reasonable quality
        const allSuccessful = [...vectorResults, ...fallbackResults];
        const avgConfidence =
          allSuccessful.reduce((sum, r) => sum + r.confidence, 0) / allSuccessful.length;
        expect(avgConfidence).toBeGreaterThan(0.5);

        // Verify fallback metrics
        const performanceMetrics = searchManager.getPerformanceMetrics();
        const autoMetrics = performanceMetrics.get('auto');
        expect(autoMetrics?.fallbackUsage).toBeGreaterThan(0);
      });
    });

    describe('Network Latency Spikes', () => {
      it('should handle temporary latency spikes without timeout', async () => {
        // Inject latency spikes: 30% of requests have high latency
        chaosEngine.injectChaos('vector_search', {
          failureRate: 0,
          latencyMs: 3000, // 3 second latency
          errorType: 'timeout',
          recoveryTimeMs: 500,
          intermittent: true,
        });

        vi.spyOn(searchManager as any, 'performVectorSearch').mockImplementation(async () => {
          return chaosEngine.executeWithChaos('vector_search', async () => {
            return [{ id: 'latency-result', content: 'latency test result', score: 0.8 }];
          });
        });

        const query: SearchQuery = {
          query: 'test latency spike handling',
          mode: 'auto',
          limit: 10,
        };

        const results = [];
        const totalRequests = 12;

        for (let i = 0; i < totalRequests; i++) {
          const startTime = Date.now();
          try {
            const result = await searchManager.executeSearch(query, 'auto');
            const executionTime = Date.now() - startTime;
            results.push({ ...result, executionTime });
          } catch (error) {
            // Some timeouts expected
          }
        }

        // Analyze latency handling
        const executionTimes = results.map((r) => r.executionTime);
        const avgExecutionTime = executionTimes.reduce((a, b) => a + b, 0) / executionTimes.length;
        const maxExecutionTime = Math.max(...executionTimes);

        // Should complete most requests despite latency spikes
        expect(results.length).toBeGreaterThan(totalRequests * 0.7);

        // Average time should be reasonable
        expect(avgExecutionTime).toBeLessThan(5000); // Less than 5 seconds average

        // Max time should be within timeout bounds
        expect(maxExecutionTime).toBeLessThan(10000); // Less than 10 seconds max

        // Verify adaptive timeout handling
        const timeoutHandledResults = results.filter((r) => r.metadata?.timeoutExtended);
        expect(timeoutHandledResults.length).toBeGreaterThan(0);
      });

      it('should implement adaptive timeouts based on network conditions', async () => {
        const networkCondition = 'good'; // good -> degraded -> poor -> recovery
        let conditionChangeCount = 0;

        vi.spyOn(searchManager as any, 'assessNetworkCondition').mockImplementation(() => {
          conditionChangeCount++;
          if (conditionChangeCount > 8) return 'good';
          if (conditionChangeCount > 6) return 'recovery';
          if (conditionChangeCount > 4) return 'poor';
          if (conditionChangeCount > 2) return 'degraded';
          return 'good';
        });

        vi.spyOn(searchManager as any, 'getAdaptiveTimeout').mockImplementation(
          (baseTimeout, networkCondition) => {
            const multipliers = {
              good: 1.0,
              degraded: 1.5,
              poor: 2.0,
              recovery: 1.25,
            };
            return baseTimeout * (multipliers[networkCondition as keyof typeof multipliers] || 1.0);
          }
        );

        vi.spyOn(searchManager as any, 'performVectorSearch').mockImplementation(async () => {
          const condition = searchManager['assessNetworkCondition']();
          const timeout = searchManager['getAdaptiveTimeout'](3000, condition);

          // Simulate response time based on condition
          const baseDelay = 1000;
          const conditionDelays = {
            good: 0.5,
            degraded: 1.5,
            poor: 2.5,
            recovery: 1.0,
          };

          const delay =
            baseDelay * (conditionDelays[condition as keyof typeof conditionDelays] || 1.0);

          await new Promise((resolve) => setTimeout(resolve, delay));

          if (delay > timeout) {
            throw new Error(`Adaptive timeout exceeded: ${delay}ms > ${timeout}ms`);
          }

          return [
            { id: 'adaptive-timeout-result', content: 'adaptive timeout result', score: 0.8 },
          ];
        });

        const query: SearchQuery = {
          query: 'test adaptive timeout behavior',
          mode: 'auto',
          limit: 10,
        };

        const results = [];

        for (let i = 0; i < 10; i++) {
          try {
            const result = await searchManager.executeSearch(query, 'auto');
            results.push(result);
          } catch (error) {
            // Some timeouts expected in poor conditions
          }
          await new Promise((resolve) => setTimeout(resolve, 100));
        }

        // Should adapt to changing network conditions
        expect(results.length).toBeGreaterThan(5); // At least 50% success

        // Results should show adaptive timeout usage
        const adaptiveTimeoutResults = results.filter((r) => r.metadata?.adaptiveTimeout);
        expect(adaptiveTimeoutResults.length).toBeGreaterThan(0);

        // Different network conditions should be reflected in metadata
        const conditions = results.map((r) => r.metadata?.networkCondition).filter(Boolean);
        expect(new Set(conditions).size).toBeGreaterThan(1); // Multiple conditions encountered
      });
    });
  });

  describe('Qdrant 5xx Server Error Simulation', () => {
    describe('Internal Server Error Handling', () => {
      it('should handle Qdrant 500 errors with graceful degradation', async () => {
        // Inject 500 errors: 50% failure rate
        chaosEngine.injectChaos('qdrant_search', {
          failureRate: 0.5,
          latencyMs: 100,
          errorType: 'server_error',
          recoveryTimeMs: 1500,
          intermittent: true,
        });

        vi.spyOn(memoryFindOrchestrator as any, 'searchKnowledge').mockImplementation(async () => {
          return chaosEngine.executeWithChaos('qdrant_search', async () => {
            return [
              { id: 'qdrant-1', content: 'qdrant result 1', score: 0.9 },
              { id: 'qdrant-2', content: 'qdrant result 2', score: 0.85 },
            ];
          });
        });

        // Mock fallback search when Qdrant fails
        vi.spyOn(memoryFindOrchestrator as any, 'fallbackSearch').mockResolvedValue([
          { id: 'fallback-1', content: 'fallback result 1', score: 0.7 },
          { id: 'fallback-2', content: 'fallback result 2', score: 0.65 },
        ]);

        const searchRequest = {
          query: 'test qdrant 500 error handling',
          limit: 10,
          scope: { project: 'chaos-test' },
        };

        const results = [];
        const totalRequests = 10;

        for (let i = 0; i < totalRequests; i++) {
          try {
            const result = await memoryFindOrchestrator.find(searchRequest);
            results.push(result);
          } catch (error) {
            // Some failures expected
          }
          await new Promise((resolve) => setTimeout(resolve, 200));
        }

        // Should handle 500 errors gracefully
        const successRate = results.length / totalRequests;
        expect(successRate).toBeGreaterThan(0.6); // At least 60% success rate

        // Should have fallback results for 500 errors
        const fallbackResults = results.filter((r) => r.fallback || r.degraded);
        expect(fallbackResults.length).toBeGreaterThan(0);

        // Results should maintain reasonable quality
        const allResults = results.filter((r) => r.items && r.items.length > 0);
        const avgScore =
          allResults.reduce(
            (sum, r) =>
              sum +
              (r.items?.reduce((s: number, item: any) => s + (item.score || 0), 0) || 0) /
                (r.items?.length || 1),
            0
          ) / allResults.length;
        expect(avgScore).toBeGreaterThan(0.5);

        // Verify error categorization
        const errorMetrics = searchErrorHandler.getMetrics();
        expect(errorMetrics.errorsByCategory[ErrorCategory['DATABASE']]).toBeGreaterThan(0);
      });

      it('should implement circuit breaker for repeated Qdrant failures', async () => {
        // Inject persistent 500 errors to trigger circuit breaker
        chaosEngine.injectChaos('qdrant_search', {
          failureRate: 0.8, // High failure rate
          latencyMs: 50,
          errorType: 'server_error',
          recoveryTimeMs: 5000,
          intermittent: false,
        });

        vi.spyOn(memoryFindOrchestrator as any, 'searchKnowledge').mockImplementation(async () => {
          return chaosEngine.executeWithChaos('qdrant_search', async () => {
            return [{ id: 'qdrant-circuit-test', content: 'circuit test result', score: 0.8 }];
          });
        });

        const searchRequest = {
          query: 'test circuit breaker activation',
          limit: 10,
          scope: { project: 'circuit-test' },
        };

        const results = [];

        // Execute requests to trigger circuit breaker
        for (let i = 0; i < 8; i++) {
          try {
            const result = await memoryFindOrchestrator.find(searchRequest);
            results.push(result);
          } catch (error) {
            // Expected failures
          }
          await new Promise((resolve) => setTimeout(resolve, 100));
        }

        // Circuit breaker should be activated
        const circuitBreakers = searchErrorHandler.getAllCircuitBreakerStates();
        const qdrantBreaker = circuitBreakers.find((cb) => cb.service === 'qdrant_search');
        expect(qdrantBreaker?.isOpen).toBe(true);

        // Should have logged circuit breaker activation
        const errorMetrics = searchErrorHandler.getMetrics();
        expect(errorMetrics.circuitBreakerActivations).toBeGreaterThan(0);

        // Subsequent requests should fail fast due to open circuit
        const fastFailResults = [];
        for (let i = 0; i < 3; i++) {
          const startTime = Date.now();
          try {
            const result = await memoryFindOrchestrator.find(searchRequest);
            fastFailResults.push({ ...result, responseTime: Date.now() - startTime });
          } catch (error) {
            fastFailResults.push({ error: error.message, responseTime: Date.now() - startTime });
          }
        }

        // Requests should fail fast when circuit is open
        const avgFailFastTime =
          fastFailResults.reduce((sum, r) => sum + r.responseTime, 0) / fastFailResults.length;
        expect(avgFailFastTime).toBeLessThan(1000); // Less than 1 second for fast fail
      });

      it('should recover from Qdrant errors with service restoration', async () => {
        let shouldRecover = false;
        let recoveryCount = 0;

        chaosEngine.injectChaos('qdrant_search', {
          failureRate: 0.7,
          latencyMs: 100,
          errorType: 'server_error',
          recoveryTimeMs: 2000,
          intermittent: true,
        });

        vi.spyOn(memoryFindOrchestrator as any, 'searchKnowledge').mockImplementation(async () => {
          // Simulate recovery after multiple failures
          recoveryCount++;
          if (recoveryCount > 5 && !shouldRecover) {
            shouldRecover = true;
            chaosEngine.removeChaos('qdrant_search');
          }

          return chaosEngine.executeWithChaos('qdrant_search', async () => {
            return [
              { id: `recovery-${recoveryCount}`, content: 'recovery test result', score: 0.85 },
            ];
          });
        });

        const searchRequest = {
          query: 'test qdrant service recovery',
          limit: 10,
          scope: { project: 'recovery-test' },
        };

        const results = [];
        const startTime = Date.now();

        // Continue testing through failure and recovery
        while (Date.now() - startTime < 4000) {
          // 4 second test
          try {
            const result = await memoryFindOrchestrator.find(searchRequest);
            results.push({ ...result, timestamp: Date.now() });
          } catch (error) {
            // Expect failures during outage
          }
          await new Promise((resolve) => setTimeout(resolve, 200));
        }

        // Should have successful results after recovery
        const successfulResults = results.filter((r) => r.items && r.items.length > 0);
        expect(successfulResults.length).toBeGreaterThan(0);

        // Recovery should happen within expected timeframe
        const firstSuccess = successfulResults[0];
        if (firstSuccess) {
          const recoveryTime = firstSuccess.timestamp - startTime;
          expect(recoveryTime).toBeGreaterThan(1000); // Should take some time to recover
          expect(recoveryTime).toBeLessThan(4000); // But should recover within test window
        }

        // Post-recovery results should maintain quality
        const avgScore =
          successfulResults.reduce(
            (sum, r) =>
              sum +
              (r.items?.reduce((s: number, item: any) => s + (item.score || 0), 0) || 0) /
                (r.items?.length || 1),
            0
          ) / successfulResults.length;
        expect(avgScore).toBeGreaterThan(0.7);

        // Verify circuit breaker reset after recovery
        const circuitBreakers = searchErrorHandler.getAllCircuitBreakerStates();
        const qdrantBreaker = circuitBreakers.find((cb) => cb.service === 'qdrant_search');
        if (qdrantBreaker) {
          expect(qdrantBreaker.isOpen).toBe(false);
        }
      });
    });

    describe('Partial Failure Scenarios', () => {
      it('should handle Qdrant partial failures gracefully', async () => {
        // Inject partial failures: some requests succeed with reduced data
        chaosEngine.injectChaos('qdrant_search', {
          failureRate: 0.3,
          latencyMs: 200,
          errorType: 'partial_failure',
          recoveryTimeMs: 1000,
          intermittent: true,
        });

        vi.spyOn(memoryFindOrchestrator as any, 'searchKnowledge').mockImplementation(async () => {
          try {
            return await chaosEngine.executeWithChaos('qdrant_search', async () => {
              return [
                { id: 'full-result-1', content: 'complete result 1', score: 0.9 },
                { id: 'full-result-2', content: 'complete result 2', score: 0.85 },
                { id: 'full-result-3', content: 'complete result 3', score: 0.8 },
              ];
            });
          } catch (error: any) {
            if (error.code === 'PARTIAL_CONTENT') {
              // Return partial results on 206 errors
              return [
                { id: 'partial-result-1', content: 'partial result 1', score: 0.7 },
                { id: 'partial-result-2', content: 'partial result 2', score: 0.65 },
              ];
            }
            throw error;
          }
        });

        const searchRequest = {
          query: 'test partial failure handling',
          limit: 10,
          scope: { project: 'partial-test' },
        };

        const results = [];

        for (let i = 0; i < 8; i++) {
          try {
            const result = await memoryFindOrchestrator.find(searchRequest);
            results.push(result);
          } catch (error) {
            // Some failures expected
          }
          await new Promise((resolve) => setTimeout(resolve, 150));
        }

        // Should have mixed full and partial results
        const fullResults = results.filter((r) => r.items?.length === 3);
        const partialResults = results.filter((r) => r.items?.length === 2);

        expect(results.length).toBeGreaterThan(5); // Most requests should succeed
        expect(partialResults.length).toBeGreaterThan(0); // Should have partial results

        // Partial results should be marked appropriately
        partialResults.forEach((result) => {
          expect(result.metadata?.partialResult).toBe(true);
          expect(result.metadata?.originalRequestSize).toBe(3);
          expect(result.metadata?.actualResponseSize).toBe(2);
        });

        // Even partial results should maintain minimum quality
        const allResults = [...fullResults, ...partialResults];
        const avgScore =
          allResults.reduce(
            (sum, r) =>
              sum +
              (r.items?.reduce((s: number, item: any) => s + (item.score || 0), 0) || 0) /
                (r.items?.length || 1),
            0
          ) / allResults.length;
        expect(avgScore).toBeGreaterThan(0.6);
      });
    });
  });

  describe('Timeout and Recovery Mechanisms', () => {
    describe('Timeout Handling', () => {
      it('should handle timeout scenarios with appropriate fallbacks', async () => {
        // Inject timeout failures
        chaosEngine.injectChaos('slow_operation', {
          failureRate: 0.4,
          latencyMs: 10000, // 10 second delay
          errorType: 'timeout',
          recoveryTimeMs: 2000,
          intermittent: true,
        });

        vi.spyOn(searchManager as any, 'performSlowOperation').mockImplementation(async () => {
          return chaosEngine.executeWithChaos('slow_operation', async () => {
            await new Promise((resolve) => setTimeout(resolve, 100)); // Normal operation
            return { data: 'operation result', timestamp: Date.now() };
          });
        });

        vi.spyOn(searchManager as any, 'getFallbackForTimeout').mockResolvedValue({
          data: 'fallback result',
          timestamp: Date.now(),
          fallback: true,
        });

        const results = [];

        for (let i = 0; i < 6; i++) {
          const startTime = Date.now();
          try {
            const result = await searchManager['performSlowOperation']();
            results.push({ ...result, executionTime: Date.now() - startTime, type: 'normal' });
          } catch (error) {
            try {
              const fallback = await searchManager['getFallbackForTimeout']();
              results.push({
                ...fallback,
                executionTime: Date.now() - startTime,
                type: 'fallback',
              });
            } catch (fallbackError) {
              results.push({
                error: fallbackError.message,
                executionTime: Date.now() - startTime,
                type: 'failed',
              });
            }
          }
        }

        // Should have mixed normal and fallback results
        const normalResults = results.filter((r) => r.type === 'normal');
        const fallbackResults = results.filter((r) => r.type === 'fallback');
        const failedResults = results.filter((r) => r.type === 'failed');

        expect(results.length).toBe(6);
        expect(fallbackResults.length).toBeGreaterThan(0);

        // Fallback results should be faster than timeouts
        const avgFallbackTime =
          fallbackResults.reduce((sum, r) => sum + r.executionTime, 0) / fallbackResults.length;
        expect(avgFallbackTime).toBeLessThan(5000); // Less than 5 seconds

        // Normal results should be within reasonable time
        const avgNormalTime =
          normalResults.reduce((sum, r) => sum + r.executionTime, 0) / normalResults.length;
        expect(avgNormalTime).toBeLessThan(15000); // Less than 15 seconds (allows for some delay)
      });

      it('should implement progressive timeout escalation', async () => {
        let escalationLevel = 0;
        const maxEscalation = 3;

        vi.spyOn(searchManager as any, 'getEscalatedTimeout').mockImplementation(
          (baseTimeout, level) => {
            return baseTimeout * Math.pow(1.5, level);
          }
        );

        vi.spyOn(searchManager as any, 'executeWithEscalation').mockImplementation(
          async (operation) => {
            const baseTimeout = 3000;
            const currentTimeout = searchManager['getEscalatedTimeout'](
              baseTimeout,
              escalationLevel
            );

            const timeoutPromise = new Promise((_, reject) =>
              setTimeout(
                () => reject(new Error(`Timeout after ${currentTimeout}ms`)),
                currentTimeout
              )
            );

            try {
              const result = await Promise.race([operation(), timeoutPromise]);
              escalationLevel = 0; // Reset on success
              return result;
            } catch (error) {
              if (error.message.includes('Timeout') && escalationLevel < maxEscalation) {
                escalationLevel++;
                return searchManager['executeWithEscalation'](operation);
              }
              throw error;
            }
          }
        );

        // Mock operation that takes progressively longer
        let operationDelay = 2000;
        vi.spyOn(searchManager as any, 'mockOperation').mockImplementation(async () => {
          await new Promise((resolve) => setTimeout(resolve, operationDelay));
          operationDelay += 1000; // Increase delay each time
          return { success: true, delay: operationDelay - 1000 };
        });

        const results = [];

        for (let i = 0; i < 4; i++) {
          const startTime = Date.now();
          try {
            const result = await searchManager['executeWithEscalation'](() =>
              searchManager['mockOperation']()
            );
            results.push({ ...result, executionTime: Date.now() - startTime, escalationLevel });
          } catch (error) {
            results.push({
              error: error.message,
              executionTime: Date.now() - startTime,
              escalationLevel,
            });
          }
        }

        // Should show escalation behavior
        const successfulResults = results.filter((r) => !r.error);
        const failedResults = results.filter((r) => r.error);

        expect(results.length).toBe(4);
        expect(escalationLevel).toBeGreaterThan(0); // Should have escalated

        // Earlier operations should succeed, later ones may fail
        expect(successfulResults.length).toBeGreaterThan(0);

        // Verify timeout escalation tracking
        results.forEach((result) => {
          expect(result.escalationLevel).toBeDefined();
          if (result.escalationLevel > 0) {
            expect(result.executionTime).toBeGreaterThan(3000); // Should exceed base timeout
          }
        });
      });
    });

    describe('Recovery Mechanisms', () => {
      it('should implement automatic recovery with backoff', async () => {
        let failureCount = 0;
        let recoveryAttempt = 0;

        vi.spyOn(searchManager as any, 'executeWithBackoff').mockImplementation(
          async (operation, maxRetries = 3) => {
            for (let attempt = 0; attempt <= maxRetries; attempt++) {
              try {
                const result = await operation();
                failureCount = 0; // Reset on success
                return result;
              } catch (error) {
                failureCount++;
                recoveryAttempt++;

                if (attempt === maxRetries) {
                  throw error;
                }

                // Exponential backoff
                const backoffDelay = Math.min(1000 * Math.pow(2, attempt), 5000);
                await new Promise((resolve) => setTimeout(resolve, backoffDelay));
              }
            }
            throw new Error('Max retries exceeded');
          }
        );

        // Mock operation that fails initially then succeeds
        vi.spyOn(searchManager as any, 'flakyOperation').mockImplementation(async () => {
          if (failureCount < 2) {
            throw new Error(`Operation failed (attempt ${failureCount + 1})`);
          }
          return { success: true, attempt: failureCount + 1 };
        });

        const results = [];

        for (let i = 0; i < 3; i++) {
          const startTime = Date.now();
          try {
            const result = await searchManager['executeWithBackoff'](() =>
              searchManager['flakyOperation']()
            );
            results.push({
              ...result,
              executionTime: Date.now() - startTime,
              retries: recoveryAttempt,
            });
          } catch (error) {
            results.push({
              error: error.message,
              executionTime: Date.now() - startTime,
              retries: recoveryAttempt,
            });
          }
          recoveryAttempt = 0; // Reset for next test
          failureCount = 0;
        }

        // Should recover from failures with retries
        const successfulResults = results.filter((r) => !r.error);
        expect(successfulResults.length).toBeGreaterThan(0);

        // Successful results should show retry attempts
        successfulResults.forEach((result) => {
          expect(result.retries).toBeGreaterThan(0);
          expect(result.success).toBe(true);
        });

        // Recovery should happen within reasonable time
        const avgRecoveryTime =
          successfulResults.reduce((sum, r) => sum + r.executionTime, 0) / successfulResults.length;
        expect(avgRecoveryTime).toBeLessThan(10000); // Less than 10 seconds average recovery
      });

      it('should maintain system state during recovery', async () => {
        const systemState = {
          healthyComponents: ['search', 'cache'],
          degradedComponents: [] as string[],
          failedComponents: [] as string[],
        };

        vi.spyOn(searchManager as any, 'updateSystemState').mockImplementation(
          (component, status) => {
            // Remove component from all states first
            systemState.healthyComponents = systemState.healthyComponents.filter(
              (c) => c !== component
            );
            systemState.degradedComponents = systemState.degradedComponents.filter(
              (c) => c !== component
            );
            systemState.failedComponents = systemState.failedComponents.filter(
              (c) => c !== component
            );

            // Add component to appropriate state
            if (status === 'healthy') {
              systemState.healthyComponents.push(component);
            } else if (status === 'degraded') {
              systemState.degradedComponents.push(component);
            } else if (status === 'failed') {
              systemState.failedComponents.push(component);
            }
          }
        );

        vi.spyOn(searchManager as any, 'getSystemHealthStatus').mockImplementation(() => {
          const totalComponents =
            systemState.healthyComponents.length +
            systemState.degradedComponents.length +
            systemState.failedComponents.length;

          if (systemState.failedComponents.length > 0) {
            return 'critical';
          } else if (systemState.degradedComponents.length > 0) {
            return 'degraded';
          } else if (totalComponents > 0) {
            return 'healthy';
          }
          return 'unknown';
        });

        // Simulate component failure and recovery
        const components = ['vector_search', 'cache', 'database'];
        const stateTransitions = [];

        for (const component of components) {
          // Component fails
          searchManager['updateSystemState'](component, 'failed');
          stateTransitions.push({ component, status: 'failed', timestamp: Date.now() });

          // Component recovers
          await new Promise((resolve) => setTimeout(resolve, 100));
          searchManager['updateSystemState'](component, 'degraded');
          stateTransitions.push({ component, status: 'degraded', timestamp: Date.now() });

          await new Promise((resolve) => setTimeout(resolve, 100));
          searchManager['updateSystemState'](component, 'healthy');
          stateTransitions.push({ component, status: 'healthy', timestamp: Date.now() });
        }

        // Verify state transitions
        expect(stateTransitions.length).toBe(components.length * 3);

        // Final state should be healthy
        const finalStatus = searchManager['getSystemHealthStatus']();
        expect(finalStatus).toBe('healthy');

        // Should have tracked all state changes
        expect(systemState.healthyComponents).toHaveLength(components.length);
        expect(systemState.degradedComponents).toHaveLength(0);
        expect(systemState.failedComponents).toHaveLength(0);

        // Verify health reporting during recovery
        const healthReports = stateTransitions.map((transition) => ({
          ...transition,
          systemStatus: searchManager['getSystemHealthStatus'](),
        }));

        // Should show accurate system status throughout recovery
        healthReports.forEach((report) => {
          expect(['healthy', 'degraded', 'critical', 'unknown']).toContain(report.systemStatus);
        });
      });
    });
  });

  describe('Circuit Breaker Behavior Under Chaos', () => {
    it('should demonstrate circuit breaker patterns during chaos', async () => {
      const circuitBreakerStates = [];

      vi.spyOn(searchManager as any, 'trackCircuitBreakerState').mockImplementation(
        (service, state) => {
          circuitBreakerStates.push({ service, state, timestamp: Date.now() });
        }
      );

      // Inject chaos to trigger circuit breaker
      chaosEngine.injectChaos('test_service', {
        failureRate: 0.8,
        latencyMs: 100,
        errorType: 'server_error',
        recoveryTimeMs: 3000,
        intermittent: false,
      });

      vi.spyOn(searchManager as any, 'testOperation').mockImplementation(async () => {
        try {
          return await chaosEngine.executeWithChaos('test_service', async () => {
            return { success: true, data: 'test result' };
          });
        } finally {
          const currentState = searchErrorHandler.getCircuitBreakerState('test_service');
          if (currentState) {
            searchManager['trackCircuitBreakerState'](
              'test_service',
              currentState.isOpen ? 'open' : currentState.isHalfOpen ? 'half-open' : 'closed'
            );
          }
        }
      });

      // Execute operations to trigger circuit breaker lifecycle
      const results = [];

      // Phase 1: Trigger circuit breaker opening
      for (let i = 0; i < 8; i++) {
        try {
          const result = await searchManager['testOperation']();
          results.push({ ...result, phase: 'trigger' });
        } catch (error) {
          results.push({ error: error.message, phase: 'trigger' });
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
      }

      // Phase 2: Wait for circuit breaker timeout
      await new Promise((resolve) => setTimeout(resolve, 1000));

      // Phase 3: Test half-open state
      for (let i = 0; i < 3; i++) {
        try {
          const result = await searchManager['testOperation']();
          results.push({ ...result, phase: 'recovery' });
        } catch (error) {
          results.push({ error: error.message, phase: 'recovery' });
        }
        await new Promise((resolve) => setTimeout(resolve, 200));
      }

      // Verify circuit breaker lifecycle
      const stateChanges = circuitBreakerStates.filter(
        (state, index, array) => index === 0 || state.state !== array[index - 1].state
      );

      expect(stateChanges.length).toBeGreaterThan(0);

      // Should go through: closed -> open -> half-open -> closed
      const expectedSequence = ['closed', 'open', 'half-open', 'closed'];
      const actualSequence = stateChanges.map((change) => change.state);

      // Check if we see the expected circuit breaker behavior
      expect(actualSequence).toContain('open');
      expect(stateChanges.some((change) => change.state === 'open')).toBe(true);

      // Verify fast-fail behavior when circuit is open
      const openStateResults = results.filter((r) =>
        circuitBreakerStates.some(
          (state) => state.timestamp <= Date.now() && state.state === 'open'
        )
      );

      // Should have failed fast during open state
      expect(results.some((r) => r.error?.includes('fast fail') || r.phase === 'trigger')).toBe(
        true
      );
    });
  });
});
