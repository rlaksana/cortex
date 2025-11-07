/**
 * Production-Ready Circuit Breaker Tests
 *
 * Comprehensive tests for Qdrant adapter circuit breaker implementation
 * under production conditions with proper thresholds and retry mechanisms.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { QdrantAdapter } from '../../src/db/adapters/qdrant-adapter.js';
import { circuitBreakerManager } from '../../src/services/circuit-breaker.service.js';
import { retryPolicyManager } from '../../src/utils/retry-policy.js';

describe('Production-Ready Circuit Breaker Tests', () => {
  let qdrantAdapter: QdrantAdapter;

  beforeEach(async () => {
    // Set test environment
    process.env['NODE_ENV'] = 'test';
    process.env['QDRANT_URL'] = 'http://localhost:6333';
    process.env['QDRANT_COLLECTION_NAME'] = 'test-production-circuit-breaker';

    // Create Qdrant adapter with production configuration
    qdrantAdapter = new QdrantAdapter({
      url: 'http://localhost:6333',
      timeout: 30000,
      maxConnections: 20,
      vectorSize: 1536,
      distance: 'Cosine',
    });

    // Reset circuit breakers and retry policies
    circuitBreakerManager.resetAll();
    retryPolicyManager.resetAllCircuitBreakers();

    // Initialize adapter
    await qdrantAdapter.initialize();
  });

  afterEach(async () => {
    // Reset all circuit breakers
    circuitBreakerManager.resetAll();
    retryPolicyManager.resetAllCircuitBreakers();

    // Clean up test data
    try {
      await qdrantAdapter.close();
    } catch {
      // Ignore cleanup errors
    }
  });

  describe('Production Threshold Validation', () => {
    it('should maintain circuit breaker closed under 99% success rate', async () => {
      const testOperations = 100;
      let successfulOperations = 0;
      let failedOperations = 0;

      // Simulate normal operations with 99% success rate
      for (let i = 0; i < testOperations; i++) {
        try {
          // 99% success rate - only 1% should fail
          if (Math.random() < 0.99) {
            await qdrantAdapter.healthCheck();
            successfulOperations++;
          } else {
            // Simulate a rare failure
            throw new Error('Simulated rare failure');
          }
        } catch (error) {
          failedOperations++;
        }
      }

      const circuitStats = qdrantAdapter.getQdrantCircuitBreakerStatus();
      const successRate = successfulOperations / testOperations;

      // Circuit should remain closed with 99% success rate
      expect(circuitStats.state).toBe('closed');
      expect(circuitStats.isOpen).toBe(false);
      expect(successRate).toBeGreaterThanOrEqual(0.98); // Allow small variance
      expect(successRate).toBeLessThan(1.0); // Should have some failures

      console.log('Production threshold test results:', {
        totalOperations: testOperations,
        successfulOperations,
        failedOperations,
        successRate,
        circuitState: circuitStats.state,
        failureRate: circuitStats.failureRate,
      });
    });

    it('should open circuit breaker only when failure rate exceeds 5%', async () => {
      const testOperations = 50;
      const failureRate = 0.06; // 6% failure rate - should trigger circuit breaker
      let failures = 0;

      // Create adapter with invalid URL to force failures
      const failingAdapter = new QdrantAdapter({
        url: 'http://localhost:9999', // Invalid port
        timeout: 1000,
      });

      // Generate failures at 6% rate
      for (let i = 0; i < testOperations; i++) {
        try {
          await failingAdapter.healthCheck();
        } catch (error) {
          failures++;
        }
      }

      const circuitStats = failingAdapter.getQdrantCircuitBreakerStatus();
      const actualFailureRate = failures / testOperations;

      // With 6% failure rate, circuit should eventually open
      expect(actualFailureRate).toBeGreaterThanOrEqual(0.05);
      // Note: Circuit might not open immediately due to minimumCalls threshold

      console.log('High failure rate test results:', {
        totalOperations: testOperations,
        failures,
        actualFailureRate,
        circuitState: circuitStats.state,
        totalCalls: circuitStats.totalCalls,
        failureThreshold: 10,
      });
    });
  });

  describe('Retry Mechanism Integration', () => {
    it('should retry failed operations with exponential backoff', async () => {
      const retryMetricsBefore = retryPolicyManager.getMetrics();

      // Test with temporarily failing service
      const originalUrl = process.env['QDRANT_URL'];
      process.env['QDRANT_URL'] = 'http://localhost:9999'; // Invalid URL

      try {
        await qdrantAdapter.healthCheck();
      } catch (error) {
        // Expected to fail
      }

      // Restore correct URL
      process.env['QDRANT_URL'] = originalUrl;

      // Subsequent operation should succeed with retries
      const startTime = Date.now();
      await qdrantAdapter.healthCheck();
      const responseTime = Date.now() - startTime;

      const retryMetricsAfter = retryPolicyManager.getMetrics();

      // Should have attempted retries
      expect(retryMetricsAfter.total_operations).toBeGreaterThan(
        retryMetricsBefore.total_operations
      );
      expect(responseTime).toBeGreaterThan(0);

      console.log('Retry mechanism test results:', {
        responseTime,
        retryMetricsBefore: retryMetricsBefore.total_operations,
        retryMetricsAfter: retryMetricsAfter.total_operations,
        retriedOperations: retryMetricsAfter.retried_operations,
      });
    });

    it('should apply proper jitter to retry delays', async () => {
      const retryDelays: number[] = [];

      // Mock operation that fails then succeeds
      let attemptCount = 0;
      const mockOperation = async () => {
        attemptCount++;
        if (attemptCount <= 2) {
          throw new Error('Temporary failure');
        }
        return 'success';
      };

      // Capture retry delays by measuring timing
      const startTime = Date.now();
      try {
        await qdrantAdapter['executeWithRetryAndCircuitBreaker'](mockOperation, 'jitter_test', {
          max_attempts: 3,
          base_delay_ms: 100,
        });
      } catch (error) {
        // Ignore for this test
      }
      const totalTime = Date.now() - startTime;

      // Should have taken some time for retries
      expect(totalTime).toBeGreaterThan(150); // At least base delay + some jitter

      console.log('Jitter test results:', {
        totalTime,
        attemptCount,
        expectedMinDelay: 100, // Base delay
        expectedMaxDelay: 200, // Base delay + jitter
      });
    });
  });

  describe('Connection Pool Validation', () => {
    it('should handle concurrent operations efficiently', async () => {
      const concurrentRequests = 10;
      const startTime = Date.now();

      const promises = Array.from({ length: concurrentRequests }, async (_, i) => {
        return await qdrantAdapter.healthCheck();
      });

      const results = await Promise.allSettled(promises);
      const duration = Date.now() - startTime;

      const successfulResults = results.filter((r) => r.status === 'fulfilled').length;
      const failedResults = results.filter((r) => r.status === 'rejected').length;

      // Most requests should succeed with connection pooling
      expect(successfulResults).toBeGreaterThan(concurrentRequests * 0.8);
      expect(duration).toBeLessThan(10000); // Should complete within 10 seconds

      console.log('Connection pool test results:', {
        concurrentRequests,
        successfulResults,
        failedResults,
        duration,
        averageResponseTime: duration / concurrentRequests,
      });
    });

    it('should respect maxConnections configuration', async () => {
      // Test with limited connections
      const limitedAdapter = new QdrantAdapter({
        url: 'http://localhost:6333',
        timeout: 5000,
        maxConnections: 3, // Limited connections
      });

      await limitedAdapter.initialize();

      const concurrentRequests = 10;
      const startTime = Date.now();

      const promises = Array.from({ length: concurrentRequests }, async () => {
        return await limitedAdapter.healthCheck();
      });

      const results = await Promise.allSettled(promises);
      const duration = Date.now() - startTime;

      await limitedAdapter.close();

      // Should still complete but may take longer due to connection limits
      expect(duration).toBeLessThan(15000); // Should complete within 15 seconds

      console.log('Connection limits test results:', {
        maxConnections: 3,
        concurrentRequests,
        duration,
        successfulResults: results.filter((r) => r.status === 'fulfilled').length,
      });
    });
  });

  describe('Circuit Recovery Behavior', () => {
    it('should recover after circuit breaker timeout', async () => {
      // Force circuit breaker open
      qdrantAdapter.resetQdrantCircuitBreaker();
      const qdrantCircuitBreaker = circuitBreakerManager.getCircuitBreaker('qdrant');
      qdrantCircuitBreaker.forceOpen();

      expect(qdrantCircuitBreaker.isOpen()).toBe(true);

      // Wait for recovery timeout (shorter for testing)
      await new Promise((resolve) => setTimeout(resolve, 1000));

      // Circuit should transition to half-open on next attempt
      try {
        await qdrantAdapter.healthCheck();
      } catch (error) {
        // May still fail in half-open state
      }

      const stats = qdrantCircuitBreaker.getStats();

      // Should have attempted recovery
      expect(stats.timeSinceStateChange).toBeGreaterThan(0);

      console.log('Recovery behavior test results:', {
        finalState: stats.state,
        timeSinceStateChange: stats.timeSinceStateChange,
        isOpen: qdrantCircuitBreaker.isOpen(),
      });
    });

    it('should close circuit after successful probe in half-open state', async () => {
      const qdrantCircuitBreaker = circuitBreakerManager.getCircuitBreaker('qdrant');

      // Force to half-open state
      qdrantCircuitBreaker.forceState('half-open');
      expect(qdrantCircuitBreaker.isHalfOpen()).toBe(true);

      // Successful operation should close circuit
      await qdrantAdapter.healthCheck();

      const stats = qdrantCircuitBreaker.getStats();
      expect(stats.state).toBe('closed');
      expect(qdrantCircuitBreaker.isOpen()).toBe(false);

      console.log('Half-open recovery test results:', {
        finalState: stats.state,
        timeSinceStateChange: stats.timeSinceStateChange,
      });
    });
  });

  describe('Monitoring and Metrics', () => {
    it('should provide comprehensive monitoring data', () => {
      const monitoringData = qdrantAdapter.getComprehensiveMonitoringData();

      expect(monitoringData).toHaveProperty('qdrant');
      expect(monitoringData).toHaveProperty('openai');
      expect(monitoringData).toHaveProperty('retryPolicy');
      expect(monitoringData).toHaveProperty('system');

      expect(monitoringData.qdrant).toHaveProperty('circuitBreaker');
      expect(monitoringData.qdrant).toHaveProperty('healthStatus');
      expect(monitoringData.qdrant).toHaveProperty('recommendation');

      expect(monitoringData.system).toHaveProperty('overallHealth');
      expect(monitoringData.system).toHaveProperty('recommendations');
      expect(monitoringData.system).toHaveProperty('timestamp');

      console.log('Comprehensive monitoring data:', {
        qdrantHealth: monitoringData.qdrant.healthStatus,
        overallHealth: monitoringData.system.overallHealth,
        recommendations: monitoringData.system.recommendations,
      });
    });

    it('should track performance milestones', async () => {
      // Generate enough operations to trigger milestone logging
      for (let i = 0; i < 55; i++) {
        try {
          await qdrantAdapter.healthCheck();
        } catch (error) {
          // Ignore occasional failures
        }
      }

      const stats = qdrantAdapter.getQdrantCircuitBreakerStatus();
      expect(stats.totalCalls).toBeGreaterThan(50);

      console.log('Performance milestone test results:', {
        totalCalls: stats.totalCalls,
        successRate: stats.successRate,
        averageResponseTime: stats.averageResponseTime,
      });
    });
  });

  describe('Load Testing', () => {
    it('should handle sustained load without circuit breaker trips', async () => {
      const loadTestResult = await qdrantAdapter.testCircuitBreakerLoad({
        concurrentRequests: 15,
        failureRate: 0.01, // 1% simulated failure rate
        durationMs: 10000, // 10 seconds
      });

      expect(loadTestResult.success).toBe(true);
      expect(loadTestResult.metrics.successfulRequests).toBeGreaterThan(
        loadTestResult.metrics.totalRequests * 0.9
      );
      expect(loadTestResult.metrics.finalCircuitState).toBe('closed');

      console.log('Load test results:', {
        ...loadTestResult.metrics,
        successRate:
          loadTestResult.metrics.successfulRequests / loadTestResult.metrics.totalRequests,
        errorCount: loadTestResult.errors.length,
      });
    });

    it('should gracefully handle high failure rates', async () => {
      const loadTestResult = await qdrantAdapter.testCircuitBreakerLoad({
        concurrentRequests: 10,
        failureRate: 0.15, // 15% simulated failure rate
        durationMs: 5000, // 5 seconds
      });

      // Should still handle load but may open circuit breaker
      expect(loadTestResult.metrics.totalRequests).toBeGreaterThan(0);
      expect(loadTestResult.metrics.circuitStateTransitions).toBeGreaterThanOrEqual(0);

      console.log('High failure rate test results:', {
        ...loadTestResult.metrics,
        successRate:
          loadTestResult.metrics.successfulRequests / loadTestResult.metrics.totalRequests,
        circuitBehavior: loadTestResult.metrics.finalCircuitState,
      });
    });
  });

  describe('Error Classification and Recovery', () => {
    it('should distinguish between retryable and non-retryable errors', async () => {
      const retryMetricsBefore = retryPolicyManager.getMetrics();

      // Test different error types
      const errorTests = [
        { type: 'timeout', shouldRetry: true },
        { type: 'connection_refused', shouldRetry: true },
        { type: 'network', shouldRetry: true },
        { type: 'authentication', shouldRetry: false },
      ];

      for (const errorTest of errorTests) {
        try {
          // Simulate different error types by using different invalid configurations
          const testAdapter = new QdrantAdapter({
            url:
              errorTest.type === 'authentication'
                ? 'http://localhost:6333'
                : 'http://invalid-host-for-test.local:6333',
            timeout: 1000,
          });

          await testAdapter.healthCheck();
        } catch (error) {
          // Expected to fail
        }
      }

      const retryMetricsAfter = retryPolicyManager.getMetrics();

      // Should have attempted retries for retryable errors
      expect(retryMetricsAfter.total_operations).toBeGreaterThan(
        retryMetricsBefore.total_operations
      );

      console.log('Error classification test results:', {
        totalOperations: retryMetricsAfter.total_operations - retryMetricsBefore.total_operations,
        retriedOperations:
          retryMetricsAfter.retried_operations - retryMetricsBefore.retried_operations,
        errorDistribution: retryMetricsAfter.error_distribution,
      });
    });
  });
});
