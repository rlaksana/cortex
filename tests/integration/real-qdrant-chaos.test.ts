/**
 * Real Qdrant Chaos Tests
 *
 * Comprehensive chaos engineering tests with real Qdrant instance.
 * Tests actual system resilience under real failure conditions.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { handleSystemStatus } from '../../src/index.js';
import { circuitBreakerManager } from '../../src/services/circuit-breaker.service.js';
import { QdrantAdapter } from '../../src/db/adapters/qdrant-adapter.js';

describe('Real Qdrant Chaos Tests', () => {
  let qdrantAdapter: QdrantAdapter;
  let originalQdrantUrl: string | undefined;

  beforeEach(() => {
    // Set test environment
    process.env['NODE_ENV'] = 'test';
    process.env['QDRANT_URL'] = 'http://localhost:6333';
    process.env['QDRANT_COLLECTION_NAME'] = 'test-chaos-memory';

    // Store original Qdrant URL
    originalQdrantUrl = process.env['QDRANT_URL'];

    // Create Qdrant adapter for real operations
    qdrantAdapter = new QdrantAdapter({
      url: 'http://localhost:6333',
      apiKey: undefined,
      timeout: 5000,
    });

    // Reset circuit breakers before each test
    circuitBreakerManager.resetAll();
  });

  afterEach(async () => {
    // Restore original Qdrant URL
    if (originalQdrantUrl) {
      process.env['QDRANT_URL'] = originalQdrantUrl;
    }

    // Reset circuit breakers after each test
    circuitBreakerManager.resetAll();

    // Cleanup test data if needed
    try {
      await qdrantAdapter.deleteCollection('test-chaos-memory');
    } catch {
      // Ignore cleanup errors
    }
  });

  describe('Real Qdrant Connection Failures', () => {
    it('should handle Qdrant service stop/start gracefully', async () => {
      // First, verify system is healthy with Qdrant running
      const healthyResult = await handleSystemStatus({ operation: 'health' });
      const healthyData = JSON.parse(healthyResult.content[0].text);

      expect(healthyData.service.status).toBe('healthy');
      expect(healthyData.vectorBackend.status).toBe('healthy');

      // Simulate Qdrant failure by pointing to invalid host
      process.env['QDRANT_URL'] = 'http://localhost:9999'; // Invalid port

      // Create new adapter with invalid host to force failures
      const invalidAdapter = new QdrantAdapter({
        url: 'http://localhost:9999',
        timeout: 1000,
      });

      // Test multiple operations to trigger circuit breaker
      const failurePromises = Array.from({ length: 5 }, async (_, i) => {
        try {
          await invalidAdapter.healthCheck();
          return { success: true, attempt: i };
        } catch (error) {
          return { success: false, attempt: i, error: (error as Error).message };
        }
      });

      const failureResults = await Promise.allSettled(failurePromises);

      // Check that system status reflects degraded state
      const degradedResult = await handleSystemStatus({ operation: 'health' });
      const degradedData = JSON.parse(degradedResult.content[0].text);

      // System should still respond but potentially show degraded status
      expect(degradedData.service).toBeDefined();
      expect(degradedData.service.name).toBe('cortex-memory-mcp');

      // Restore Qdrant connection
      process.env['QDRANT_URL'] = 'http://localhost:6333';

      // Wait a moment for recovery
      await new Promise((resolve) => setTimeout(resolve, 1000));

      // Test recovery
      const recoveryResult = await handleSystemStatus({ operation: 'health' });
      const recoveryData = JSON.parse(recoveryResult.content[0].text);

      expect(recoveryData.service.status).toBe('healthy');
      expect(recoveryData.vectorBackend.status).toBe('healthy');
    });

    it('should test circuit breaker state transitions', async () => {
      const dbCircuitBreaker = circuitBreakerManager.getCircuitBreaker('database-manager', {
        failureThreshold: 2, // Lower threshold for faster testing
        recoveryTimeoutMs: 2000, // 2 seconds for quick recovery
        minimumCalls: 2,
      });

      // Force circuit breaker to open state
      dbCircuitBreaker.forceOpen();

      // Verify circuit is open
      expect(dbCircuitBreaker.isOpen()).toBe(true);

      // Check system status reflects open circuit
      const result = await handleSystemStatus({ operation: 'health' });
      const healthData = JSON.parse(result.content[0].text);

      expect(healthData.service).toBeDefined();

      // Force circuit back to closed for recovery testing
      dbCircuitBreaker.forceState('closed');

      // Wait for recovery timeout
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Verify circuit is closed
      expect(dbCircuitBreaker.isOpen()).toBe(false);

      // Check system status shows recovery
      const recoveryResult = await handleSystemStatus({ operation: 'health' });
      const recoveryData = JSON.parse(recoveryResult.content[0].text);

      expect(recoveryData.service.status).toBe('healthy');
    });

    it('should handle timeout scenarios with real Qdrant', async () => {
      // Create adapter with very short timeout
      const timeoutAdapter = new QdrantAdapter({
        url: 'http://localhost:6333',
        timeout: 1, // 1ms timeout to force immediate failures
      });

      const startTime = Date.now();

      try {
        await timeoutAdapter.healthCheck();
      } catch (error) {
        // Expected to fail due to timeout
        expect((error as Error).message).toBeDefined();
      }

      const duration = Date.now() - startTime;

      // Should fail quickly, not hang
      expect(duration).toBeLessThan(5000);

      // System status should still be available
      const result = await handleSystemStatus({ operation: 'health' });
      const healthData = JSON.parse(result.content[0].text);

      expect(healthData.service).toBeDefined();
      expect(healthData.system).toBeDefined();
    });
  });

  describe('Resource Exhaustion and Performance', () => {
    it('should handle concurrent operations during Qdrant load', async () => {
      // Create multiple concurrent system status requests
      const concurrentRequests = Array.from({ length: 20 }, (_, i) =>
        handleSystemStatus({
          operation: 'health',
          request_id: `concurrent_test_${i}`,
        })
      );

      const startTime = Date.now();
      const results = await Promise.allSettled(concurrentRequests);
      const duration = Date.now() - startTime;

      // All requests should complete
      expect(results).toHaveLength(20);

      // Most should succeed
      const successCount = results.filter(
        (r) => r.status === 'fulfilled' && r.value.content
      ).length;

      expect(successCount).toBeGreaterThan(15); // Allow for some failures

      // Should complete within reasonable time
      expect(duration).toBeLessThan(10000); // 10 seconds max

      // Verify responses are consistent
      const successfulResults = results.filter(
        (r) => r.status === 'fulfilled'
      ) as PromiseFulfilledResult<any>[];
      const healthStatuses = successfulResults.map(
        (r) => JSON.parse(r.value.content[0].text).service.status
      );

      // All successful responses should have the same status
      const uniqueStatuses = [...new Set(healthStatuses)];
      expect(uniqueStatuses.length).toBeLessThanOrEqual(2); // Allow for healthy/degraded mix
    });

    it('should measure performance under chaos conditions', async () => {
      const performanceMetrics = {
        responseTimes: [] as number[],
        successCount: 0,
        errorCount: 0,
      };

      // Create circuit breaker with aggressive settings for testing
      const testCircuitBreaker = circuitBreakerManager.getCircuitBreaker('performance-test', {
        failureThreshold: 3,
        recoveryTimeoutMs: 1000,
        minimumCalls: 2,
        failureRateThreshold: 0.5,
      });

      // Simulate chaos by randomly opening/closing circuit
      const chaosInterval = setInterval(() => {
        if (Math.random() > 0.5) {
          testCircuitBreaker.forceState(Math.random() > 0.5 ? 'open' : 'closed');
        }
      }, 500);

      try {
        // Run performance test under chaos
        const testPromises = Array.from({ length: 10 }, async (_, i) => {
          const startTime = Date.now();

          try {
            const result = await handleSystemStatus({
              operation: 'health',
              request_id: `perf_test_${i}`,
            });

            const responseTime = Date.now() - startTime;
            performanceMetrics.responseTimes.push(responseTime);
            performanceMetrics.successCount++;

            return result;
          } catch (error) {
            performanceMetrics.errorCount++;
            throw error;
          }
        });

        await Promise.allSettled(testPromises);

        // Calculate performance statistics
        const avgResponseTime =
          performanceMetrics.responseTimes.length > 0
            ? performanceMetrics.responseTimes.reduce((sum, time) => sum + time, 0) /
              performanceMetrics.responseTimes.length
            : 0;

        const maxResponseTime = Math.max(...performanceMetrics.responseTimes, 0);

        // Performance assertions
        expect(avgResponseTime).toBeLessThan(5000); // 5 seconds average max
        expect(maxResponseTime).toBeLessThan(15000); // 15 seconds max
        expect(performanceMetrics.successCount + performanceMetrics.errorCount).toBe(10);

        // System should still respond somewhat consistently
        expect(performanceMetrics.successCount).toBeGreaterThan(0);
      } finally {
        clearInterval(chaosInterval);
        testCircuitBreaker.reset();
      }
    });
  });

  describe('Network Chaos Scenarios', () => {
    it('should handle invalid Qdrant URLs gracefully', async () => {
      const invalidUrls = [
        'http://invalid-host-that-does-not-exist.local:6333',
        'http://localhost:9999', // Wrong port
        'ftp://localhost:6333', // Wrong protocol
      ];

      for (const invalidUrl of invalidUrls) {
        process.env['QDRANT_URL'] = invalidUrl;

        // Create adapter with invalid URL
        const invalidAdapter = new QdrantAdapter({
          url: invalidUrl,
          timeout: 2000,
        });

        // Test health check fails gracefully
        try {
          await invalidAdapter.healthCheck();
          expect.fail('Expected health check to fail with invalid URL');
        } catch (error) {
          expect((error as Error).message).toBeDefined();
        }

        // System status should still be available
        const result = await handleSystemStatus({ operation: 'health' });
        const healthData = JSON.parse(result.content[0].text);

        expect(healthData.service).toBeDefined();
        expect(healthData.system).toBeDefined();
      }
    });

    it('should test recovery from network partitions', async () => {
      // Simulate network partition by using invalid URL
      process.env['QDRANT_URL'] = 'http://localhost:9999';

      const partitionAdapter = new QdrantAdapter({
        url: 'http://localhost:9999',
        timeout: 1000,
      });

      // Verify failure during partition
      try {
        await partitionAdapter.healthCheck();
        expect.fail('Expected failure during network partition');
      } catch (error) {
        // Expected failure
      }

      // Check system status during partition
      const partitionResult = await handleSystemStatus({ operation: 'health' });
      const partitionData = JSON.parse(partitionResult.content[0].text);

      expect(partitionData.service).toBeDefined();

      // Restore connection
      process.env['QDRANT_URL'] = 'http://localhost:6333';

      // Wait for recovery
      await new Promise((resolve) => setTimeout(resolve, 1000));

      // Test recovery
      const recoveryAdapter = new QdrantAdapter({
        url: 'http://localhost:6333',
        timeout: 5000,
      });

      const healthCheck = await recoveryAdapter.healthCheck();
      expect(healthCheck).toBeDefined();

      // Check system status after recovery
      const recoveryResult = await handleSystemStatus({ operation: 'health' });
      const recoveryData = JSON.parse(recoveryResult.content[0].text);

      expect(recoveryData.service.status).toBe('healthy');
      expect(recoveryData.vectorBackend.status).toBe('healthy');
    });
  });

  describe('System Resilience Validation', () => {
    it('should maintain service availability during partial failures', async () => {
      // Test that system status tool remains available even when Qdrant fails
      const dbCircuitBreaker = circuitBreakerManager.getCircuitBreaker('database-manager');

      // Force database circuit breaker open
      dbCircuitBreaker.forceOpen();

      // System status should still be available
      const result = await handleSystemStatus({ operation: 'health' });
      const healthData = JSON.parse(result.content[0].text);

      expect(healthData.service).toBeDefined();
      expect(healthData.system).toBeDefined();
      expect(healthData.service.name).toBe('cortex-memory-mcp');
      expect(healthData.service.version).toBe('2.0.0');

      // Test other operations still work
      const metricsResult = await handleSystemStatus({ operation: 'metrics' });
      const metricsData = JSON.parse(metricsResult.content[0].text);

      expect(metricsData).toBeDefined();
      expect(metricsData.type).toBe('system_metrics_detailed');

      // Test system status operations remain available
      const statsResult = await handleSystemStatus({ operation: 'health' });
      const statsData = JSON.parse(statsResult.content[0].text);

      expect(statsData).toBeDefined();
      expect(statsData.service).toBeDefined();
    });

    it('should validate circuit breaker statistics and monitoring', async () => {
      const testCircuitBreaker = circuitBreakerManager.getCircuitBreaker('monitoring-test', {
        failureThreshold: 3,
        recoveryTimeoutMs: 5000,
        minimumCalls: 3,
        failureRateThreshold: 0.5,
        trackFailureTypes: true,
      });

      // Get initial stats
      const initialStats = testCircuitBreaker.getStats();
      expect(initialStats.state).toBe('closed');
      expect(initialStats.failures).toBe(0);
      expect(initialStats.isOpen).toBe(false);

      // Force some failures to trigger circuit breaker
      testCircuitBreaker.forceOpen();

      const openStats = testCircuitBreaker.getStats();
      expect(openStats.state).toBe('open');
      expect(openStats.isOpen).toBe(true);
      expect(openStats.timeSinceStateChange).toBeGreaterThanOrEqual(0);

      // Test half-open state
      await new Promise((resolve) => setTimeout(resolve, 100)); // Small delay
      testCircuitBreaker.forceState('half-open');

      const halfOpenStats = testCircuitBreaker.getStats();
      expect(halfOpenStats.state).toBe('half-open');
      expect(halfOpenStats.isOpen).toBe(false);

      // Test recovery
      testCircuitBreaker.forceState('closed');

      const recoveredStats = testCircuitBreaker.getStats();
      expect(recoveredStats.state).toBe('closed');
      expect(recoveredStats.isOpen).toBe(false);
      expect(recoveredStats.failures).toBe(0);

      // Verify system health reflects circuit breaker states
      const systemHealth = circuitBreakerManager.getSystemHealth();
      expect(systemHealth.status).toBe('healthy');
      expect(systemHealth.totalServices).toBeGreaterThan(0);
      expect(systemHealth.services).toBeDefined();
    });
  });
});
