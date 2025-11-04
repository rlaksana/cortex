/**
 * System Status Chaos Tests
 *
 * Chaos engineering tests for system status tool under various failure conditions.
 * Tests ensure the MCP server can handle Qdrant dependency failures gracefully
 * and provide accurate health status reporting during degradation scenarios.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { handleSystemStatus } from '../../src/index.js';
import { performanceMonitor } from '../../src/utils/performance-monitor.js';
import { circuitBreakerManager } from '../../src/services/circuit-breaker.service.js';

describe('System Status Chaos Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Set test environment
    process.env.NODE_ENV = 'test';
    process.env.QDRANT_URL = 'http://localhost:6333';
    process.env.QDRANT_COLLECTION_NAME = 'test-chaos-memory';
  });

  afterEach(() => {
    vi.restoreAllMocks();
    // Reset circuit breakers after each test
    circuitBreakerManager.resetAll();
  });

  describe('Qdrant Connection Failures', () => {
    it('should report degraded status when Qdrant is unreachable', async () => {
      // Force creation of circuit breakers by accessing them
      const dbCircuitBreaker = circuitBreakerManager.getCircuitBreaker('database-manager');
      const qdrantCircuitBreaker = circuitBreakerManager.getCircuitBreaker('qdrant-adapter');

      // Simulate circuit breaker failures for database services
      const databaseManagerOpened = circuitBreakerManager.simulateServiceFailure('database-manager');
      const qdrantAdapterOpened = circuitBreakerManager.simulateServiceFailure('qdrant-adapter');

      expect(databaseManagerOpened || qdrantAdapterOpened).toBe(true);

      const result = await handleSystemStatus({ operation: 'health' });

      expect(result.content).toBeDefined();
      const healthData = JSON.parse(result.content[0].text);

      // Should report degraded status but still respond
      expect(healthData.service.status).toBe('degraded');
      expect(healthData.vectorBackend.status).toBe('error');
      expect(healthData.vectorBackend.error).toContain('Circuit breaker open');
      expect(healthData.readiness.readyForOperations).toBe(false);
    });

    it('should handle Qdrant timeout scenarios gracefully', async () => {
      // Mock Qdrant timeout
      const timeoutError = new Error('ETIMEDOUT');
      timeoutError.name = 'TimeoutError';

      vi.doMock('../../src/services/orchestrators/memory-store-orchestrator.js', () => ({
        MemoryStoreOrchestrator: vi.fn().mockImplementation(() => ({
          storeItems: vi.fn().mockRejectedValue(timeoutError),
          isHealthy: vi.fn().mockResolvedValue(false),
        }))
      }));

      vi.doMock('../../src/services/orchestrators/memory-find-orchestrator.js', () => ({
        MemoryFindOrchestrator: vi.fn().mockImplementation(() => ({
          findItems: vi.fn().mockRejectedValue(timeoutError),
          isHealthy: vi.fn().mockResolvedValue(false),
        }))
      }));

      const startTime = Date.now();
      const result = await handleSystemStatus({ operation: 'health' });
      const duration = Date.now() - startTime;

      expect(result.content).toBeDefined();
      const healthData = JSON.parse(result.content[0].text);

      // Should complete quickly even with timeout
      expect(duration).toBeLessThan(5000);
      expect(healthData.service.status).toBe('degraded');
      expect(healthData.vectorBackend.error).toContain('TIMEOUT');
    });

    it('should implement circuit breaker for repeated Qdrant failures', async () => {
      let failureCount = 0;
      const mockHealthCheck = vi.fn().mockImplementation(() => {
        failureCount++;
        if (failureCount < 3) {
          return Promise.reject(new Error('Connection refused'));
        }
        return Promise.resolve({ status: 'healthy' });
      });

      vi.doMock('../../src/services/orchestrators/memory-store-orchestrator.js', () => ({
        MemoryStoreOrchestrator: vi.fn().mockImplementation(() => ({
          storeItems: vi.fn().mockRejectedValue(new Error('Connection refused')),
          healthCheck: mockHealthCheck,
          getCircuitStatus: vi.fn().mockReturnValue({
            isOpen: failureCount >= 3,
            failureCount: failureCount,
            lastFailureTime: Date.now(),
          }),
        }))
      }));

      // First call should fail
      const result1 = await handleSystemStatus({ operation: 'health' });
      const health1 = JSON.parse(result1.content[0].text);
      expect(health1.service.status).toBe('degraded');

      // Second call should also fail
      const result2 = await handleSystemStatus({ operation: 'health' });
      const health2 = JSON.parse(result2.content[0].text);
      expect(health2.service.status).toBe('degraded');

      // Third call should trigger circuit breaker
      const result3 = await handleSystemStatus({ operation: 'health' });
      const health3 = JSON.parse(result3.content[0].text);
      expect(health3.service.status).toBe('degraded');
      expect(health3.vectorBackend.error).toContain('circuit breaker');
    });
  });

  describe('Partial Service Degradation', () => {
    it('should handle memory store failures while keeping search available', async () => {
      vi.doMock('../../src/services/orchestrators/memory-store-orchestrator.js', () => ({
        MemoryStoreOrchestrator: vi.fn().mockImplementation(() => ({
          storeItems: vi.fn().mockRejectedValue(new Error('Store service unavailable')),
          isHealthy: vi.fn().mockResolvedValue(false),
        }))
      }));

      vi.doMock('../../src/services/orchestrators/memory-find-orchestrator.js', () => ({
        MemoryFindOrchestrator: vi.fn().mockImplementation(() => ({
          findItems: vi.fn().mockResolvedValue({
            items: [],
            total_count: 0,
            observability: { strategy: 'fallback', degraded: true },
          }),
          isHealthy: vi.fn().mockResolvedValue(true),
        }))
      }));

      const result = await handleSystemStatus({ operation: 'health' });
      const healthData = JSON.parse(result.content[0].text);

      expect(healthData.service.status).toBe('degraded');
      expect(healthData.activeServices.memoryStore.status).toBe('error');
      expect(healthData.activeServices.memoryFind.status).toBe('active');
      expect(healthData.readiness.supportedOperations).toContain('memory_find');
      expect(healthData.readiness.supportedOperations).not.toContain('memory_store');
    });

    it('should handle search failures while keeping store available', async () => {
      vi.doMock('../../src/services/orchestrators/memory-store-orchestrator.js', () => ({
        MemoryStoreOrchestrator: vi.fn().mockImplementation(() => ({
          storeItems: vi.fn().mockResolvedValue({
            stored: [],
            summary: { total: 0, stored: 0 },
            errors: [],
          }),
          isHealthy: vi.fn().mockResolvedValue(true),
        }))
      }));

      vi.doMock('../../src/services/orchestrators/memory-find-orchestrator.js', () => ({
        MemoryFindOrchestrator: vi.fn().mockImplementation(() => ({
          findItems: vi.fn().mockRejectedValue(new Error('Search service unavailable')),
          isHealthy: vi.fn().mockResolvedValue(false),
        }))
      }));

      const result = await handleSystemStatus({ operation: 'health' });
      const healthData = JSON.parse(result.content[0].text);

      expect(healthData.service.status).toBe('degraded');
      expect(healthData.activeServices.memoryStore.status).toBe('active');
      expect(healthData.activeServices.memoryFind.status).toBe('error');
      expect(healthData.readiness.supportedOperations).toContain('memory_store');
      expect(healthData.readiness.supportedOperations).not.toContain('memory_find');
    });
  });

  describe('Resource Exhaustion Scenarios', () => {
    it('should handle high memory usage gracefully', async () => {
      // Mock high memory usage
      const originalMemoryUsage = process.memoryUsage;
      process.memoryUsage = vi.fn().mockReturnValue({
        rss: 1024 * 1024 * 1024, // 1GB
        heapUsed: 800 * 1024 * 1024, // 800MB
        heapTotal: 1024 * 1024 * 1024, // 1GB
        external: 100 * 1024 * 1024, // 100MB
        arrayBuffers: 50 * 1024 * 1024, // 50MB
      });

      try {
        const result = await handleSystemStatus({ operation: 'metrics' });
        const metricsData = JSON.parse(result.content[0].text);

        expect(metricsData.health_status.resource_utilization.memory_usage_kb).toBeGreaterThan(800000);
        expect(metricsData.performance_indicators.error_rate).toBeDefined();

        // Should still respond despite high memory usage
        expect(result.content).toBeDefined();
        expect(metricsData.type).toBe('system_metrics_detailed');
      } finally {
        process.memoryUsage = originalMemoryUsage;
      }
    });

    it('should handle rapid request bursts during status checks', async () => {
      // Mock orchestrators that respond slowly under load
      vi.doMock('../../src/services/orchestrators/memory-store-orchestrator.js', () => ({
        MemoryStoreOrchestrator: vi.fn().mockImplementation(() => ({
          storeItems: vi.fn().mockImplementation(() =>
            new Promise(resolve => setTimeout(resolve, 100))
          ),
          isHealthy: vi.fn().mockResolvedValue(true),
        }))
      }));

      vi.doMock('../../src/services/orchestrators/memory-find-orchestrator.js', () => ({
        MemoryFindOrchestrator: vi.fn().mockImplementation(() => ({
          findItems: vi.fn().mockImplementation(() =>
            new Promise(resolve => setTimeout(resolve, 100))
          ),
          isHealthy: vi.fn().mockResolvedValue(true),
        }))
      }));

      // Fire multiple concurrent status requests
      const promises = Array.from({ length: 10 }, (_, i) =>
        handleSystemStatus({
          operation: 'health',
          request_id: `burst_test_${i}`
        })
      );

      const results = await Promise.all(promises);

      // All requests should complete successfully
      expect(results).toHaveLength(10);
      results.forEach(result => {
        expect(result.content).toBeDefined();
        const healthData = JSON.parse(result.content[0].text);
        expect(healthData.service).toBeDefined();
      });
    });
  });

  describe('Network Partition Scenarios', () => {
    it('should handle intermittent network connectivity issues', async () => {
      let callCount = 0;
      const mockHealthCheck = vi.fn().mockImplementation(() => {
        callCount++;
        if (callCount % 2 === 0) {
          return Promise.resolve({ status: 'healthy', uptime: 12345 });
        }
        return Promise.reject(new Error('Network unreachable'));
      });

      vi.doMock('../../src/services/orchestrators/memory-store-orchestrator.js', () => ({
        MemoryStoreOrchestrator: vi.fn().mockImplementation(() => ({
          storeItems: vi.fn().mockImplementation(() => {
            if (Math.random() > 0.5) {
              return Promise.reject(new Error('Network partition detected'));
            }
            return Promise.resolve({ stored: [], summary: { total: 0, stored: 0 } });
          }),
          healthCheck: mockHealthCheck,
        }))
      }));

      // Test multiple status calls during intermittent failures
      const results = [];
      for (let i = 0; i < 5; i++) {
        const result = await handleSystemStatus({ operation: 'health' });
        results.push(result);
        // Small delay between calls
        await new Promise(resolve => setTimeout(resolve, 50));
      }

      expect(results).toHaveLength(5);

      // Some calls should succeed, some should fail gracefully
      const successCount = results.filter(r => {
        const healthData = JSON.parse(r.content[0].text);
        return healthData.service.status !== 'error';
      }).length;

      const degradedCount = results.filter(r => {
        const healthData = JSON.parse(r.content[0].text);
        return healthData.service.status === 'degraded';
      }).length;

      // Should have mixed results during network issues
      expect(successCount + degradedCount).toBe(5);
      expect(degradedCount).toBeGreaterThan(0);
    });

    it('should provide fallback status during complete network isolation', async () => {
      // Mock complete network failure
      vi.doMock('../../src/services/orchestrators/memory-store-orchestrator.js', () => ({
        MemoryStoreOrchestrator: vi.fn().mockImplementation(() => ({
          storeItems: vi.fn().mockRejectedValue(new Error('ENOTFOUND')),
          healthCheck: vi.fn().mockRejectedValue(new Error('Network unreachable')),
        }))
      }));

      vi.doMock('../../src/services/orchestrators/memory-find-orchestrator.js', () => ({
        MemoryFindOrchestrator: vi.fn().mockImplementation(() => ({
          findItems: vi.fn().mockRejectedValue(new Error('ENOTFOUND')),
          healthCheck: vi.fn().mockRejectedValue(new Error('Network unreachable')),
        }))
      }));

      const result = await handleSystemStatus({ operation: 'health' });
      const healthData = JSON.parse(result.content[0].text);

      // Should still provide basic service information
      expect(healthData.service.name).toBe('cortex-memory-mcp');
      expect(healthData.service.version).toBe('2.0.0');
      expect(healthData.service.status).toBe('error');
      expect(healthData.vectorBackend.status).toBe('error');
      expect(healthData.vectorBackend.error).toContain('Network');

      // Should include system information even when backend is down
      expect(healthData.system).toBeDefined();
      expect(healthData.system.pid).toBe(process.pid);
      expect(healthData.system.platform).toBeDefined();
    });
  });

  describe('Recovery and Self-Healing', () => {
    it('should detect and report service recovery', async () => {
      let isHealthy = false;
      const mockHealthCheck = vi.fn().mockImplementation(() => {
        return Promise.resolve({
          status: isHealthy ? 'healthy' : 'unhealthy',
          uptime: isHealthy ? 12345 : 0,
        });
      });

      vi.doMock('../../src/services/orchestrators/memory-store-orchestrator.js', () => ({
        MemoryStoreOrchestrator: vi.fn().mockImplementation(() => ({
          storeItems: vi.fn().mockImplementation(() => {
            if (!isHealthy) {
              return Promise.reject(new Error('Service temporarily unavailable'));
            }
            return Promise.resolve({ stored: [], summary: { total: 1, stored: 1 } });
          }),
          healthCheck: mockHealthCheck,
        }))
      }));

      // Initial check should show degraded status
      const result1 = await handleSystemStatus({ operation: 'health' });
      const health1 = JSON.parse(result1.content[0].text);
      expect(health1.service.status).toBe('degraded');

      // Simulate service recovery
      isHealthy = true;

      // Next check should show recovered status
      const result2 = await handleSystemStatus({ operation: 'health' });
      const health2 = JSON.parse(result2.content[0].text);
      expect(health2.service.status).toBe('healthy');
      expect(health2.vectorBackend.status).toBe('healthy');
    });

    it('should implement progressive backoff for failing services', async () => {
      let callCount = 0;
      const callTimes = [];

      const mockHealthCheck = vi.fn().mockImplementation(async () => {
        callTimes.push(Date.now());
        callCount++;
        await new Promise(resolve => setTimeout(resolve, 50)); // Add delay
        throw new Error(`Service failure #${callCount}`);
      });

      vi.doMock('../../src/services/orchestrators/memory-store-orchestrator.js', () => ({
        MemoryStoreOrchestrator: vi.fn().mockImplementation(() => ({
          healthCheck: mockHealthCheck,
        }))
      }));

      // Make multiple calls to test backoff
      const startTime = Date.now();
      const promises = Array.from({ length: 3 }, (_, i) =>
        handleSystemStatus({ operation: 'health', attempt: i + 1 })
      );

      await Promise.allSettled(promises);
      const totalTime = Date.now() - startTime;

      // Should see progressive delay due to backoff
      expect(callCount).toBeGreaterThan(0);
      expect(callTimes).toHaveLength(callCount);

      // Each subsequent call should be delayed (backoff behavior)
      if (callTimes.length > 1) {
        for (let i = 1; i < callTimes.length; i++) {
          const interval = callTimes[i] - callTimes[i - 1];
          expect(interval).toBeGreaterThan(40); // Should have some backoff delay
        }
      }
    });
  });
});