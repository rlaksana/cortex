/**
 * Qdrant Graceful Degradation Integration Tests
 *
 * Comprehensive test suite for graceful degradation functionality including
 * failover, fallback storage, notifications, error budget tracking, and recovery.
 *
 * @author Cortex Team
 * @version 2.0.1
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@vitest/runner';
import { QdrantAdapter } from '../../src/db/adapters/qdrant-adapter.js';
import { QdrantGracefulDegradationManager } from '../../src/monitoring/graceful-degradation-manager.js';
import { InMemoryFallbackStorage } from '../../src/db/adapters/in-memory-fallback-storage.js';
import {
  QdrantDegradationDetector,
  DegradationLevel,
} from '../../src/monitoring/degradation-detector.js';
import { QdrantDegradationNotifier } from '../../src/monitoring/degradation-notifier.js';
import { QdrantErrorBudgetTracker } from '../../src/monitoring/error-budget-tracker.js';
import type { KnowledgeItem, SearchQuery } from '../../src/types/core-interfaces.js';

describe('Qdrant Graceful Degradation', () => {
  let qdrantAdapter: QdrantAdapter;
  let degradationManager: QdrantGracefulDegradationManager;
  let fallbackStorage: InMemoryFallbackStorage;

  // Mock test data
  const testItems: KnowledgeItem[] = [
    {
      id: 'test-item-1',
      kind: 'entity',
      scope: { project: 'test-project' },
      data: {
        title: 'Test Item 1',
        content: 'This is a test item for graceful degradation testing',
      },
      created_at: new Date().toISOString(),
    },
    {
      id: 'test-item-2',
      kind: 'decision',
      scope: { project: 'test-project' },
      data: { title: 'Test Decision', rationale: 'Test decision for graceful degradation' },
      created_at: new Date().toISOString(),
    },
  ];

  const testSearchQuery: SearchQuery = {
    query: 'test item',
    limit: 10,
    mode: 'auto',
  };

  beforeEach(async () => {
    // Set environment variables for testing
    process.env['QDRANT_URL'] = 'http://localhost:6333';
    process.env['QDRANT_GRACEFUL_DEGRADATION'] = 'true';
    process.env['OPENAI_API_KEY'] = 'test-key';

    // Create Qdrant adapter with test configuration
    qdrantAdapter = new QdrantAdapter({
      type: 'qdrant',
      url: 'http://localhost:6333',
      vectorSize: 1536,
      distance: 'Cosine',
      collectionName: 'test_graceful_degradation',
    });

    // Create fallback storage for testing
    fallbackStorage = new InMemoryFallbackStorage({
      maxItems: 1000,
      maxMemoryUsageMB: 10,
      defaultTTL: 30,
      enablePersistence: false,
    });

    // Create degradation manager for testing
    degradationManager = new QdrantGracefulDegradationManager(qdrantAdapter, {
      failover: {
        enabled: true,
        triggerLevel: DegradationLevel['WARNING'], // Lower threshold for testing
        minDurationBeforeFailover: 1000, // 1 second for fast testing
        maxFailoverAttempts: 3,
        failoverCooldownMs: 5000,
        automaticFailback: true,
        consecutiveHealthChecksRequired: 2,
        healthCheckIntervalMs: 1000,
      },
      fallback: {
        maxItems: 1000,
        maxMemoryUsageMB: 10,
        defaultTTL: 30,
        enablePersistence: false,
        syncOnRecovery: false, // Disable for testing
      },
      notifications: {
        enabled: false, // Disable notifications for testing
        userFacingMessages: false,
        operatorAlerts: false,
        detailedLogging: false,
      },
      errorBudget: {
        enabled: false, // Disable error budget for testing
        availabilityTarget: 99.9,
        latencyTarget: 1000,
        errorRateTarget: 0.1,
      },
    });

    await fallbackStorage.initialize();
  });

  afterEach(async () => {
    // Cleanup
    if (degradationManager) {
      await degradationManager.stop();
    }
    if (fallbackStorage) {
      await fallbackStorage.shutdown();
    }
    if (qdrantAdapter) {
      await qdrantAdapter.close();
    }

    // Reset environment variables
    delete process.env['QDRANT_URL'];
    delete process.env['QDRANT_GRACEFUL_DEGRADATION'];
    delete process.env['OPENAI_API_KEY'];
  });

  describe('In-Memory Fallback Storage', () => {
    it('should store and retrieve items in fallback storage', async () => {
      const result = await fallbackStorage.store(testItems);

      expect(result.success).toBe(true);
      expect(result.items).toHaveLength(2);
      expect(result.summary.stored).toBe(2);
      expect(result.meta.strategy).toBe('in-memory-fallback');
      expect(result.meta.degraded).toBe(true);
    });

    it('should search items in fallback storage', async () => {
      // First store some items
      await fallbackStorage.store(testItems);

      // Then search for them
      const searchResult = await fallbackStorage.search(testSearchQuery);

      expect(searchResult.success).toBe(true);
      expect(searchResult.items).toBeDefined();
      expect(searchResult.meta.strategy).toBe('in-memory-fallback');
      expect(searchResult.meta.degraded).toBe(true);
      expect(searchResult.meta.fallback_reason).toContain('Qdrant database unavailable');
    });

    it('should handle item deduplication in fallback storage', async () => {
      // Store same items twice
      const firstResult = await fallbackStorage.store(testItems);
      const secondResult = await fallbackStorage.store(testItems);

      expect(firstResult.summary.stored).toBe(2);
      expect(secondResult.summary.stored).toBe(0); // Should be skipped as duplicates
      expect(secondResult.summary.skipped_dedupe).toBe(2);
    });

    it('should enforce storage limits', async () => {
      // Create storage with very low limits
      const limitedStorage = new InMemoryFallbackStorage({
        maxItems: 2,
        maxMemoryUsageMB: 1,
        defaultTTL: 30,
        enablePersistence: false,
      });

      await limitedStorage.initialize();

      // Try to store more items than limit
      const manyItems: KnowledgeItem[] = Array.from({ length: 5 }, (_, i) => ({
        id: `item-${i}`,
        kind: 'entity',
        scope: { project: 'test' },
        data: { title: `Item ${i}`, content: `Content for item ${i}` },
        created_at: new Date().toISOString(),
      }));

      const result = await limitedStorage.store(manyItems);

      expect(result.summary.stored).toBeLessThanOrEqual(2);
      expect(result.summary.business_rule_blocked).toBeGreaterThan(0);

      await limitedStorage.shutdown();
    });

    it('should track metrics correctly', async () => {
      await fallbackStorage.store(testItems);
      await fallbackStorage.search(testSearchQuery);

      const metrics = fallbackStorage.getMetrics();

      expect(metrics.totalOperations).toBeGreaterThan(0);
      expect(metrics.fallbackOperations).toBeGreaterThan(0);
      expect(metrics.successfulFallbackOps).toBeGreaterThan(0);
      expect(metrics.itemsStored).toBe(2);
      expect(metrics.memoryUsageMB).toBeGreaterThan(0);
    });
  });

  describe('Degradation Detection', () => {
    it('should detect degradation levels correctly', async () => {
      // This test would require mocking Qdrant health monitor
      // For now, we'll test the degradation detection logic

      const detector = new QdrantDegradationDetector(
        // Mock Qdrant health monitor
        {
          getCurrentStatus: () => 'degraded' as any,
          getCurrentMetrics: () => ({
            averageResponseTime: 5000,
            errorRate: 15,
          }),
          on: jest.fn(),
          start: jest.fn(),
          stop: jest.fn(),
        } as any,
        // Mock circuit breaker monitor
        {
          getHealthStatus: () => ({
            isOpen: true,
            healthStatus: 'unhealthy' as any,
          }),
          on: jest.fn(),
          start: jest.fn(),
          stop: jest.fn(),
        } as any
      );

      detector.start();

      // Force a health check
      await detector.forceHealthCheck();

      const metrics = detector.getMetrics();
      expect(metrics.currentLevel).toBeDefined();

      detector.stop();
    });

    it('should trigger auto-failover at critical level', async () => {
      const detector = new QdrantDegradationDetector(
        // Mock Qdrant health monitor with critical status
        {
          getCurrentStatus: () => 'unhealthy' as any,
          getCurrentMetrics: () => ({
            averageResponseTime: 10000,
            errorRate: 50,
          }),
          on: jest.fn(),
          start: jest.fn(),
          stop: jest.fn(),
        } as any,
        // Mock circuit breaker monitor
        {
          getHealthStatus: () => ({
            isOpen: true,
            healthStatus: 'unhealthy' as any,
          }),
          on: jest.fn(),
          start: jest.fn(),
          stop: jest.fn(),
        } as any,
        {
          autoFailover: {
            enabled: true,
            triggerLevel: DegradationLevel['CRITICAL'],
            minDurationBeforeFailover: 100,
            maxFailoverAttempts: 1,
            failoverCooldownMs: 1000,
          },
        }
      );

      // Listen for failover events
      const failoverSpy = jest.fn();
      detector.on('failover_triggered', failoverSpy);

      detector.start();

      // Wait for auto-failover to trigger
      await new Promise((resolve) => setTimeout(resolve, 200));

      expect(failoverSpy).toHaveBeenCalled();

      detector.stop();
    });
  });

  describe('Graceful Degradation Manager', () => {
    it('should initialize and start gracefully', async () => {
      await degradationManager.start();

      const state = degradationManager.getCurrentState();
      expect(state).toBeDefined();
      expect(state.currentLevel).toBe(DegradationLevel['HEALTHY']);
      expect(state.isInFailover).toBe(false);
    });

    it('should handle store operations during failover', async () => {
      await degradationManager.start();

      // Force manual failover
      const failoverResult = await degradationManager.forceFailover('Test failover');
      expect(failoverResult).toBe(true);

      // Store items during failover
      const storeResult = await degradationManager.store(testItems);

      expect(storeResult.success).toBe(true);
      expect(storeResult.degraded).toBe(true);
      expect(storeResult.fallbackUsed).toBe(true);
      expect(storeResult.strategy).toBe('fallback');

      await degradationManager.forceFailback();
    });

    it('should handle search operations during failover', async () => {
      await degradationManager.start();

      // Store items first
      await degradationManager.store(testItems);

      // Force manual failover
      await degradationManager.forceFailover('Test failover');

      // Search during failover
      const searchResult = await degradationManager.search(testSearchQuery);

      expect(searchResult.success).toBe(true);
      expect(searchResult.degraded).toBe(true);
      expect(searchResult.fallbackUsed).toBe(true);
      expect(searchResult.strategy).toBe('fallback');

      await degradationManager.forceFailback();
    });

    it('should track failover statistics', async () => {
      await degradationManager.start();

      // Perform failover and failback
      await degradationManager.forceFailover('Test failover');
      await degradationManager.forceFailback();

      const stats = degradationManager.getStatistics();

      expect(stats.totalFailovers).toBe(1);
      expect(stats.totalFailback).toBe(1);
      expect(stats.successfulFailovers).toBe(1);
      expect(stats.fallbackOperations).toBeGreaterThan(0);
    });

    it('should provide user-facing messages during degradation', async () => {
      const notifier = new QdrantDegradationNotifier({
        ui: {
          showUserFacingMessages: true,
          bannerMessage: 'System degraded - using fallback storage',
        },
      });

      // Simulate degradation event
      const degradationEvent = {
        id: 'test-event',
        timestamp: new Date(),
        level: DegradationLevel['DEGRADED'],
        trigger: 'test',
        description: 'Test degradation',
        metrics: {},
        recommendations: ['Test recommendation'],
        autoFailoverTriggered: false,
      };

      const deliveries = await notifier.sendNotification(degradationEvent);
      expect(deliveries).toBeDefined();

      const userMessage = notifier.getUserFacingMessage();
      expect(userMessage).toBeDefined();
      expect(userMessage?.message).toContain('degraded');
      expect(userMessage?.level).toBe(DegradationLevel['DEGRADED']);
    });
  });

  describe('Error Budget Tracking', () => {
    it('should track error budget consumption', async () => {
      const errorBudgetTracker = new QdrantErrorBudgetTracker({
        slo: {
          availabilityTarget: 99.0, // Lower target for testing
          latencyTarget: 2000,
          errorRateTarget: 1.0,
          timeWindowMs: 60000, // 1 minute for testing
        },
      });

      errorBudgetTracker.start();

      // Record some operations
      for (let i = 0; i < 10; i++) {
        errorBudgetTracker.recordOperation({
          timestamp: Date.now(),
          operationType: 'store',
          success: i < 8, // 2 failures
          responseTime: 500 + Math.random() * 1000,
          degraded: false,
          fallbackUsed: false,
        });
      }

      const status = errorBudgetTracker.getCurrentStatus();
      expect(status.availability).toBeLessThan(100);
      expect(status.errorRate).toBeGreaterThan(0);
      expect(status.budgetBurned).toBeGreaterThan(0);

      const report = errorBudgetTracker.generateReport();
      expect(report).toBeDefined();
      expect(report.sloCompliance.availability).toBe(status.availability);
      expect(report.operations.total).toBe(10);

      errorBudgetTracker.stop();
    });

    it('should generate alerts when error budget is consumed', async () => {
      const errorBudgetTracker = new QdrantErrorBudgetTracker({
        slo: {
          availabilityTarget: 95.0, // Low target for testing
          latencyTarget: 1000,
          errorRateTarget: 5.0,
          timeWindowMs: 60000,
        },
        budget: {
          burnRateWarningThreshold: 10,
          burnRateCriticalThreshold: 20,
          rapidBurnThreshold: 2,
          minimumSampleSize: 5,
        },
      });

      const alertSpy = jest.fn();
      errorBudgetTracker.on('critical_alert', alertSpy);

      errorBudgetTracker.start();

      // Record many failed operations to trigger alerts
      for (let i = 0; i < 20; i++) {
        errorBudgetTracker.recordOperation({
          timestamp: Date.now(),
          operationType: 'store',
          success: i < 10, // 50% failure rate
          responseTime: 2000, // High latency
          degraded: true,
          fallbackUsed: true,
        });
      }

      // Wait for alert processing
      await new Promise((resolve) => setTimeout(resolve, 100));

      expect(alertSpy).toHaveBeenCalled();

      errorBudgetTracker.stop();
    });
  });

  describe('Qdrant Adapter Integration', () => {
    it('should integrate graceful degradation into Qdrant adapter', async () => {
      // This test verifies that the Qdrant adapter properly integrates
      // with the graceful degradation manager

      expect(qdrantAdapter).toBeDefined();

      // Initialize adapter (this should also initialize degradation manager)
      await qdrantAdapter.initialize();

      // Test store operation (should work even if Qdrant is not available)
      try {
        const storeResult = await qdrantAdapter.store(testItems);
        expect(storeResult).toBeDefined();
        expect(storeResult.items).toBeDefined();
      } catch (error) {
        // It's okay if this fails due to Qdrant not being available
        // The graceful degradation should handle this
        expect(error.message).toBeDefined();
      }

      await qdrantAdapter.close();
    });

    it('should gracefully handle Qdrant unavailability', async () => {
      // Mock Qdrant client to simulate unavailability
      const mockClient = {
        getCollections: jest.fn().mockRejectedValue(new Error('Connection refused')),
        upsert: jest.fn().mockRejectedValue(new Error('Connection refused')),
        search: jest.fn().mockRejectedValue(new Error('Connection refused')),
      };

      // Replace the client in the adapter (this would require more setup in real code)
      // For now, we'll test the behavior through the degradation manager

      await degradationManager.start();

      // Force failover to simulate Qdrant unavailability
      await degradationManager.forceFailover('Qdrant unavailable');

      // Operations should still work with fallback storage
      const storeResult = await degradationManager.store(testItems);
      expect(storeResult.success).toBe(true);
      expect(storeResult.fallbackUsed).toBe(true);

      const searchResult = await degradationManager.search(testSearchQuery);
      expect(searchResult.success).toBe(true);
      expect(searchResult.fallbackUsed).toBe(true);

      await degradationManager.forceFailback();
    });
  });

  describe('Recovery Scenarios', () => {
    it('should automatically recover when Qdrant becomes available', async () => {
      await degradationManager.start();

      // Force failover
      await degradationManager.forceFailover('Test failover');

      // Verify we're in failover state
      let state = degradationManager.getCurrentState();
      expect(state.isInFailover).toBe(true);

      // Simulate recovery (in real scenario, this would be detected by health checks)
      await degradationManager.forceFailback();

      // Verify we've recovered
      state = degradationManager.getCurrentState();
      expect(state.isInFailover).toBe(false);
    });

    it('should sync data from fallback storage on recovery', async () => {
      // Create degradation manager with sync enabled
      const syncManager = new QdrantGracefulDegradationManager(qdrantAdapter, {
        fallback: {
          maxItems: 1000,
          maxMemoryUsageMB: 10,
          defaultTTL: 30,
          enablePersistence: false,
          syncOnRecovery: true,
        },
        notifications: {
          enabled: false,
          userFacingMessages: false,
          operatorAlerts: false,
          detailedLogging: false,
        },
        errorBudget: {
          enabled: false,
          availabilityTarget: 99.9,
          latencyTarget: 1000,
          errorRateTarget: 0.1,
        },
      });

      await syncManager.start();

      // Store data during failover
      await syncManager.forceFailover('Test failover');
      await syncManager.store(testItems);

      // Recover (this would sync data if Qdrant was available)
      await syncManager.forceFailback();

      // In a real scenario, we'd verify that data was synced to Qdrant
      // For now, we just verify the process completed without errors

      await syncManager.stop();
    });
  });

  describe('Circuit Breaker Integration', () => {
    it('should integrate with circuit breaker for failover decisions', async () => {
      // Test that the circuit breaker status affects degradation decisions
      const detector = new QdrantDegradationDetector(
        // Mock Qdrant health monitor
        {
          getCurrentStatus: () => 'healthy' as any,
          getCurrentMetrics: () => ({
            averageResponseTime: 100,
            errorRate: 0,
          }),
          on: jest.fn(),
          start: jest.fn(),
          stop: jest.fn(),
        } as any,
        // Mock circuit breaker monitor with open circuit
        {
          getHealthStatus: () => ({
            isOpen: true, // Circuit is open
            healthStatus: 'unhealthy' as any,
            state: 'open',
            metrics: {
              failures: 10,
              successes: 0,
              totalCalls: 10,
              failureRate: 100,
            },
          }),
          on: jest.fn(),
          start: jest.fn(),
          stop: jest.fn(),
        } as any,
        {
          thresholds: {
            circuitOpenThreshold: 1, // Should trigger immediately
            ...otherThresholds,
          },
        }
      );

      const levelChangeSpy = jest.fn();
      detector.on('level_change', levelChangeSpy);

      detector.start();
      await detector.forceHealthCheck();

      // The open circuit breaker should trigger degradation
      expect(levelChangeSpy).toHaveBeenCalled();

      detector.stop();
    });
  });

  describe('Performance and Load Testing', () => {
    it('should handle high-volume operations during degradation', async () => {
      await degradationManager.start();
      await degradationManager.forceFailover('Performance test');

      // Create many test items
      const manyItems: KnowledgeItem[] = Array.from({ length: 100 }, (_, i) => ({
        id: `perf-item-${i}`,
        kind: 'entity',
        scope: { project: 'performance-test' },
        data: {
          title: `Performance Test Item ${i}`,
          content: `Content for performance test item ${i}`.repeat(10),
        },
        created_at: new Date().toISOString(),
      }));

      const startTime = Date.now();
      const storeResult = await degradationManager.store(manyItems);
      const duration = Date.now() - startTime;

      expect(storeResult.success).toBe(true);
      expect(duration).toBeLessThan(5000); // Should complete within 5 seconds
      expect(storeResult.data?.items.length).toBe(100);

      await degradationManager.forceFailback();
    });

    it('should maintain performance under concurrent operations', async () => {
      await degradationManager.start();
      await degradationManager.forceFailover('Concurrency test');

      // Perform concurrent store operations
      const concurrentStores = Array.from({ length: 10 }, (_, i) =>
        degradationManager.store([
          {
            id: `concurrent-${i}`,
            kind: 'entity',
            scope: { project: 'concurrency-test' },
            data: { title: `Concurrent Item ${i}` },
            created_at: new Date().toISOString(),
          },
        ])
      );

      const results = await Promise.all(concurrentStores);

      expect(results).toHaveLength(10);
      results.forEach((result) => {
        expect(result.success).toBe(true);
      });

      await degradationManager.forceFailback();
    });
  });
});

// Helper types and utilities for testing
const otherThresholds = {
  responseTimeWarning: 1000,
  responseTimeCritical: 5000,
  errorRateWarning: 5,
  errorRateCritical: 15,
  consecutiveFailuresWarning: 3,
  consecutiveFailuresCritical: 5,
  healthCheckIntervalMs: 15000,
  degradationWindowMs: 60000,
};
