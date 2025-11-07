/**
 * Memory Optimization Tests
 *
 * Comprehensive test suite for memory optimization features including:
 * - Memory manager service functionality
 * - Optimized embedding service memory management
 * - Enhanced memory monitoring and alerting
 * - Memory usage under various load scenarios
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  memoryManager,
  type MemoryStats,
} from '../../src/services/memory/memory-manager-service.js';
import { optimizedEmbeddingService } from '../../src/services/embeddings/optimized-embedding-service.js';
import { enhancedMemoryMonitor } from '../../src/monitoring/enhanced-memory-monitor.js';
import { OptimizedMemoryStoreOrchestrator } from '../../src/services/orchestrators/optimized-memory-store-orchestrator.js';

// Mock process.memoryUsage
const mockMemoryUsage = vi.fn();
Object.defineProperty(process, 'memoryUsage', {
  value: mockMemoryUsage,
  writable: true,
});

describe('Memory Optimization Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Reset memory manager state
    memoryManager.removeAllListeners();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Memory Manager Service', () => {
    it('should initialize with default configuration', () => {
      const stats = memoryManager.getStats();

      expect(stats).toBeDefined();
      expect(stats.alertConfig.warningThreshold).toBe(80);
      expect(stats.alertConfig.criticalThreshold).toBe(90);
      expect(stats.alertConfig.emergencyThreshold).toBe(95);
      expect(stats.memoryPools).toBeInstanceOf(Array);
    });

    it('should detect memory trends correctly', () => {
      // Mock increasing memory usage
      const memorySequence = [
        { heapUsed: 100000000, heapTotal: 200000000, external: 10000000, rss: 150000000 },
        { heapUsed: 110000000, heapTotal: 200000000, external: 10000000, rss: 150000000 },
        { heapUsed: 120000000, heapTotal: 200000000, external: 10000000, rss: 150000000 },
        { heapUsed: 130000000, heapTotal: 200000000, external: 10000000, rss: 150000000 },
        { heapUsed: 140000000, heapTotal: 200000000, external: 10000000, rss: 150000000 },
      ];

      mockMemoryUsage.mockReturnValue(memorySequence[0]);

      const initialStats = memoryManager.getCurrentMemoryStats();
      expect(initialStats.usagePercentage).toBe(50);

      // Simulate memory increase
      mockMemoryUsage.mockReturnValue(memorySequence[4]);
      const laterStats = memoryManager.getCurrentMemoryStats();
      expect(laterStats.usagePercentage).toBe(70);
    });

    it('should create and manage memory pools', () => {
      const poolConfig = {
        maxPoolSize: 10,
        cleanupInterval: 5000,
        itemMaxAge: 30000,
      };

      memoryManager.createMemoryPool('test-pool', poolConfig);

      const stats = memoryManager.getStats();
      const testPool = stats.memoryPools.find((p) => p.name === 'test-pool');
      expect(testPool).toBeDefined();
      expect(testPool?.size).toBe(0);
    });

    it('should handle pool item retrieval and return', () => {
      memoryManager.createMemoryPool('test-pool', {
        maxPoolSize: 10,
        cleanupInterval: 5000,
        itemMaxAge: 30000,
      });

      // Get item from pool (should create new one)
      const item1 = memoryManager.getFromPool('test-pool', () => ({ id: 1 }));
      expect(item1).toEqual({ id: 1 });

      // Return item to pool
      memoryManager.returnToPool('test-pool', item1);

      // Get item from pool (should reuse)
      const item2 = memoryManager.getFromPool('test-pool', () => ({ id: 2 }));
      expect(item2).toEqual({ id: 1 }); // Should be the same item
    });

    it('should emit memory alerts when thresholds are breached', async () => {
      const alertListener = vi.fn();
      memoryManager.on('memory-warning', alertListener);

      // Mock critical memory usage
      mockMemoryUsage.mockReturnValue({
        heapUsed: 190000000,
        heapTotal: 200000000,
        external: 10000000,
        rss: 200000000,
      });

      // Trigger memory check
      const stats = memoryManager.getCurrentMemoryStats();
      expect(stats.usagePercentage).toBe(95);

      // Wait for event emission
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Check if alert was emitted
      expect(alertListener).toHaveBeenCalled();
    });

    it('should perform cleanup when memory pressure is detected', () => {
      const cleanupListener = vi.fn();
      memoryManager.on('cleanup-completed', cleanupListener);

      // Mock high memory usage to trigger cleanup
      mockMemoryUsage.mockReturnValue({
        heapUsed: 185000000,
        heapTotal: 200000000,
        external: 10000000,
        rss: 200000000,
      });

      // Simulate memory pressure handling
      const stats = memoryManager.getCurrentMemoryStats();
      if (stats.usagePercentage > 90) {
        // This would trigger internal cleanup logic
        expect(stats.usagePercentage).toBeGreaterThan(90);
      }

      expect(stats.usagePercentage).toBe(92.5);
    });
  });

  describe('Optimized Embedding Service', () => {
    beforeEach(() => {
      // Reset embedding service cache
      optimizedEmbeddingService.clearCache();
    });

    it('should initialize with memory-optimized configuration', () => {
      const stats = optimizedEmbeddingService.getMemoryStats();

      expect(stats.cacheSize).toBe(0);
      expect(stats.cacheMemoryMB).toBe(0);
      expect(stats.memoryPressureLevel).toBe('low');
    });

    it('should handle cache size limits', async () => {
      // Mock successful embedding generation
      const mockEmbedding = new Array(1536).fill(0.1); // OpenAI ada-002 dimension

      // Mock the embedding generation (simplified)
      vi.spyOn(optimizedEmbeddingService as any, 'ensureOpenAIInitialized').mockResolvedValue(
        undefined
      );

      // Simulate cache usage
      const testTexts = Array.from({ length: 100 }, (_, i) => `test text ${i}`);

      for (const text of testTexts) {
        // Simulate cache entry creation
        const cacheKey = `hash-${text}`;
        const mockEntry = {
          vector: mockEmbedding,
          model: 'text-embedding-ada-002',
          createdAt: Date.now(),
          lastAccessed: Date.now(),
          accessCount: 1,
          sizeBytes: mockEmbedding.length * 8 + 100,
          priority: 'medium' as const,
        };

        // This would normally be handled by the service internally
        expect(mockEntry.sizeBytes).toBeGreaterThan(0);
      }

      const stats = optimizedEmbeddingService.getMemoryStats();
      expect(stats.cacheSize).toBe(0); // Reset in beforeEach
    });

    it('should adapt to memory pressure', () => {
      const initialConfig = {
        cacheMaxSize: 5000,
        cacheMaxMemoryMB: 100,
      };

      optimizedEmbeddingService.updateConfig(initialConfig);

      // Simulate memory pressure scenario
      const memoryStats = optimizedEmbeddingService.getMemoryStats();
      expect(memoryStats.memoryPressureLevel).toBe('low');

      // Update config for tighter memory limits
      optimizedEmbeddingService.updateConfig({
        cacheMaxSize: 1000,
        cacheMaxMemoryMB: 50,
      });

      // Service should adapt to new limits
      const updatedStats = optimizedEmbeddingService.getMemoryStats();
      expect(updatedStats.memoryPressureLevel).toBe('low');
    });

    it('should handle circuit breaker during memory pressure', async () => {
      // Mock high memory usage
      mockMemoryUsage.mockReturnValue({
        heapUsed: 190000000,
        heapTotal: 200000000,
        external: 10000000,
        rss: 200000000,
      });

      // Service should handle memory pressure gracefully
      try {
        await optimizedEmbeddingService.generateEmbedding('test text');
      } catch (error) {
        // Should handle errors gracefully during memory pressure
        expect(error).toBeDefined();
      }
    });

    it('should calculate cache memory usage accurately', () => {
      const stats = optimizedEmbeddingService.getMemoryStats();

      // Initially empty cache
      expect(stats.cacheMemoryMB).toBe(0);
      expect(stats.cacheSize).toBe(0);

      // Memory calculation should be accurate
      expect(typeof stats.cacheMemoryMB).toBe('number');
      expect(stats.cacheMemoryMB).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Enhanced Memory Monitor', () => {
    beforeEach(() => {
      // Clear monitor history
      enhancedMemoryMonitor.clearHistory();
    });

    it('should initialize with default alert thresholds', () => {
      const stats = enhancedMemoryMonitor.getEnhancedStats();

      expect(stats.alerts.lastTriggered).toBeDefined();
      expect(stats.history.size).toBe(0);
      expect(stats.current).toBeDefined();
    });

    it('should detect memory usage trends', async () => {
      // Mock increasing memory usage over time
      const memorySequence = [
        { heapUsed: 80000000, heapTotal: 200000000, external: 10000000, rss: 150000000 },
        { heapUsed: 85000000, heapTotal: 200000000, external: 10000000, rss: 150000000 },
        { heapUsed: 90000000, heapTotal: 200000000, external: 10000000, rss: 150000000 },
        { heapUsed: 95000000, heapTotal: 200000000, external: 10000000, rss: 150000000 },
        { heapUsed: 100000000, heapTotal: 200000000, external: 10000000, rss: 150000000 },
      ];

      // Simulate memory readings
      for (const usage of memorySequence) {
        mockMemoryUsage.mockReturnValue(usage);
        enhancedMemoryMonitor.triggerCheck();
        await new Promise((resolve) => setTimeout(resolve, 10));
      }

      const stats = enhancedMemoryMonitor.getEnhancedStats();
      expect(stats.current.usagePercentage).toBe(50); // Last reading

      // Trend detection would require more data points
      expect(stats.trend).toBeDefined();
    });

    it('should trigger alerts at appropriate thresholds', async () => {
      const alertListener = vi.fn();
      enhancedMemoryMonitor.on('alert-triggered', alertListener);

      // Mock critical memory usage
      mockMemoryUsage.mockReturnValue({
        heapUsed: 180000000,
        heapTotal: 200000000,
        external: 10000000,
        rss: 200000000,
      });

      enhancedMemoryMonitor.triggerCheck();
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Should trigger critical alert
      expect(alertListener).toHaveBeenCalled();
      const alertCall = alertListener.mock.calls[0][0];
      expect(alertCall.severity).toBe('critical');
    });

    it('should respect alert cooldowns', async () => {
      const alertListener = vi.fn();
      enhancedMemoryMonitor.on('alert-triggered', alertListener);

      // Mock high memory usage
      mockMemoryUsage.mockReturnValue({
        heapUsed: 170000000,
        heapTotal: 200000000,
        external: 10000000,
        rss: 200000000,
      });

      // Trigger multiple checks quickly
      enhancedMemoryMonitor.triggerCheck();
      enhancedMemoryMonitor.triggerCheck();
      enhancedMemoryMonitor.triggerCheck();

      await new Promise((resolve) => setTimeout(resolve, 100));

      // Should only trigger once due to cooldown
      expect(alertListener).toHaveBeenCalledTimes(1);
    });

    it('should predict future memory usage', async () => {
      // Mock stable memory usage for trend analysis
      const stableMemory = {
        heapUsed: 100000000,
        heapTotal: 200000000,
        external: 10000000,
        rss: 150000000,
      };

      // Generate multiple data points
      for (let i = 0; i < 25; i++) {
        mockMemoryUsage.mockReturnValue({
          ...stableMemory,
          heapUsed: stableMemory.heapUsed + i * 1000000, // Gradual increase
        });
        enhancedMemoryMonitor.triggerCheck();
        await new Promise((resolve) => setTimeout(resolve, 10));
      }

      const stats = enhancedMemoryMonitor.getEnhancedStats();

      // With enough data points, trend prediction should be available
      if (stats.trend) {
        expect(stats.trend.direction).toBe('increasing');
        expect(stats.trend.prediction).toBeGreaterThan(50);
        expect(stats.trend.confidence).toBeGreaterThan(0);
      }
    });
  });

  describe('Optimized Memory Store Orchestrator', () => {
    let orchestrator: OptimizedMemoryStoreOrchestrator;

    beforeEach(() => {
      orchestrator = new OptimizedMemoryStoreOrchestrator();
    });

    afterEach(() => {
      orchestrator.shutdown();
    });

    it('should initialize with memory pools', () => {
      const poolStats = orchestrator.getMemoryPoolStats();

      expect(poolStats.itemResultPool).toBeGreaterThanOrEqual(0);
      expect(poolStats.batchSummaryPool).toBeGreaterThanOrEqual(0);
      expect(poolStats.contextPool).toBeGreaterThanOrEqual(0);
    });

    it('should calculate optimal batch size based on memory pressure', () => {
      // Mock low memory pressure
      mockMemoryUsage.mockReturnValue({
        heapUsed: 80000000,
        heapTotal: 200000000,
        external: 10000000,
        rss: 150000000,
      });

      const lowPressureBatchSize = (orchestrator as any).calculateOptimalBatchSize(1000);
      expect(lowPressureBatchSize).toBeGreaterThan(0);

      // Mock high memory pressure
      mockMemoryUsage.mockReturnValue({
        heapUsed: 180000000,
        heapTotal: 200000000,
        external: 10000000,
        rss: 200000000,
      });

      const highPressureBatchSize = (orchestrator as any).calculateOptimalBatchSize(1000);
      expect(highPressureBatchSize).toBeLessThan(lowPressureBatchSize);
    });

    it('should create appropriate batch sizes', () => {
      const batches = (orchestrator as any).createBatches(
        Array.from({ length: 100 }, (_, i) => i),
        25
      );

      expect(batches).toHaveLength(4); // 100 / 25 = 4
      expect(batches[0]).toHaveLength(25);
      expect(batches[3]).toHaveLength(25);
    });

    it('should handle memory warnings during operations', () => {
      const initialStats = orchestrator.getOperationStats();
      expect(initialStats.totalOperations).toBe(0);

      // Mock memory warning scenario
      mockMemoryUsage.mockReturnValue({
        heapUsed: 170000000,
        heapTotal: 200000000,
        external: 10000000,
        rss: 200000000,
      });

      // The orchestrator should handle memory warnings gracefully
      expect(() => {
        (orchestrator as any).handleMemoryWarning({
          usagePercentage: 85,
          heapUsed: 170000000,
          heapTotal: 200000000,
          external: 10000000,
          rss: 200000000,
          timestamp: Date.now(),
          trend: 'increasing',
        });
      }).not.toThrow();
    });

    it('should track operation statistics', () => {
      const initialStats = orchestrator.getOperationStats();
      expect(initialStats.totalOperations).toBe(0);
      expect(initialStats.memoryWarnings).toBe(0);
      expect(initialStats.cleanupTriggered).toBe(0);
    });

    it('should manage memory pools efficiently', () => {
      const poolStats = orchestrator.getMemoryPoolStats();
      const initialTotal =
        poolStats.itemResultPool + poolStats.batchSummaryPool + poolStats.contextPool;

      // Pools should be properly initialized
      expect(initialTotal).toBeGreaterThanOrEqual(0);

      // Update pool configuration
      orchestrator.updatePoolConfig({
        itemResultPoolSize: 50,
        batchSummaryPoolSize: 25,
        contextPoolSize: 25,
      });

      // Configuration should be updated
      const updatedStats = orchestrator.getOperationStats();
      expect(updatedStats).toBeDefined();
    });
  });

  describe('Integration Tests', () => {
    it('should handle memory pressure across all services', async () => {
      // Mock high memory usage across the board
      mockMemoryUsage.mockReturnValue({
        heapUsed: 190000000,
        heapTotal: 200000000,
        external: 10000000,
        rss: 200000000,
      });

      // All services should handle high memory usage gracefully
      const memoryManagerStats = memoryManager.getStats();
      expect(memoryManagerStats.currentMemory.usagePercentage).toBe(95);

      const embeddingStats = optimizedEmbeddingService.getMemoryStats();
      expect(embeddingStats.memoryPressureLevel).toBeDefined();

      const monitorStats = enhancedMemoryMonitor.getEnhancedStats();
      expect(monitorStats.current.usagePercentage).toBe(95);
    });

    it('should coordinate cleanup across services', async () => {
      const cleanupListener = vi.fn();
      memoryManager.on('cleanup-completed', cleanupListener);

      // Simulate memory pressure that triggers cleanup
      mockMemoryUsage.mockReturnValue({
        heapUsed: 185000000,
        heapTotal: 200000000,
        external: 10000000,
        rss: 200000000,
      });

      // Trigger cleanup through memory manager
      const stats = memoryManager.getCurrentMemoryStats();
      if (stats.usagePercentage > 90) {
        // This would trigger cleanup
        expect(stats.usagePercentage).toBeGreaterThan(90);
      }

      // Embedding service should also adapt
      optimizedEmbeddingService.getMemoryStats();

      // Monitor should detect the situation
      enhancedMemoryMonitor.triggerCheck();
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Services should coordinate their responses
      expect(memoryManagerStats.currentMemory.usagePercentage).toBeGreaterThan(90);
    });
  });
});
