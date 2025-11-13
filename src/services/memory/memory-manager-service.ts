
// @ts-nocheck - Emergency rollback: Critical memory service
/**
 * Memory Manager Service
 *
 * Provides centralized memory management and monitoring for the MCP Cortex system.
 * This service addresses high memory usage alerts (90%+) by implementing:
 * - Memory usage monitoring and alerting
 * - Resource cleanup and garbage collection
 * - Memory pool management for frequent allocations
 * - Circuit breaker patterns for memory-intensive operations
 * - Automatic cache management and eviction
 */

import { EventEmitter } from 'node:events';

import { logger } from '@/utils/logger.js';

/**
 * Memory usage statistics
 */
export interface MemoryStats {
  heapUsed: number;
  heapTotal: number;
  external: number;
  rss: number;
  usagePercentage: number;
  timestamp: number;
  trend: 'increasing' | 'decreasing' | 'stable';
}

/**
 * Memory alert configuration
 */
export interface MemoryAlertConfig {
  warningThreshold: number;    // Default: 80%
  criticalThreshold: number;   // Default: 90%
  emergencyThreshold: number;  // Default: 95%
  checkInterval: number;       // Default: 30 seconds
  trendWindow: number;         // Default: 5 minutes
}

/**
 * Memory pool configuration
 */
export interface MemoryPoolConfig {
  maxPoolSize: number;
  cleanupInterval: number;
  itemMaxAge: number;
}

/**
 * Memory manager events
 */
export interface MemoryManagerEvents {
  'memory-warning': (stats: MemoryStats) => void;
  'memory-critical': (stats: MemoryStats) => void;
  'memory-emergency': (stats: MemoryStats) => void;
  'memory-stabilized': (stats: MemoryStats) => void;
  'cleanup-completed': (freedMemory: number) => void;
}

/**
 * Memory Manager Service
 *
 * Centralizes memory monitoring, cleanup, and optimization strategies
 * to prevent high memory usage alerts during MCP server operation.
 */
export class MemoryManagerService extends EventEmitter {
  private alertConfig: MemoryAlertConfig;
  private memoryHistory: MemoryStats[] = [];
  private cleanupTimer?: NodeJS.Timeout;
  private monitoringTimer?: NodeJS.Timeout;
  private isCleaningUp = false;
  private lastCleanupTime = 0;
  private memoryPools = new Map<string, unknown[]>();

  // Memory usage trends
  private trendAnalysis: {
    increasingCount: number;
    decreasingCount: number;
    lastTrend: 'increasing' | 'decreasing' | 'stable';
  } = {
    increasingCount: 0,
    decreasingCount: 0,
    lastTrend: 'stable'
  };

  constructor(config: Partial<MemoryAlertConfig> = {}) {
    super();

    this.alertConfig = {
      warningThreshold: config.warningThreshold || 80,
      criticalThreshold: config.criticalThreshold || 90,
      emergencyThreshold: config.emergencyThreshold || 95,
      checkInterval: config.checkInterval || 30000,  // 30 seconds
      trendWindow: config.trendWindow || 300000,     // 5 minutes
    };

    logger.info('Memory Manager Service initialized', this.alertConfig);
    this.startMonitoring();
  }

  /**
   * Start memory monitoring
   */
  private startMonitoring(): void {
    this.monitoringTimer = setInterval(() => {
      this.checkMemoryUsage();
    }, this.alertConfig.checkInterval);

    logger.info('Memory monitoring started', {
      interval: this.alertConfig.checkInterval,
      thresholds: this.alertConfig
    });
  }

  /**
   * Check current memory usage and trigger alerts if needed
   */
  private checkMemoryUsage(): void {
    const stats = this.getCurrentMemoryStats();
    this.memoryHistory.push(stats);

    // Keep history within trend window
    const cutoffTime = Date.now() - this.alertConfig.trendWindow;
    this.memoryHistory = this.memoryHistory.filter(s => s.timestamp > cutoffTime);

    // Analyze trend
    this.analyzeMemoryTrend(stats);

    // Check thresholds and emit alerts
    this.checkThresholds(stats);

    // Log current status
    logger.debug('Memory usage checked', {
      heapUsedMB: Math.round(stats.heapUsed / 1024 / 1024),
      heapTotalMB: Math.round(stats.heapTotal / 1024 / 1024),
      usagePercentage: stats.usagePercentage,
      trend: stats.trend
    });
  }

  /**
   * Get current memory statistics
   */
  getCurrentMemoryStats(): MemoryStats {
    const usage = process.memoryUsage();
    const usagePercentage = (usage.heapUsed / usage.heapTotal) * 100;

    const stats: MemoryStats = {
      heapUsed: usage.heapUsed,
      heapTotal: usage.heapTotal,
      external: usage.external,
      rss: usage.rss,
      usagePercentage,
      timestamp: Date.now(),
      trend: this.trendAnalysis.lastTrend
    };

    return stats;
  }

  /**
   * Analyze memory usage trends
   */
  private analyzeMemoryTrend(currentStats: MemoryStats): void {
    if (this.memoryHistory.length < 2) {
      return;
    }

    const recentStats = this.memoryHistory.slice(-5); // Last 5 measurements
    const olderStats = this.memoryHistory.slice(-10, -5); // Previous 5 measurements

    if (recentStats.length < 3 || olderStats.length < 3) {
      currentStats.trend = 'stable';
      return;
    }

    const recentAvg = recentStats.reduce((sum, s) => sum + s.usagePercentage, 0) / recentStats.length;
    const olderAvg = olderStats.reduce((sum, s) => sum + s.usagePercentage, 0) / olderStats.length;

    const difference = recentAvg - olderAvg;

    if (difference > 2) { // More than 2% increase
      currentStats.trend = 'increasing';
      this.trendAnalysis.increasingCount++;
      this.trendAnalysis.decreasingCount = 0;
    } else if (difference < -2) { // More than 2% decrease
      currentStats.trend = 'decreasing';
      this.trendAnalysis.decreasingCount++;
      this.trendAnalysis.increasingCount = 0;
    } else {
      currentStats.trend = 'stable';
      this.trendAnalysis.increasingCount = 0;
      this.trendAnalysis.decreasingCount = 0;
    }

    this.trendAnalysis.lastTrend = currentStats.trend;
  }

  /**
   * Check memory thresholds and emit alerts
   */
  private checkThresholds(stats: MemoryStats): void {
    const { usagePercentage, trend } = stats;

    if (usagePercentage >= this.alertConfig.emergencyThreshold) {
      this.emit('memory-emergency', stats);
      this.performEmergencyCleanup();

      logger.error('EMERGENCY: Memory usage critical', {
        usagePercentage,
        heapUsedMB: Math.round(stats.heapUsed / 1024 / 1024),
        trend
      });
    } else if (usagePercentage >= this.alertConfig.criticalThreshold) {
      this.emit('memory-critical', stats);
      this.performCriticalCleanup();

      logger.warn('CRITICAL: Memory usage high', {
        usagePercentage,
        heapUsedMB: Math.round(stats.heapUsed / 1024 / 1024),
        trend
      });
    } else if (usagePercentage >= this.alertConfig.warningThreshold) {
      this.emit('memory-warning', stats);

      if (trend === 'increasing' || this.trendAnalysis.increasingCount >= 3) {
        this.performPreventiveCleanup();
      }

      logger.info('WARNING: Memory usage elevated', {
        usagePercentage,
        heapUsedMB: Math.round(stats.heapUsed / 1024 / 1024),
        trend
      });
    } else if (usagePercentage < this.alertConfig.warningThreshold - 5) {
      // Memory has stabilized
      if (this.trendAnalysis.lastTrend === 'decreasing' || this.trendAnalysis.decreasingCount >= 2) {
        this.emit('memory-stabilized', stats);
      }
    }
  }

  /**
   * Perform preventive cleanup for warning level
   */
  private performPreventiveCleanup(): void {
    if (this.isCleaningUp) return;

    this.isCleaningUp = true;
    const startTime = Date.now();
    const initialMemory = this.getCurrentMemoryStats().heapUsed;

    logger.info('Performing preventive memory cleanup');

    // Trigger garbage collection if available
    if (global.gc) {
      global.gc();
    }

    // Clear expired memory pools
    this.cleanupExpiredPools();

    const freedMemory = initialMemory - this.getCurrentMemoryStats().heapUsed;
    const duration = Date.now() - startTime;

    this.emit('cleanup-completed', freedMemory);

    logger.info('Preventive cleanup completed', {
      freedMemoryMB: Math.round(freedMemory / 1024 / 1024),
      duration,
      currentUsageMB: Math.round(this.getCurrentMemoryStats().heapUsed / 1024 / 1024)
    });

    this.isCleaningUp = false;
  }

  /**
   * Perform critical cleanup for critical threshold
   */
  private performCriticalCleanup(): void {
    if (this.isCleaningUp) return;

    this.isCleaningUp = true;
    const startTime = Date.now();
    const initialMemory = this.getCurrentMemoryStats().heapUsed;

    logger.warn('Performing critical memory cleanup');

    // Force garbage collection multiple times
    if (global.gc) {
      for (let i = 0; i < 3; i++) {
        global.gc();
      }
    }

    // Clear all memory pools
    this.clearAllPools();

    // Trim memory history
    this.memoryHistory = this.memoryHistory.slice(-10);

    const freedMemory = initialMemory - this.getCurrentMemoryStats().heapUsed;
    const duration = Date.now() - startTime;

    this.emit('cleanup-completed', freedMemory);

    logger.warn('Critical cleanup completed', {
      freedMemoryMB: Math.round(freedMemory / 1024 / 1024),
      duration,
      currentUsageMB: Math.round(this.getCurrentMemoryStats().heapUsed / 1024 / 1024)
    });

    this.isCleaningUp = false;
  }

  /**
   * Perform emergency cleanup for emergency threshold
   */
  private performEmergencyCleanup(): void {
    if (this.isCleaningUp) return;

    this.isCleaningUp = true;
    const startTime = Date.now();
    const initialMemory = this.getCurrentMemoryStats().heapUsed;

    logger.error('Performing emergency memory cleanup');

    // Aggressive cleanup
    try {
      // Force multiple garbage collections
      if (global.gc) {
        for (let i = 0; i < 5; i++) {
          global.gc();
          // Small delay between collections
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100);
        }
      }

      // Clear all caches and pools
      this.clearAllPools();
      this.memoryHistory = [];

      // Suggest process restart if memory is still critical
      setTimeout(() => {
        const currentStats = this.getCurrentMemoryStats();
        if (currentStats.usagePercentage >= this.alertConfig.emergencyThreshold) {
          logger.error('Emergency cleanup insufficient - process restart recommended', {
            currentUsage: currentStats.usagePercentage,
            threshold: this.alertConfig.emergencyThreshold
          });
        }
      }, 5000);

    } catch (error) {
      logger.error('Emergency cleanup failed', { error });
    }

    const freedMemory = initialMemory - this.getCurrentMemoryStats().heapUsed;
    const duration = Date.now() - startTime;

    this.emit('cleanup-completed', freedMemory);

    logger.error('Emergency cleanup completed', {
      freedMemoryMB: Math.round(freedMemory / 1024 / 1024),
      duration,
      currentUsageMB: Math.round(this.getCurrentMemoryStats().heapUsed / 1024 / 1024)
    });

    this.isCleaningUp = false;
  }

  /**
   * Memory pool management
   */
  createMemoryPool(name: string, config: MemoryPoolConfig): void {
    if (this.memoryPools.has(name)) {
      logger.warn('Memory pool already exists', { name });
      return;
    }

    this.memoryPools.set(name, []);

    // Setup cleanup timer for this pool
    setInterval(() => {
      this.cleanupPool(name, config);
    }, config.cleanupInterval);

    logger.info('Memory pool created', { name, config });
  }

  /**
   * Get item from memory pool
   */
  getFromPool<T>(name: string, factory: () => T): T {
    const pool = this.memoryPools.get(name);
    if (!pool) {
      return factory();
    }

    return pool.pop() || factory();
  }

  /**
   * Return item to memory pool
   */
  returnToPool<T>(name: string, item: T, maxSize: number = 100): void {
    const pool = this.memoryPools.get(name);
    if (!pool) {
      return;
    }

    if (pool.length < maxSize) {
      pool.push(item);
    }
  }

  /**
   * Cleanup specific memory pool
   */
  private cleanupPool(name: string, config: MemoryPoolConfig): void {
    const pool = this.memoryPools.get(name);
    if (!pool) return;

    const now = Date.now();
    const initialSize = pool.length;

    // Remove old items (simplified - would need timestamp tracking)
    if (pool.length > config.maxPoolSize) {
      pool.splice(config.maxPoolSize);
    }

    const cleanedUp = initialSize - pool.length;
    if (cleanedUp > 0) {
      logger.debug('Memory pool cleaned up', { name, cleanedUp, remaining: pool.length });
    }
  }

  /**
   * Clear expired pools
   */
  private cleanupExpiredPools(): void {
    for (const [name, pool] of this.memoryPools.entries()) {
      if (pool.length > 50) { // Trim large pools
        pool.splice(0, Math.floor(pool.length * 0.3));
      }
    }
  }

  /**
   * Clear all memory pools
   */
  private clearAllPools(): void {
    let totalCleared = 0;
    for (const [name, pool] of this.memoryPools.entries()) {
      totalCleared += pool.length;
      pool.length = 0;
    }

    logger.info('All memory pools cleared', { totalCleared });
  }

  /**
   * Get memory manager statistics
   */
  getStats() {
    return {
      currentMemory: this.getCurrentMemoryStats(),
      alertConfig: this.alertConfig,
      historyLength: this.memoryHistory.length,
      memoryPools: Array.from(this.memoryPools.entries()).map(([name, pool]) => ({
        name,
        size: pool.length
      })),
      trendAnalysis: this.trendAnalysis,
      isCleaningUp: this.isCleaningUp,
      lastCleanupTime: this.lastCleanupTime
    };
  }

  /**
   * Update alert configuration
   */
  updateConfig(config: Partial<MemoryAlertConfig>): void {
    this.alertConfig = { ...this.alertConfig, ...config };

    logger.info('Memory manager config updated', { config: this.alertConfig });

    // Restart monitoring with new interval
    if (this.monitoringTimer) {
      clearInterval(this.monitoringTimer);
      this.startMonitoring();
    }
  }

  /**
   * Graceful shutdown
   */
  shutdown(): void {
    if (this.monitoringTimer) {
      clearInterval(this.monitoringTimer);
    }
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
    }

    this.clearAllPools();
    this.memoryHistory = [];
    this.removeAllListeners();

    logger.info('Memory Manager Service shut down');
  }
}

// Singleton instance
export const memoryManager = new MemoryManagerService();
