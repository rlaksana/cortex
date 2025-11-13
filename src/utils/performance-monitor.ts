/**
 * Performance Monitor Utility
 *
 * Provides comprehensive performance monitoring and observability for Cortex MCP operations.
 * Tracks execution times, resource usage, and performance bottlenecks with real-time alerts.
 *
 * Features:
 * - Operation timing with automatic metadata collection
 * - Resource usage monitoring (memory, CPU)
 * - Performance anomaly detection
 * - Real-time alerts and thresholds
 * - Historical performance trends
 */

import { logger } from '@/utils/logger.js';

export interface PerformanceMetric {
  operation: string;
  startTime: number;
  endTime?: number;
  duration?: number;
  metadata: Record<string, unknown>;
  status: 'running' | 'completed' | 'failed';
  error?: Error;
}

export interface PerformanceThreshold {
  operation: string;
  maxDuration: number;
  alertThreshold: number;
  criticalThreshold: number;
}

export interface ResourceUsage {
  timestamp: number;
  memoryUsage: {
    used: number;
    total: number;
    percentage: number;
  };
  cpuUsage: number;
  activeOperations: number;
}

export class PerformanceMonitor {
  private static instance: PerformanceMonitor;
  private activeOperations = new Map<string, PerformanceMetric>();
  private completedOperations: PerformanceMetric[] = [];
  private thresholds = new Map<string, PerformanceThreshold>();
  private resourceHistory: ResourceUsage[] = [];
  private monitoringInterval?: NodeJS.Timeout;

  private constructor() {
    this.setupDefaultThresholds();
  }

  static getInstance(): PerformanceMonitor {
    if (!PerformanceMonitor.instance) {
      PerformanceMonitor.instance = new PerformanceMonitor();
    }
    return PerformanceMonitor.instance;
  }

  /**
   * Start monitoring an operation
   */
  startOperation(operation: string, metadata: Record<string, unknown> = {}): string {
    const id = this.generateOperationId(operation);
    const metric: PerformanceMetric = {
      operation,
      startTime: Date.now(),
      metadata,
      status: 'running',
    };

    this.activeOperations.set(id, metric);

    logger.debug(`Started monitoring operation: ${operation}`, {
      id,
      metadata,
    });

    return id;
  }

  /**
   * Complete an operation with optional error
   */
  completeOperation(id: string, error?: Error): PerformanceMetric | null {
    const metric = this.activeOperations.get(id);
    if (!metric) {
      logger.warn(`Attempted to complete unknown operation: ${id}`);
      return null;
    }

    metric.endTime = Date.now();
    metric.duration = metric.endTime - metric.startTime;
    metric.status = error ? 'failed' : 'completed';
    if (error) {
      metric.error = error;
    }

    this.activeOperations.delete(id);
    this.completedOperations.push(metric);

    // Check performance thresholds
    this.checkThresholds(metric);

    // Trim history to prevent memory leaks
    if (this.completedOperations.length > 1000) {
      this.completedOperations = this.completedOperations.slice(-800);
    }

    logger.debug(`Completed operation: ${metric.operation}`, {
      id,
      duration: metric.duration,
      status: metric.status,
    });

    return metric;
  }

  /**
   * Get current performance metrics
   */
  getCurrentMetrics(): {
    active: PerformanceMetric[];
    recent: PerformanceMetric[];
    summary: {
      totalOperations: number;
      averageDuration: number;
      successRate: number;
      activeCount: number;
    };
  } {
    const recent = this.completedOperations.slice(-50);
    const successful = recent.filter((m) => m.status === 'completed' && m.duration);

    return {
      active: Array.from(this.activeOperations.values()),
      recent,
      summary: {
        totalOperations: this.completedOperations.length,
        averageDuration:
          successful.length > 0
            ? successful.reduce((sum, m) => sum + (m.duration || 0), 0) / successful.length
            : 0,
        successRate:
          recent.length > 0
            ? (recent.filter((m) => m.status === 'completed').length / recent.length) * 100
            : 100,
        activeCount: this.activeOperations.size,
      },
    };
  }

  /**
   * Start continuous resource monitoring
   */
  startResourceMonitoring(intervalMs: number = 5000): void {
    if (this.monitoringInterval) {
      return;
    }

    this.monitoringInterval = setInterval(() => {
      this.collectResourceMetrics();
    }, intervalMs);

    logger.info('Started resource monitoring');
  }

  /**
   * Stop resource monitoring
   */
  stopResourceMonitoring(): void {
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
      this.monitoringInterval = undefined;
      logger.info('Stopped resource monitoring');
    }
  }

  /**
   * Get resource usage history
   */
  getResourceHistory(limit: number = 100): ResourceUsage[] {
    return this.resourceHistory.slice(-limit);
  }

  /**
   * Set custom performance threshold
   */
  setThreshold(threshold: PerformanceThreshold): void {
    this.thresholds.set(threshold.operation, threshold);
    logger.debug(`Set threshold for ${threshold.operation}`, threshold);
  }

  /**
   * Get operations by time range
   */
  getOperationsByTimeRange(startTime: number, endTime: number): PerformanceMetric[] {
    return this.completedOperations.filter(
      (metric) => metric.startTime >= startTime && metric.startTime <= endTime
    );
  }

  /**
   * Get operations by type
   */
  getOperationsByType(operation: string): PerformanceMetric[] {
    return this.completedOperations.filter((metric) => metric.operation === operation);
  }

  /**
   * Generate performance report
   */
  generateReport(): {
    summary: unknown;
    operations: PerformanceMetric[];
    resources: ResourceUsage[];
    alerts: unknown[];
  } {
    const metrics = this.getCurrentMetrics();
    const alerts = this.generateAlerts();

    return {
      summary: metrics.summary,
      operations: metrics.recent,
      resources: this.getResourceHistory(50),
      alerts,
    };
  }

  private setupDefaultThresholds(): void {
    const defaults: PerformanceThreshold[] = [
      {
        operation: 'memory_store',
        maxDuration: 5000,
        alertThreshold: 3000,
        criticalThreshold: 5000,
      },
      {
        operation: 'memory_find',
        maxDuration: 2000,
        alertThreshold: 1000,
        criticalThreshold: 2000,
      },
      {
        operation: 'system_status',
        maxDuration: 1000,
        alertThreshold: 500,
        criticalThreshold: 1000,
      },
      {
        operation: 'database_operation',
        maxDuration: 3000,
        alertThreshold: 2000,
        criticalThreshold: 3000,
      },
    ];

    defaults.forEach((threshold) => this.setThreshold(threshold));
  }

  private collectResourceMetrics(): void {
    try {
      const usage = process.memoryUsage();
      const resourceUsage: ResourceUsage = {
        timestamp: Date.now(),
        memoryUsage: {
          used: usage.heapUsed,
          total: usage.heapTotal,
          percentage: (usage.heapUsed / usage.heapTotal) * 100,
        },
        cpuUsage: process.cpuUsage().user / 1000000, // Convert to milliseconds
        activeOperations: this.activeOperations.size,
      };

      this.resourceHistory.push(resourceUsage);

      // Trim history
      if (this.resourceHistory.length > 1000) {
        this.resourceHistory = this.resourceHistory.slice(-800);
      }

      // Check for resource alerts
      this.checkResourceAlerts(resourceUsage);
    } catch (error) {
      logger.warn('Failed to collect resource metrics:', error);
    }
  }

  private checkThresholds(metric: PerformanceMetric): void {
    const threshold = this.thresholds.get(metric.operation);
    if (!threshold || !metric.duration) return;

    if (metric.duration > threshold.criticalThreshold) {
      logger.error(`Critical performance threshold exceeded`, {
        operation: metric.operation,
        duration: metric.duration,
        threshold: threshold.criticalThreshold,
        metadata: metric.metadata,
      });
    } else if (metric.duration > threshold.alertThreshold) {
      logger.warn(`Performance alert threshold exceeded`, {
        operation: metric.operation,
        duration: metric.duration,
        threshold: threshold.alertThreshold,
        metadata: metric.metadata,
      });
    }
  }

  private checkResourceAlerts(usage: ResourceUsage): void {
    // Memory usage alert
    if (usage.memoryUsage.percentage > 90) {
      logger.error(`Critical memory usage detected`, {
        percentage: usage.memoryUsage.percentage,
        used: usage.memoryUsage.used,
        total: usage.memoryUsage.total,
      });
    } else if (usage.memoryUsage.percentage > 80) {
      logger.warn(`High memory usage detected`, {
        percentage: usage.memoryUsage.percentage,
        used: usage.memoryUsage.used,
        total: usage.memoryUsage.total,
      });
    }

    // Active operations alert
    if (usage.activeOperations > 50) {
      logger.warn(`High number of active operations`, {
        count: usage.activeOperations,
      });
    }
  }

  private generateAlerts(): unknown[] {
    const alerts: unknown[] = [];
    const metrics = this.getCurrentMetrics();

    // Performance alerts
    metrics.recent.forEach((metric) => {
      if (metric.status === 'failed') {
        alerts.push({
          type: 'operation_failure',
          operation: metric.operation,
          timestamp: metric.endTime,
          error: metric.error?.message,
        });
      }
    });

    // Resource alerts
    const recentResources = this.getResourceHistory(10);
    recentResources.forEach((resource) => {
      if (resource.memoryUsage.percentage > 80) {
        alerts.push({
          type: 'high_memory',
          timestamp: resource.timestamp,
          percentage: resource.memoryUsage.percentage,
        });
      }
    });

    return alerts;
  }

  private generateOperationId(operation: string): string {
    const timestamp = Date.now();
    const random = Math.random().toString(36).substr(2, 6);
    return `${operation}_${timestamp}_${random}`;
  }

  getRecentResponseTimes?: unknown

  getStats?: unknown
}

export const performanceMonitor = PerformanceMonitor.getInstance();

/**
 * Performance monitoring decorator for functions
 */
export function withPerformanceMonitoring(operation: string) {
  return function (target: unknown, propertyName: string, descriptor: PropertyDescriptor) {
    const method = descriptor.value;

    descriptor.value = async function (...args: any[]) {
      const id = performanceMonitor.startOperation(operation, {
        method: propertyName,
        args: args.length,
      });

      try {
        const result = await method.apply(this, args);
        performanceMonitor.completeOperation(id);
        return result;
      } catch (error) {
        performanceMonitor.completeOperation(id, error as Error);
        throw error;
      }
    };

    return descriptor;
  };
}
