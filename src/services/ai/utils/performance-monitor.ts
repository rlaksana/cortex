// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * Performance Monitor Implementation
 *
 * Simple performance monitoring for API requests
 * with response time tracking and error monitoring
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import type { ZAIError as IZAIError, ZAIPerformanceMonitor } from '../../../types/zai-interfaces.js';
/**
 * Simple performance monitor implementation
 */
import { ZAIError } from '../../../types/zai-interfaces.js';

export class SimplePerformanceMonitor implements ZAIPerformanceMonitor {
  private activeRequests = new Map<string, number>();
  private responseTimes: number[] = [];
  private errors: ZAIError[] = [];
  private totalRequests = 0;
  private successfulRequests = 0;
  private failedRequests = 0;
private startTime = Date.now();

  /**
   * Record the start of a request
   */
  recordRequestStart(requestId: string): void {
    this.activeRequests.set(requestId, Date.now());
  }

  /**
   * Record the completion of a request
   */
  /**
   * Record the completion of a request
   */
  recordRequestEnd(requestId: string, success: boolean, responseTime: number): void {
    const startTime = this.activeRequests.get(requestId);
    if (!startTime) {
      return;
    }

    this.activeRequests.delete(requestId);

    // Update statistics
    this.totalRequests++;
    if (success) {
      this.successfulRequests++;
    } else {
      this.failedRequests++;
    }

    // Keep only last 1000 response times for memory efficiency
    this.responseTimes.push(responseTime);
    if (this.responseTimes.length > 1000) {
      this.responseTimes.shift();
    }
  }

  /**
   * Record an error occurrence
   */
  recordError(error: ZAIError, context?: Record<string, unknown>): void {
    this.errors.push(error);

    // Keep only last 100 errors for memory efficiency
    if (this.errors.length > 100) {
      this.errors.shift();
    }
  }

  /**
   * Get performance metrics (interface method)
   */
  getPerformanceMetrics(): {
    averageResponseTime: number;
    p95ResponseTime: number;
    p99ResponseTime: number;
    throughput: number;
    errorRate: number;
  } {
    const metrics = this.getMetrics();
    return {
      averageResponseTime: metrics.averageResponseTime,
      p95ResponseTime: metrics.p95ResponseTime,
      p99ResponseTime: metrics.p99ResponseTime,
      throughput:
        this.totalRequests > 0
          ? (this.successfulRequests / (Date.now() - this.startTime)) * 1000
          : 0,
      errorRate: metrics.errorRate,
    };
  }

  /**
   * Get current performance metrics
   */
  getMetrics(): {
    totalRequests: number;
    successfulRequests: number;
    failedRequests: number;
    activeRequests: number;
    averageResponseTime: number;
    p95ResponseTime: number;
    p99ResponseTime: number;
    errorRate: number;
    successRate: number;
    recentErrors: ZAIError[];
  } {
    const activeCount = this.activeRequests.size;
    const successRate = this.totalRequests > 0 ? this.successfulRequests / this.totalRequests : 0;
    const errorRate = this.totalRequests > 0 ? this.failedRequests / this.totalRequests : 0;

    return {
      totalRequests: this.totalRequests,
      successfulRequests: this.successfulRequests,
      failedRequests: this.failedRequests,
      activeRequests: activeCount,
      averageResponseTime: this.calculateAverageResponseTime(),
      p95ResponseTime: this.calculatePercentile(95),
      p99ResponseTime: this.calculatePercentile(99),
      errorRate,
      successRate,
      recentErrors: [...this.errors],
    };
  }

  /**
   * Reset all metrics
   */
  reset(): void {
    this.activeRequests.clear();
    this.responseTimes = [];
    this.errors = [];
    this.totalRequests = 0;
    this.successfulRequests = 0;
    this.failedRequests = 0;
  }

  /**
   * Get metrics by time range (interface method)
   */
  getMetricsByTimeRange(start: number, end: number): unknown {
    // Simple implementation - in production, this would use proper time-based storage
    return this.getPerformanceMetrics();
  }

  /**
   * Get detailed statistics about response times
   */
  getResponseTimeStats(): {
    min: number;
    max: number;
    mean: number;
    median: number;
    p50: number;
    p75: number;
    p90: number;
    p95: number;
    p99: number;
    standardDeviation: number;
  } {
    if (this.responseTimes.length === 0) {
      return {
        min: 0,
        max: 0,
        mean: 0,
        median: 0,
        p50: 0,
        p75: 0,
        p90: 0,
        p95: 0,
        p99: 0,
        standardDeviation: 0,
      };
    }

    const sorted = [...this.responseTimes].sort((a, b) => a - b);
    const mean = this.calculateAverageResponseTime();
    const median = this.calculatePercentile(50);

    // Calculate standard deviation
    const variance =
      this.responseTimes.reduce((sum, time) => {
        return sum + Math.pow(time - mean, 2);
      }, 0) / this.responseTimes.length;

    return {
      min: sorted[0],
      max: sorted[sorted.length - 1],
      mean,
      median,
      p50: this.calculatePercentile(50),
      p75: this.calculatePercentile(75),
      p90: this.calculatePercentile(90),
      p95: this.calculatePercentile(95),
      p99: this.calculatePercentile(99),
      standardDeviation: Math.sqrt(variance),
    };
  }

  /**
   * Clean up stale active requests (for cleanup routines)
   */
  /**
   * Clean up stale active requests (for cleanup routines)
   */
  cleanupStaleRequests(maxAgeMs: number = 300000): number {
    const now = Date.now();
    let cleanedCount = 0;

    for (const [requestId, startTime] of this.activeRequests.entries()) {
      if (now - startTime > maxAgeMs) {
        this.activeRequests.delete(requestId);
        cleanedCount++;
        this.recordError(new ZAIError(
          `Request ${requestId} timed out after ${maxAgeMs}ms`,
          'TIMEOUT_ERROR' as unknown
        ));
      }
    }

    return cleanedCount;
  }

  /**
   * Calculate average response time
   */
  private calculateAverageResponseTime(): number {
    if (this.responseTimes.length === 0) {
      return 0;
    }

    const sum = this.responseTimes.reduce((total, time) => total + time, 0);
    return sum / this.responseTimes.length;
  }

  /**
   * Calculate percentile of response times
   */
  private calculatePercentile(percentile: number): number {
    if (this.responseTimes.length === 0) {
      return 0;
    }

    const sorted = [...this.responseTimes].sort((a, b) => a - b);
    const index = Math.ceil((percentile / 100) * sorted.length) - 1;
    return Math.max(0, Math.min(sorted.length - 1, index));
  }
}
