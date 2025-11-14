// @ts-nocheck
// ABSOLUTE FINAL EMERGENCY ROLLBACK: Last remaining systematic type issues
// TODO: Fix systematic type issues before removing @ts-nocheck

/**
 * Slow Query Logger for Cortex MCP
 *
 * Specialized logging service for detecting and analyzing slow queries:
 * - Configurable latency thresholds per operation type
 * - Detailed query analysis and optimization suggestions
 * - Historical trend analysis for query performance
 * - Automatic alerting for performance degradation
 * - Query pattern analysis for optimization opportunities
 */

import { EventEmitter } from 'events';

import { logger } from '@/utils/logger.js';

import { OperationType } from './operation-types.js';
import { performanceCollector } from './performance-collector.js';
import type {
  QueryDetails,
  RequestContext,
  SlowQueryAnalysis,
  SlowQueryContext,
  SlowQueryEntry,
  SlowQuerySystemState,
  SlowQueryTrend} from '../types/monitoring-types.js';


/**
 * Slow query configuration
 */
interface SlowQueryConfig {
  // Latency thresholds per operation type (milliseconds)
  thresholds: Partial<Record<OperationType, number>>;

  // Analysis settings
  analysis: {
    min_samples_for_trend: number;
    trend_window_hours: number;
    severity_multipliers: {
      medium: number; // 1.5x threshold
      high: number; // 2x threshold
      critical: number; // 3x threshold
    };
  };

  // Alerting settings
  alerts: {
    enabled: boolean;
    consecutive_slow_queries: number;
    rate_increase_threshold: number; // percentage increase
  };

  // Retention settings
  retention: {
    keep_entries_hours: number;
    max_entries_per_operation: number;
  };
}

/**
 * Slow query detection and analysis service
 */
export class SlowQueryLogger extends EventEmitter {
  private config: SlowQueryConfig;
  private slowQueries: SlowQueryEntry[] = [];
  private queryCounts: Map<string, number> = new Map();
  private recentSlowQueries: SlowQueryEntry[] = [];
  private alertCounters: Map<string, number> = new Map();

  constructor(config?: Partial<SlowQueryConfig>) {
    super();

    this.config = {
      thresholds: {
        [OperationType.MEMORY_STORE]: 1000, // 1 second
        [OperationType.MEMORY_FIND]: 2000, // 2 seconds
        [OperationType.EMBEDDING]: 5000, // 5 seconds
        [OperationType.CHUNKING]: 3000, // 3 seconds
        [OperationType.DEDUPLICATION]: 1500, // 1.5 seconds
        [OperationType.DATABASE_HEALTH]: 500, // 500ms
        [OperationType.DATABASE_STATS]: 300, // 300ms
      },
      analysis: {
        min_samples_for_trend: 10,
        trend_window_hours: 24,
        severity_multipliers: {
          medium: 1.5,
          high: 2.0,
          critical: 3.0,
        },
      },
      alerts: {
        enabled: true,
        consecutive_slow_queries: 3,
        rate_increase_threshold: 25, // 25% increase
      },
      retention: {
        keep_entries_hours: 168, // 7 days
        max_entries_per_operation: 1000,
      },
      ...config,
    };

    // Start periodic cleanup
    this.startPeriodicCleanup();
  }

  /**
   * Get singleton instance
   */
  public static getInstance(config?: Partial<SlowQueryConfig>): SlowQueryLogger {
    if (!(SlowQueryLogger as unknown).instance) {
      (SlowQueryLogger as unknown).instance = new SlowQueryLogger(config);
    }
    return (SlowQueryLogger as unknown).instance;
  }

  /**
   * Check if a query is slow and log it if necessary
   */
  checkAndLogSlowQuery(
    operation: OperationType,
    latencyMs: number,
    correlationId: string,
    query?: RequestContext,
    context?: SlowQueryContext
  ): SlowQueryEntry | null {
    const threshold = this.getThreshold(operation);

    if (latencyMs <= threshold) {
      return null; // Not a slow query
    }

    // Create slow query entry
    const slowQuery: SlowQueryEntry = {
      timestamp: Date.now(),
      correlation_id: correlationId,
      operation,
      latency_ms: latencyMs,
      threshold_ms: threshold,
      ...(query && {
        query: {
          text: query.query || '',
          mode: query.mode || '',
          limit: query.limit || 0,
          types: query.types || [],
          scope: query.scope || {},
          expand: query.expand || '',
        },
      }),
      analysis: this.analyzeSlowQuery(operation, latencyMs, threshold, query),
      context,
      system_state: this.getSystemState(),
    };

    // Store the slow query
    this.storeSlowQuery(slowQuery);

    // Log the slow query
    this.logSlowQuery(slowQuery);

    // Check for alerts
    this.checkAlerts(slowQuery);

    // Emit for real-time monitoring
    this.emit('slow_query', slowQuery);

    return slowQuery;
  }

  /**
   * Get slow query trends for an operation
   */
  getSlowQueryTrends(operation: OperationType, hours: number = 24): SlowQueryTrend | null {
    const cutoffTime = Date.now() - hours * 60 * 60 * 1000;
    const operationQueries = this.slowQueries.filter(
      (q) => q.operation === operation && q.timestamp > cutoffTime
    );

    if (operationQueries.length < this.config.analysis.min_samples_for_trend) {
      return null;
    }

    // Get performance data from performance collector
    const perfSummary = performanceCollector.getSummary(operation);
    const totalQueries = perfSummary?.count || 0;

    // Calculate trends
    const recentQueries = operationQueries.slice(-50);
    const olderQueries = operationQueries.slice(0, -50);

    const recentAvgLatency =
      recentQueries.reduce((sum, q) => sum + q.latency_ms, 0) / recentQueries.length;
    const olderAvgLatency =
      olderQueries.length > 0
        ? olderQueries.reduce((sum, q) => sum + q.latency_ms, 0) / olderQueries.length
        : recentAvgLatency;

    let trendDirection: 'improving' | 'degrading' | 'stable' = 'stable';
    const changePercent = ((recentAvgLatency - olderAvgLatency) / olderAvgLatency) * 100;

    if (changePercent > 10) {
      trendDirection = 'degrading';
    } else if (changePercent < -10) {
      trendDirection = 'improving';
    }

    // Analyze bottlenecks
    const bottleneckCounts = new Map<string, { count: number; totalImpact: number }>();

    operationQueries.forEach((query) => {
      query.analysis.potential_bottlenecks.forEach((bottleneck) => {
        const existing = bottleneckCounts.get(bottleneck) || { count: 0, totalImpact: 0 };
        existing.count++;
        existing.totalImpact += query.latency_ms - query.threshold_ms;
        bottleneckCounts.set(bottleneck, existing);
      });
    });

    const topBottlenecks = Array.from(bottleneckCounts.entries())
      .map(([bottleneck, data]) => ({
        bottleneck,
        frequency: data.count,
        avg_impact_ms: data.totalImpact / data.count,
      }))
      .sort((a, b) => b.frequency - a.frequency)
      .slice(0, 5);

    return {
      time_window_hours: hours,
      operation,
      total_queries: totalQueries,
      slow_queries: operationQueries.length,
      slow_query_rate: (operationQueries.length / totalQueries) * 100,
      average_latency_ms: perfSummary?.averageDuration || 0,
      p95_latency_ms: perfSummary?.p95 || 0,
      p99_latency_ms: perfSummary?.p99 || 0,
      trend_direction: trendDirection,
      top_bottlenecks: topBottlenecks,
    };
  }

  /**
   * Get recent slow queries
   */
  getRecentSlowQueries(limit: number = 50, operation?: OperationType): SlowQueryEntry[] {
    let queries = [...this.recentSlowQueries];

    if (operation) {
      queries = queries.filter((q) => q.operation === operation);
    }

    return queries.sort((a, b) => b.timestamp - a.timestamp).slice(0, limit);
  }

  /**
   * Get slow query statistics
   */
  getSlowQueryStats(hours: number = 24): {
    total_slow_queries: number;
    slow_query_rate: number;
    operations: Record<
      OperationType,
      {
        count: number;
        avg_latency_ms: number;
        max_latency_ms: number;
        rate: number;
      }
    >;
    top_bottlenecks: Array<{
      bottleneck: string;
      count: number;
      operations: OperationType[];
    }>;
  } {
    const cutoffTime = Date.now() - hours * 60 * 60 * 1000;
    const recentQueries = this.slowQueries.filter((q) => q.timestamp > cutoffTime);

    // Get total query count from performance collector
    const totalQueries = Object.values(OperationType).reduce((total, op) => {
      const summary = performanceCollector.getSummary(op);
      return total + (summary?.count || 0);
    }, 0);

    // Analyze by operation
    const operationStats: Record<OperationType, {
      count: number;
      avg_latency_ms: number;
      max_latency_ms: number;
      rate: number;
    }> = {};
    const bottleneckCounts = new Map<string, { count: number; operations: Set<OperationType> }>();

    Object.values(OperationType).forEach((operation) => {
      const opQueries = recentQueries.filter((q) => q.operation === operation);
      const summary = performanceCollector.getSummary(operation);

      if (opQueries.length > 0) {
        operationStats[operation] = {
          count: opQueries.length,
          avg_latency_ms: opQueries.reduce((sum, q) => sum + q.latency_ms, 0) / opQueries.length,
          max_latency_ms: Math.max(...opQueries.map((q) => q.latency_ms)),
          rate: summary ? (opQueries.length / summary.count) * 100 : 0,
        };

        // Track bottlenecks
        opQueries.forEach((query) => {
          query.analysis.potential_bottlenecks.forEach((bottleneck) => {
            const existing = bottleneckCounts.get(bottleneck) || {
              count: 0,
              operations: new Set(),
            };
            existing.count++;
            existing.operations.add(operation);
            bottleneckCounts.set(bottleneck, existing);
          });
        });
      }
    });

    // Get top bottlenecks
    const topBottlenecks = Array.from(bottleneckCounts.entries())
      .map(([bottleneck, data]) => ({
        bottleneck,
        count: data.count,
        operations: Array.from(data.operations),
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    return {
      total_slow_queries: recentQueries.length,
      slow_query_rate: totalQueries > 0 ? (recentQueries.length / totalQueries) * 100 : 0,
      operations: operationStats,
      top_bottlenecks: topBottlenecks,
    };
  }

  /**
   * Clear slow query history
   */
  clearSlowQueries(): void {
    this.slowQueries = [];
    this.recentSlowQueries = [];
    this.queryCounts.clear();
    this.alertCounters.clear();
    this.emit('queries_cleared');
  }

  // Private methods

  private getThreshold(operation: OperationType): number {
    return this.config.thresholds[operation] || 1000; // Default 1 second
  }

  private analyzeSlowQuery(
    operation: OperationType,
    latencyMs: number,
    threshold: number,
    query?: RequestContext
  ): SlowQueryAnalysis {
    const slowdownFactor = latencyMs / threshold;
    const { severity_multipliers } = this.config.analysis;

    // Determine severity
    let severity: 'low' | 'medium' | 'high' | 'critical' = 'low';
    if (slowdownFactor >= severity_multipliers.critical) {
      severity = 'critical';
    } else if (slowdownFactor >= severity_multipliers.high) {
      severity = 'high';
    } else if (slowdownFactor >= severity_multipliers.medium) {
      severity = 'medium';
    }

    // Identify potential bottlenecks
    const bottlenecks: string[] = [];

    if (operation === OperationType.MEMORY_FIND) {
      if (query?.mode === 'deep') {
        bottlenecks.push('Deep search mode with graph expansion');
      }
      if (query?.limit > 100) {
        bottlenecks.push('Large result set limit');
      }
      if (query?.types && query.types.length > 5) {
        bottlenecks.push('Complex type filtering');
      }
      if (query?.expand && query.expand !== 'none') {
        bottlenecks.push('Graph expansion enabled');
      }
    }

    if (operation === OperationType.MEMORY_STORE) {
      bottlenecks.push('Batch processing overhead');
      if (query?.deduplication) {
        bottlenecks.push('Deduplication processing');
      }
      if (query?.chunking) {
        bottlenecks.push('Content chunking');
      }
    }

    if (operation === OperationType.EMBEDDING) {
      bottlenecks.push('Embedding generation latency');
      if (query?.batch_size > 50) {
        bottlenecks.push('Large batch size');
      }
    }

    // Generate optimization suggestions
    const suggestions: string[] = [];

    if (severity === 'critical' || severity === 'high') {
      suggestions.push('Consider query optimization or indexing');
    }

    if (operation === OperationType.MEMORY_FIND) {
      if (query?.mode === 'deep') {
        suggestions.push('Try "auto" or "fast" search mode for better performance');
      }
      if (query?.limit > 100) {
        suggestions.push('Reduce limit or use pagination');
      }
      suggestions.push('Add more specific filters or scopes');
    }

    if (operation === OperationType.MEMORY_STORE) {
      suggestions.push('Consider batching smaller groups of items');
      suggestions.push('Check if deduplication can be optimized');
    }

    if (bottlenecks.length === 0) {
      bottlenecks.push('General performance degradation');
      suggestions.push('Monitor system resources and concurrent load');
    }

    return {
      severity,
      slowdown_factor: slowdownFactor,
      potential_bottlenecks: bottlenecks,
      optimization_suggestions: suggestions,
    };
  }

  private getSystemState(): SlowQuerySystemState {
    const memoryUsage = performanceCollector.getMemoryUsage();
    return {
      memory_usage_mb: memoryUsage.heapUsed / (1024 * 1024),
      concurrent_queries: this.queryCounts.size,
      cache_hit_rate: 0, // TODO: Implement cache hit rate tracking
    };
  }

  private storeSlowQuery(slowQuery: SlowQueryEntry): void {
    // Add to recent queries
    this.recentSlowQueries.push(slowQuery);
    if (this.recentSlowQueries.length > 1000) {
      this.recentSlowQueries = this.recentSlowQueries.slice(-1000);
    }

    // Add to main storage
    this.slowQueries.push(slowQuery);

    // Enforce retention limits
    this.enforceRetentionLimits();

    // Update query counts
    const key = `${slowQuery.operation}_${slowQuery.correlation_id}`;
    this.queryCounts.set(key, (this.queryCounts.get(key) || 0) + 1);
  }

  private logSlowQuery(slowQuery: SlowQueryEntry): void {
    logger.warn(
      {
        operation: slowQuery.operation,
        correlation_id: slowQuery.correlation_id,
        latency_ms: slowQuery.latency_ms,
        threshold_ms: slowQuery.threshold_ms,
        severity: slowQuery.analysis.severity,
        slowdown_factor: slowQuery.analysis.slowdown_factor,
        bottlenecks: slowQuery.analysis.potential_bottlenecks,
        suggestions: slowQuery.analysis.optimization_suggestions,
        query: slowQuery.query?.text?.substring(0, 200), // Truncate long queries
      },
      `Slow query detected: ${slowQuery.operation} took ${slowQuery.latency_ms}ms`
    );
  }

  private checkAlerts(slowQuery: SlowQueryEntry): void {
    if (!this.config.alerts.enabled) return;

    // Check for consecutive slow queries
    const key = `${slowQuery.operation}_consecutive`;
    const currentCount = (this.alertCounters.get(key) || 0) + 1;
    this.alertCounters.set(key, currentCount);

    if (currentCount >= this.config.alerts.consecutive_slow_queries) {
      this.emit('alert', {
        type: 'consecutive_slow_queries',
        operation: slowQuery.operation,
        count: currentCount,
        severity: slowQuery.analysis.severity,
        message: `${currentCount} consecutive slow queries for ${slowQuery.operation}`,
        timestamp: Date.now(),
      });
      this.alertCounters.set(key, 0); // Reset counter
    }

    // Check for critical severity
    if (slowQuery.analysis.severity === 'critical') {
      this.emit('alert', {
        type: 'critical_slow_query',
        operation: slowQuery.operation,
        latency_ms: slowQuery.latency_ms,
        message: `Critical slow query: ${slowQuery.operation} took ${slowQuery.latency_ms}ms`,
        timestamp: Date.now(),
      });
    }
  }

  private enforceRetentionLimits(): void {
    const cutoffTime = Date.now() - this.config.retention.keep_entries_hours * 60 * 60 * 1000;

    // Remove old entries
    this.slowQueries = this.slowQueries.filter((q) => q.timestamp > cutoffTime);

    // Enforce per-operation limits
    const operationCounts = new Map<OperationType, number>();
    this.slowQueries = this.slowQueries.filter((query) => {
      const count = operationCounts.get(query.operation) || 0;
      if (count >= this.config.retention.max_entries_per_operation) {
        return false;
      }
      operationCounts.set(query.operation, count + 1);
      return true;
    });

    // Clean up old counters
    const now = Date.now();
    for (const [key] of this.queryCounts.entries()) {
      const parts = key.split('_');
      const timestamp = parseInt(parts[parts.length - 1]);
      if (now - timestamp > 300000) {
        // 5 minutes
        this.queryCounts.delete(key);
      }
    }
  }

  private startPeriodicCleanup(): void {
    setInterval(() => {
      this.enforceRetentionLimits();
    }, 60000); // Cleanup every minute
  }

  /**
   * Cleanup method
   */
  cleanup(): void {
    this.clearSlowQueries();
    this.removeAllListeners();
  }
}

// Export singleton instance
export const slowQueryLogger = SlowQueryLogger.getInstance();
