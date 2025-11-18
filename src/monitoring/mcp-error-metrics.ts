// EMERGENCY ROLLBACK: MCP error metrics during TypeScript transition

/**
 * MCP Error Metrics System
 *
 * Extends the existing monitoring patterns with MCP-specific error tracking,
 * providing comprehensive metrics collection, aggregation, and analysis for
 * tool execution errors and protocol-level issues.
 *
 * Features:
 * - Tool-specific error tracking
 * - Error cascade detection
 * - Performance impact analysis
 * - Error trend analysis
 * - Real-time alerting
 * - Integration with existing metrics collector
 */

import { EventEmitter } from 'events';

import {
  type McpBaseError,
  McpErrorCategory,
  McpErrorCode,
} from '@/types/mcp-error-types.js';

import { MetricsCollector } from './metrics-collector.js';
import { TrendDirection } from '../types/metrics-types.js';

// Error metrics configuration
export interface McpErrorMetricsConfig {
  retentionPeriodMs?: number;
  aggregationWindowMs?: number;
  alertThresholds?: {
    errorRate?: number;
    consecutiveErrors?: number;
    responseTimeIncrease?: number;
  };
  enableCascadeDetection?: boolean;
  enableRealTimeAlerting?: boolean;
}

// Tool error metrics
export interface ToolErrorMetrics {
  toolName: string;
  totalErrors: number;
  errorsByCode: Record<McpErrorCode, number>;
  errorsByCategory: Record<McpErrorCategory, number>;
  averageResponseTime: number;
  errorRate: number;
  lastErrorTimestamp?: string;
  consecutiveErrors: number;
  cascadingErrors: number;
}

// Error cascade information
export interface ErrorCascade {
  cascadeId: string;
  rootError: McpBaseError;
  relatedErrors: Array<{
    error: McpBaseError;
    timestamp: string;
    correlationId?: string;
    parentCorrelationId?: string;
  }>;
  severity: 'low' | 'medium' | 'high' | 'critical';
  affectedTools: string[];
  duration: number;
  detectedAt: string;
}

// Error trend analysis
export interface ErrorTrendAnalysis {
  period: { start: string; end: string };
  overallTrend: TrendDirection;
  trendByTool: Record<string, TrendDirection>;
  trendByCategory: Record<McpErrorCategory, TrendDirection>;
  errorRateChange: number;
  predictedErrors: number;
  confidence: number;
  recommendations: string[];
}

// Performance impact metrics
export interface ErrorPerformanceImpact {
  toolName: string;
  baselineResponseTime: number;
  currentResponseTime: number;
  responseTimeDegradation: number;
  throughputImpact: number;
  userImpact: {
    affectedUsers: number;
    totalImpactedOperations: number;
    averageDelayPerUser: number;
  };
  businessImpact: {
    estimatedRevenueImpact?: number;
    slaCompliance: number;
    customerSatisfactionImpact: 'low' | 'medium' | 'high';
  };
}

// Real-time alert
export interface McpErrorAlert {
  alertId: string;
  type: 'error_threshold' | 'error_cascade' | 'performance_degradation' | 'availability_issue';
  severity: 'low' | 'medium' | 'high' | 'critical';
  toolName?: string;
  message: string;
  details: Record<string, unknown>;
  timestamp: string;
  resolved: boolean;
  resolvedAt?: string;
}

/**
 * MCP Error Metrics Collector
 *
 * Extends the base metrics collector with MCP-specific error tracking
 * and analysis capabilities.
 */
export class McpErrorMetrics extends EventEmitter {
  private config: Required<McpErrorMetricsConfig>;
  private metricsCollector: MetricsCollector;
  private toolMetrics: Map<string, ToolErrorMetrics> = new Map();
  private errorHistory: Array<{
    error: McpBaseError;
    timestamp: string;
    correlationId?: string;
    toolName: string;
  }> = [];
  private activeCascades: Map<string, ErrorCascade> = new Map();
  private alerts: Map<string, McpErrorAlert> = new Map();
  private performanceBaselines: Map<string, number> = new Map();

  constructor(config: McpErrorMetricsConfig = {}) {
    super();

    this.config = {
      retentionPeriodMs: config.retentionPeriodMs || 24 * 60 * 60 * 1000, // 24 hours
      aggregationWindowMs: config.aggregationWindowMs || 60 * 60 * 1000, // 1 hour
      alertThresholds: {
        errorRate: config.alertThresholds?.errorRate || 0.1, // 10%
        consecutiveErrors: config.alertThresholds?.consecutiveErrors || 5,
        responseTimeIncrease: config.alertThresholds?.responseTimeIncrease || 2.0, // 2x
      },
      enableCascadeDetection: config.enableCascadeDetection ?? true,
      enableRealTimeAlerting: config.enableRealTimeAlerting ?? true,
    };

    this.metricsCollector = new MetricsCollector({
      maxBuckets: Math.ceil(this.config.retentionPeriodMs / (60 * 1000)), // minute buckets
    });

    // Set up periodic cleanup
    this.setupPeriodicCleanup();
  }

  /**
   * Record an error occurrence
   */
  recordError(error: McpBaseError, correlationId?: string): void {
    const toolName = error.toolContext?.toolName || 'unknown';
    const timestamp = new Date();

    // Initialize tool metrics if needed
    if (!this.toolMetrics.has(toolName)) {
      this.toolMetrics.set(toolName, {
        toolName,
        totalErrors: 0,
        errorsByCode: {} as Record<McpErrorCode, number>,
        errorsByCategory: {} as Record<McpErrorCategory, number>,
        averageResponseTime: 0,
        errorRate: 0,
        consecutiveErrors: 0,
        cascadingErrors: 0,
      });
    }

    const metrics = this.toolMetrics.get(toolName)!;

    // Update error counts
    metrics.totalErrors++;

    // Safely convert error code and category to proper enum types
    const errorCode = this.safeConvertMcpErrorCode(error.code);
    const errorCategory = this.safeConvertMcpErrorCategory(error.category);

    metrics.errorsByCode[errorCode] = (metrics.errorsByCode[errorCode] || 0) + 1;
    metrics.errorsByCategory[errorCategory] = (metrics.errorsByCategory[errorCategory] || 0) + 1;

    metrics.consecutiveErrors++;
    metrics.lastErrorTimestamp = timestamp.toISOString();

    // Record in history
    this.errorHistory.push({
      error,
      timestamp: timestamp.toISOString(),
      correlationId,
      toolName,
    });

    // Record in metrics collector
    this.metricsCollector.record(1, timestamp, {
      tool: toolName,
      error_code: error.code,
      error_category: error.category,
      severity: error.severity,
    });

    // Check for error cascades
    if (this.config.enableCascadeDetection) {
      this.detectErrorCascades(error, correlationId);
    }

    // Check alert thresholds
    if (this.config.enableRealTimeAlerting) {
      this.checkAlertThresholds(toolName, error, correlationId);
    }

    // Emit event for real-time monitoring
    this.emit('error:recorded', {
      toolName,
      error,
      correlationId,
      timestamp: timestamp.toISOString(),
    });

    // Cleanup old data
    this.cleanupOldData();
  }

  /**
   * Record successful operation for baseline calculations
   */
  recordSuccess(toolName: string, responseTime: number, correlationId?: string): void {
    // Reset consecutive error counter on success
    const metrics = this.toolMetrics.get(toolName);
    if (metrics) {
      metrics.consecutiveErrors = 0;
    }

    // Update performance baseline
    this.updatePerformanceBaseline(toolName, responseTime);

    // Record success in metrics collector
    this.metricsCollector.record(0, new Date(), {
      tool: toolName,
      success: 1, // Convert boolean to number for metrics compatibility
      response_time: responseTime,
    });

    // Emit success event
    this.emit('operation:success', {
      toolName,
      responseTime,
      correlationId,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Detect error cascades
   */
  private detectErrorCascades(error: McpBaseError, correlationId?: string): void {
    const toolName = error.toolContext?.toolName || 'unknown';
    const recentErrors = this.getRecentErrors(5000); // Last 5 seconds

    // Look for related errors that might indicate a cascade
    const relatedErrors = recentErrors.filter((recentError) => {
      if (recentError.correlationId === correlationId) {
        return true;
      }

      // Check for similar error patterns in the same time window
      const timeDiff =
        new Date(error.timestamp).getTime() - new Date(recentError.timestamp).getTime();
      return timeDiff < 2000 && recentError.toolName === toolName; // 2 second window
    });

    if (relatedErrors.length >= 3) {
      // Potential cascade detected
      const cascadeId = `cascade_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

      const cascade: ErrorCascade = {
        cascadeId,
        rootError: relatedErrors[0].error,
        relatedErrors: relatedErrors.map((re) => ({
          error: re.error,
          timestamp: re.timestamp,
          correlationId: re.correlationId,
        })),
        severity: this.calculateCascadeSeverity(relatedErrors),
        affectedTools: Array.from(new Set(relatedErrors.map((re) => re.toolName))),
        duration:
          new Date(error.timestamp).getTime() - new Date(relatedErrors[0].timestamp).getTime(),
        detectedAt: new Date().toISOString(),
      };

      this.activeCascades.set(cascadeId, cascade);

      // Update tool metrics
      cascade.affectedTools.forEach((tool) => {
        const metrics = this.toolMetrics.get(tool);
        if (metrics) {
          metrics.cascadingErrors++;
        }
      });

      // Emit cascade event
      this.emit('cascade:detected', cascade);

      // Create alert if critical
      if (cascade.severity === 'critical' || cascade.severity === 'high') {
        this.createAlert({
          type: 'error_cascade',
          severity: cascade.severity,
          message: `Error cascade detected affecting ${cascade.affectedTools.length} tools`,
          details: {
            cascadeId: cascade.cascadeId,
            affectedTools: cascade.affectedTools,
            errorCount: cascade.relatedErrors.length,
            duration: cascade.duration,
          },
        });
      }
    }
  }

  /**
   * Check alert thresholds
   */
  private checkAlertThresholds(
    toolName: string,
    error: McpBaseError,
    correlationId?: string
  ): void {
    const metrics = this.toolMetrics.get(toolName);
    if (!metrics) return;

    // Check consecutive error threshold
    if (metrics.consecutiveErrors >= this.config.alertThresholds.consecutiveErrors) {
      this.createAlert({
        type: 'error_threshold',
        severity: 'high',
        toolName,
        message: `Consecutive error threshold exceeded for ${toolName}`,
        details: {
          consecutiveErrors: metrics.consecutiveErrors,
          threshold: this.config.alertThresholds.consecutiveErrors,
          lastError: error.message,
        },
      });
    }

    // Check error rate (calculated from recent history)
    const recentOperations = this.getRecentOperations(60000); // Last minute
    const errorRate =
      recentOperations.filter((op) => op.type === 'error').length /
      Math.max(recentOperations.length, 1);

    if (errorRate >= this.config.alertThresholds.errorRate) {
      this.createAlert({
        type: 'error_threshold',
        severity: 'medium',
        toolName,
        message: `Error rate threshold exceeded for ${toolName}`,
        details: {
          currentErrorRate: errorRate,
          threshold: this.config.alertThresholds.errorRate,
          recentErrors: recentOperations.filter((op) => op.type === 'error').length,
          totalRecentOperations: recentOperations.length,
        },
      });
    }
  }

  /**
   * Get metrics for a specific tool
   */
  getToolMetrics(toolName: string): ToolErrorMetrics | null {
    const metrics = this.toolMetrics.get(toolName);
    if (!metrics) return null;

    // Calculate current error rate
    const recentOperations = this.getRecentOperations(this.config.aggregationWindowMs);
    const toolOperations = recentOperations.filter((op) => op.toolName === toolName);
    const toolErrors = toolOperations.filter((op) => op.type === 'error');
    const errorRate = toolErrors.length / Math.max(toolOperations.length, 1);

    return {
      ...metrics,
      errorRate,
    };
  }

  /**
   * Get all tool metrics
   */
  getAllToolMetrics(): ToolErrorMetrics[] {
    return Array.from(this.toolMetrics.values()).map((metrics) => ({
      ...metrics,
      errorRate: this.calculateErrorRate(metrics.toolName),
    }));
  }

  /**
   * Get error trend analysis
   */
  getErrorTrendAnalysis(toolName?: string, periodMs: number = 3600000): ErrorTrendAnalysis {
    const endTime = new Date();
    const startTime = new Date(endTime.getTime() - periodMs);

    const errors = this.getErrorsInTimeRange(startTime, endTime, toolName);
    const buckets = this.groupErrorsByTimeWindow(errors, periodMs / 10); // 10 buckets

    const trend = this.calculateTrend(buckets);
    const recommendations = this.generateRecommendations(trend, errors);

    return {
      period: {
        start: startTime.toISOString(),
        end: endTime.toISOString(),
      },
      overallTrend: trend.direction,
      trendByTool: this.calculateTrendsByTool(errors, periodMs),
      trendByCategory: this.calculateTrendsByCategory(errors, periodMs),
      errorRateChange: trend.changeRate,
      predictedErrors: trend.predictedErrors,
      confidence: trend.confidence,
      recommendations,
    };
  }

  /**
   * Get performance impact analysis
   */
  getPerformanceImpact(toolName: string): ErrorPerformanceImpact | null {
    const metrics = this.toolMetrics.get(toolName);
    if (!metrics) return null;

    const baseline = this.performanceBaselines.get(toolName) || 1000; // Default 1s baseline
    const currentResponseTime = this.calculateAverageResponseTime(toolName, 300000); // Last 5 minutes

    const responseTimeDegradation = currentResponseTime / baseline;
    const throughputImpact = Math.max(0, 1 - 1 / responseTimeDegradation);

    return {
      toolName,
      baselineResponseTime: baseline,
      currentResponseTime,
      responseTimeDegradation,
      throughputImpact,
      userImpact: this.calculateUserImpact(toolName),
      businessImpact: this.calculateBusinessImpact(toolName, responseTimeDegradation),
    };
  }

  /**
   * Get active alerts
   */
  getActiveAlerts(): McpErrorAlert[] {
    return Array.from(this.alerts.values()).filter((alert) => !alert.resolved);
  }

  /**
   * Resolve an alert
   */
  resolveAlert(alertId: string): void {
    const alert = this.alerts.get(alertId);
    if (alert && !alert.resolved) {
      alert.resolved = true;
      alert.resolvedAt = new Date().toISOString();
      this.emit('alert:resolved', alert);
    }
  }

  /**
   * Reset metrics for a tool
   */
  resetToolMetrics(toolName: string): void {
    this.toolMetrics.delete(toolName);
    this.emit('metrics:reset', { toolName });
  }

  /**
   * Get comprehensive error statistics
   */
  getErrorStatistics(): {
    totalErrors: number;
    errorsByTool: Record<string, number>;
    errorsByCode: Record<McpErrorCode, number>;
    errorsByCategory: Record<McpErrorCategory, number>;
    activeCascades: number;
    activeAlerts: number;
    averageErrorRate: number;
  } {
    const allMetrics = this.getAllToolMetrics();
    const totalErrors = allMetrics.reduce((sum, metrics) => sum + metrics.totalErrors, 0);

    const errorsByTool: Record<string, number> = {};
    const errorsByCode: Record<McpErrorCode, number> = {} as Record<McpErrorCode, number>;
    const errorsByCategory: Record<McpErrorCategory, number> = {} as Record<
      McpErrorCategory,
      number
    >;

    allMetrics.forEach((metrics) => {
      errorsByTool[metrics.toolName] = metrics.totalErrors;

      Object.entries(metrics.errorsByCode).forEach(([code, count]) => {
        errorsByCode[code as McpErrorCode] = (errorsByCode[code as McpErrorCode] || 0) + count;
      });

      Object.entries(metrics.errorsByCategory).forEach(([category, count]) => {
        errorsByCategory[category as McpErrorCategory] =
          (errorsByCategory[category as McpErrorCategory] || 0) + count;
      });
    });

    const averageErrorRate =
      allMetrics.length > 0
        ? allMetrics.reduce((sum, metrics) => sum + metrics.errorRate, 0) / allMetrics.length
        : 0;

    return {
      totalErrors,
      errorsByTool,
      errorsByCode,
      errorsByCategory,
      activeCascades: this.activeCascades.size,
      activeAlerts: this.getActiveAlerts().length,
      averageErrorRate,
    };
  }

  // Private helper methods
  private getRecentErrors(timeWindowMs: number): typeof this.errorHistory {
    const cutoff = new Date(Date.now() - timeWindowMs);
    return this.errorHistory.filter((entry) => new Date(entry.timestamp) >= cutoff);
  }

  private getRecentOperations(
    timeWindowMs: number
  ): Array<{ type: 'error' | 'success'; toolName: string; timestamp: string }> {
    const cutoff = new Date(Date.now() - timeWindowMs);
    const operations: Array<{ type: 'error' | 'success'; toolName: string; timestamp: string }> =
      [];

    // Add error operations
    this.errorHistory.forEach((entry) => {
      if (new Date(entry.timestamp) >= cutoff) {
        operations.push({
          type: 'error',
          toolName: entry.toolName,
          timestamp: entry.timestamp,
        });
      }
    });

    // Add success operations from metrics collector
    const successMetrics = this.metricsCollector.query({
      from: cutoff,
      to: new Date(),
    });

    successMetrics.forEach((metric) => {
      if (metric.labels?.success === 1) {
        operations.push({
          type: 'success',
          toolName: (metric.labels?.tool as string) || 'unknown',
          timestamp: metric.timestamp.toISOString(),
        });
      }
    });

    return operations;
  }

  private updatePerformanceBaseline(toolName: string, responseTime: number): void {
    const currentBaseline = this.performanceBaselines.get(toolName) || responseTime;
    const newBaseline = currentBaseline * 0.9 + responseTime * 0.1; // Exponential moving average
    this.performanceBaselines.set(toolName, newBaseline);
  }

  private calculateErrorRate(toolName: string): number {
    const recentOperations = this.getRecentOperations(this.config.aggregationWindowMs);
    const toolOperations = recentOperations.filter((op) => op.toolName === toolName);
    const toolErrors = toolOperations.filter((op) => op.type === 'error');
    return toolErrors.length / Math.max(toolOperations.length, 1);
  }

  private calculateCascadeSeverity(
    errors: typeof this.errorHistory
  ): 'low' | 'medium' | 'high' | 'critical' {
    if (errors.length >= 10) return 'critical';
    if (errors.length >= 7) return 'high';
    if (errors.length >= 5) return 'medium';
    return 'low';
  }

  private createAlert(alertData: Omit<McpErrorAlert, 'alertId' | 'timestamp' | 'resolved'>): void {
    const alert: McpErrorAlert = {
      alertId: `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date().toISOString(),
      resolved: false,
      ...alertData,
    };

    this.alerts.set(alert.alertId, alert);
    this.emit('alert:created', alert);
  }

  private calculateAverageResponseTime(toolName: string, timeWindowMs: number): number {
    const metrics = this.metricsCollector.query({
      from: new Date(Date.now() - timeWindowMs),
      to: new Date(),
    });

    const toolMetrics = metrics.filter((metric) => metric.labels?.tool === toolName);
    if (toolMetrics.length === 0) return 0;

    const responseTimes = toolMetrics
      .filter((metric) => metric.labels?.response_time !== undefined)
      .map((metric) => metric.labels?.response_time as number);

    return responseTimes.length > 0
      ? responseTimes.reduce((sum, time) => sum + time, 0) / responseTimes.length
      : 0;
  }

  private calculateUserImpact(toolName: string) {
    // Placeholder implementation - would integrate with user tracking
    return {
      affectedUsers: Math.floor(Math.random() * 100), // Mock data
      totalImpactedOperations: Math.floor(Math.random() * 500), // Mock data
      averageDelayPerUser: Math.floor(Math.random() * 2000), // Mock data in ms
    };
  }

  private calculateBusinessImpact(toolName: string, responseTimeDegradation: number) {
    // Placeholder implementation - would integrate with business metrics
    return {
      estimatedRevenueImpact:
        responseTimeDegradation > 2 ? Math.floor(Math.random() * 1000) : undefined,
      slaCompliance: Math.max(0, 100 - (responseTimeDegradation - 1) * 20),
      customerSatisfactionImpact: (
          responseTimeDegradation > 1.5
            ? 'high'
            : responseTimeDegradation > 1.2
              ? 'medium'
              : 'low'
        ) as 'high' | 'medium' | 'low',
    };
  }

  private getErrorsInTimeRange(
    startTime: Date,
    endTime: Date,
    toolName?: string
  ): typeof this.errorHistory {
    return this.errorHistory.filter((entry) => {
      const timestamp = new Date(entry.timestamp);
      const inRange = timestamp >= startTime && timestamp <= endTime;
      const matchesTool = !toolName || entry.toolName === toolName;
      return inRange && matchesTool;
    });
  }

  private groupErrorsByTimeWindow(
    errors: typeof this.errorHistory,
    windowSizeMs: number
  ): Array<{ timestamp: Date; count: number }> {
    const buckets: Map<number, number> = new Map();

    errors.forEach((entry) => {
      const timestamp = new Date(entry.timestamp);
      const bucketKey = Math.floor(timestamp.getTime() / windowSizeMs) * windowSizeMs;
      buckets.set(bucketKey, (buckets.get(bucketKey) || 0) + 1);
    });

    return Array.from(buckets.entries())
      .map(([timestamp, count]) => ({
        timestamp: new Date(timestamp),
        count,
      }))
      .sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  }

  private calculateTrend(buckets: Array<{ timestamp: Date; count: number }>) {
    if (buckets.length < 2) {
      return {
        direction: TrendDirection.STABLE,
        changeRate: 0,
        predictedErrors: 0,
        confidence: 0,
      };
    }

    const recentAverage =
      buckets.slice(-3).reduce((sum, b) => sum + b.count, 0) / Math.min(3, buckets.length);
    const olderAverage =
      buckets.slice(0, 3).reduce((sum, b) => sum + b.count, 0) / Math.min(3, buckets.length);

    const changeRate = (recentAverage - olderAverage) / Math.max(olderAverage, 1);
    let direction: TrendDirection;

    if (Math.abs(changeRate) < 0.1) {
      direction = TrendDirection.STABLE;
    } else if (changeRate > 0.1) {
      direction = TrendDirection.INCREASING;
    } else {
      direction = TrendDirection.DECREASING;
    }

    const predictedErrors = recentAverage * (1 + changeRate);
    const confidence = Math.min(0.9, buckets.length / 10);

    return {
      direction,
      changeRate,
      predictedErrors,
      confidence,
    };
  }

  private calculateTrendsByTool(
    errors: typeof this.errorHistory,
    periodMs: number
  ): Record<string, TrendDirection> {
    const tools = Array.from(new Set(errors.map((e) => e.toolName)));
    const trends: Record<string, TrendDirection> = {};

    tools.forEach((tool) => {
      const toolErrors = errors.filter((e) => e.toolName === tool);
      const buckets = this.groupErrorsByTimeWindow(toolErrors, periodMs / 10);
      const trend = this.calculateTrend(buckets);
      trends[tool] = trend.direction;
    });

    return trends;
  }

  private calculateTrendsByCategory(
    errors: typeof this.errorHistory,
    periodMs: number
  ): Record<McpErrorCategory, TrendDirection> {
    // Get only MCP-specific error categories
    const mcpCategories = Object.values(McpErrorCategory);
    const trends: Record<McpErrorCategory, TrendDirection> = {} as Record<
      McpErrorCategory,
      TrendDirection
    >;

    mcpCategories.forEach((category) => {
      const categoryErrors = errors.filter((e) => String(e.error.category) === String(category));
      const buckets = this.groupErrorsByTimeWindow(categoryErrors, periodMs / 10);
      const trend = this.calculateTrend(buckets);
      trends[category] = trend.direction;
    });

    return trends;
  }

  private generateRecommendations(trend: { direction: TrendDirection }, errors: typeof this.errorHistory): string[] {
    const recommendations: string[] = [];

    if (trend.direction === TrendDirection.INCREASING) {
      recommendations.push('Error rate is increasing - investigate recent changes');
      recommendations.push('Consider implementing circuit breakers for affected tools');
    }

    if (errors.length > 50) {
      recommendations.push('High error volume detected - review error handling patterns');
    }

    const commonErrors = errors.reduce(
      (acc, e) => {
        acc[e.error.code] = (acc[e.error.code] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>
    );

    const mostCommonError = Object.entries(commonErrors).sort(([, a], [, b]) => b - a)[0];
    if (mostCommonError) {
      recommendations.push(`Most common error: ${mostCommonError[0]} - prioritize fixes`);
    }

    return recommendations;
  }

  private setupPeriodicCleanup(): void {
    setInterval(() => {
      this.cleanupOldData();
    }, 60000); // Cleanup every minute
  }

  private cleanupOldData(): void {
    const cutoff = new Date(Date.now() - this.config.retentionPeriodMs);

    // Clean error history
    const initialSize = this.errorHistory.length;
    this.errorHistory = this.errorHistory.filter((entry) => new Date(entry.timestamp) >= cutoff);
    const cleanedErrors = initialSize - this.errorHistory.length;

    // Clean resolved alerts older than retention period
    const initialAlerts = this.alerts.size;
    for (const [alertId, alert] of Array.from(this.alerts.entries())) {
      if (alert.resolved && alert.resolvedAt && new Date(alert.resolvedAt) < cutoff) {
        this.alerts.delete(alertId);
      }
    }
    const cleanedAlerts = initialAlerts - this.alerts.size;

    // Clean old cascades
    const initialCascades = this.activeCascades.size;
    for (const [cascadeId, cascade] of Array.from(this.activeCascades.entries())) {
      if (new Date(cascade.detectedAt) < cutoff) {
        this.activeCascades.delete(cascadeId);
      }
    }
    const cleanedCascades = initialCascades - this.activeCascades.size;

    if (cleanedErrors > 0 || cleanedAlerts > 0 || cleanedCascades > 0) {
      this.emit('cleanup:completed', {
        cleanedErrors,
        cleanedAlerts,
        cleanedCascades,
        retentionPeriod: this.config.retentionPeriodMs,
      });
    }
  }

  /**
   * Validate McpErrorCode enum value with proper type guard
   */
  private validateMcpErrorCode(code: unknown): code is McpErrorCode {
    if (typeof code !== 'string') {
      return false;
    }

    const validErrorCodes: readonly string[] = [
      'E2000', // TOOL_NOT_FOUND
      'E2001', // TOOL_EXECUTION_FAILED
      'E2002', // TOOL_TIMEOUT
      'E2003', // TOOL_CANCELLED
      'E2004', // TOOL_INVALID_ARGUMENTS
      'E2005', // TOOL_PERMISSION_DENIED
      'E2006', // TOOL_RESOURCE_UNAVAILABLE
      'E2007', // TOOL_DEPENDENCY_FAILED
      'E2100', // PROTOCOL_VIOLATION
      'E2101', // INVALID_REQUEST_FORMAT
      'E2102', // MISSING_CORRELATION_ID
      'E2103', // RESPONSE_TOO_LARGE
      'E2104', // UNEXPECTED_RESPONSE_FORMAT
      'E2200', // ARGUMENT_SCHEMA_VIOLATION
      'E2201', // REQUIRED_ARGUMENT_MISSING
      'E2202', // INVALID_ARGUMENT_TYPE
      'E2203', // ARGUMENT_OUT_OF_RANGE
      'E2204', // ARGUMENT_PATTERN_MISMATCH
      'E2300', // CONTEXT_NOT_FOUND
      'E2301', // CONTEXT_EXPIRED
      'E2302', // STATE_CORRUPTION
      'E2303', // CONCURRENT_MODIFICATION
      'E2400', // RESOURCE_QUOTA_EXCEEDED
      'E2401', // MEMORY_LIMIT_EXCEEDED
      'E2402', // TEMPORARY_STORAGE_FULL
      'E2403', // RATE_LIMIT_EXCEEDED
    ] as const;

    return validErrorCodes.includes(code);
  }

  /**
   * Validate McpErrorCategory enum value with proper type guard
   */
  private validateMcpErrorCategory(category: unknown): category is McpErrorCategory {
    if (typeof category !== 'string') {
      return false;
    }

    const validErrorCategories: readonly string[] = [
      'tool_execution',
      'protocol',
      'argument_validation',
      'context_management',
      'resource_management',
      'mcp_system'
    ] as const;

    return validErrorCategories.includes(category);
  }

  /**
   * Safely convert unknown to McpErrorCode
   */
  private safeConvertMcpErrorCode(code: unknown): McpErrorCode {
    return this.validateMcpErrorCode(code) ? code : McpErrorCode.TOOL_EXECUTION_FAILED;
  }

  /**
   * Safely convert unknown to McpErrorCategory
   */
  private safeConvertMcpErrorCategory(category: unknown): McpErrorCategory {
    return this.validateMcpErrorCategory(category) ? category : McpErrorCategory.MCP_SYSTEM;
  }
}

// Export singleton instance for global monitoring
export const mcpErrorMetrics = new McpErrorMetrics();
