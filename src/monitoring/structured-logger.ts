/**
 * Structured Logging Service
 *
 * Provides consistent, structured logging per operation with:
 * - Op, latency_ms, strategy, dedup, TTL, scope tracking
 * - JSON format for log aggregation
 * - Performance metrics and error tracking
 * - Correlation IDs for request tracing
 */

import { logger } from '../utils/logger.js';
import type { AuthContext } from '../types/auth-types.js';
import { OperationType } from './operation-types.js';
import { metricsService } from './metrics-service.js';
import { slowQueryLogger } from './slow-query-logger.js';

/**
 * Search strategies for logging
 */
export enum SearchStrategy {
  HYBRID_CACHED = 'hybrid-cached',
  ERROR = 'error',
}

/**
 * Deduplication strategies
 */
export enum DeduplicationStrategy {
  SCOPE_ISOLATION = 'scope_isolation',
}

/**
 * Structured log entry interface
 */
export interface StructuredLogEntry {
  // Core fields
  timestamp: string;
  operation: OperationType;
  level: 'info' | 'warn' | 'error' | 'debug';
  correlation_id: string;

  // Performance metrics
  latency_ms: number;
  success: boolean;

  // Operation context
  user_context?: {
    user_id: string;
    username: string;
    role: string;
    scopes: string[];
  };

  request_context?: {
    query?: string;
    mode?: string;
    limit?: number;
    types?: string[];
    scope?: Record<string, any>;
    expand?: string;
  };

  // Result metrics
  result_metrics?: {
    total_count?: number;
    result_count?: number;
    duplicates_found?: number;
    newer_versions_allowed?: number;
    chunks_created?: number;
    cache_hit?: boolean;
  };

  // Strategy information
  strategy?: SearchStrategy;
  deduplication?: DeduplicationStrategy;

  // TTL information
  ttl_info?: {
    ttl_hours?: number;
    ttl_preset?: string;
    expires_at?: string;
  };

  // Error information
  error?: {
    type: string;
    message: string;
    stack?: string;
    code?: string;
  };

  // System health
  system_health?: {
    qdrant_status?: 'healthy' | 'degraded' | 'unhealthy';
    database_status?: 'connected' | 'error' | 'timeout';
    embedding_service_status?: 'healthy' | 'error';
    memory_usage_mb?: number;
    cpu_usage_percent?: number;
  };

  // Additional metadata
  metadata?: Record<string, any>;
}

/**
 * Structured logger configuration
 */
interface StructuredLoggerConfig {
  enableConsoleOutput: boolean;
  enableFileOutput: boolean;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  enableMetrics: boolean;
  enableCorrelation: boolean;
  maxMetadataSize: number;
}

/**
 * Service for structured logging across all operations
 */
export class StructuredLogger {
  private config: StructuredLoggerConfig = {
    enableConsoleOutput: true,
    enableFileOutput: true,
    logLevel: 'info',
    enableMetrics: true,
    enableCorrelation: true,
    maxMetadataSize: 1024,
  };

  private operationMetrics = new Map<
    string,
    {
      count: number;
      totalLatency: number;
      errors: number;
      lastUpdate: number;
    }
  >();

  private constructor() {}

  /**
   * Get singleton instance
   */
  public static getInstance(): StructuredLogger {
    if (!(StructuredLogger as any).instance) {
      (StructuredLogger as any).instance = new StructuredLogger();
    }
    return (StructuredLogger as any).instance;
  }

  /**
   * Log an operation with structured data
   */
  logOperation(entry: Omit<StructuredLogEntry, 'timestamp'>): void {
    const fullEntry: StructuredLogEntry = {
      ...entry,
      timestamp: new Date().toISOString(),
    };

    // Filter by log level
    if (!this.shouldLog(fullEntry.level)) {
      return;
    }

    // Check for slow queries
    slowQueryLogger.checkAndLogSlowQuery(
      entry.operation,
      entry.latency_ms,
      entry.correlation_id,
      entry.request_context,
      entry.user_context
    );

    // Update internal metrics
    this.updateMetrics(fullEntry);

    // Record in comprehensive metrics service
    const metadata: any = {};
    if (entry.strategy !== undefined) metadata.strategy = entry.strategy;
    if (entry.deduplication !== undefined) metadata.deduplication = entry.deduplication;
    if (entry.result_metrics?.result_count !== undefined)
      metadata.result_count = entry.result_metrics.result_count;
    if (entry.result_metrics?.duplicates_found !== undefined)
      metadata.duplicates_found = entry.result_metrics.duplicates_found;
    if (entry.result_metrics?.cache_hit !== undefined)
      metadata.cache_hit = entry.result_metrics.cache_hit;
    if (entry.ttl_info?.ttl_hours !== undefined) metadata.ttl_hours = entry.ttl_info.ttl_hours;

    metricsService.recordOperation(entry.operation, entry.latency_ms, entry.success, metadata);

    // Log with structured format
    this.logStructured(fullEntry);
  }

  /**
   * Log a memory store operation
   */
  logMemoryStore(
    correlationId: string,
    latencyMs: number,
    success: boolean,
    itemCount: number,
    resultMetrics: any,
    authContext?: AuthContext,
    requestContext?: any,
    error?: Error
  ): void {
    this.logOperation({
      operation: OperationType.MEMORY_STORE,
      level: success ? 'info' : 'error',
      correlation_id: correlationId,
      latency_ms: latencyMs,
      success,
      user_context: this.formatUserContext(authContext),
      request_context: this.formatRequestContext(requestContext),
      result_metrics: {
        total_count: itemCount,
        result_count: resultMetrics?.stored || 0,
        duplicates_found: resultMetrics?.duplicates || 0,
        newer_versions_allowed: resultMetrics?.newerVersionsAllowed || 0,
      },
      error: error ? this.formatError(error) : undefined,
      metadata: {
        chunking_enabled: resultMetrics?.chunkingEnabled || false,
        deduplication_enabled: resultMetrics?.deduplicationEnabled || false,
        batch_id: resultMetrics?.batchId,
      },
    });
  }

  /**
   * Log a memory find operation
   */
  logMemoryFind(
    correlationId: string,
    latencyMs: number,
    success: boolean,
    strategy: SearchStrategy,
    resultCount: number,
    totalCount: number,
    authContext?: AuthContext,
    requestContext?: any,
    error?: Error
  ): void {
    this.logOperation({
      operation: OperationType.MEMORY_FIND,
      level: success ? 'info' : 'error',
      correlation_id: correlationId,
      latency_ms: latencyMs,
      success,
      strategy,
      user_context: this.formatUserContext(authContext),
      request_context: this.formatRequestContext(requestContext),
      result_metrics: {
        result_count: resultCount,
        total_count: totalCount,
        cache_hit: strategy === SearchStrategy.HYBRID_CACHED,
      },
      error: error ? this.formatError(error) : undefined,
      metadata: {
        search_complexity: this.calculateSearchComplexity(requestContext),
        expansion_used: requestContext?.expand !== 'none',
      },
    });
  }

  /**
   * Log chunking operation
   */
  logChunking(
    correlationId: string,
    latencyMs: number,
    success: boolean,
    originalLength: number,
    chunksCreated: number,
    strategy: string,
    error?: Error
  ): void {
    this.logOperation({
      operation: OperationType.CHUNKING,
      level: success ? 'info' : 'error',
      correlation_id: correlationId,
      latency_ms: latencyMs,
      success,
      result_metrics: {
        chunks_created: chunksCreated,
        total_count: chunksCreated,
      },
      error: error ? this.formatError(error) : undefined,
      metadata: {
        original_length: originalLength,
        chunking_strategy: strategy,
        compression_ratio: originalLength > 0 ? chunksCreated / originalLength : 0,
      },
    });
  }

  /**
   * Log deduplication operation
   */
  logDeduplication(
    correlationId: string,
    latencyMs: number,
    success: boolean,
    strategy: DeduplicationStrategy,
    duplicatesFound: number,
    newerVersionsAllowed: number,
    authContext?: AuthContext,
    error?: Error
  ): void {
    this.logOperation({
      operation: OperationType.DEDUPLICATION,
      level: success ? 'info' : 'warn',
      correlation_id: correlationId,
      latency_ms: latencyMs,
      success,
      deduplication: strategy,
      user_context: this.formatUserContext(authContext),
      result_metrics: {
        duplicates_found: duplicatesFound,
        newer_versions_allowed: newerVersionsAllowed,
      },
      error: error ? this.formatError(error) : undefined,
      metadata: {
        deduplication_threshold: 0.85,
        scope_isolation: strategy === DeduplicationStrategy.SCOPE_ISOLATION,
      },
    });
  }

  /**
   * Log authentication operation
   */
  logAuthentication(
    correlationId: string,
    success: boolean,
    userId?: string,
    username?: string,
    role?: string,
    scopes?: string[],
    error?: Error
  ): void {
    this.logOperation({
      operation: OperationType.AUTHENTICATION,
      level: success ? 'info' : 'warn',
      correlation_id: correlationId,
      latency_ms: 0,
      success,
      user_context: {
        user_id: userId || 'unknown',
        username: username || 'unknown',
        role: role || 'unknown',
        scopes: scopes || [],
      },
      error: error ? this.formatError(error) : undefined,
    });
  }

  /**
   * Log rate limit operation
   */
  logRateLimit(
    correlationId: string,
    latencyMs: number,
    success: boolean,
    entityId: string,
    entityType: 'api_key' | 'organization',
    operation: OperationType,
    tokensRequested: number,
    violationType?: string,
    error?: Error
  ): void {
    this.logOperation({
      operation: OperationType.RATE_LIMIT,
      level: success ? 'info' : 'warn',
      correlation_id: correlationId,
      latency_ms: latencyMs,
      success,
      user_context: {
        user_id: entityId,
        username: entityType,
        role: 'client',
        scopes: [],
      },
      request_context: {
        query: operation,
        mode: violationType || 'allowed',
        limit: tokensRequested,
        types: [entityType],
      },
      result_metrics: {
        total_count: tokensRequested,
        result_count: success ? tokensRequested : 0,
      },
      error: error ? this.formatError(error) : undefined,
      metadata: {
        violation_type: violationType,
        entity_type: entityType,
        tokens_requested: tokensRequested,
      },
    });
  }

  /**
   * Log system health
   */
  logSystemHealth(
    correlationId: string,
    systemHealth: {
      qdrantStatus?: 'healthy' | 'degraded' | 'unhealthy';
      databaseStatus?: 'connected' | 'error' | 'timeout';
      embeddingServiceStatus?: 'healthy' | 'error';
      memoryUsageMb?: number;
      cpuUsagePercent?: number;
    }
  ): void {
    const convertedSystemHealth: any = {};
    if (systemHealth.qdrantStatus !== undefined)
      convertedSystemHealth.qdrant_status = systemHealth.qdrantStatus;
    if (systemHealth.databaseStatus !== undefined)
      convertedSystemHealth.database_status = systemHealth.databaseStatus;
    if (systemHealth.embeddingServiceStatus !== undefined)
      convertedSystemHealth.embedding_service_status = systemHealth.embeddingServiceStatus;
    if (systemHealth.memoryUsageMb !== undefined)
      convertedSystemHealth.memory_usage_mb = systemHealth.memoryUsageMb;
    if (systemHealth.cpuUsagePercent !== undefined)
      convertedSystemHealth.cpu_usage_percent = systemHealth.cpuUsagePercent;

    this.logOperation({
      operation: OperationType.SYSTEM,
      level: 'info',
      correlation_id: correlationId,
      latency_ms: 0,
      success: true,
      system_health: convertedSystemHealth,
      metadata: {
        health_check_timestamp: new Date().toISOString(),
      },
    });
  }

  /**
   * Get operation metrics
   */
  getOperationMetrics(operation: OperationType): {
    count: number;
    averageLatency: number;
    errorRate: number;
    lastUpdate: Date;
  } {
    const metrics = this.operationMetrics.get(operation);
    if (!metrics) {
      return {
        count: 0,
        averageLatency: 0,
        errorRate: 0,
        lastUpdate: new Date(),
      };
    }

    return {
      count: metrics.count,
      averageLatency: metrics.count > 0 ? metrics.totalLatency / metrics.count : 0,
      errorRate: metrics.count > 0 ? (metrics.errors / metrics.count) * 100 : 0,
      lastUpdate: new Date(metrics.lastUpdate),
    };
  }

  /**
   * Get all metrics
   */
  getAllMetrics(): Record<string, any> {
    const allMetrics: Record<string, any> = {};

    for (const [operation, metrics] of this.operationMetrics.entries()) {
      allMetrics[operation] = {
        count: metrics.count,
        averageLatency: metrics.count > 0 ? metrics.totalLatency / metrics.count : 0,
        errorRate: metrics.count > 0 ? (metrics.errors / metrics.count) * 100 : 0,
        lastUpdate: new Date(metrics.lastUpdate).toISOString(),
      };
    }

    return allMetrics;
  }

  /**
   * Reset metrics
   */
  resetMetrics(): void {
    this.operationMetrics.clear();
  }

  /**
   * Check if entry should be logged based on level
   */
  private shouldLog(level: string): boolean {
    const levels = ['debug', 'info', 'warn', 'error'];
    const currentLevelIndex = levels.indexOf(this.config.logLevel);
    const entryLevelIndex = levels.indexOf(level);

    return entryLevelIndex >= currentLevelIndex;
  }

  /**
   * Update operation metrics
   */
  private updateMetrics(entry: StructuredLogEntry): void {
    if (!this.config.enableMetrics) {
      return;
    }

    const operation = entry.operation;
    const existing = this.operationMetrics.get(operation) || {
      count: 0,
      totalLatency: 0,
      errors: 0,
      lastUpdate: Date.now(),
    };

    existing.count++;
    existing.totalLatency += entry.latency_ms;
    if (!entry.success) {
      existing.errors++;
    }
    existing.lastUpdate = Date.now();

    this.operationMetrics.set(operation, existing);
  }

  /**
   * Log structured entry
   */
  private logStructured(entry: StructuredLogEntry): void {
    // Truncate metadata if too large
    if (entry.metadata && JSON.stringify(entry.metadata).length > this.config.maxMetadataSize) {
      entry.metadata = {
        ...entry.metadata,
        _truncated: true,
        _original_size: JSON.stringify(entry.metadata).length,
      };
    }

    // Log using existing logger
    logger[entry.level](entry, `${entry.operation} operation`);
  }

  /**
   * Format user context for logging
   */
  private formatUserContext(authContext?: AuthContext): any {
    if (!authContext) {
      return undefined;
    }

    return {
      user_id: authContext.user.id,
      username: authContext.user.username,
      role: authContext.user.role,
      scopes: authContext.scopes,
    };
  }

  /**
   * Format request context for logging
   */
  private formatRequestContext(context?: any): any {
    if (!context) {
      return undefined;
    }

    return {
      query: context.query,
      mode: context.mode,
      limit: context.limit,
      types: context.types,
      scope: context.scope,
      expand: context.expand,
    };
  }

  /**
   * Format error for logging
   */
  private formatError(error: Error): any {
    return {
      type: error.constructor.name,
      message: error.message,
      stack: error.stack,
      code: (error as any).code,
    };
  }

  /**
   * Calculate search complexity
   */
  private calculateSearchComplexity(context?: any): 'low' | 'medium' | 'high' {
    if (!context) {
      return 'low';
    }

    let complexity = 0;

    // Query length
    if (context.query) {
      complexity += Math.min(context.query.length / 50, 2);
    }

    // Mode complexity
    if (context.mode === 'deep') {
      complexity += 3;
    } else if (context.mode === 'auto') {
      complexity += 2;
    } else if (context.mode === 'fast') {
      complexity += 1;
    }

    // Expansion complexity
    if (context.expand && context.expand !== 'none') {
      complexity += 2;
    }

    // Type filter complexity
    if (context.types && context.types.length > 0) {
      complexity += Math.min(context.types.length / 5, 1);
    }

    if (complexity <= 2) return 'low';
    if (complexity <= 4) return 'medium';
    return 'high';
  }

  /**
   * Generate correlation ID
   */
  generateCorrelationId(prefix?: string): string {
    const timestamp = Date.now();
    const random = Math.random().toString(36).substr(2, 9);
    return `${prefix || 'op'}_${timestamp}_${random}`;
  }
}

// Export singleton instance
export const structuredLogger = StructuredLogger.getInstance();
