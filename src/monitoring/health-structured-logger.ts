// @ts-nocheck
/**
 * Structured Health Event Logger
 *
 * Comprehensive structured logging system for health events with correlation IDs,
 * proper severity levels, and detailed context. Provides structured logs suitable
 * for monitoring systems, log aggregation, and debugging.
 *
 * @author Cortex Team
 * @version 2.0.1
 */

import { EventEmitter } from 'events';
import {
  HealthStatus,
  DependencyType
} from '../types/unified-health-interfaces.js';
import type { MCPServerHealthMetrics } from './mcp-server-health-monitor.js';
import type { CircuitBreakerEvent } from './circuit-breaker-monitor.js';
import { CircuitBreakerEventType } from './circuit-breaker-monitor.js';
import type { QdrantHealthCheckResult } from './qdrant-health-monitor.js';
import type { ProbeResult } from './container-probes.js';

/**
 * Log severity levels
 */
export enum LogLevel {
  DEBUG = 'debug',
  INFO = 'info',
  WARN = 'warn',
  ERROR = 'error',
  FATAL = 'fatal',
}

/**
 * Health event categories
 */
export enum HealthEventCategory {
  SYSTEM_HEALTH = 'system_health',
  COMPONENT_HEALTH = 'component_health',
  CIRCUIT_BREAKER = 'circuit_breaker',
  PERFORMANCE = 'performance',
  RESOURCE_USAGE = 'resource_usage',
  PROBE_RESULT = 'probe_result',
  ALERT = 'alert',
  RECOVERY = 'recovery',
  DEGRADATION = 'degradation',
}

/**
 * Structured log entry
 */
export interface StructuredLogEntry {
  // Basic log fields
  timestamp: string;
  level: LogLevel;
  message: string;
  category: HealthEventCategory;
  service: string;
  version: string;
  environment: string;

  // Correlation and tracing
  correlationId: string;
  traceId?: string;
  spanId?: string;
  parentSpanId?: string;

  // Health-specific fields
  healthStatus?: HealthStatus;
  componentName?: string;
  componentType?: DependencyType;
  previousStatus?: HealthStatus;

  // Performance and metrics
  duration?: number;
  responseTime?: number;
  throughput?: number;
  errorRate?: number;
  memoryUsage?: number;
  cpuUsage?: number;

  // Error information
  error?: {
    type: string;
    message: string;
    stack?: string;
    code?: string;
  };

  // Alert information
  alert?: {
    type: string;
    severity: 'info' | 'warning' | 'critical';
    threshold?: number;
    actualValue?: number;
  };

  // Additional context
  context: Record<string, any>;
  metadata: Record<string, any>;
}

/**
 * Health event logger configuration
 */
export interface HealthStructuredLoggerConfig {
  // Logging configuration
  level: LogLevel;
  service: string;
  version: string;
  environment: string;

  // Output configuration
  outputs: {
    console: {
      enabled: boolean;
      format: 'json' | 'pretty';
      colorize: boolean;
    };
    file: {
      enabled: boolean;
      path: string;
      maxSize: string;
      maxFiles: number;
    };
    external: {
      enabled: boolean;
      endpoint?: string;
      apiKey?: string;
      batchSize: number;
      flushIntervalMs: number;
    };
  };

  // Correlation configuration
  correlation: {
    generateIds: boolean;
    includeTraceId: boolean;
    maxHistorySize: number;
  };

  // Filtering configuration
  filtering: {
    categories: HealthEventCategory[];
    levels: LogLevel[];
    components: string[];
    includeHealthyEvents: boolean;
  };

  // Enrichment
  enrichment: {
    includeSystemInfo: boolean;
    includeProcessInfo: boolean;
    includeEnvironmentVars: boolean;
    customFields: Record<string, any>;
  };
}

/**
 * Health Structured Logger
 */
export class HealthStructuredLogger extends EventEmitter {
  private config: HealthStructuredLoggerConfig;
  private correlationHistory: Map<string, { timestamp: number; traceId?: string }> = new Map();
  private externalLogBuffer: StructuredLogEntry[] = [];
  private externalFlushInterval: NodeJS.Timeout | null = null;

  constructor(config?: Partial<HealthStructuredLoggerConfig>) {
    super();

    this.config = {
      level: LogLevel.INFO,
      service: process.env.SERVICE_NAME || 'cortex-mcp',
      version: process.env.npm_package_version || '2.0.1',
      environment: process.env.NODE_ENV || 'development',
      outputs: {
        console: {
          enabled: true,
          format: 'json',
          colorize: process.env.NODE_ENV !== 'production',
        },
        file: {
          enabled: false,
          path: './logs/health.log',
          maxSize: '100m',
          maxFiles: 10,
        },
        external: {
          enabled: false,
          batchSize: 100,
          flushIntervalMs: 5000,
        },
      },
      correlation: {
        generateIds: true,
        includeTraceId: true,
        maxHistorySize: 1000,
      },
      filtering: {
        categories: Object.values(HealthEventCategory),
        levels: [LogLevel.DEBUG, LogLevel.INFO, LogLevel.WARN, LogLevel.ERROR, LogLevel.FATAL],
        components: [],
        includeHealthyEvents: false,
      },
      enrichment: {
        includeSystemInfo: true,
        includeProcessInfo: true,
        includeEnvironmentVars: false,
        customFields: {},
      },
      ...config,
    };

    // Start external log flushing if enabled
    if (this.config.outputs.external.enabled) {
      this.startExternalLogFlushing();
    }
  }

  /**
   * Log system health check result
   */
  logSystemHealthCheck(
    status: HealthStatus,
    previousStatus: HealthStatus,
    metrics: MCPServerHealthMetrics,
    correlationId?: string
  ): void {
    const level = this.getLogLevelForHealthStatus(status);
    const category = HealthEventCategory.SYSTEM_HEALTH;

    // Skip healthy events if not configured to include them
    if (!this.config.filtering.includeHealthyEvents && status === HealthStatus.HEALTHY) {
      return;
    }

    this.log({
      level,
      message: `System health check: ${status}`,
      category,
      healthStatus: status,
      previousStatus,
      duration: 0, // Would be provided by health check
      responseTime: metrics.averageResponseTime,
      throughput: metrics.requestsPerSecond,
      errorRate: metrics.errorRate,
      memoryUsage: metrics.memoryUsagePercent,
      cpuUsage: metrics.cpuUsagePercent,
      correlationId: correlationId || this.generateCorrelationId(),
      context: {
        metrics,
        components: {
          activeConnections: metrics.activeConnections,
          totalSessions: metrics.totalSessions,
          toolExecutionSuccessRate: metrics.toolExecutionSuccessRate,
        },
      },
      metadata: {},
    });
  }

  /**
   * Log component health check result
   */
  logComponentHealthCheck(
    componentName: string,
    componentType: DependencyType,
    status: HealthStatus,
    previousStatus: HealthStatus,
    responseTime: number,
    error?: string,
    correlationId?: string
  ): void {
    const level = this.getLogLevelForHealthStatus(status);
    const category = HealthEventCategory.COMPONENT_HEALTH;

    // Skip healthy events if not configured to include them
    if (!this.config.filtering.includeHealthyEvents && status === HealthStatus.HEALTHY) {
      return;
    }

    this.log({
      level,
      message: `Component health check: ${componentName} - ${status}`,
      category,
      componentName,
      componentType,
      healthStatus: status,
      previousStatus,
      responseTime,
      correlationId: correlationId || this.generateCorrelationId(),
      context: {
        componentName,
        componentType,
      },
      error: error ? {
        type: 'component_error',
        message: error,
      } : undefined,
      metadata: {},
    });
  }

  /**
   * Log circuit breaker event
   */
  logCircuitBreakerEvent(event: CircuitBreakerEvent): void {
    const level = this.getLogLevelForCircuitEvent(event);
    const category = HealthEventCategory.CIRCUIT_BREAKER;

    this.log({
      level,
      message: `Circuit breaker event: ${event.serviceName} - ${event.eventType}`,
      category,
      componentName: event.serviceName,
      componentType: DependencyType.MONITORING,
      correlationId: this.generateCorrelationId(),
      duration: event.responseTime,
      context: {
        serviceName: event.serviceName,
        eventType: event.eventType,
        previousState: event.previousState,
        currentState: event.currentState,
        consecutiveFailures: event.consecutiveFailures,
        failureRate: event.failureRate,
      },
      error: event.error ? {
        type: 'circuit_breaker_error',
        message: event.error,
      } : undefined,
      metadata: event.metadata || {},
    });
  }

  /**
   * Log Qdrant health check result
   */
  logQdrantHealthCheck(result: QdrantHealthCheckResult): void {
    const level = this.getLogLevelForHealthStatus(result.status);
    const category = HealthEventCategory.COMPONENT_HEALTH;

    // Skip healthy events if not configured to include them
    if (!this.config.filtering.includeHealthyEvents && result.status === HealthStatus.HEALTHY) {
      return;
    }

    this.log({
      level,
      message: `Qdrant health check: ${result.status}`,
      category,
      componentName: 'qdrant-vector-db',
      componentType: DependencyType.VECTOR_DB,
      healthStatus: result.status,
      duration: result.responseTime,
      responseTime: result.responseTime,
      correlationId: this.generateCorrelationId(),
      context: {
        connectionStatus: result.connectionStatus,
        collections: result.details.collections.length,
        systemInfo: result.details.systemInfo,
      },
      error: result.error ? {
        type: 'qdrant_error',
        message: result.error,
      } : undefined,
      metadata: {},
    });
  }

  /**
   * Log probe result (readiness/liveness/startup)
   */
  logProbeResult(
    probeType: 'readiness' | 'liveness' | 'startup',
    result: ProbeResult,
    correlationId?: string
  ): void {
    const level = result.success ? LogLevel.INFO : LogLevel.WARN;
    const category = HealthEventCategory.PROBE_RESULT;

    this.log({
      level,
      message: `${probeType} probe: ${result.success ? 'success' : 'failure'}`,
      category,
      healthStatus: result.success ? HealthStatus.HEALTHY : HealthStatus.UNHEALTHY,
      duration: result.duration,
      responseTime: result.details.responseTime,
      memoryUsage: result.details.memoryUsage,
      correlationId: correlationId || this.generateCorrelationId(),
      context: {
        probeType,
        uptime: result.details.uptime,
        componentHealth: result.details.componentHealth,
        circuitBreakerStates: result.details.circuitBreakerStates,
      },
      metadata: {},
    });
  }

  /**
   * Log performance alert
   */
  logPerformanceAlert(
    alertType: string,
    severity: 'info' | 'warning' | 'critical',
    componentName: string,
    threshold: number,
    actualValue: number,
    correlationId?: string
  ): void {
    const level = this.getLogLevelForSeverity(severity);
    const category = HealthEventCategory.ALERT;

    this.log({
      level,
      message: `Performance alert: ${alertType} for ${componentName}`,
      category,
      componentName,
      alert: {
        type: alertType,
        severity,
        threshold,
        actualValue,
      },
      correlationId: correlationId || this.generateCorrelationId(),
      context: {
        alertType,
        componentName,
        threshold,
        actualValue,
        deviation: ((actualValue - threshold) / threshold) * 100,
      },
      metadata: {},
    });
  }

  /**
   * Log recovery event
   */
  logRecoveryEvent(
    componentName: string,
    fromStatus: HealthStatus,
    toStatus: HealthStatus,
    duration: number,
    correlationId?: string
  ): void {
    const level = LogLevel.INFO;
    const category = HealthEventCategory.RECOVERY;

    this.log({
      level,
      message: `Recovery event: ${componentName} recovered from ${fromStatus} to ${toStatus}`,
      category,
      componentName,
      healthStatus: toStatus,
      previousStatus: fromStatus,
      duration,
      correlationId: correlationId || this.generateCorrelationId(),
      context: {
        componentName,
        fromStatus,
        toStatus,
        recoveryTime: duration,
      },
      metadata: {},
    });
  }

  /**
   * Log degradation event
   */
  logDegradationEvent(
    componentName: string,
    fromStatus: HealthStatus,
    toStatus: HealthStatus,
    reason: string,
    correlationId?: string
  ): void {
    const level = LogLevel.WARN;
    const category = HealthEventCategory.DEGRADATION;

    this.log({
      level,
      message: `Degradation event: ${componentName} degraded from ${fromStatus} to ${toStatus}`,
      category,
      componentName,
      healthStatus: toStatus,
      previousStatus: fromStatus,
      correlationId: correlationId || this.generateCorrelationId(),
      context: {
        componentName,
        fromStatus,
        toStatus,
        reason,
      },
      metadata: {},
    });
  }

  /**
   * Log performance metrics
   */
  logPerformanceMetrics(
    metrics: {
      operation: string;
      responseTime: number;
      throughput?: number;
      errorRate?: number;
      percentile95?: number;
      percentile99?: number;
    },
    correlationId?: string
  ): void {
    const level = LogLevel.DEBUG;
    const category = HealthEventCategory.PERFORMANCE;

    this.log({
      level,
      message: `Performance metrics: ${metrics.operation}`,
      category,
      duration: metrics.responseTime,
      responseTime: metrics.responseTime,
      throughput: metrics.throughput,
      errorRate: metrics.errorRate,
      correlationId: correlationId || this.generateCorrelationId(),
      context: {
        operation: metrics.operation,
        percentile95: metrics.percentile95,
        percentile99: metrics.percentile99,
      },
      metadata: {},
    });
  }

  /**
   * Log resource usage
   */
  logResourceUsage(
    resources: {
      memoryUsage: number;
      cpuUsage: number;
      diskUsage?: number;
      networkIO?: number;
    },
    correlationId?: string
  ): void {
    const level = LogLevel.DEBUG;
    const category = HealthEventCategory.RESOURCE_USAGE;

    // Check if any resource usage is concerning
    let shouldUpgrade = false;
    if (resources.memoryUsage > 90 || resources.cpuUsage > 90) {
      shouldUpgrade = true;
    }

    this.log({
      level: shouldUpgrade ? LogLevel.WARN : level,
      message: `Resource usage: Memory ${resources.memoryUsage}%, CPU ${resources.cpuUsage}%`,
      category,
      memoryUsage: resources.memoryUsage,
      cpuUsage: resources.cpuUsage,
      correlationId: correlationId || this.generateCorrelationId(),
      context: {
        diskUsage: resources.diskUsage,
        networkIO: resources.networkIO,
      },
      metadata: {},
    });
  }

  /**
   * Generic log method
   */
  private log(entry: Omit<StructuredLogEntry, 'timestamp' | 'service' | 'version' | 'environment'>): void {
    // Apply filtering
    if (!this.shouldLog(entry)) {
      return;
    }

    // Enrich log entry
    const enrichedEntry: StructuredLogEntry = {
      timestamp: new Date().toISOString(),
      service: this.config.service,
      version: this.config.version,
      environment: this.config.environment,
      ...entry,
    };

    // Add system enrichment
    if (this.config.enrichment.includeSystemInfo) {
      enrichedEntry.context.system = this.getSystemInfo();
    }

    if (this.config.enrichment.includeProcessInfo) {
      enrichedEntry.context.process = this.getProcessInfo();
    }

    if (this.config.enrichment.includeEnvironmentVars) {
      enrichedEntry.context.environment = this.getEnvironmentInfo();
    }

    // Add custom fields
    if (Object.keys(this.config.enrichment.customFields).length > 0) {
      enrichedEntry.context.custom = this.config.enrichment.customFields;
    }

    // Track correlation
    this.trackCorrelation(enrichedEntry.correlationId, enrichedEntry.traceId);

    // Output to configured destinations
    this.outputToConsole(enrichedEntry);
    this.outputToFile(enrichedEntry);
    this.outputToExternal(enrichedEntry);

    // Emit event for listeners
    this.emit('log', enrichedEntry);
  }

  /**
   * Check if entry should be logged based on filtering rules
   */
  private shouldLog(entry: Omit<StructuredLogEntry, 'timestamp' | 'service' | 'version' | 'environment'>): boolean {
    // Check level filtering
    if (!this.config.filtering.levels.includes(entry.level)) {
      return false;
    }

    // Check category filtering
    if (!this.config.filtering.categories.includes(entry.category)) {
      return false;
    }

    // Check component filtering
    if (
      this.config.filtering.components.length > 0 &&
      entry.componentName &&
      !this.config.filtering.components.includes(entry.componentName)
    ) {
      return false;
    }

    return true;
  }

  /**
   * Output to console
   */
  private outputToConsole(entry: StructuredLogEntry): void {
    if (!this.config.outputs.console.enabled) return;

    const output = this.config.outputs.console.format === 'json'
      ? JSON.stringify(entry, null, 2)
      : this.formatPretty(entry);

    if (this.config.outputs.console.colorize) {
      // Add color based on level
      const colorCode = this.getColorCode(entry.level);
      console.log(`\x1b[${colorCode}m%s\x1b[0m`, output);
    } else {
      console.log(output);
    }
  }

  /**
   * Output to file
   */
  private outputToFile(entry: StructuredLogEntry): void {
    if (!this.config.outputs.file.enabled) return;

    // In a real implementation, this would write to a file with rotation
    // For now, just emit the event for potential file handlers
    this.emit('file_log', entry);
  }

  /**
   * Output to external system
   */
  private outputToExternal(entry: StructuredLogEntry): void {
    if (!this.config.outputs.external.enabled) return;

    this.externalLogBuffer.push(entry);

    // Flush if buffer is full
    if (this.externalLogBuffer.length >= this.config.outputs.external.batchSize) {
      this.flushExternalLogs();
    }
  }

  /**
   * Start external log flushing
   */
  private startExternalLogFlushing(): void {
    this.externalFlushInterval = setInterval(
      () => this.flushExternalLogs(),
      this.config.outputs.external.flushIntervalMs
    );
  }

  /**
   * Flush external logs
   */
  private flushExternalLogs(): void {
    if (this.externalLogBuffer.length === 0) return;

    const logs = [...this.externalLogBuffer];
    this.externalLogBuffer = [];

    // In a real implementation, this would send logs to external service
    this.emit('external_logs', logs);
  }

  /**
   * Format log entry for pretty printing
   */
  private formatPretty(entry: StructuredLogEntry): string {
    const timestamp = entry.timestamp;
    const level = entry.level.toUpperCase().padEnd(5);
    const category = entry.category.padEnd(20);
    const componentName = entry.componentName || 'system';
    const message = entry.message;

    let output = `${timestamp} ${level} ${category} [${componentName}] ${message}`;

    // Add key context fields
    if (entry.healthStatus) {
      output += ` | status: ${entry.healthStatus}`;
    }
    if (entry.duration) {
      output += ` | duration: ${entry.duration}ms`;
    }
    if (entry.responseTime) {
      output += ` | responseTime: ${entry.responseTime}ms`;
    }
    if (entry.error) {
      output += ` | error: ${entry.error.message}`;
    }

    return output;
  }

  /**
   * Get color code for log level
   */
  private getColorCode(level: LogLevel): string {
    switch (level) {
      case LogLevel.DEBUG: return '36'; // Cyan
      case LogLevel.INFO: return '32';  // Green
      case LogLevel.WARN: return '33';  // Yellow
      case LogLevel.ERROR: return '31'; // Red
      case LogLevel.FATAL: return '35'; // Magenta
      default: return '0';
    }
  }

  /**
   * Get log level for health status
   */
  private getLogLevelForHealthStatus(status: HealthStatus): LogLevel {
    switch (status) {
      case HealthStatus.HEALTHY: return LogLevel.INFO;
      case HealthStatus.WARNING:
      case HealthStatus.DEGRADED: return LogLevel.WARN;
      case HealthStatus.CRITICAL:
      case HealthStatus.UNHEALTHY: return LogLevel.ERROR;
      default: return LogLevel.INFO;
    }
  }

  /**
   * Get log level for circuit breaker event
   */
  private getLogLevelForCircuitEvent(event: CircuitBreakerEvent): LogLevel {
    switch (event.eventType) {
      case CircuitBreakerEventType.SUCCESS:
      case CircuitBreakerEventType.RECOVERY: return LogLevel.INFO;
      case CircuitBreakerEventType.STATE_CHANGE: return LogLevel.WARN;
      case CircuitBreakerEventType.FAILURE:
      case CircuitBreakerEventType.TIMEOUT:
      case CircuitBreakerEventType.THRESHOLD_EXCEEDED: return LogLevel.ERROR;
      default: return LogLevel.INFO;
    }
  }

  /**
   * Get log level for alert severity
   */
  private getLogLevelForSeverity(severity: 'info' | 'warning' | 'critical'): LogLevel {
    switch (severity) {
      case 'info': return LogLevel.INFO;
      case 'warning': return LogLevel.WARN;
      case 'critical': return LogLevel.ERROR;
      default: return LogLevel.INFO;
    }
  }

  /**
   * Generate correlation ID
   */
  private generateCorrelationId(): string {
    if (!this.config.correlation.generateIds) {
      return 'no-correlation';
    }

    return `corr_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Track correlation ID
   */
  private trackCorrelation(correlationId: string, traceId?: string): void {
    this.correlationHistory.set(correlationId, {
      timestamp: Date.now(),
      traceId,
    });

    // Clean up old entries
    const maxAge = this.config.correlation.maxHistorySize * 1000; // Convert to ms
    const cutoff = Date.now() - maxAge;

    for (const [id, entry] of this.correlationHistory) {
      if (entry.timestamp < cutoff) {
        this.correlationHistory.delete(id);
      }
    }
  }

  /**
   * Get system information
   */
  private getSystemInfo(): any {
    import('os').then(os => {
      return {
        hostname: os.hostname(),
        platform: process.platform,
        arch: process.arch,
        nodeVersion: process.version,
        uptime: process.uptime(),
      };
    }).catch(() => {
      return {
        hostname: 'unknown',
        platform: process.platform,
        arch: process.arch,
        nodeVersion: process.version,
        uptime: process.uptime(),
      };
    });

    // Synchronous fallback
    return {
      hostname: 'unknown',
      platform: process.platform,
      arch: process.arch,
      nodeVersion: process.version,
      uptime: process.uptime(),
    };
  }

  /**
   * Get process information
   */
  private getProcessInfo(): any {
    return {
      pid: process.pid,
      memoryUsage: process.memoryUsage(),
      cpuUsage: process.cpuUsage(),
    };
  }

  /**
   * Get environment information
   */
  private getEnvironmentInfo(): Record<string, string> {
    const env: Record<string, string> = {};
    const allowedVars = ['NODE_ENV', 'SERVICE_NAME', 'VERSION', 'CLUSTER_NAME'];

    for (const varName of allowedVars) {
      if (process.env[varName]) {
        env[varName] = process.env[varName];
      }
    }

    return env;
  }

  /**
   * Get correlation history
   */
  getCorrelationHistory(): Map<string, { timestamp: number; traceId?: string }> {
    return new Map(this.correlationHistory);
  }

  /**
   * Update configuration
   */
  updateConfig(config: Partial<HealthStructuredLoggerConfig>): void {
    this.config = { ...this.config, ...config };

    // Restart external log flushing if needed
    if (this.config.outputs.external.enabled && !this.externalFlushInterval) {
      this.startExternalLogFlushing();
    } else if (!this.config.outputs.external.enabled && this.externalFlushInterval) {
      clearInterval(this.externalFlushInterval);
      this.externalFlushInterval = null;
    }
  }

  /**
   * Flush all pending logs
   */
  flush(): void {
    this.flushExternalLogs();
  }

  /**
   * Cleanup
   */
  cleanup(): void {
    if (this.externalFlushInterval) {
      clearInterval(this.externalFlushInterval);
      this.externalFlushInterval = null;
    }

    this.flush();
    this.removeAllListeners();
  }
}

// Export singleton instance
export const healthStructuredLogger = new HealthStructuredLogger();