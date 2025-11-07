// @ts-nocheck
/**
 * Enhanced MCP Server Health Monitor
 *
 * Comprehensive health monitoring system specifically designed for MCP server operations.
 * Provides real-time monitoring of server health, connection status, and performance metrics
 * with support for container orchestration and automated alerting.
 *
 * @author Cortex Team
 * @version 2.0.1
 */

import { EventEmitter } from 'events';
import {
  HealthStatus,
  SystemHealthResult,
  ComponentHealth,
  DependencyStatus,
  DependencyType
} from '../types/unified-health-interfaces.js';
import { circuitBreakerManager, type CircuitBreakerStats } from '../services/circuit-breaker.service.js';
import { logger } from '@/utils/logger.js';
import { performanceCollector } from './performance-collector.js';
import { metricsService } from './metrics-service.js';

/**
 * MCP Server specific health metrics
 */
export interface MCPServerHealthMetrics {
  // Connection metrics
  activeConnections: number;
  totalConnections: number;
  connectionErrors: number;
  averageConnectionTime: number;

  // Request metrics
  requestsPerSecond: number;
  averageResponseTime: number;
  p95ResponseTime: number;
  p99ResponseTime: number;
  errorRate: number;

  // MCP specific metrics
  activeSessions: number;
  totalSessions: number;
  mcpProtocolErrors: number;
  toolExecutionSuccessRate: number;
  toolExecutionAverageTime: number;

  // Resource metrics
  memoryUsageMB: number;
  memoryUsagePercent: number;
  cpuUsagePercent: number;
  eventLoopLag: number;

  // Database metrics
  qdrantConnectionStatus: boolean;
  qdrantResponseTime: number;
  qdrantErrorRate: number;
  vectorOperationsPerSecond: number;
}

/**
 * Health check configuration for MCP server
 */
export interface MCPServerHealthConfig {
  // Health check intervals
  healthCheckIntervalMs: number;
  metricsCollectionIntervalMs: number;

  // Thresholds for alerts
  thresholds: {
    errorRateWarning: number;      // percentage
    errorRateCritical: number;     // percentage
    responseTimeWarning: number;   // milliseconds
    responseTimeCritical: number;  // milliseconds
    memoryUsageWarning: number;    // percentage
    memoryUsageCritical: number;   // percentage
    cpuUsageWarning: number;       // percentage
    cpuUsageCritical: number;      // percentage
    connectionErrorRateWarning: number;  // percentage
    connectionErrorRateCritical: number; // percentage
  };

  // Circuit breaker monitoring
  circuitBreakerMonitoring: {
    enabled: boolean;
    alertOnOpen: boolean;
    alertOnHalfOpen: boolean;
    checkIntervalMs: number;
  };

  // Grace period for startup (allow higher resource usage during startup)
  startupGracePeriodMs: number;

  // Health history retention
  healthHistoryRetentionMinutes: number;
}

/**
 * Health history entry
 */
export interface HealthHistoryEntry {
  timestamp: Date;
  status: HealthStatus;
  metrics: MCPServerHealthMetrics;
  issues: string[];
  circuitBreakerStates: Record<string, CircuitBreakerStats>;
}

/**
 * MCP Server Health Monitor
 */
export class MCPServerHealthMonitor extends EventEmitter {
  private config: MCPServerHealthConfig;
  private startTime: number;
  private isRunning = false;
  private healthCheckInterval: NodeJS.Timeout | null = null;
  private metricsCollectionInterval: NodeJS.Timeout | null = null;

  // Health state
  private currentStatus: HealthStatus = HealthStatus.UNKNOWN;
  private currentMetrics: MCPServerHealthMetrics;
  private healthHistory: HealthHistoryEntry[] = [];
  private lastHealthCheck: Date | null = null;

  // Statistics
  private totalHealthChecks = 0;
  private consecutiveHealthyChecks = 0;
  private consecutiveUnhealthyChecks = 0;

  constructor(config?: Partial<MCPServerHealthConfig>) {
    super();

    this.config = {
      healthCheckIntervalMs: 30000,      // 30 seconds
      metricsCollectionIntervalMs: 10000, // 10 seconds
      thresholds: {
        errorRateWarning: 5,          // 5%
        errorRateCritical: 15,        // 15%
        responseTimeWarning: 1000,    // 1 second
        responseTimeCritical: 5000,   // 5 seconds
        memoryUsageWarning: 80,       // 80%
        memoryUsageCritical: 95,      // 95%
        cpuUsageWarning: 80,          // 80%
        cpuUsageCritical: 95,         // 95%
        connectionErrorRateWarning: 5,   // 5%
        connectionErrorRateCritical: 15,  // 15%
      },
      circuitBreakerMonitoring: {
        enabled: true,
        alertOnOpen: true,
        alertOnHalfOpen: true,
        checkIntervalMs: 15000,       // 15 seconds
      },
      startupGracePeriodMs: 120000,    // 2 minutes
      healthHistoryRetentionMinutes: 60, // 1 hour
      ...config,
    };

    this.startTime = Date.now();
    this.currentMetrics = this.getInitialMetrics();

    // Bind methods
    this.performHealthCheck = this.performHealthCheck.bind(this);
    this.collectMetrics = this.collectMetrics.bind(this);
  }

  /**
   * Start health monitoring
   */
  start(): void {
    if (this.isRunning) {
      logger.warn('MCP server health monitor is already running');
      return;
    }

    this.isRunning = true;

    // Start health check interval
    this.healthCheckInterval = setInterval(
      this.performHealthCheck,
      this.config.healthCheckIntervalMs
    );

    // Start metrics collection interval
    this.metricsCollectionInterval = setInterval(
      this.collectMetrics,
      this.config.metricsCollectionIntervalMs
    );

    // Perform initial health check and metrics collection
    this.performHealthCheck();
    this.collectMetrics();

    logger.info(
      {
        healthCheckInterval: this.config.healthCheckIntervalMs,
        metricsCollectionInterval: this.config.metricsCollectionIntervalMs,
      },
      'MCP server health monitor started'
    );

    this.emit('started');
  }

  /**
   * Stop health monitoring
   */
  stop(): void {
    if (!this.isRunning) {
      logger.warn('MCP server health monitor is not running');
      return;
    }

    this.isRunning = false;

    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
      this.healthCheckInterval = null;
    }

    if (this.metricsCollectionInterval) {
      clearInterval(this.metricsCollectionInterval);
      this.metricsCollectionInterval = null;
    }

    logger.info('MCP server health monitor stopped');
    this.emit('stopped');
  }

  /**
   * Get current health status
   */
  getCurrentStatus(): HealthStatus {
    return this.currentStatus;
  }

  /**
   * Get current metrics
   */
  getCurrentMetrics(): MCPServerHealthMetrics {
    return { ...this.currentMetrics };
  }

  /**
   * Get health history
   */
  getHealthHistory(limit?: number): HealthHistoryEntry[] {
    const history = [...this.healthHistory].reverse(); // Most recent first
    return limit ? history.slice(0, limit) : history;
  }

  /**
   * Perform comprehensive health check
   */
  private async performHealthCheck(): Promise<void> {
    const startTime = Date.now();
    this.totalHealthChecks++;

    try {
      const components: ComponentHealth[] = [];
      const issues: string[] = [];

      // Check MCP server specific components
      const mcpServerHealth = this.checkMCPServerHealth();
      components.push(mcpServerHealth);

      // Check Qdrant connectivity
      const qdrantHealth = await this.checkQdrantHealth();
      components.push(qdrantHealth);

      // Check circuit breakers
      const circuitBreakerHealth = this.checkCircuitBreakerHealth();
      components.push(circuitBreakerHealth);

      // Check system resources
      const systemHealth = this.checkSystemResources();
      components.push(systemHealth);

      // Check performance metrics
      const performanceHealth = this.checkPerformanceMetrics();
      components.push(performanceHealth);

      // Calculate overall status
      const overallStatus = this.calculateOverallStatus(components, issues);

      // Update state
      this.updateHealthState(overallStatus, issues);

      // Create health check result
      const healthResult: SystemHealthResult = {
        status: overallStatus,
        timestamp: new Date(),
        duration: Date.now() - startTime,
        uptime_seconds: Math.floor((Date.now() - this.startTime) / 1000),
        version: process.env.npm_package_version || '2.0.1',
        components,
        system_metrics: {
          memory_usage_mb: this.currentMetrics.memoryUsageMB,
          cpu_usage_percent: this.currentMetrics.cpuUsagePercent,
          active_connections: this.currentMetrics.activeConnections,
          qps: this.currentMetrics.requestsPerSecond,
        },
        summary: {
          total_components: components.length,
          healthy_components: components.filter(c => c.status === HealthStatus.HEALTHY).length,
          degraded_components: components.filter(c => c.status === HealthStatus.DEGRADED).length,
          unhealthy_components: components.filter(c => c.status === HealthStatus.UNHEALTHY).length,
        },
        issues,
      };

      this.lastHealthCheck = new Date();

      // Emit health check result
      this.emit('health_check', healthResult);

      // Log health status changes
      if (this.currentStatus !== overallStatus) {
        const previousStatus = this.currentStatus;
        this.currentStatus = overallStatus;

        logger[this.getLogLevelForStatus(overallStatus)](
          {
            previousStatus,
            newStatus: overallStatus,
            issues,
            metrics: this.currentMetrics,
            duration: Date.now() - startTime,
          },
          `MCP server health status changed from ${previousStatus} to ${overallStatus}`
        );

        this.emit('status_change', { previous: previousStatus, current: overallStatus, issues });
      }

    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      logger.error({ error }, 'Health check failed');

      this.updateHealthState(HealthStatus.UNHEALTHY, [`Health check failed: ${errorMsg}`]);

      this.emit('health_check_error', error);
    }
  }

  /**
   * Collect current metrics
   */
  private collectMetrics(): void {
    try {
      const memUsage = process.memoryUsage();
      const cpuUsage = process.cpuUsage();
      const realTimeMetrics = metricsService.getRealTimeMetrics();

      // Update current metrics
      this.currentMetrics = {
        // Connection metrics
        activeConnections: realTimeMetrics.system.active_connections,
        totalConnections: this.getTotalConnections(),
        connectionErrors: this.getConnectionErrors(),
        averageConnectionTime: realTimeMetrics.performance.store_p95_ms,

        // Request metrics
        requestsPerSecond: realTimeMetrics.qps.total_qps,
        averageResponseTime: realTimeMetrics.performance.store_p95_ms,
        p95ResponseTime: realTimeMetrics.performance.store_p95_ms,
        p99ResponseTime: realTimeMetrics.performance.store_p99_ms,
        errorRate: realTimeMetrics.quality.embedding_fail_rate,

        // MCP specific metrics
        activeSessions: this.getActiveSessions(),
        totalSessions: this.getTotalSessions(),
        mcpProtocolErrors: this.getMCPProtocolErrors(),
        toolExecutionSuccessRate: this.getToolExecutionSuccessRate(),
        toolExecutionAverageTime: this.getToolExecutionAverageTime(),

        // Resource metrics
        memoryUsageMB: memUsage.heapUsed / (1024 * 1024),
        memoryUsagePercent: (memUsage.heapUsed / memUsage.heapTotal) * 100,
        cpuUsagePercent: realTimeMetrics.system.cpu_usage_percent,
        eventLoopLag: this.getEventLoopLag(),

        // Database metrics
        qdrantConnectionStatus: this.getQdrantConnectionStatus(),
        qdrantResponseTime: this.getQdrantResponseTime(),
        qdrantErrorRate: this.getQdrantErrorRate(),
        vectorOperationsPerSecond: this.getVectorOperationsPerSecond(),
      };

      this.emit('metrics_collected', this.currentMetrics);

    } catch (error) {
      logger.error({ error }, 'Failed to collect metrics');
    }
  }

  /**
   * Check MCP server specific health
   */
  private checkMCPServerHealth(): ComponentHealth {
    const startTime = Date.now();

    try {
      const issues: string[] = [];
      let status = HealthStatus.HEALTHY;

      // Check if we're in startup grace period
      const uptime = Date.now() - this.startTime;
      const inGracePeriod = uptime < this.config.startupGracePeriodMs;

      // Check error rate
      if (this.currentMetrics.errorRate > this.config.thresholds.errorRateCritical) {
        status = HealthStatus.UNHEALTHY;
        issues.push(`Critical error rate: ${this.currentMetrics.errorRate.toFixed(2)}%`);
      } else if (this.currentMetrics.errorRate > this.config.thresholds.errorRateWarning) {
        status = HealthStatus.DEGRADED;
        issues.push(`High error rate: ${this.currentMetrics.errorRate.toFixed(2)}%`);
      }

      // Check response time
      if (this.currentMetrics.averageResponseTime > this.config.thresholds.responseTimeCritical) {
        status = HealthStatus.UNHEALTHY;
        issues.push(`Critical response time: ${this.currentMetrics.averageResponseTime}ms`);
      } else if (this.currentMetrics.averageResponseTime > this.config.thresholds.responseTimeWarning) {
        status = HealthStatus.DEGRADED;
        issues.push(`High response time: ${this.currentMetrics.averageResponseTime}ms`);
      }

      // Check connection error rate
      const connectionErrorRate = this.currentMetrics.totalConnections > 0
        ? (this.currentMetrics.connectionErrors / this.currentMetrics.totalConnections) * 100
        : 0;

      if (connectionErrorRate > this.config.thresholds.connectionErrorRateCritical) {
        status = HealthStatus.UNHEALTHY;
        issues.push(`Critical connection error rate: ${connectionErrorRate.toFixed(2)}%`);
      } else if (connectionErrorRate > this.config.thresholds.connectionErrorRateWarning) {
        status = HealthStatus.DEGRADED;
        issues.push(`High connection error rate: ${connectionErrorRate.toFixed(2)}%`);
      }

      // Allow degraded status during grace period
      if (inGracePeriod && status === HealthStatus.UNHEALTHY) {
        status = HealthStatus.DEGRADED;
        issues.push('System in startup grace period');
      }

      return {
        name: 'mcp-server',
        type: DependencyType.MONITORING,
        status,
        last_check: new Date(),
        response_time_ms: Date.now() - startTime,
        error_rate: this.currentMetrics.errorRate,
        uptime_percentage: 100 - this.currentMetrics.errorRate,
        details: {
          activeConnections: this.currentMetrics.activeConnections,
          requestsPerSecond: this.currentMetrics.requestsPerSecond,
          errorRate: this.currentMetrics.errorRate,
          averageResponseTime: this.currentMetrics.averageResponseTime,
          connectionErrorRate,
          activeSessions: this.currentMetrics.activeSessions,
          inGracePeriod,
          issues,
        },
      };

    } catch (error) {
      return {
        name: 'mcp-server',
        type: DependencyType.MONITORING,
        status: HealthStatus.UNHEALTHY,
        last_check: new Date(),
        response_time_ms: Date.now() - startTime,
        error_rate: 100,
        uptime_percentage: 0,
        error: error instanceof Error ? error.message : 'Unknown error',
        details: {},
      };
    }
  }

  /**
   * Check Qdrant health with enhanced monitoring
   */
  private async checkQdrantHealth(): Promise<ComponentHealth> {
    const startTime = Date.now();

    try {
      const issues: string[] = [];
      let status = HealthStatus.HEALTHY;

      // Check connection status
      if (!this.currentMetrics.qdrantConnectionStatus) {
        status = HealthStatus.UNHEALTHY;
        issues.push('Qdrant connection is down');
      } else {
        // Check response time
        if (this.currentMetrics.qdrantResponseTime > this.config.thresholds.responseTimeCritical) {
          status = HealthStatus.UNHEALTHY;
          issues.push(`Qdrant response time critical: ${this.currentMetrics.qdrantResponseTime}ms`);
        } else if (this.currentMetrics.qdrantResponseTime > this.config.thresholds.responseTimeWarning) {
          status = HealthStatus.DEGRADED;
          issues.push(`Qdrant response time high: ${this.currentMetrics.qdrantResponseTime}ms`);
        }

        // Check error rate
        if (this.currentMetrics.qdrantErrorRate > this.config.thresholds.errorRateCritical) {
          status = HealthStatus.UNHEALTHY;
          issues.push(`Qdrant error rate critical: ${this.currentMetrics.qdrantErrorRate.toFixed(2)}%`);
        } else if (this.currentMetrics.qdrantErrorRate > this.config.thresholds.errorRateWarning) {
          status = HealthStatus.DEGRADED;
          issues.push(`Qdrant error rate high: ${this.currentMetrics.qdrantErrorRate.toFixed(2)}%`);
        }

        // Check vector operations rate
        if (this.currentMetrics.vectorOperationsPerSecond === 0) {
          status = HealthStatus.DEGRADED;
          issues.push('No vector operations detected');
        }
      }

      return {
        name: 'qdrant-vector-db',
        type: DependencyType.VECTOR_DB,
        status,
        last_check: new Date(),
        response_time_ms: this.currentMetrics.qdrantResponseTime,
        error_rate: this.currentMetrics.qdrantErrorRate,
        uptime_percentage: this.currentMetrics.qdrantConnectionStatus ? 100 - this.currentMetrics.qdrantErrorRate : 0,
        details: {
          connectionStatus: this.currentMetrics.qdrantConnectionStatus,
          responseTime: this.currentMetrics.qdrantResponseTime,
          errorRate: this.currentMetrics.qdrantErrorRate,
          vectorOperationsPerSecond: this.currentMetrics.vectorOperationsPerSecond,
          issues,
        },
      };

    } catch (error) {
      return {
        name: 'qdrant-vector-db',
        type: DependencyType.VECTOR_DB,
        status: HealthStatus.UNHEALTHY,
        last_check: new Date(),
        response_time_ms: Date.now() - startTime,
        error_rate: 100,
        uptime_percentage: 0,
        error: error instanceof Error ? error.message : 'Unknown Qdrant error',
        details: {},
      };
    }
  }

  /**
   * Check circuit breaker health
   */
  private checkCircuitBreakerHealth(): ComponentHealth {
    const startTime = Date.now();

    try {
      const circuitStats = circuitBreakerManager.getAllStats();
      const openCircuits = circuitBreakerManager.getOpenCircuits();
      const issues: string[] = [];
      let status = HealthStatus.HEALTHY;

      // Check for open circuits
      if (openCircuits.length > 0) {
        status = HealthStatus.DEGRADED;
        issues.push(`Open circuits: ${openCircuits.join(', ')}`);

        // If critical services have open circuits, mark as unhealthy
        const criticalOpenCircuits = openCircuits.filter(name =>
          ['qdrant', 'memory-store', 'memory-find'].includes(name)
        );

        if (criticalOpenCircuits.length > 0) {
          status = HealthStatus.UNHEALTHY;
          issues.push(`Critical circuits open: ${criticalOpenCircuits.join(', ')}`);
        }
      }

      // Check failure rates across all circuits
      let totalFailures = 0;
      let totalCalls = 0;

      for (const [serviceName, stats] of Object.entries(circuitStats)) {
        totalFailures += stats.totalCalls - stats.successRate * stats.totalCalls;
        totalCalls += stats.totalCalls;

        // Check individual circuit failure rates
        if (stats.failureRate > this.config.thresholds.errorRateCritical) {
          status = HealthStatus.UNHEALTHY;
          issues.push(`Circuit ${serviceName} has critical failure rate: ${(stats.failureRate * 100).toFixed(2)}%`);
        } else if (stats.failureRate > this.config.thresholds.errorRateWarning) {
          if (status === HealthStatus.HEALTHY) status = HealthStatus.DEGRADED;
          issues.push(`Circuit ${serviceName} has high failure rate: ${(stats.failureRate * 100).toFixed(2)}%`);
        }
      }

      const overallFailureRate = totalCalls > 0 ? (totalFailures / totalCalls) * 100 : 0;

      return {
        name: 'circuit-breakers',
        type: DependencyType.MONITORING,
        status,
        last_check: new Date(),
        response_time_ms: Date.now() - startTime,
        error_rate: overallFailureRate,
        uptime_percentage: 100 - overallFailureRate,
        details: {
          totalCircuits: Object.keys(circuitStats).length,
          openCircuits: openCircuits.length,
          circuitStats,
          overallFailureRate,
          issues,
        },
      };

    } catch (error) {
      return {
        name: 'circuit-breakers',
        type: DependencyType.MONITORING,
        status: HealthStatus.UNHEALTHY,
        last_check: new Date(),
        response_time_ms: Date.now() - startTime,
        error_rate: 100,
        uptime_percentage: 0,
        error: error instanceof Error ? error.message : 'Unknown circuit breaker error',
        details: {},
      };
    }
  }

  /**
   * Check system resources
   */
  private checkSystemResources(): ComponentHealth {
    const startTime = Date.now();

    try {
      const issues: string[] = [];
      let status = HealthStatus.HEALTHY;

      // Check memory usage
      if (this.currentMetrics.memoryUsagePercent > this.config.thresholds.memoryUsageCritical) {
        status = HealthStatus.UNHEALTHY;
        issues.push(`Critical memory usage: ${this.currentMetrics.memoryUsagePercent.toFixed(2)}%`);
      } else if (this.currentMetrics.memoryUsagePercent > this.config.thresholds.memoryUsageWarning) {
        status = HealthStatus.DEGRADED;
        issues.push(`High memory usage: ${this.currentMetrics.memoryUsagePercent.toFixed(2)}%`);
      }

      // Check CPU usage
      if (this.currentMetrics.cpuUsagePercent > this.config.thresholds.cpuUsageCritical) {
        status = HealthStatus.UNHEALTHY;
        issues.push(`Critical CPU usage: ${this.currentMetrics.cpuUsagePercent.toFixed(2)}%`);
      } else if (this.currentMetrics.cpuUsagePercent > this.config.thresholds.cpuUsageWarning) {
        status = HealthStatus.DEGRADED;
        issues.push(`High CPU usage: ${this.currentMetrics.cpuUsagePercent.toFixed(2)}%`);
      }

      // Check event loop lag
      if (this.currentMetrics.eventLoopLag > 100) { // 100ms threshold
        status = HealthStatus.UNHEALTHY;
        issues.push(`Critical event loop lag: ${this.currentMetrics.eventLoopLag}ms`);
      } else if (this.currentMetrics.eventLoopLag > 50) { // 50ms threshold
        if (status === HealthStatus.HEALTHY) status = HealthStatus.DEGRADED;
        issues.push(`High event loop lag: ${this.currentMetrics.eventLoopLag}ms`);
      }

      return {
        name: 'system-resources',
        type: DependencyType.MONITORING,
        status,
        last_check: new Date(),
        response_time_ms: Date.now() - startTime,
        error_rate: 0,
        uptime_percentage: 100,
        details: {
          memoryUsageMB: this.currentMetrics.memoryUsageMB,
          memoryUsagePercent: this.currentMetrics.memoryUsagePercent,
          cpuUsagePercent: this.currentMetrics.cpuUsagePercent,
          eventLoopLag: this.currentMetrics.eventLoopLag,
          issues,
        },
      };

    } catch (error) {
      return {
        name: 'system-resources',
        type: DependencyType.MONITORING,
        status: HealthStatus.UNHEALTHY,
        last_check: new Date(),
        response_time_ms: Date.now() - startTime,
        error_rate: 100,
        uptime_percentage: 0,
        error: error instanceof Error ? error.message : 'Unknown system resource error',
        details: {},
      };
    }
  }

  /**
   * Check performance metrics
   */
  private checkPerformanceMetrics(): ComponentHealth {
    const startTime = Date.now();

    try {
      const issues: string[] = [];
      let status = HealthStatus.HEALTHY;

      // Check tool execution success rate
      if (this.currentMetrics.toolExecutionSuccessRate < 90) {
        status = HealthStatus.UNHEALTHY;
        issues.push(`Low tool execution success rate: ${this.currentMetrics.toolExecutionSuccessRate.toFixed(2)}%`);
      } else if (this.currentMetrics.toolExecutionSuccessRate < 95) {
        status = HealthStatus.DEGRADED;
        issues.push(`Tool execution success rate below optimal: ${this.currentMetrics.toolExecutionSuccessRate.toFixed(2)}%`);
      }

      // Check tool execution time
      if (this.currentMetrics.toolExecutionAverageTime > 10000) { // 10 seconds
        status = HealthStatus.UNHEALTHY;
        issues.push(`Critical tool execution time: ${this.currentMetrics.toolExecutionAverageTime}ms`);
      } else if (this.currentMetrics.toolExecutionAverageTime > 5000) { // 5 seconds
        if (status === HealthStatus.HEALTHY) status = HealthStatus.DEGRADED;
        issues.push(`High tool execution time: ${this.currentMetrics.toolExecutionAverageTime}ms`);
      }

      return {
        name: 'performance-metrics',
        type: DependencyType.MONITORING,
        status,
        last_check: new Date(),
        response_time_ms: Date.now() - startTime,
        error_rate: 100 - this.currentMetrics.toolExecutionSuccessRate,
        uptime_percentage: this.currentMetrics.toolExecutionSuccessRate,
        details: {
          toolExecutionSuccessRate: this.currentMetrics.toolExecutionSuccessRate,
          toolExecutionAverageTime: this.currentMetrics.toolExecutionAverageTime,
          requestsPerSecond: this.currentMetrics.requestsPerSecond,
          p95ResponseTime: this.currentMetrics.p95ResponseTime,
          issues,
        },
      };

    } catch (error) {
      return {
        name: 'performance-metrics',
        type: DependencyType.MONITORING,
        status: HealthStatus.UNHEALTHY,
        last_check: new Date(),
        response_time_ms: Date.now() - startTime,
        error_rate: 100,
        uptime_percentage: 0,
        error: error instanceof Error ? error.message : 'Unknown performance metrics error',
        details: {},
      };
    }
  }

  /**
   * Calculate overall health status
   */
  private calculateOverallStatus(components: ComponentHealth[], issues: string[]): HealthStatus {
    const unhealthyComponents = components.filter(c => c.status === HealthStatus.UNHEALTHY);
    const degradedComponents = components.filter(c => c.status === HealthStatus.DEGRADED);

    if (unhealthyComponents.length > 0) {
      return HealthStatus.UNHEALTHY;
    } else if (degradedComponents.length > 0) {
      return HealthStatus.DEGRADED;
    } else {
      return HealthStatus.HEALTHY;
    }
  }

  /**
   * Update health state and history
   */
  private updateHealthState(status: HealthStatus, issues: string[]): void {
    this.currentStatus = status;

    // Update consecutive counters
    if (status === HealthStatus.HEALTHY) {
      this.consecutiveHealthyChecks++;
      this.consecutiveUnhealthyChecks = 0;
    } else {
      this.consecutiveUnhealthyChecks++;
      this.consecutiveHealthyChecks = 0;
    }

    // Add to health history
    const historyEntry: HealthHistoryEntry = {
      timestamp: new Date(),
      status,
      metrics: { ...this.currentMetrics },
      issues: [...issues],
      circuitBreakerStates: circuitBreakerManager.getAllStats(),
    };

    this.healthHistory.push(historyEntry);

    // Trim history if needed
    const maxHistorySize = Math.floor(
      (this.config.healthHistoryRetentionMinutes * 60 * 1000) / this.config.healthCheckIntervalMs
    );

    if (this.healthHistory.length > maxHistorySize) {
      this.healthHistory = this.healthHistory.slice(-maxHistorySize);
    }
  }

  /**
   * Get initial metrics
   */
  private getInitialMetrics(): MCPServerHealthMetrics {
    return {
      activeConnections: 0,
      totalConnections: 0,
      connectionErrors: 0,
      averageConnectionTime: 0,
      requestsPerSecond: 0,
      averageResponseTime: 0,
      p95ResponseTime: 0,
      p99ResponseTime: 0,
      errorRate: 0,
      activeSessions: 0,
      totalSessions: 0,
      mcpProtocolErrors: 0,
      toolExecutionSuccessRate: 100,
      toolExecutionAverageTime: 0,
      memoryUsageMB: 0,
      memoryUsagePercent: 0,
      cpuUsagePercent: 0,
      eventLoopLag: 0,
      qdrantConnectionStatus: false,
      qdrantResponseTime: 0,
      qdrantErrorRate: 0,
      vectorOperationsPerSecond: 0,
    };
  }

  /**
   * Get log level for health status
   */
  private getLogLevelForStatus(status: HealthStatus): 'info' | 'warn' | 'error' {
    switch (status) {
      case HealthStatus.HEALTHY:
        return 'info';
      case HealthStatus.DEGRADED:
      case HealthStatus.WARNING:
        return 'warn';
      case HealthStatus.UNHEALTHY:
      case HealthStatus.CRITICAL:
        return 'error';
      default:
        return 'info';
    }
  }

  // Placeholder methods for MCP-specific metrics
  // These would need to be implemented based on actual MCP server metrics

  private getTotalConnections(): number {
    // This would be implemented based on actual connection tracking
    return metricsService.getRealTimeMetrics().system.active_connections;
  }

  private getConnectionErrors(): number {
    // This would be implemented based on actual error tracking
    return Math.floor(this.currentMetrics.requestsPerSecond * this.currentMetrics.errorRate / 100);
  }

  private getActiveSessions(): number {
    // This would be implemented based on actual session tracking
    return this.currentMetrics.activeConnections;
  }

  private getTotalSessions(): number {
    // This would be implemented based on actual session tracking
    return this.currentMetrics.totalConnections;
  }

  private getMCPProtocolErrors(): number {
    // This would be implemented based on actual MCP protocol error tracking
    return Math.floor(this.currentMetrics.requestsPerSecond * this.currentMetrics.errorRate / 200);
  }

  private getToolExecutionSuccessRate(): number {
    // This would be implemented based on actual tool execution metrics
    return Math.max(85, 100 - this.currentMetrics.errorRate);
  }

  private getToolExecutionAverageTime(): number {
    // This would be implemented based on actual tool execution metrics
    return this.currentMetrics.averageResponseTime * 2;
  }

  private getEventLoopLag(): number {
    // Simple implementation - would need more sophisticated monitoring
    const start = process.hrtime.bigint();
    setImmediate(() => {
      const lag = Number(process.hrtime.bigint() - start) / 1000000; // Convert to milliseconds
      return lag;
    });
    return 0;
  }

  private getQdrantConnectionStatus(): boolean {
    // This would check actual Qdrant connection status
    try {
      const qdrantCircuitStats = circuitBreakerManager.getAllStats().qdrant;
      return qdrantCircuitStats ? !qdrantCircuitStats.isOpen : false;
    } catch {
      return false;
    }
  }

  private getQdrantResponseTime(): number {
    // This would get actual Qdrant response time
    try {
      const qdrantCircuitStats = circuitBreakerManager.getAllStats().qdrant;
      return qdrantCircuitStats ? qdrantCircuitStats.averageResponseTime : 0;
    } catch {
      return 0;
    }
  }

  private getQdrantErrorRate(): number {
    // This would get actual Qdrant error rate
    try {
      const qdrantCircuitStats = circuitBreakerManager.getAllStats().qdrant;
      return qdrantCircuitStats ? qdrantCircuitStats.failureRate * 100 : 0;
    } catch {
      return 100;
    }
  }

  private getVectorOperationsPerSecond(): number {
    // This would get actual vector operations rate
    return this.currentMetrics.requestsPerSecond * 0.3; // Estimate
  }
}

// Export singleton instance
export const mcpServerHealthMonitor = new MCPServerHealthMonitor();
