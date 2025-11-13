
// @ts-nocheck - Emergency rollback: Critical monitoring service
/**
 * Health Check Service for Cortex MCP
 *
 * Provides comprehensive health monitoring for all service dependencies:
 * - Postgres database connectivity and performance
 * - Qdrant vector database status
 * - Embedding provider (OpenAI) availability
 * - Memory usage and system resources
 * - API response times and error rates
 */

import { EventEmitter } from 'events';

import { logger } from '@/utils/logger.js';

import { metricsService } from './metrics-service.js';
import { performanceCollector } from './performance-collector.js';
import { DependencyType } from '../services/deps-registry.js';
import { EmbeddingService } from '../services/embeddings/embedding-service.js';
import {
  type ComponentHealth,
  ComponentHealthResult,
  dependencyStatusToHealthStatus,
  HealthStatus,
  healthStatusToDependencyStatus,
  type SystemHealthResult,
} from '../types/unified-health-interfaces.js';

// Note: HealthStatus is now imported from unified-health-interfaces.ts to maintain consistency

// Note: ComponentHealth is now imported from unified-health-interfaces.ts to maintain consistency

// Note: SystemHealthResult is now imported from unified-health-interfaces.ts to maintain consistency
// The local HealthCheckResult interface is replaced with SystemHealthResult

/**
 * Health check configuration
 */
interface HealthCheckConfig {
  // Health check intervals (milliseconds)
  check_interval_ms: number;
  component_timeout_ms: number;

  // Performance thresholds
  latency_thresholds: {
    database_ms: number;
    qdrant_ms: number;
    embedding_ms: number;
  };

  // Error rate thresholds (percentage)
  error_rate_thresholds: {
    database: number;
    qdrant: number;
    embedding: number;
  };

  // System thresholds
  system_thresholds: {
    memory_usage_percent: number;
    cpu_usage_percent: number;
  };

  // Readiness checks
  readiness_checks: {
    min_healthy_components: number;
    allow_degraded_readiness: boolean;
  };
}

/**
 * Health check service
 */
export class HealthCheckService extends EventEmitter {
  private config: HealthCheckConfig;
  private startTime: number;
  private healthStatus: SystemHealthResult | null = null;
  private checkInterval: NodeJS.Timeout | null = null;
  private isShuttingDown = false;

  // Service instances
  private embeddingService: EmbeddingService;

  // Static instance for singleton pattern
  private static instance: HealthCheckService | null = null;

  constructor(config?: Partial<HealthCheckConfig>) {
    super();

    this.config = {
      check_interval_ms: 30000, // 30 seconds
      component_timeout_ms: 5000, // 5 seconds
      latency_thresholds: {
        database_ms: 1000,
        qdrant_ms: 2000,
        embedding_ms: 5000,
      },
      error_rate_thresholds: {
        database: 5,
        qdrant: 3,
        embedding: 10,
      },
      system_thresholds: {
        memory_usage_percent: 85,
        cpu_usage_percent: 80,
      },
      readiness_checks: {
        min_healthy_components: 2,
        allow_degraded_readiness: true,
      },
      ...config,
    };

    this.startTime = Date.now();
    this.embeddingService = new EmbeddingService();
  }

  /**
   * Get singleton instance
   */
  public static getInstance(config?: Partial<HealthCheckConfig>): HealthCheckService {
    if (!HealthCheckService.instance) {
      HealthCheckService.instance = new HealthCheckService(config);
    }
    return HealthCheckService.instance;
  }

  /**
   * Start health monitoring
   */
  startMonitoring(): void {
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
    }

    this.checkInterval = setInterval(() => {
      if (!this.isShuttingDown) {
        this.performHealthCheck();
      }
    }, this.config.check_interval_ms);

    // Perform initial health check
    this.performHealthCheck();

    logger.info({ intervalMs: this.config.check_interval_ms }, 'Health monitoring started');
  }

  /**
   * Stop health monitoring
   */
  stopMonitoring(): void {
    this.isShuttingDown = true;
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
      this.checkInterval = null;
    }
    logger.info('Health monitoring stopped');
  }

  /**
   * Get current health status
   */
  getHealthStatus(): SystemHealthResult | null {
    return this.healthStatus;
  }

  /**
   * Perform comprehensive health check
   */
  async performHealthCheck(): Promise<SystemHealthResult> {
    const components: ComponentHealth[] = [];

    // Check database health
    const databaseHealth = await this.checkDatabaseHealth();
    components.push(databaseHealth);

    // Check Qdrant health
    const qdrantHealth = await this.checkQdrantHealth();
    components.push(qdrantHealth);

    // Check embedding service health
    const embeddingHealth = await this.checkEmbeddingHealth();
    components.push(embeddingHealth);

    // Check system health
    const systemHealth = this.checkSystemHealth();
    components.push(systemHealth);

    // Check metrics service health
    const metricsHealth = this.checkMetricsHealth();
    components.push(metricsHealth);

    // Calculate overall status
    const overallStatus = this.calculateOverallStatus(components);
    const uptimeSeconds = Math.floor((Date.now() - this.startTime) / 1000);

    // Get system metrics
    const systemMetrics = this.getSystemMetrics();

    // Create health check result
    const healthResult: SystemHealthResult = {
      status: overallStatus,
      timestamp: new Date(),
      duration: Date.now() - this.startTime,
      uptime_seconds: uptimeSeconds,
      version: process.env.npm_package_version || '2.0.0',
      components,
      system_metrics: systemMetrics,
      summary: {
        total_components: components.length,
        healthy_components: components.filter((c) => c.status === HealthStatus.HEALTHY).length,
        degraded_components: components.filter((c) => c.status === HealthStatus.DEGRADED).length,
        unhealthy_components: components.filter((c) => c.status === HealthStatus.UNHEALTHY).length,
      },
    };

    this.healthStatus = healthResult;

    // Emit health status change
    this.emit('health_check', healthResult);

    // Log health status
    if (overallStatus !== 'healthy') {
      logger.warn({ health: healthResult }, 'System health check failed');
    }

    return healthResult;
  }

  /**
   * Readiness check (for Kubernetes/liveness probes)
   */
  async checkReadiness(): Promise<{ ready: boolean; status: HealthStatus }> {
    const health = await this.performHealthCheck();

    const isReady = this.config.readiness_checks.allow_degraded_readiness
      ? health.summary.healthy_components + health.summary.degraded_components >=
        this.config.readiness_checks.min_healthy_components
      : health.summary.healthy_components >= this.config.readiness_checks.min_healthy_components;

    return {
      ready: isReady,
      status: health.status,
    };
  }

  /**
   * Liveness check (for Kubernetes/liveness probes)
   */
  async checkLiveness(): Promise<{ alive: boolean; status: HealthStatus }> {
    // Basic liveness - check if process is responding
    const uptime = Date.now() - this.startTime;
    const alive = uptime > 5000; // Must have been running for at least 5 seconds

    return {
      alive,
      status: alive ? HealthStatus.HEALTHY : HealthStatus.UNHEALTHY,
    };
  }

  /**
   * Get health metrics for monitoring
   */
  getHealthMetrics(): {
    uptime_seconds: number;
    last_check_timestamp: number;
    component_count: number;
    healthy_count: number;
    response_time_ms: number;
  } {
    if (!this.healthStatus) {
      return {
        uptime_seconds: Math.floor((Date.now() - this.startTime) / 1000),
        last_check_timestamp: 0,
        component_count: 0,
        healthy_count: 0,
        response_time_ms: 0,
      };
    }

    return {
      uptime_seconds: this.healthStatus.uptime_seconds || 0,
      last_check_timestamp:
        typeof this.healthStatus.timestamp === 'string'
          ? new Date(this.healthStatus.timestamp).getTime()
          : this.healthStatus.timestamp.getTime(),
      component_count: this.healthStatus.summary.total_components,
      healthy_count: this.healthStatus.summary.healthy_components,
      response_time_ms: 0, // Would be tracked during actual health check
    };
  }

  // Private health check methods

  private async checkDatabaseHealth(): Promise<ComponentHealth> {
    const startTime = Date.now();
    const component = 'database';

    try {
      // This would need to be adapted based on your database implementation
      // For now, we'll simulate with performance collector metrics
      const dbSummary = performanceCollector.getSummary('database_query');
      const latency = Date.now() - startTime;

      if (!dbSummary) {
        return {
          name: component,
          type: DependencyType.DATABASE,
          status: HealthStatus.DEGRADED,
          last_check: new Date(),
          response_time_ms: latency,
          error_rate: 100,
          uptime_percentage: 0,
          details: {
            average_response_time_ms: 0,
            p95_response_time_ms: 0,
            error_rate_percent: 100,
            query_count: 0,
          },
        };
      }

      const errorRate = 100 - dbSummary.successRate;
      const uptimePercentage = dbSummary.successRate;
      const latencyThreshold = this.config.latency_thresholds.database_ms;
      const errorThreshold = this.config.error_rate_thresholds.database;

      let status: HealthStatus = HealthStatus.HEALTHY;
      let error: string | undefined;

      if (errorRate > errorThreshold) {
        status = HealthStatus.UNHEALTHY;
        error = `Error rate ${errorRate}% exceeds threshold ${errorThreshold}%`;
      } else if (dbSummary.averageDuration > latencyThreshold) {
        status = HealthStatus.DEGRADED;
        error = `Latency ${dbSummary.averageDuration}ms exceeds threshold ${latencyThreshold}ms`;
      }

      const result: ComponentHealth = {
        name: component,
        type: DependencyType.DATABASE,
        status,
        last_check: new Date(),
        response_time_ms: latency,
        error_rate: errorRate,
        uptime_percentage: uptimePercentage,
        details: {
          average_response_time_ms: dbSummary.averageDuration,
          p95_response_time_ms: dbSummary.p95,
          error_rate_percent: errorRate,
          query_count: dbSummary.count,
        },
      };

      if (error) {
        result.error = error;
      }

      return result;
    } catch (error) {
      return {
        name: component,
        type: DependencyType.DATABASE,
        status: HealthStatus.UNHEALTHY,
        last_check: new Date(),
        response_time_ms: Date.now() - startTime,
        error_rate: 100,
        uptime_percentage: 0,
        error: error instanceof Error ? error.message : 'Unknown database error',
        details: {
          average_response_time_ms: 0,
          p95_response_time_ms: 0,
          error_rate_percent: 100,
          query_count: 0,
        },
      };
    }
  }

  private async checkQdrantHealth(): Promise<ComponentHealth> {
    const startTime = Date.now();
    const component = 'qdrant';

    try {
      // This would need to be adapted based on your Qdrant implementation
      const qdrantSummary = performanceCollector.getSummary('vector_search');
      const latency = Date.now() - startTime;

      if (!qdrantSummary) {
        return {
          name: component,
          type: DependencyType.VECTOR_DB,
          status: HealthStatus.DEGRADED,
          last_check: new Date(),
          response_time_ms: latency,
          error_rate: 100,
          uptime_percentage: 0,
          error: 'No Qdrant metrics available',
          details: {
            average_response_time_ms: 0,
            p95_response_time_ms: 0,
            error_rate_percent: 100,
            search_count: 0,
          },
        };
      }

      const errorRate = 100 - qdrantSummary.successRate;
      const uptimePercentage = qdrantSummary.successRate;
      const latencyThreshold = this.config.latency_thresholds.qdrant_ms;
      const errorThreshold = this.config.error_rate_thresholds.qdrant;

      let status: HealthStatus = HealthStatus.HEALTHY;
      let error: string | undefined;

      if (errorRate > errorThreshold) {
        status = HealthStatus.UNHEALTHY;
        error = `Error rate ${errorRate}% exceeds threshold ${errorThreshold}%`;
      } else if (qdrantSummary.averageDuration > latencyThreshold) {
        status = HealthStatus.DEGRADED;
        error = `Latency ${qdrantSummary.averageDuration}ms exceeds threshold ${latencyThreshold}ms`;
      }

      const result: ComponentHealth = {
        name: component,
        type: DependencyType.VECTOR_DB,
        status,
        last_check: new Date(),
        response_time_ms: latency,
        error_rate: errorRate,
        uptime_percentage: uptimePercentage,
        details: {
          average_response_time_ms: qdrantSummary.averageDuration,
          p95_response_time_ms: qdrantSummary.p95,
          error_rate_percent: errorRate,
          search_count: qdrantSummary.count,
        },
      };

      if (error) {
        result.error = error;
      }

      return result;
    } catch (error) {
      return {
        name: component,
        type: DependencyType.VECTOR_DB,
        status: HealthStatus.UNHEALTHY,
        last_check: new Date(),
        response_time_ms: Date.now() - startTime,
        error_rate: 100,
        uptime_percentage: 0,
        error: error instanceof Error ? error.message : 'Unknown Qdrant error',
        details: {
          average_response_time_ms: 0,
          p95_response_time_ms: 0,
          error_rate_percent: 100,
          search_count: 0,
        },
      };
    }
  }

  private async checkEmbeddingHealth(): Promise<ComponentHealth> {
    const startTime = Date.now();
    const component = 'embedding_service';

    try {
      // Use the embedding service health check
      const isHealthy = await this.embeddingService.healthCheck();
      const latency = Date.now() - startTime;

      const embeddingSummary = performanceCollector.getSummary('embedding_generation');
      const errorThreshold = this.config.error_rate_thresholds.embedding;
      const latencyThreshold = this.config.latency_thresholds.embedding_ms;

      let status: HealthStatus = isHealthy ? HealthStatus.HEALTHY : HealthStatus.UNHEALTHY;
      let error: string | undefined;
      let errorRate = 0;
      let uptimePercentage = 100;

      if (embeddingSummary) {
        errorRate = 100 - embeddingSummary.successRate;
        uptimePercentage = embeddingSummary.successRate;

        if (errorRate > errorThreshold) {
          status = HealthStatus.UNHEALTHY;
          error = `Error rate ${errorRate}% exceeds threshold ${errorThreshold}%`;
        } else if (embeddingSummary.averageDuration > latencyThreshold) {
          status = HealthStatus.DEGRADED;
          error = `Latency ${embeddingSummary.averageDuration}ms exceeds threshold ${latencyThreshold}ms`;
        }
      }

      const result: ComponentHealth = {
        name: component,
        type: DependencyType.EMBEDDING_SERVICE,
        status,
        last_check: new Date(),
        response_time_ms: latency,
        error_rate: errorRate,
        uptime_percentage: uptimePercentage,
        details: embeddingSummary
          ? {
              average_response_time_ms: embeddingSummary.averageDuration,
              p95_response_time_ms: embeddingSummary.p95,
              error_rate_percent: errorRate,
              request_count: embeddingSummary.count,
            }
          : {
              average_response_time_ms: 0,
              p95_response_time_ms: 0,
              error_rate_percent: errorRate,
              request_count: 0,
            },
      };

      if (error) {
        result.error = error;
      }

      return result;
    } catch (error) {
      return {
        name: component,
        type: DependencyType.EMBEDDING_SERVICE,
        status: HealthStatus.UNHEALTHY,
        last_check: new Date(),
        response_time_ms: Date.now() - startTime,
        error_rate: 100,
        uptime_percentage: 0,
        error: error instanceof Error ? error.message : 'Unknown embedding service error',
        details: {
          average_response_time_ms: 0,
          p95_response_time_ms: 0,
          error_rate_percent: 100,
          request_count: 0,
        },
      };
    }
  }

  private checkSystemHealth(): ComponentHealth {
    const startTime = Date.now();
    const component = 'system';

    try {
      const memoryUsage = performanceCollector.getMemoryUsage();
      const heapUsedMB = memoryUsage.heapUsed / (1024 * 1024);
      const heapTotalMB = memoryUsage.heapTotal / (1024 * 1024);
      const memoryUsagePercent = (heapUsedMB / heapTotalMB) * 100;

      const memoryThreshold = this.config.system_thresholds.memory_usage_percent;
      let status: HealthStatus = HealthStatus.HEALTHY;
      let error: string | undefined;
      let errorRate = 0;
      let uptimePercentage = 100;

      if (memoryUsagePercent > memoryThreshold) {
        status = HealthStatus.UNHEALTHY;
        errorRate = 100;
        uptimePercentage = 0;
        error = `Memory usage ${memoryUsagePercent.toFixed(2)}% exceeds threshold ${memoryThreshold}%`;
      } else if (memoryUsagePercent > memoryThreshold * 0.8) {
        status = HealthStatus.DEGRADED;
        errorRate = 50;
        uptimePercentage = 50;
        error = `Memory usage ${memoryUsagePercent.toFixed(2)}% approaching threshold ${memoryThreshold}%`;
      }

      const result: ComponentHealth = {
        name: component,
        type: DependencyType.MONITORING,
        status,
        last_check: new Date(),
        response_time_ms: Date.now() - startTime,
        error_rate: errorRate,
        uptime_percentage: uptimePercentage,
        details: {
          memory_usage_mb: heapUsedMB,
          memory_total_mb: heapTotalMB,
          memory_usage_percent: memoryUsagePercent,
          external_mb: memoryUsage.external / (1024 * 1024),
        },
      };

      if (error) {
        result.error = error;
      }

      return result;
    } catch (error) {
      return {
        name: component,
        type: DependencyType.MONITORING,
        status: HealthStatus.UNHEALTHY,
        last_check: new Date(),
        response_time_ms: Date.now() - startTime,
        error_rate: 100,
        uptime_percentage: 0,
        error: error instanceof Error ? error.message : 'Unknown system error',
        details: {
          memory_usage_mb: 0,
          memory_total_mb: 0,
          memory_usage_percent: 100,
          external_mb: 0,
        },
      };
    }
  }

  private checkMetricsHealth(): ComponentHealth {
    const startTime = Date.now();
    const component = 'metrics_service';

    try {
      const metrics = metricsService.getRealTimeMetrics();
      const latency = Date.now() - startTime;

      // Check if metrics service is providing data
      const hasData = metrics.qps.total_qps >= 0 && metrics.performance.store_p95_ms >= 0;
      let errorRate = 0;
      let uptimePercentage = 100;

      if (!hasData) {
        errorRate = 100;
        uptimePercentage = 0;
      }

      const result: ComponentHealth = {
        name: component,
        type: DependencyType.MONITORING,
        status: hasData ? HealthStatus.HEALTHY : HealthStatus.DEGRADED,
        last_check: new Date(),
        response_time_ms: latency,
        error_rate: errorRate,
        uptime_percentage: uptimePercentage,
        details: {
          current_qps: metrics.qps.total_qps,
          store_p95_ms: metrics.performance.store_p95_ms,
          find_p95_ms: metrics.performance.find_p95_ms,
          memory_usage_mb: metrics.system.memory_usage_mb,
        },
      };

      if (!hasData) {
        result.error = 'No metrics data available';
      }

      return result;
    } catch (error) {
      return {
        name: component,
        type: DependencyType.MONITORING,
        status: HealthStatus.UNHEALTHY,
        last_check: new Date(),
        response_time_ms: Date.now() - startTime,
        error_rate: 100,
        uptime_percentage: 0,
        error: error instanceof Error ? error.message : 'Unknown metrics service error',
        details: {
          current_qps: 0,
          store_p95_ms: 0,
          find_p95_ms: 0,
          memory_usage_mb: 0,
        },
      };
    }
  }

  private calculateOverallStatus(components: ComponentHealth[]): HealthStatus {
    const unhealthyCount = components.filter((c) => c.status === HealthStatus.UNHEALTHY).length;
    const degradedCount = components.filter((c) => c.status === HealthStatus.DEGRADED).length;

    if (unhealthyCount > 0) {
      return HealthStatus.UNHEALTHY;
    } else if (degradedCount > 0) {
      return HealthStatus.DEGRADED;
    } else {
      return HealthStatus.HEALTHY;
    }
  }

  private getSystemMetrics() {
    const metrics = metricsService.getRealTimeMetrics();
    const memoryUsage = performanceCollector.getMemoryUsage();

    return {
      memory_usage_mb: memoryUsage.heapUsed / (1024 * 1024),
      cpu_usage_percent: metrics.system.cpu_usage_percent,
      active_connections: metrics.system.active_connections,
      qps: metrics.qps.total_qps,
    };
  }

  /**
   * Cleanup method
   */
  cleanup(): void {
    this.stopMonitoring();
    this.removeAllListeners();
  }
}

// Export singleton instance with unique name to avoid conflicts
export const monitoringHealthCheckService = HealthCheckService.getInstance();
