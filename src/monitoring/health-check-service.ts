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

import { logger } from '../utils/logger.js';
import { EmbeddingService } from '../services/embeddings/embedding-service.js';
import { performanceCollector } from './performance-collector.js';
import { metricsService } from './metrics-service.js';
import { EventEmitter } from 'events';

/**
 * Health status levels
 */
export type HealthStatus = 'healthy' | 'degraded' | 'unhealthy';

/**
 * Individual component health check result
 */
export interface ComponentHealth {
  component: string;
  status: HealthStatus;
  latency_ms: number;
  error?: string;
  details: Record<string, any> | undefined;
  timestamp: number;
}

/**
 * Overall system health check result
 */
export interface HealthCheckResult {
  status: HealthStatus;
  timestamp: number;
  uptime_seconds: number;
  version: string;
  components: ComponentHealth[];
  system_metrics: {
    memory_usage_mb: number;
    cpu_usage_percent: number;
    active_connections: number;
    qps: number;
  };
  summary: {
    total_components: number;
    healthy_components: number;
    degraded_components: number;
    unhealthy_components: number;
  };
}

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
  private healthStatus: HealthCheckResult | null = null;
  private checkInterval: NodeJS.Timeout | null = null;
  private isShuttingDown = false;

  // Service instances
  private embeddingService: EmbeddingService;

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
    if (!(healthCheckService as any).instance) {
      (healthCheckService as any).instance = new HealthCheckService(config);
    }
    return (healthCheckService as any).instance;
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
  getHealthStatus(): HealthCheckResult | null {
    return this.healthStatus;
  }

  /**
   * Perform comprehensive health check
   */
  async performHealthCheck(): Promise<HealthCheckResult> {
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
    const healthResult: HealthCheckResult = {
      status: overallStatus,
      timestamp: Date.now(),
      uptime_seconds: uptimeSeconds,
      version: process.env.npm_package_version || '2.0.0',
      components,
      system_metrics: systemMetrics,
      summary: {
        total_components: components.length,
        healthy_components: components.filter(c => c.status === 'healthy').length,
        degraded_components: components.filter(c => c.status === 'degraded').length,
        unhealthy_components: components.filter(c => c.status === 'unhealthy').length,
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
      ? health.summary.healthy_components + health.summary.degraded_components >= this.config.readiness_checks.min_healthy_components
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
      status: alive ? 'healthy' : 'unhealthy',
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
      uptime_seconds: this.healthStatus.uptime_seconds,
      last_check_timestamp: this.healthStatus.timestamp,
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
          component,
          status: 'degraded',
          latency_ms: latency,
          error: 'No database metrics available',
          details: {
            average_latency_ms: 0,
            p95_latency_ms: 0,
            error_rate_percent: 100,
            query_count: 0,
          },
          timestamp: Date.now(),
        };
      }

      const errorRate = 100 - dbSummary.successRate;
      const latencyThreshold = this.config.latency_thresholds.database_ms;
      const errorThreshold = this.config.error_rate_thresholds.database;

      let status: HealthStatus = 'healthy';
      let error: string | undefined;

      if (errorRate > errorThreshold) {
        status = 'unhealthy';
        error = `Error rate ${errorRate}% exceeds threshold ${errorThreshold}%`;
      } else if (dbSummary.averageDuration > latencyThreshold) {
        status = 'degraded';
        error = `Latency ${dbSummary.averageDuration}ms exceeds threshold ${latencyThreshold}ms`;
      }

      const result: ComponentHealth = {
        component,
        status,
        latency_ms: latency,
        details: {
          average_latency_ms: dbSummary.averageDuration,
          p95_latency_ms: dbSummary.p95,
          error_rate_percent: errorRate,
          query_count: dbSummary.count,
        },
        timestamp: Date.now(),
      };

      if (error) {
        result.error = error;
      }

      return result;
    } catch (error) {
      return {
        component,
        status: 'unhealthy',
        latency_ms: Date.now() - startTime,
        error: error instanceof Error ? error.message : 'Unknown database error',
        details: {
          average_latency_ms: 0,
          p95_latency_ms: 0,
          error_rate_percent: 100,
          query_count: 0,
        },
        timestamp: Date.now(),
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
          component,
          status: 'degraded',
          latency_ms: latency,
          error: 'No Qdrant metrics available',
          details: {
            average_latency_ms: 0,
            p95_latency_ms: 0,
            error_rate_percent: 100,
            search_count: 0,
          },
          timestamp: Date.now(),
        };
      }

      const errorRate = 100 - qdrantSummary.successRate;
      const latencyThreshold = this.config.latency_thresholds.qdrant_ms;
      const errorThreshold = this.config.error_rate_thresholds.qdrant;

      let status: HealthStatus = 'healthy';
      let error: string | undefined;

      if (errorRate > errorThreshold) {
        status = 'unhealthy';
        error = `Error rate ${errorRate}% exceeds threshold ${errorThreshold}%`;
      } else if (qdrantSummary.averageDuration > latencyThreshold) {
        status = 'degraded';
        error = `Latency ${qdrantSummary.averageDuration}ms exceeds threshold ${latencyThreshold}ms`;
      }

      const result: ComponentHealth = {
        component,
        status,
        latency_ms: latency,
        details: {
          average_latency_ms: qdrantSummary.averageDuration,
          p95_latency_ms: qdrantSummary.p95,
          error_rate_percent: errorRate,
          search_count: qdrantSummary.count,
        },
        timestamp: Date.now(),
      };

      if (error) {
        result.error = error;
      }

      return result;
    } catch (error) {
      return {
        component,
        status: 'unhealthy',
        latency_ms: Date.now() - startTime,
        error: error instanceof Error ? error.message : 'Unknown Qdrant error',
        details: {
          average_latency_ms: 0,
          p95_latency_ms: 0,
          error_rate_percent: 100,
          search_count: 0,
        },
        timestamp: Date.now(),
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

      let status: HealthStatus = isHealthy ? 'healthy' : 'unhealthy';
      let error: string | undefined;

      if (embeddingSummary) {
        const errorRate = 100 - embeddingSummary.successRate;

        if (errorRate > errorThreshold) {
          status = 'unhealthy';
          error = `Error rate ${errorRate}% exceeds threshold ${errorThreshold}%`;
        } else if (embeddingSummary.averageDuration > latencyThreshold) {
          status = 'degraded';
          error = `Latency ${embeddingSummary.averageDuration}ms exceeds threshold ${latencyThreshold}ms`;
        }
      }

      const result: ComponentHealth = {
        component,
        status,
        latency_ms: latency,
        details: embeddingSummary ? {
          average_latency_ms: embeddingSummary.averageDuration,
          p95_latency_ms: embeddingSummary.p95,
          error_rate_percent: 100 - embeddingSummary.successRate,
          request_count: embeddingSummary.count,
        } : undefined,
        timestamp: Date.now(),
      };

      if (error) {
        result.error = error;
      }

      return result;
    } catch (error) {
      return {
        component,
        status: 'unhealthy',
        latency_ms: Date.now() - startTime,
        error: error instanceof Error ? error.message : 'Unknown embedding service error',
        details: {
          average_latency_ms: 0,
          p95_latency_ms: 0,
          error_rate_percent: 100,
          request_count: 0,
        },
        timestamp: Date.now(),
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
      let status: HealthStatus = 'healthy';
      let error: string | undefined;

      if (memoryUsagePercent > memoryThreshold) {
        status = 'unhealthy';
        error = `Memory usage ${memoryUsagePercent.toFixed(2)}% exceeds threshold ${memoryThreshold}%`;
      } else if (memoryUsagePercent > memoryThreshold * 0.8) {
        status = 'degraded';
        error = `Memory usage ${memoryUsagePercent.toFixed(2)}% approaching threshold ${memoryThreshold}%`;
      }

      const result: ComponentHealth = {
        component,
        status,
        latency_ms: Date.now() - startTime,
        details: {
          memory_usage_mb: heapUsedMB,
          memory_total_mb: heapTotalMB,
          memory_usage_percent: memoryUsagePercent,
          external_mb: memoryUsage.external / (1024 * 1024),
        },
        timestamp: Date.now(),
      };

      if (error) {
        result.error = error;
      }

      return result;
    } catch (error) {
      return {
        component,
        status: 'unhealthy',
        latency_ms: Date.now() - startTime,
        error: error instanceof Error ? error.message : 'Unknown system error',
        details: {
          memory_usage_mb: 0,
          memory_total_mb: 0,
          memory_usage_percent: 100,
          external_mb: 0,
        },
        timestamp: Date.now(),
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

      const result: ComponentHealth = {
        component,
        status: hasData ? 'healthy' : 'degraded',
        latency_ms: latency,
        details: {
          current_qps: metrics.qps.total_qps,
          store_p95_ms: metrics.performance.store_p95_ms,
          find_p95_ms: metrics.performance.find_p95_ms,
          memory_usage_mb: metrics.system.memory_usage_mb,
        },
        timestamp: Date.now(),
      };

      if (!hasData) {
        result.error = 'No metrics data available';
      }

      return result;
    } catch (error) {
      return {
        component,
        status: 'unhealthy',
        latency_ms: Date.now() - startTime,
        error: error instanceof Error ? error.message : 'Unknown metrics service error',
        details: {
          current_qps: 0,
          store_p95_ms: 0,
          find_p95_ms: 0,
          memory_usage_mb: 0,
        },
        timestamp: Date.now(),
      };
    }
  }

  private calculateOverallStatus(components: ComponentHealth[]): HealthStatus {
    const unhealthyCount = components.filter(c => c.status === 'unhealthy').length;
    const degradedCount = components.filter(c => c.status === 'degraded').length;

    if (unhealthyCount > 0) {
      return 'unhealthy';
    } else if (degradedCount > 0) {
      return 'degraded';
    } else {
      return 'healthy';
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

// Export singleton instance
export const healthCheckService = HealthCheckService.getInstance();