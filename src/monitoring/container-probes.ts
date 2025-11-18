// EMERGENCY ROLLBACK: Monitoring system type compatibility issues

/**
 * Container-Ready Probes for Kubernetes/Docker Orchestration
 *
 * Implements Kubernetes/Docker compatible readiness and liveness probes
 * with comprehensive health checks, proper HTTP status codes, and detailed
 * diagnostics for container orchestration platforms.
 *
 * @author Cortex Team
 * @version 2.0.1
 */

import { type Request, type Response } from 'express';

import { logger } from '@/utils/logger.js';

import { mcpServerHealthMonitor } from './mcp-server-health-monitor.js';
import { circuitBreakerManager } from '../services/circuit-breaker.service.js';
import { HealthStatus } from '../types/unified-health-interfaces.js';

/**
 * Probe configuration
 */
export interface ContainerProbeConfig {
  // Readiness probe configuration
  readiness: {
    enabled: boolean;
    path: string;
    initialDelaySeconds: number;
    periodSeconds: number;
    timeoutSeconds: number;
    failureThreshold: number;
    successThreshold: number;
    minHealthyComponents: number;
    allowDegradedReadiness: boolean;
    requireQdrantConnection: boolean;
    requireCircuitBreakersClosed: boolean;
  };

  // Liveness probe configuration
  liveness: {
    enabled: boolean;
    path: string;
    initialDelaySeconds: number;
    periodSeconds: number;
    timeoutSeconds: number;
    failureThreshold: number;
    successThreshold: number;
    maxStartupTimeSeconds: number;
    responseTimeThreshold: number;
    memoryThresholdPercent: number;
  };

  // Startup probe configuration
  startup: {
    enabled: boolean;
    path: string;
    initialDelaySeconds: number;
    periodSeconds: number;
    timeoutSeconds: number;
    failureThreshold: number;
    successThreshold: number;
    maxStartupTimeSeconds: number;
  };

  // Additional health checks
  additionalChecks: {
    diskSpaceCheck: boolean;
    memoryPressureCheck: boolean;
    eventLoopCheck: boolean;
    mcpProtocolCheck: boolean;
  };
}

/**
 * Probe result
 */
export interface ProbeResult {
  success: boolean;
  status: number;
  message: string;
  timestamp: Date;
  duration: number;
  details: {
    uptime: number;
    memoryUsage: number;
    responseTime: number;
    componentHealth: Record<
      string,
      {
        status: HealthStatus;
        responseTime: number;
        error?: string;
      }
    >;
    circuitBreakerStates: Record<
      string,
      {
        state: string;
        isOpen: boolean;
        failureRate: number;
      }
    >;
  };
}

/**
 * Container health state
 */
export interface ContainerHealthState {
  isReady: boolean;
  isAlive: boolean;
  isStarted: boolean;
  startTime: number;
  readyTime: number | null;
  lastReadyCheck: Date | null;
  lastAliveCheck: Date | null;
  readyCheckCount: number;
  aliveCheckCount: number;
  consecutiveReadinessFailures: number;
  consecutiveLivenessFailures: number;
}

/**
 * Container-Ready Probes Handler
 */
export class ContainerProbesHandler {
  private config: ContainerProbeConfig;
  private healthState: ContainerHealthState;
  private startTime: number;

  constructor(config?: Partial<ContainerProbeConfig>) {
    this.config = {
      readiness: {
        enabled: true,
        path: '/ready',
        initialDelaySeconds: 10,
        periodSeconds: 5,
        timeoutSeconds: 3,
        failureThreshold: 3,
        successThreshold: 1,
        minHealthyComponents: 2,
        allowDegradedReadiness: true,
        requireQdrantConnection: true,
        requireCircuitBreakersClosed: false,
      },
      liveness: {
        enabled: true,
        path: '/health/live',
        initialDelaySeconds: 30,
        periodSeconds: 10,
        timeoutSeconds: 5,
        failureThreshold: 3,
        successThreshold: 1,
        maxStartupTimeSeconds: 120,
        responseTimeThreshold: 5000,
        memoryThresholdPercent: 95,
      },
      startup: {
        enabled: true,
        path: '/startup',
        initialDelaySeconds: 0,
        periodSeconds: 10,
        timeoutSeconds: 5,
        failureThreshold: 30,
        successThreshold: 1,
        maxStartupTimeSeconds: 120,
      },
      additionalChecks: {
        diskSpaceCheck: true,
        memoryPressureCheck: true,
        eventLoopCheck: true,
        mcpProtocolCheck: true,
      },
      ...config,
    };

    this.startTime = Date.now();
    this.healthState = this.getInitialHealthState();
  }

  /**
   * Get current health state
   */
  getHealthState(): ContainerHealthState {
    return { ...this.healthState };
  }

  /**
   * Readiness probe handler
   */
  async readinessProbe(req: Request, res: Response): Promise<void> {
    if (!this.config.readiness.enabled) {
      res.status(404).json({
        error: 'Not Found',
        message: 'Readiness probe is disabled',
      });
      return;
    }

    const startTime = Date.now();

    try {
      const result = await this.performReadinessCheck();
      const duration = Date.now() - startTime;

      this.healthState.lastReadyCheck = new Date();
      this.healthState.readyCheckCount++;

      if (result.success) {
        this.healthState.isReady = true;
        this.healthState.consecutiveReadinessFailures = 0;

        if (!this.healthState.readyTime) {
          this.healthState.readyTime = Date.now();
        }

        res.status(200).json({
          status: 'ready',
          timestamp: result.timestamp.toISOString(),
          duration,
          uptime: result.details.uptime,
          checks: result.details.componentHealth,
          message: result.message,
        });
      } else {
        this.healthState.isReady = false;
        this.healthState.consecutiveReadinessFailures++;

        logger.warn(
          {
            message: result.message,
            duration,
            consecutiveFailures: this.healthState.consecutiveReadinessFailures,
            componentHealth: result.details.componentHealth,
          },
          'Readiness probe failed'
        );

        res.status(503).json({
          status: 'not-ready',
          timestamp: result.timestamp.toISOString(),
          duration,
          uptime: result.details.uptime,
          checks: result.details.componentHealth,
          message: result.message,
          consecutiveFailures: this.healthState.consecutiveReadinessFailures,
        });
      }
    } catch (error) {
      const duration = Date.now() - startTime;
      this.healthState.isReady = false;
      this.healthState.consecutiveReadinessFailures++;

      logger.error(
        {
          error: error instanceof Error ? error.message : 'Unknown error',
          duration,
          consecutiveFailures: this.healthState.consecutiveReadinessFailures,
        },
        'Readiness probe error'
      );

      res.status(503).json({
        status: 'not-ready',
        timestamp: new Date().toISOString(),
        duration,
        error: 'Readiness check failed',
        message: error instanceof Error ? error.message : 'Unknown error',
        consecutiveFailures: this.healthState.consecutiveReadinessFailures,
      });
    }
  }

  /**
   * Liveness probe handler
   */
  async livenessProbe(req: Request, res: Response): Promise<void> {
    if (!this.config.liveness.enabled) {
      res.status(404).json({
        error: 'Not Found',
        message: 'Liveness probe is disabled',
      });
      return;
    }

    const startTime = Date.now();

    try {
      const result = await this.performLivenessCheck();
      const duration = Date.now() - startTime;

      this.healthState.lastAliveCheck = new Date();
      this.healthState.aliveCheckCount++;

      if (result.success) {
        this.healthState.isAlive = true;
        this.healthState.consecutiveLivenessFailures = 0;

        res.status(200).json({
          status: 'alive',
          timestamp: result.timestamp.toISOString(),
          duration,
          uptime: result.details.uptime,
          memoryUsage: result.details.memoryUsage,
          responseTime: result.details.responseTime,
          message: result.message,
        });
      } else {
        this.healthState.isAlive = false;
        this.healthState.consecutiveLivenessFailures++;

        logger.error(
          {
            message: result.message,
            duration,
            uptime: result.details.uptime,
            memoryUsage: result.details.memoryUsage,
            consecutiveFailures: this.healthState.consecutiveLivenessFailures,
          },
          'Liveness probe failed'
        );

        res.status(503).json({
          status: 'not-alive',
          timestamp: result.timestamp.toISOString(),
          duration,
          uptime: result.details.uptime,
          memoryUsage: result.details.memoryUsage,
          responseTime: result.details.responseTime,
          message: result.message,
          consecutiveFailures: this.healthState.consecutiveLivenessFailures,
        });
      }
    } catch (error) {
      const duration = Date.now() - startTime;
      this.healthState.isAlive = false;
      this.healthState.consecutiveLivenessFailures++;

      logger.error(
        {
          error: error instanceof Error ? error.message : 'Unknown error',
          duration,
          consecutiveFailures: this.healthState.consecutiveLivenessFailures,
        },
        'Liveness probe error'
      );

      res.status(503).json({
        status: 'not-alive',
        timestamp: new Date().toISOString(),
        duration,
        error: 'Liveness check failed',
        message: error instanceof Error ? error.message : 'Unknown error',
        consecutiveFailures: this.healthState.consecutiveLivenessFailures,
      });
    }
  }

  /**
   * Startup probe handler
   */
  async startupProbe(req: Request, res: Response): Promise<void> {
    if (!this.config.startup.enabled) {
      res.status(404).json({
        error: 'Not Found',
        message: 'Startup probe is disabled',
      });
      return;
    }

    const startTime = Date.now();

    try {
      const result = await this.performStartupCheck();
      const duration = Date.now() - startTime;

      if (result.success) {
        this.healthState.isStarted = true;

        res.status(200).json({
          status: 'started',
          timestamp: result.timestamp.toISOString(),
          duration,
          uptime: result.details.uptime,
          message: result.message,
        });
      } else {
        res.status(503).json({
          status: 'starting',
          timestamp: result.timestamp.toISOString(),
          duration,
          uptime: result.details.uptime,
          message: result.message,
        });
      }
    } catch (error) {
      const duration = Date.now() - startTime;

      res.status(503).json({
        status: 'starting',
        timestamp: new Date().toISOString(),
        duration,
        error: 'Startup check failed',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  /**
   * Perform readiness check
   */
  private async performReadinessCheck(): Promise<ProbeResult> {
    const startTime = Date.now();
    const uptime = Date.now() - this.startTime;
    const memUsage = process.memoryUsage();
    const memoryUsagePercent = (memUsage.heapUsed / memUsage.heapTotal) * 100;

    const componentHealth: Record<
      string,
      {
        status: HealthStatus;
        responseTime: number;
        error?: string;
      }
    > = {};

    const issues: string[] = [];
    let isReady = true;

    // Check MCP server health
    const mcpStartTime = Date.now();
    const mcpStatus = mcpServerHealthMonitor.getCurrentStatus();
    const mcpMetrics = mcpServerHealthMonitor.getCurrentMetrics();
    componentHealth['mcp-server'] = {
      status: mcpStatus,
      responseTime: Date.now() - mcpStartTime,
    };

    if (!this.config.readiness.allowDegradedReadiness && mcpStatus !== HealthStatus.HEALTHY) {
      isReady = false;
      issues.push(`MCP server status: ${mcpStatus}`);
    } else if (mcpStatus === HealthStatus.UNHEALTHY) {
      isReady = false;
      issues.push(`MCP server is unhealthy: ${mcpStatus}`);
    }

    // Check Qdrant connection if required
    if (this.config.readiness.requireQdrantConnection) {
      const qdrantStartTime = Date.now();
      const qdrantStatus = this.checkQdrantConnection();
      componentHealth['qdrant'] = {
        status: qdrantStatus.status,
        responseTime: Date.now() - qdrantStartTime,
        error: qdrantStatus.error,
      };

      if (qdrantStatus.status !== HealthStatus.HEALTHY) {
        isReady = false;
        issues.push(`Qdrant connection: ${qdrantStatus.error || qdrantStatus.status}`);
      }
    }

    // Check circuit breakers if required
    if (this.config.readiness.requireCircuitBreakersClosed) {
      const circuitStats = circuitBreakerManager.getAllStats();
      const openCircuits = Object.entries(circuitStats).filter(([name, stats]) => stats.isOpen);

      for (const [name, stats] of Object.entries(circuitStats)) {
        componentHealth[`circuit-breaker-${name}`] = {
          status: stats.isOpen ? HealthStatus.UNHEALTHY : HealthStatus.HEALTHY,
          responseTime: 0,
        };
      }

      if (openCircuits.length > 0) {
        isReady = false;
        issues.push(`Open circuit breakers: ${openCircuits.map(([name]) => name).join(', ')}`);
      }
    }

    // Check minimum healthy components
    const healthyComponents = Object.values(componentHealth).filter(
      (c) => c.status === HealthStatus.HEALTHY
    ).length;
    if (healthyComponents < this.config.readiness.minHealthyComponents) {
      isReady = false;
      issues.push(
        `Insufficient healthy components: ${healthyComponents}/${this.config.readiness.minHealthyComponents}`
      );
    }

    // Additional checks
    if (this.config.additionalChecks.diskSpaceCheck) {
      const diskCheck = await this.checkDiskSpace();
      if (diskCheck.status !== HealthStatus.HEALTHY) {
        isReady = false;
        issues.push(`Disk space: ${diskCheck.error}`);
      }
      componentHealth['disk-space'] = {
        status: diskCheck.status,
        responseTime: diskCheck.responseTime,
        error: diskCheck.error,
      };
    }

    if (this.config.additionalChecks.memoryPressureCheck) {
      const memoryCheck = this.checkMemoryPressure(memoryUsagePercent);
      if (memoryCheck.status !== HealthStatus.HEALTHY) {
        isReady = false;
        issues.push(`Memory pressure: ${memoryCheck.error}`);
      }
      componentHealth['memory-pressure'] = {
        status: memoryCheck.status,
        responseTime: memoryCheck.responseTime,
        error: memoryCheck.error,
      };
    }

    if (this.config.additionalChecks.eventLoopCheck) {
      const eventLoopCheck = await this.checkEventLoopHealth();
      if (eventLoopCheck.status !== HealthStatus.HEALTHY) {
        isReady = false;
        issues.push(`Event loop: ${eventLoopCheck.error}`);
      }
      componentHealth['event-loop'] = {
        status: eventLoopCheck.status,
        responseTime: eventLoopCheck.responseTime,
        error: eventLoopCheck.error,
      };
    }

    const duration = Date.now() - startTime;

    return {
      success: isReady,
      status: isReady ? 200 : 503,
      message: isReady ? 'Service is ready' : `Service not ready: ${issues.join(', ')}`,
      timestamp: new Date(),
      duration,
      details: {
        uptime,
        memoryUsage: memoryUsagePercent,
        responseTime: duration,
        componentHealth,
        circuitBreakerStates: circuitBreakerManager.getAllStats(),
      },
    };
  }

  /**
   * Perform liveness check
   */
  private async performLivenessCheck(): Promise<ProbeResult> {
    const startTime = Date.now();
    const uptime = Date.now() - this.startTime;
    const memUsage = process.memoryUsage();
    const memoryUsagePercent = (memUsage.heapUsed / memUsage.heapTotal) * 100;

    const issues: string[] = [];
    let isAlive = true;

    // Check if process is responsive
    const responseTime = Date.now() - startTime;
    if (responseTime > this.config.liveness.responseTimeThreshold) {
      isAlive = false;
      issues.push(`Response time too high: ${responseTime}ms`);
    }

    // Check memory usage
    if (memoryUsagePercent > this.config.liveness.memoryThresholdPercent) {
      isAlive = false;
      issues.push(`Memory usage too high: ${memoryUsagePercent.toFixed(2)}%`);
    }

    // Check if we've been running long enough
    if (uptime < this.config.liveness.initialDelaySeconds * 1000) {
      isAlive = false;
      issues.push('Service still starting up');
    }

    // Check event loop
    if (this.config.additionalChecks.eventLoopCheck) {
      const eventLoopCheck = await this.checkEventLoopHealth();
      if (eventLoopCheck.status === HealthStatus.CRITICAL) {
        isAlive = false;
        issues.push(`Event loop critical: ${eventLoopCheck.error}`);
      }
    }

    return {
      success: isAlive,
      status: isAlive ? 200 : 503,
      message: isAlive ? 'Service is alive' : `Service not alive: ${issues.join(', ')}`,
      timestamp: new Date(),
      duration: responseTime,
      details: {
        uptime,
        memoryUsage: memoryUsagePercent,
        responseTime,
        componentHealth: {},
        circuitBreakerStates: {},
      },
    };
  }

  /**
   * Perform startup check
   */
  private async performStartupCheck(): Promise<ProbeResult> {
    const startTime = Date.now();
    const uptime = Date.now() - this.startTime;
    const maxStartupTime = this.config.startup.maxStartupTimeSeconds * 1000;

    // Check if we've exceeded startup time
    if (uptime > maxStartupTime) {
      return {
        success: false,
        status: 503,
        message: `Startup timeout exceeded: ${uptime}ms > ${maxStartupTime}ms`,
        timestamp: new Date(),
        duration: Date.now() - startTime,
        details: {
          uptime,
          memoryUsage: 0,
          responseTime: Date.now() - startTime,
          componentHealth: {},
          circuitBreakerStates: {},
        },
      };
    }

    // Check if basic services are initialized
    const isStarted = this.checkBasicServicesInitialized();

    return {
      success: isStarted,
      status: isStarted ? 200 : 503,
      message: isStarted ? 'Service has started' : 'Service still starting',
      timestamp: new Date(),
      duration: Date.now() - startTime,
      details: {
        uptime,
        memoryUsage: 0,
        responseTime: Date.now() - startTime,
        componentHealth: {},
        circuitBreakerStates: {},
      },
    };
  }

  /**
   * Check Qdrant connection
   */
  private checkQdrantConnection(): { status: HealthStatus; error?: string } {
    try {
      const circuitStats = circuitBreakerManager.getAllStats().qdrant;
      if (!circuitStats) {
        return { status: HealthStatus.UNKNOWN, error: 'Qdrant circuit breaker not found' };
      }

      if (circuitStats.isOpen) {
        return { status: HealthStatus.UNHEALTHY, error: 'Qdrant circuit breaker is open' };
      }

      if (circuitStats.failureRate > 0.5) {
        return { status: HealthStatus.DEGRADED, error: 'High Qdrant failure rate' };
      }

      return { status: HealthStatus.HEALTHY };
    } catch (error) {
      return {
        status: HealthStatus.UNHEALTHY,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Check disk space
   */
  private async checkDiskSpace(): Promise<{
    status: HealthStatus;
    responseTime: number;
    error?: string;
  }> {
    const startTime = Date.now();

    try {
      // This is a simplified check - in practice, you'd check actual disk usage
      const hasSpace = true; // Placeholder

      return {
        status: hasSpace ? HealthStatus.HEALTHY : HealthStatus.UNHEALTHY,
        responseTime: Date.now() - startTime,
        error: hasSpace ? undefined : 'Insufficient disk space',
      };
    } catch (error) {
      return {
        status: HealthStatus.UNHEALTHY,
        responseTime: Date.now() - startTime,
        error: error instanceof Error ? error.message : 'Unknown disk check error',
      };
    }
  }

  /**
   * Check memory pressure
   */
  private checkMemoryPressure(memoryUsagePercent: number): {
    status: HealthStatus;
    responseTime: number;
    error?: string;
  } {
    const startTime = Date.now();

    if (memoryUsagePercent > 95) {
      return {
        status: HealthStatus.CRITICAL,
        responseTime: Date.now() - startTime,
        error: `Critical memory usage: ${memoryUsagePercent.toFixed(2)}%`,
      };
    } else if (memoryUsagePercent > 85) {
      return {
        status: HealthStatus.WARNING,
        responseTime: Date.now() - startTime,
        error: `High memory usage: ${memoryUsagePercent.toFixed(2)}%`,
      };
    }

    return {
      status: HealthStatus.HEALTHY,
      responseTime: Date.now() - startTime,
    };
  }

  /**
   * Check event loop health
   */
  private async checkEventLoopHealth(): Promise<{ status: HealthStatus; responseTime: number; error?: string }> {
    const startTime = Date.now();
    const start = process.hrtime.bigint();

    return new Promise((resolve) => {
      setImmediate(() => {
        const lag = Number(process.hrtime.bigint() - start) / 1000000; // Convert to milliseconds

        if (lag > 100) {
          resolve({
            status: HealthStatus.CRITICAL,
            responseTime: Date.now() - startTime,
            error: `Critical event loop lag: ${lag.toFixed(2)}ms`,
          });
        } else if (lag > 50) {
          resolve({
            status: HealthStatus.WARNING,
            responseTime: Date.now() - startTime,
            error: `High event loop lag: ${lag.toFixed(2)}ms`,
          });
        } else {
          resolve({
            status: HealthStatus.HEALTHY,
            responseTime: Date.now() - startTime,
          });
        }
      });
    });
  }

  /**
   * Check if basic services are initialized
   */
  private checkBasicServicesInitialized(): boolean {
    // Check if critical components are ready
    const uptime = Date.now() - this.startTime;
    const minStartupTime = 5000; // 5 seconds minimum startup time

    if (uptime < minStartupTime) {
      return false;
    }

    // Check if MCP server is responsive
    const mcpStatus = mcpServerHealthMonitor.getCurrentStatus();
    if (mcpStatus === HealthStatus.UNKNOWN) {
      return false;
    }

    return true;
  }

  /**
   * Get initial health state
   */
  private getInitialHealthState(): ContainerHealthState {
    return {
      isReady: false,
      isAlive: false,
      isStarted: false,
      startTime: Date.now(),
      readyTime: null,
      lastReadyCheck: null,
      lastAliveCheck: null,
      readyCheckCount: 0,
      aliveCheckCount: 0,
      consecutiveReadinessFailures: 0,
      consecutiveLivenessFailures: 0,
    };
  }

  /**
   * Get Kubernetes pod spec for probes
   */
  getKubernetesPodSpec(): unknown {
    return {
      containers: [
        {
          name: 'cortex-mcp',
          image: 'cortex-mcp:latest',
          ports: [{ containerPort: 3000 }],
          livenessProbe: this.config.liveness.enabled
            ? {
                httpGet: {
                  path: this.config.liveness.path,
                  port: 3000,
                },
                initialDelaySeconds: this.config.liveness.initialDelaySeconds,
                periodSeconds: this.config.liveness.periodSeconds,
                timeoutSeconds: this.config.liveness.timeoutSeconds,
                failureThreshold: this.config.liveness.failureThreshold,
                successThreshold: this.config.liveness.successThreshold,
              }
            : undefined,
          readinessProbe: this.config.readiness.enabled
            ? {
                httpGet: {
                  path: this.config.readiness.path,
                  port: 3000,
                },
                initialDelaySeconds: this.config.readiness.initialDelaySeconds,
                periodSeconds: this.config.readiness.periodSeconds,
                timeoutSeconds: this.config.readiness.timeoutSeconds,
                failureThreshold: this.config.readiness.failureThreshold,
                successThreshold: this.config.readiness.successThreshold,
              }
            : undefined,
          startupProbe: this.config.startup.enabled
            ? {
                httpGet: {
                  path: this.config.startup.path,
                  port: 3000,
                },
                initialDelaySeconds: this.config.startup.initialDelaySeconds,
                periodSeconds: this.config.startup.periodSeconds,
                timeoutSeconds: this.config.startup.timeoutSeconds,
                failureThreshold: this.config.startup.failureThreshold,
                successThreshold: this.config.startup.successThreshold,
              }
            : undefined,
        },
      ],
    };
  }

  /**
   * Get Docker health check configuration
   */
  getDockerHealthCheck(): unknown {
    if (!this.config.liveness.enabled) {
      return undefined;
    }

    return {
      test: [`CMD-SHELL`, `curl -f http://localhost:3000${this.config.liveness.path} || exit 1`],
      interval: `${this.config.liveness.periodSeconds}s`,
      timeout: `${this.config.liveness.timeoutSeconds}s`,
      retries: this.config.liveness.failureThreshold,
      startPeriod: `${this.config.liveness.initialDelaySeconds}s`,
    };
  }
}

// Export singleton instance
export const containerProbesHandler = new ContainerProbesHandler();
