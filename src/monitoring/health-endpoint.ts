/**
 * Production Health Endpoint
 *
 * RESTful health check endpoints for production monitoring and container orchestration.
 * Provides liveness, readiness, and comprehensive health checks with proper HTTP status codes.
 *
 * @author Cortex Team
 * @version 2.0.1
 */

import { Request, Response, NextFunction } from 'express';
import { ProductionHealthChecker, HealthCheckResult } from './production-health-checker.js';
import { ProductionLogger } from './production-logger.js';

export interface HealthEndpointConfig {
  enableDetailedEndpoints: boolean;
  enableMetricsEndpoint: boolean;
  enableReadinessProbe: boolean;
  enableLivenessProbe: boolean;
  authenticationRequired: boolean;
  allowedIPs: string[];
}

export class HealthEndpointManager {
  private healthChecker: ProductionHealthChecker;
  private logger: ProductionLogger;
  private config: HealthEndpointConfig;
  private lastHealthCheck: HealthCheckResult | null = null;
  private healthCheckCache: Map<string, { result: HealthCheckResult; timestamp: number }> = new Map();
  private readonly CACHE_TTL = 30000; // 30 seconds

  constructor(config?: Partial<HealthEndpointConfig>) {
    this.healthChecker = new ProductionHealthChecker();
    this.logger = new ProductionLogger('health-endpoint');

    this.config = {
      enableDetailedEndpoints: process.env.ENABLE_DETAILED_HEALTH_ENDPOINTS === 'true',
      enableMetricsEndpoint: process.env.ENABLE_METRICS_ENDPOINT === 'true',
      enableReadinessProbe: process.env.ENABLE_READINESS_PROBE !== 'false',
      enableLivenessProbe: process.env.ENABLE_LIVENESS_PROBE !== 'false',
      authenticationRequired: process.env.HEALTH_ENDPOINT_AUTH_REQUIRED === 'true',
      allowedIPs: (process.env.HEALTH_ENDPOINT_ALLOWED_IPS || '').split(',').filter(ip => ip.trim())
    };
  }

  /**
   * Main health check endpoint
   */
  async healthCheck(req: Request, res: Response): Promise<void> {
    try {
      const startTime = Date.now();
      const result = await this.getCachedHealthCheck('comprehensive');
      const duration = Date.now() - startTime;

      // Set appropriate HTTP status code
      const statusCode = this.getHttpStatusCode(result);
      res.status(statusCode);

      // Add cache headers
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('X-Health-Check-Duration', duration.toString());

      // Log health check request
      this.logger.info('Health check requested', {
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        status: result.status,
        duration,
        statusCode
      });

      res.json(result);
    } catch (error) {
      this.logger.error('Health check failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        ip: req.ip
      });

      res.status(503).json({
        status: 'unhealthy',
        timestamp: new Date().toISOString(),
        error: 'Health check service unavailable',
        message: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  /**
   * Liveness probe endpoint
   */
  async livenessProbe(req: Request, res: Response): Promise<Response> {
    try {
      if (!this.config.enableLivenessProbe) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'Liveness probe is disabled'
        });
      }

      const startTime = Date.now();
      const result = await this.getCachedHealthCheck('liveness');
      const duration = Date.now() - startTime;

      const statusCode = result.status === 'healthy' ? 200 : 503;

      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('X-Health-Check-Duration', duration.toString());

      return res.status(statusCode).json({
        status: result.status === 'healthy' ? 'ok' : 'not-healthy',
        timestamp: result.timestamp,
        checks: result.checks.filter(c => c.critical),
        uptime: process.uptime(),
        version: process.env.npm_package_version || '2.0.1'
      });
    } catch (error) {
      return res.status(503).json({
        status: 'not-healthy',
        timestamp: new Date().toISOString(),
        error: 'Liveness probe failed'
      });
    }
  }

  /**
   * Readiness probe endpoint
   */
  async readinessProbe(req: Request, res: Response): Promise<Response> {
    try {
      if (!this.config.enableReadinessProbe) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'Readiness probe is disabled'
        });
      }

      const startTime = Date.now();
      const result = await this.getCachedHealthCheck('readiness');
      const duration = Date.now() - startTime;

      const statusCode = result.status === 'healthy' ? 200 : 503;

      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('X-Health-Check-Duration', duration.toString());

      return res.status(statusCode).json({
        status: result.status === 'healthy' ? 'ready' : 'not-ready',
        timestamp: result.timestamp,
        checks: result.checks.filter(c => c.critical),
        dependencies: {
          qdrant: result.checks.find(c => c.name === 'qdrant-connection')?.status || 'unknown',
          openai: result.checks.find(c => c.name === 'openai-connection')?.status || 'unknown'
        }
      });
    } catch (error) {
      return res.status(503).json({
        status: 'not-ready',
        timestamp: new Date().toISOString(),
        error: 'Readiness probe failed'
      });
    }
  }

  /**
   * Detailed health check endpoint
   */
  async detailedHealthCheck(req: Request, res: Response): Promise<Response> {
    try {
      if (!this.config.enableDetailedEndpoints) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'Detailed health endpoints are disabled'
        });
      }

      const result = await this.healthChecker.performPostStartupHealthCheck();
      const statusCode = this.getHttpStatusCode(result);

      return res.status(statusCode).json({
        ...result,
        system: {
          nodeVersion: process.version,
          platform: process.platform,
          arch: process.arch,
          pid: process.pid,
          uptime: process.uptime(),
          memoryUsage: process.memoryUsage(),
          cpuUsage: process.cpuUsage()
        },
        environment: {
          nodeEnv: process.env.NODE_ENV,
          logLevel: process.env.LOG_LEVEL,
          enableMetrics: process.env.ENABLE_METRICS_COLLECTION === 'true',
          enableDebug: process.env.ENABLE_DEBUG_MODE === 'true'
        }
      });
    } catch (error) {
      this.logger.error('Detailed health check failed', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });

      return res.status(503).json({
        status: 'unhealthy',
        timestamp: new Date().toISOString(),
        error: 'Detailed health check failed',
        message: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  /**
   * Metrics endpoint
   */
  async metrics(req: Request, res: Response): Promise<Response> {
    try {
      if (!this.config.enableMetricsEndpoint) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'Metrics endpoint is disabled'
        });
      }

      const healthResult = await this.getCachedHealthCheck('comprehensive');

      const metrics = {
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: {
          rss: process.memoryUsage().rss,
          heapUsed: process.memoryUsage().heapUsed,
          heapTotal: process.memoryUsage().heapTotal,
          external: process.memoryUsage().external,
          arrayBuffers: process.memoryUsage().arrayBuffers
        },
        cpu: process.cpuUsage(),
        health: {
          status: healthResult.status,
          checks: healthResult.summary,
          lastCheck: healthResult.timestamp
        },
        performance: {
          eventLoopDelay: this.getEventLoopDelay(),
          gcStats: this.getGCStats()
        },
        application: {
          version: process.env.npm_package_version || '2.0.1',
          environment: process.env.NODE_ENV,
          logLevel: process.env.LOG_LEVEL
        }
      };

      res.setHeader('Content-Type', 'application/json');
      return res.json(metrics);
    } catch (error) {
      this.logger.error('Metrics collection failed', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });

      return res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to collect metrics',
        timestamp: new Date().toISOString()
      });
    }
  }

  /**
   * Authentication middleware for health endpoints
   */
  authenticateHealthEndpoint(req: Request, res: Response, next: NextFunction): void {
    // Skip authentication if not required
    if (!this.config.authenticationRequired) {
      next();
      return;
    }

    // Check IP whitelist
    if (this.config.allowedIPs.length > 0) {
      const clientIP = req.ip || req.connection.remoteAddress || '';
      if (!this.config.allowedIPs.includes(clientIP) && !this.config.allowedIPs.includes('*')) {
        this.logger.warn('Health endpoint access denied - IP not whitelisted', {
          ip: clientIP,
          userAgent: req.headers['user-agent']
        });

        res.status(403).json({
          error: 'Forbidden',
          message: 'Access denied from this IP address'
        });
        return;
      }
    }

    // Check for API key if configured
    const requiredApiKey = process.env.HEALTH_ENDPOINT_API_KEY;
    if (requiredApiKey) {
      const providedApiKey = req.headers['x-api-key'] as string;
      if (!providedApiKey || providedApiKey !== requiredApiKey) {
        this.logger.warn('Health endpoint access denied - invalid API key', {
          ip: req.ip,
          userAgent: req.headers['user-agent']
        });

        res.status(401).json({
          error: 'Unauthorized',
          message: 'Valid API key required'
        });
        return;
      }
    }

    next();
  }

  /**
   * Get cached health check result
   */
  private async getCachedHealthCheck(type: string): Promise<HealthCheckResult> {
    const cached = this.healthCheckCache.get(type);
    const now = Date.now();

    if (cached && (now - cached.timestamp) < this.CACHE_TTL) {
      return cached.result;
    }

    // Perform new health check
    let result: HealthCheckResult;
    switch (type) {
      case 'liveness':
        result = await this.healthChecker.livenessProbe();
        break;
      case 'readiness':
        result = await this.healthChecker.readinessProbe();
        break;
      case 'comprehensive':
      default:
        result = await this.healthChecker.performPostStartupHealthCheck();
        break;
    }

    // Cache the result
    this.healthCheckCache.set(type, { result, timestamp: now });

    // Clean up old cache entries
    this.cleanupCache();

    return result;
  }

  /**
   * Clean up old cache entries
   */
  private cleanupCache(): void {
    const now = Date.now();
    for (const [key, value] of this.healthCheckCache.entries()) {
      if (now - value.timestamp > this.CACHE_TTL) {
        this.healthCheckCache.delete(key);
      }
    }
  }

  /**
   * Get appropriate HTTP status code for health check result
   */
  private getHttpStatusCode(result: HealthCheckResult): number {
    switch (result.status) {
      case 'healthy':
        return 200;
      case 'degraded':
        return 200; // Still serving traffic, but with warnings
      case 'unhealthy':
        return 503;
      default:
        return 500;
    }
  }

  /**
   * Get event loop delay (simplified implementation)
   */
  private getEventLoopDelay(): number {
    const start = process.hrtime.bigint();
    setImmediate(() => {
      const delay = Number(process.hrtime.bigint() - start) / 1000000; // Convert to milliseconds
      return delay;
    });
    return 0; // Placeholder - would need more sophisticated implementation
  }

  /**
   * Get GC statistics (simplified implementation)
   */
  private getGCStats(): Record<string, any> {
    // This would require additional monitoring setup
    // For now, return basic memory-based GC estimation
    const memUsage = process.memoryUsage();
    return {
      heapUsedPercent: (memUsage.heapUsed / memUsage.heapTotal) * 100,
      estimatedGCPressure: memUsage.heapUsed / memUsage.heapTotal > 0.8 ? 'high' : 'normal'
    };
  }

  /**
   * Setup all health endpoints
   */
  setupEndpoints(app: any): void {
    // Main health check endpoint
    app.get('/health', this.authenticateHealthEndpoint.bind(this), this.healthCheck.bind(this));

    // Kubernetes/Docker-style probes
    app.get('/health/live', this.authenticateHealthEndpoint.bind(this), this.livenessProbe.bind(this));
    app.get('/health/ready', this.authenticateHealthEndpoint.bind(this), this.readinessProbe.bind(this));

    // Detailed endpoints (if enabled)
    if (this.config.enableDetailedEndpoints) {
      app.get('/health/detailed', this.authenticateHealthEndpoint.bind(this), this.detailedHealthCheck.bind(this));
    }

    // Metrics endpoint (if enabled)
    if (this.config.enableMetricsEndpoint) {
      app.get('/metrics', this.authenticateHealthEndpoint.bind(this), this.metrics.bind(this));
    }

    this.logger.info('Health endpoints configured', {
      detailedEndpoints: this.config.enableDetailedEndpoints,
      metricsEndpoint: this.config.enableMetricsEndpoint,
      authenticationRequired: this.config.authenticationRequired
    });
  }

  /**
   * Get current health check cache status
   */
  getCacheStatus(): Record<string, any> {
    return {
      cacheSize: this.healthCheckCache.size,
      cachedTypes: Array.from(this.healthCheckCache.keys()),
      cacheTTL: this.CACHE_TTL
    };
  }

  /**
   * Clear health check cache
   */
  clearCache(): void {
    this.healthCheckCache.clear();
    this.logger.info('Health check cache cleared');
  }
}

export default HealthEndpointManager;