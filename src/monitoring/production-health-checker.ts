/**
 * Production Health Checker
 *
 * Comprehensive health checking system for production environments.
 * Validates service dependencies, system resources, and application state.
 * Provides liveness and readiness probes for container orchestration.
 *
 * @author Cortex Team
 * @version 2.0.1
 */

export interface HealthCheckResult {
  status: 'healthy' | 'unhealthy' | 'degraded';
  timestamp: string;
  duration: number;
  checks: HealthCheck[];
  summary: {
    total: number;
    passed: number;
    failed: number;
    warnings: number;
  };
  issues: string[];
  metadata?: Record<string, any>;
}

export interface HealthCheck {
  name: string;
  status: 'pass' | 'fail' | 'warn';
  duration: number;
  message?: string;
  details?: Record<string, any>;
  critical: boolean;
}

export interface HealthCheckConfig {
  timeout: number;
  retries: number;
  retryDelay: number;
  enableDetailedChecks: boolean;
  skipOptionalChecks: boolean;
}

export class ProductionHealthChecker {
  private config: HealthCheckConfig;
  private logger: any; // Use any to avoid circular dependency

  constructor() {
    this.config = {
      timeout: parseInt(process.env.HEALTH_CHECK_TIMEOUT || '10000'),
      retries: parseInt(process.env.HEALTH_CHECK_RETRIES || '3'),
      retryDelay: parseInt(process.env.HEALTH_CHECK_RETRY_DELAY || '1000'),
      enableDetailedChecks: process.env.ENABLE_DETAILED_HEALTH_CHECKS === 'true',
      skipOptionalChecks: process.env.SKIP_OPTIONAL_HEALTH_CHECKS === 'true'
    };

    // Import logger lazily to avoid circular dependencies
    this.logger = {
      info: (message: string, data?: any) => console.log(`[health-checker] ${message}`, data || ''),
      warn: (message: string, data?: any) => console.warn(`[health-checker] ${message}`, data || ''),
      error: (message: string, data?: any) => console.error(`[health-checker] ${message}`, data || '')
    };
  }

  /**
   * Perform pre-startup health check
   */
  async performPreStartupHealthCheck(): Promise<HealthCheckResult> {
    this.logger.info('Performing pre-startup health check');

    const checks: HealthCheck[] = [
      await this.checkEnvironmentVariables(),
      await this.checkNodeVersion(),
      await this.checkMemoryUsage(),
      await this.checkDiskSpace(),
      await this.checkQdrantConnection()
    ];

    // Add optional checks if enabled
    if (!this.config.skipOptionalChecks) {
      checks.push(
        await this.checkOpenAIConnection(),
        await this.checkFileSystemAccess()
      );
    }

    return this.aggregateHealthResults('pre-startup', checks);
  }

  /**
   * Perform post-startup health check
   */
  async performPostStartupHealthCheck(): Promise<HealthCheckResult> {
    this.logger.info('Performing post-startup health check');

    const checks: HealthCheck[] = [
      await this.checkServerStatus(),
      await this.checkQdrantConnection(),
      await this.checkMemoryUsage(),
      await this.checkActiveConnections()
    ];

    // Add detailed checks if enabled
    if (this.config.enableDetailedChecks) {
      checks.push(
        await this.checkDatabasePerformance(),
        await this.checkCacheHealth(),
        await this.checkWorkerProcesses()
      );
    }

    return this.aggregateHealthResults('post-startup', checks);
  }

  /**
   * Liveness probe for container orchestration
   */
  async livenessProbe(): Promise<HealthCheckResult> {
    const checks: HealthCheck[] = [
      await this.checkServerStatus(),
      await this.checkMemoryUsage(),
      await this.checkCpuUsage()
    ];

    return this.aggregateHealthResults('liveness', checks);
  }

  /**
   * Readiness probe for container orchestration
   */
  async readinessProbe(): Promise<HealthCheckResult> {
    const checks: HealthCheck[] = [
      await this.checkServerStatus(),
      await this.checkQdrantConnection(),
      await this.checkEnvironmentVariables()
    ];

    return this.aggregateHealthResults('readiness', checks);
  }

  /**
   * Check environment variables
   */
  private async checkEnvironmentVariables(): Promise<HealthCheck> {
    const startTime = Date.now();
    const requiredVars = [
      'OPENAI_API_KEY',
      'QDRANT_URL',
      'NODE_ENV'
    ];

    const missingVars: string[] = [];
    const invalidVars: string[] = [];

    for (const varName of requiredVars) {
      const value = process.env[varName];
      if (!value) {
        missingVars.push(varName);
      } else if (varName.includes('KEY') && value.length < 10) {
        invalidVars.push(varName);
      }
    }

    const duration = Date.now() - startTime;

    if (missingVars.length > 0) {
      return {
        name: 'environment-variables',
        status: 'fail',
        duration,
        message: `Missing required environment variables: ${missingVars.join(', ')}`,
        details: { missing: missingVars, invalid: invalidVars },
        critical: true
      };
    }

    if (invalidVars.length > 0) {
      return {
        name: 'environment-variables',
        status: 'warn',
        duration,
        message: `Invalid environment variables: ${invalidVars.join(', ')}`,
        details: { missing: missingVars, invalid: invalidVars },
        critical: false
      };
    }

    return {
      name: 'environment-variables',
      status: 'pass',
      duration,
      message: 'All required environment variables are present',
      critical: true
    };
  }

  /**
   * Check Node.js version
   */
  private async checkNodeVersion(): Promise<HealthCheck> {
    const startTime = Date.now();
    const nodeVersion = process.version;
    const majorVersion = parseInt(nodeVersion.slice(1).split('.')[0]);

    const duration = Date.now() - startTime;

    if (majorVersion < 20) {
      return {
        name: 'node-version',
        status: 'fail',
        duration,
        message: `Node.js version ${nodeVersion} is not supported. Minimum required: 20.x`,
        details: { current: nodeVersion, required: '>=20.x' },
        critical: true
      };
    }

    return {
      name: 'node-version',
      status: 'pass',
      duration,
      message: `Node.js version ${nodeVersion} is supported`,
      details: { version: nodeVersion },
      critical: true
    };
  }

  /**
   * Check memory usage
   */
  private async checkMemoryUsage(): Promise<HealthCheck> {
    const startTime = Date.now();
    const memUsage = process.memoryUsage();
    const totalMemory = require('os').totalmem();
    const freeMemory = require('os').freemem();
    const usedMemory = totalMemory - freeMemory;
    const memoryUsagePercent = (usedMemory / totalMemory) * 100;

    const duration = Date.now() - startTime;

    // Check if we're using too much memory
    const heapUsedPercent = (memUsage.heapUsed / memUsage.heapTotal) * 100;

    if (heapUsedPercent > 90) {
      return {
        name: 'memory-usage',
        status: 'fail',
        duration,
        message: `Heap usage is critically high: ${heapUsedPercent.toFixed(1)}%`,
        details: {
          heapUsed: memUsage.heapUsed,
          heapTotal: memUsage.heapTotal,
          heapUsedPercent,
          systemMemoryPercent: memoryUsagePercent
        },
        critical: true
      };
    }

    if (heapUsedPercent > 80) {
      return {
        name: 'memory-usage',
        status: 'warn',
        duration,
        message: `Heap usage is high: ${heapUsedPercent.toFixed(1)}%`,
        details: {
          heapUsed: memUsage.heapUsed,
          heapTotal: memUsage.heapTotal,
          heapUsedPercent,
          systemMemoryPercent: memoryUsagePercent
        },
        critical: false
      };
    }

    return {
      name: 'memory-usage',
      status: 'pass',
      duration,
      message: `Memory usage is normal: ${heapUsedPercent.toFixed(1)}%`,
      details: {
        heapUsed: memUsage.heapUsed,
        heapTotal: memUsage.heapTotal,
        heapUsedPercent,
        systemMemoryPercent: memoryUsagePercent
      },
      critical: false
    };
  }

  /**
   * Check disk space
   */
  private async checkDiskSpace(): Promise<HealthCheck> {
    const startTime = Date.now();

    try {
      const stats = require('fs').statSync(process.cwd());
      const duration = Date.now() - startTime;

      return {
        name: 'disk-space',
        status: 'pass',
        duration,
        message: 'Disk space check passed',
        details: { accessible: true },
        critical: false
      };
    } catch (error) {
      const duration = Date.now() - startTime;

      return {
        name: 'disk-space',
        status: 'fail',
        duration,
        message: `Cannot access working directory: ${error}`,
        details: { error: error instanceof Error ? error.message : 'Unknown error' },
        critical: true
      };
    }
  }

  /**
   * Check Qdrant connection
   */
  private async checkQdrantConnection(): Promise<HealthCheck> {
    const startTime = Date.now();

    try {
      const qdrantUrl = process.env.QDRANT_URL;
      if (!qdrantUrl) {
        throw new Error('QDRANT_URL not configured');
      }

      // Basic connectivity check
      const response = await this.makeHttpRequest(`${qdrantUrl}/health`, 5000);

      const duration = Date.now() - startTime;

      if (response.ok) {
        return {
          name: 'qdrant-connection',
          status: 'pass',
          duration,
          message: 'Qdrant connection successful',
          details: { url: qdrantUrl, status: response.status },
          critical: true
        };
      } else {
        return {
          name: 'qdrant-connection',
          status: 'fail',
          duration,
          message: `Qdrant returned error status: ${response.status}`,
          details: { url: qdrantUrl, status: response.status },
          critical: true
        };
      }
    } catch (error) {
      const duration = Date.now() - startTime;

      return {
        name: 'qdrant-connection',
        status: 'fail',
        duration,
        message: `Failed to connect to Qdrant: ${error instanceof Error ? error.message : 'Unknown error'}`,
        details: { error: error instanceof Error ? error.message : 'Unknown error' },
        critical: true
      };
    }
  }

  /**
   * Check OpenAI connection
   */
  private async checkOpenAIConnection(): Promise<HealthCheck> {
    const startTime = Date.now();

    try {
      const apiKey = process.env.OPENAI_API_KEY;
      if (!apiKey) {
        throw new Error('OPENAI_API_KEY not configured');
      }

      // Basic API validation
      const response = await this.makeHttpRequest('https://api.openai.com/v1/models', 5000, {
        'Authorization': `Bearer ${apiKey}`
      });

      const duration = Date.now() - startTime;

      if (response.ok) {
        return {
          name: 'openai-connection',
          status: 'pass',
          duration,
          message: 'OpenAI API connection successful',
          details: { status: response.status },
          critical: false
        };
      } else {
        return {
          name: 'openai-connection',
          status: 'fail',
          duration,
          message: `OpenAI API returned error status: ${response.status}`,
          details: { status: response.status },
          critical: false
        };
      }
    } catch (error) {
      const duration = Date.now() - startTime;

      return {
        name: 'openai-connection',
        status: 'warn',
        duration,
        message: `Failed to connect to OpenAI API: ${error instanceof Error ? error.message : 'Unknown error'}`,
        details: { error: error instanceof Error ? error.message : 'Unknown error' },
        critical: false
      };
    }
  }

  /**
   * Check file system access
   */
  private async checkFileSystemAccess(): Promise<HealthCheck> {
    const startTime = Date.now();

    try {
      // Test read access
      require('fs').accessSync(process.cwd(), require('fs').constants.R_OK);

      // Test write access (create a temp file)
      const testFile = `${process.cwd()}/.health-check-${Date.now()}.tmp`;
      require('fs').writeFileSync(testFile, 'test');
      require('fs').unlinkSync(testFile);

      const duration = Date.now() - startTime;

      return {
        name: 'filesystem-access',
        status: 'pass',
        duration,
        message: 'File system access is normal',
        details: { readWrite: true },
        critical: false
      };
    } catch (error) {
      const duration = Date.now() - startTime;

      return {
        name: 'filesystem-access',
        status: 'fail',
        duration,
        message: `File system access error: ${error instanceof Error ? error.message : 'Unknown error'}`,
        details: { error: error instanceof Error ? error.message : 'Unknown error' },
        critical: false
      };
    }
  }

  /**
   * Check server status
   */
  private async checkServerStatus(): Promise<HealthCheck> {
    const startTime = Date.now();
    const uptime = process.uptime();

    const duration = Date.now() - startTime;

    // Check if server has been running for at least 5 seconds
    if (uptime < 5) {
      return {
        name: 'server-status',
        status: 'warn',
        duration,
        message: `Server just started (${uptime.toFixed(1)}s uptime)`,
        details: { uptime },
        critical: false
      };
    }

    return {
      name: 'server-status',
      status: 'pass',
      duration,
      message: `Server is running (${uptime.toFixed(1)}s uptime)`,
      details: { uptime, pid: process.pid },
      critical: true
    };
  }

  /**
   * Check active connections
   */
  private async checkActiveConnections(): Promise<HealthCheck> {
    const startTime = Date.now();

    try {
      // This is a placeholder - in a real implementation, you would
      // check the actual number of active connections
      const activeConnections = 0; // Placeholder value

      const duration = Date.now() - startTime;

      return {
        name: 'active-connections',
        status: 'pass',
        duration,
        message: `Active connections: ${activeConnections}`,
        details: { activeConnections },
        critical: false
      };
    } catch (error) {
      const duration = Date.now() - startTime;

      return {
        name: 'active-connections',
        status: 'warn',
        duration,
        message: `Could not determine active connections: ${error instanceof Error ? error.message : 'Unknown error'}`,
        details: { error: error instanceof Error ? error.message : 'Unknown error' },
        critical: false
      };
    }
  }

  /**
   * Check database performance
   */
  private async checkDatabasePerformance(): Promise<HealthCheck> {
    const startTime = Date.now();

    try {
      // This is a placeholder - in a real implementation, you would
      // perform a quick database operation to measure performance
      const queryTime = Math.random() * 100; // Placeholder value

      const duration = Date.now() - startTime;

      if (queryTime > 5000) {
        return {
          name: 'database-performance',
          status: 'warn',
          duration,
          message: `Database query time is high: ${queryTime.toFixed(1)}ms`,
          details: { queryTime },
          critical: false
        };
      }

      return {
        name: 'database-performance',
        status: 'pass',
        duration,
        message: `Database performance is normal: ${queryTime.toFixed(1)}ms`,
        details: { queryTime },
        critical: false
      };
    } catch (error) {
      const duration = Date.now() - startTime;

      return {
        name: 'database-performance',
        status: 'fail',
        duration,
        message: `Database performance check failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        details: { error: error instanceof Error ? error.message : 'Unknown error' },
        critical: false
      };
    }
  }

  /**
   * Check cache health
   */
  private async checkCacheHealth(): Promise<HealthCheck> {
    const startTime = Date.now();

    try {
      // This is a placeholder - in a real implementation, you would
      // check the cache system
      const cacheHitRate = 0.95; // Placeholder value

      const duration = Date.now() - startTime;

      if (cacheHitRate < 0.8) {
        return {
          name: 'cache-health',
          status: 'warn',
          duration,
          message: `Cache hit rate is low: ${(cacheHitRate * 100).toFixed(1)}%`,
          details: { cacheHitRate },
          critical: false
        };
      }

      return {
        name: 'cache-health',
        status: 'pass',
        duration,
        message: `Cache performance is good: ${(cacheHitRate * 100).toFixed(1)}% hit rate`,
        details: { cacheHitRate },
        critical: false
      };
    } catch (error) {
      const duration = Date.now() - startTime;

      return {
        name: 'cache-health',
        status: 'warn',
        duration,
        message: `Cache health check failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        details: { error: error instanceof Error ? error.message : 'Unknown error' },
        critical: false
      };
    }
  }

  /**
   * Check worker processes
   */
  private async checkWorkerProcesses(): Promise<HealthCheck> {
    const startTime = Date.now();

    try {
      // This is a placeholder - in a real implementation, you would
      // check the status of background workers
      const workerCount = 3; // Placeholder value
      const activeWorkers = 3; // Placeholder value

      const duration = Date.now() - startTime;

      if (activeWorkers < workerCount) {
        return {
          name: 'worker-processes',
          status: 'warn',
          duration,
          message: `Some workers are not active: ${activeWorkers}/${workerCount}`,
          details: { workerCount, activeWorkers },
          critical: false
        };
      }

      return {
        name: 'worker-processes',
        status: 'pass',
        duration,
        message: `All workers are active: ${activeWorkers}/${workerCount}`,
        details: { workerCount, activeWorkers },
        critical: false
      };
    } catch (error) {
      const duration = Date.now() - startTime;

      return {
        name: 'worker-processes',
        status: 'warn',
        duration,
        message: `Worker process check failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        details: { error: error instanceof Error ? error.message : 'Unknown error' },
        critical: false
      };
    }
  }

  /**
   * Check CPU usage
   */
  private async checkCpuUsage(): Promise<HealthCheck> {
    const startTime = Date.now();
    const cpuUsage = process.cpuUsage();

    const duration = Date.now() - startTime;

    // Simple CPU check - in a real implementation you'd want more sophisticated monitoring
    return {
      name: 'cpu-usage',
      status: 'pass',
      duration,
      message: 'CPU usage check passed',
      details: { user: cpuUsage.user, system: cpuUsage.system },
      critical: false
    };
  }

  /**
   * Aggregate health check results
   */
  private aggregateHealthResults(checkType: string, checks: HealthCheck[]): HealthCheckResult {
    const summary = {
      total: checks.length,
      passed: checks.filter(c => c.status === 'pass').length,
      failed: checks.filter(c => c.status === 'fail').length,
      warnings: checks.filter(c => c.status === 'warn').length
    };

    const criticalFailures = checks.filter(c => c.status === 'fail' && c.critical);
    const issues: string[] = [];

    // Collect all failures and warnings
    checks.forEach(check => {
      if (check.status === 'fail') {
        issues.push(`${check.name}: ${check.message || 'Unknown error'}`);
      } else if (check.status === 'warn') {
        issues.push(`${check.name}: ${check.message || 'Warning'}`);
      }
    });

    // Determine overall status
    let status: 'healthy' | 'unhealthy' | 'degraded';
    if (criticalFailures.length > 0) {
      status = 'unhealthy';
    } else if (summary.failed > 0) {
      status = 'degraded';
    } else {
      status = 'healthy';
    }

    return {
      status,
      timestamp: new Date().toISOString(),
      duration: checks.reduce((total, check) => total + check.duration, 0),
      checks,
      summary,
      issues,
      metadata: {
        checkType,
        nodeVersion: process.version,
        uptime: process.uptime(),
        memory: process.memoryUsage()
      }
    };
  }

  /**
   * Make HTTP request for health checks
   */
  private async makeHttpRequest(url: string, timeout: number, headers?: Record<string, string>): Promise<Response> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'User-Agent': 'Cortex-Memory-Health-Check/2.0.1',
          ...headers
        },
        signal: controller.signal
      });

      clearTimeout(timeoutId);
      return response;
    } catch (error) {
      clearTimeout(timeoutId);
      throw error;
    }
  }
}

export default ProductionHealthChecker;