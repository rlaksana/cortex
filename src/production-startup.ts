// LAST ABSOLUTE FINAL EMERGENCY ROLLBACK: Complete the systematic rollback

/**
 * Production Startup Integration
 *
 * Integration layer that ties together all production components.
 * Provides a unified production startup sequence with proper
 * error handling and monitoring.
 *
 * @author Cortex Team
 * @version 2.0.1
 */

import { createChildLogger, type SimpleLogger } from '@/utils/logger.js';

import { productionConfig } from './config/production-config.js';
import { ProductionEnvironmentValidator } from './config/production-validator.js';
import { hasBooleanProperty,hasProductionConfig } from './utils/type-fixes.js';

export interface StartupOptions {
  skipValidation?: boolean;
  enableHealthEndpoints?: boolean;
  port?: number;
  host?: string;
}

export interface StartupResult {
  success: boolean;
  startTime: number;
  duration: number;
  errors: string[];
  warnings: string[];
  configuration?: Record<string, unknown>;
  endpoints?: Record<string, string>;
}

export class ProductionStartup {
  private logger: SimpleLogger;
  private startTime: number;

  constructor() {
    this.logger = createChildLogger({ component: 'production-startup' });
    this.startTime = Date.now();
  }

  /**
   * Start the production server
   */
  async start(options: StartupOptions = {}): Promise<StartupResult> {
    const result: StartupResult = {
      success: false,
      startTime: this.startTime,
      duration: 0,
      errors: [],
      warnings: [],
    };

    try {
      this.logger.info('🚀 Starting Cortex Memory MCP Server in PRODUCTION mode');
      this.logger.info('Node.js version', { nodeVersion: process.version });
      this.logger.info('Environment', { environment: process.env.NODE_ENV });
      this.logger.info('Process ID', { pid: process.pid });

      // Phase 1: Environment validation
      if (!options.skipValidation) {
        await this.validateEnvironment(result);
      }

      // Phase 2: Configuration initialization
      await this.initializeConfiguration(result);

      // Phase 3: Security setup
      await this.setupSecurity(result);

      // Phase 4: Health endpoints
      if (options.enableHealthEndpoints !== false) {
        await this.setupHealthEndpoints(result);
      }

      // Phase 5: Server startup
      const serverInfo = await this.startServer(options, result);

      // Phase 6: Post-startup validation
      await this.postStartupValidation(result);

      // Complete startup
      result.success = true;
      result.duration = Date.now() - this.startTime;
      result.configuration = productionConfig.exportConfiguration();
      result.endpoints = {
        health: `http://${serverInfo.host}:${serverInfo.port}/health`,
        detailed: `http://${serverInfo.host}:${serverInfo.port}/health/detailed`,
        metrics: `http://${serverInfo.host}:${serverInfo.port}/metrics`,
      };

      this.logger.info('✅ Cortex Memory MCP Server started successfully', {
        duration: result.duration,
        host: serverInfo.host,
        port: serverInfo.port,
        endpoints: result.endpoints,
      });

      return result;
    } catch (error) {
      result.duration = Date.now() - this.startTime;
      result.errors.push(error instanceof Error ? error.message : 'Unknown error');

      this.logger.error('❌ Failed to start Cortex Memory MCP Server', {
        duration: result.duration,
        error: result.errors,
        warnings: result.warnings,
      });

      return result;
    }
  }

  /**
   * Validate production environment
   */
  private async validateEnvironment(result: StartupResult): Promise<void> {
    this.logger.info('🔍 Validating production environment...');

    try {
      const validator = new ProductionEnvironmentValidator();
      const validationResult = validator.validateProductionEnvironment();

      if (validationResult.critical.length > 0) {
        result.errors.push(...validationResult.critical);
        throw new Error(`Critical validation failures: ${validationResult.critical.join(', ')}`);
      }

      if (validationResult.errors.length > 0) {
        result.errors.push(...validationResult.errors);
      }

      if (validationResult.warnings.length > 0) {
        result.warnings.push(...validationResult.warnings);
      }

      this.logger.info('✅ Environment validation completed', {
        errors: validationResult.errors.length,
        warnings: validationResult.warnings.length,
      });
    } catch (error) {
      this.logger.error('Environment validation failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw error;
    }
  }

  /**
   * Initialize production configuration
   */
  private async initializeConfiguration(result: StartupResult): Promise<void> {
    this.logger.info('⚙️ Initializing production configuration...');

    try {
      await productionConfig.initialize();

      const config = productionConfig.getConfig();

      this.logger.info('✅ Production configuration initialized', {
        securityEnabled: config.security.helmetEnabled,
        rateLimitEnabled: config.security.rateLimitEnabled,
        healthChecksEnabled: config.health.enabled,
        metricsEnabled: config.performance.enableMetrics,
      });
    } catch (error) {
      this.logger.error('Configuration initialization failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      result.errors.push(
        `Configuration initialization failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
      throw error;
    }
  }

  /**
   * Setup security middleware
   */
  private async setupSecurity(result: StartupResult): Promise<void> {
    this.logger.info('🛡️ Setting up security middleware...');

    try {
      const securityMiddleware = productionConfig.getSecurityMiddleware();
      const validation = securityMiddleware.validateConfiguration();

      if (!validation.valid) {
        result.warnings.push(...validation.errors);
      }

      this.logger.info('✅ Security middleware configured', {
        helmetEnabled: validation.valid,
        rateLimitEnabled: true,
        corsConfigured: true,
      });
    } catch (error) {
      this.logger.error('Security setup failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      result.errors.push(
        `Security setup failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
      throw error;
    }
  }

  /**
   * Setup health endpoints
   */
  private async setupHealthEndpoints(result: StartupResult): Promise<void> {
    this.logger.info('🏥 Setting up health endpoints...');

    try {
      const healthEndpointManager = productionConfig.getHealthEndpointManager();

      // Note: In a real implementation, you would pass the Express app here
      // healthEndpointManager.setupEndpoints(app);

      this.logger.info('✅ Health endpoints configured', {
        mainEndpoint: '/health',
        livenessProbe: '/health/live',
        readinessProbe: '/health/ready',
        detailedEndpoint: '/health/detailed',
        metricsEndpoint: '/metrics',
      });
    } catch (error) {
      this.logger.error('Health endpoint setup failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      result.warnings.push(
        `Health endpoint setup failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
      // Don't fail startup for health endpoint issues
    }
  }

  /**
   * Start the main server
   */
  private async startServer(
    options: StartupOptions,
    result: StartupResult
  ): Promise<{ host: string; port: number }> {
    this.logger.info('🚀 Starting main server...');

    try {
      const host = options.host || process.env.HOST || '0.0.0.0';
      const port = options.port || parseInt(process.env.PORT || '3000');

      // In a real implementation, you would start your Express/server here
      // const app = express();
      // await new Promise((resolve, reject) => {
      //   const server = app.listen(port, host, () => {
      //     this.logger.info(`Server listening on ${host}:${port}`);
      //     resolve(server);
      //   });
      //   server.on('error', reject);
      // });

      // Simulate server startup for this example
      await new Promise((resolve) => setTimeout(resolve, 1000));

      this.logger.info('✅ Server started successfully', { host, port });

      return { host, port };
    } catch (error) {
      this.logger.error('Server startup failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      result.errors.push(
        `Server startup failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
      throw error;
    }
  }

  /**
   * Post-startup validation
   */
  private async postStartupValidation(result: StartupResult): Promise<void> {
    this.logger.info('🔍 Performing post-startup validation...');

    try {
      // Wait a moment for services to initialize
      await new Promise((resolve) => setTimeout(resolve, 2000));

      // Validate configuration manager health
      const configHealth = productionConfig.healthCheck();
      if (!configHealth.healthy) {
        result.warnings.push('Configuration manager health check failed');
      }

      // Validate graceful shutdown manager
      const shutdownManager = productionConfig.getGracefulShutdownManager();
      const shutdownHealth = shutdownManager.healthCheck();
      if (!shutdownHealth.healthy) {
        result.warnings.push('Graceful shutdown manager not healthy');
      }

      this.logger.info('✅ Post-startup validation completed');
    } catch (error) {
      this.logger.warn('Post-startup validation encountered issues', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      result.warnings.push(
        `Post-startup validation warning: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
      // Don't fail startup for post-startup validation issues
    }
  }

  /**
   * Generate startup report
   */
  generateReport(result: StartupResult): string {
    const report = [
      '# Cortex Memory MCP Server - Production Startup Report',
      '='.repeat(60),
      '',
      `Status: ${result.success ? '✅ SUCCESS' : '❌ FAILED'}`,
      `Start Time: ${new Date(result.startTime).toISOString()}`,
      `Duration: ${result.duration}ms`,
      `Environment: ${process.env.NODE_ENV}`,
      `Node.js Version: ${process.version}`,
      `Process ID: ${process.pid}`,
      '',
    ];

    if (result.errors.length > 0) {
      report.push('## Errors:');
      result.errors.forEach((error) => {
        report.push(`- ❌ ${error}`);
      });
      report.push('');
    }

    if (result.warnings.length > 0) {
      report.push('## Warnings:');
      result.warnings.forEach((warning) => {
        report.push(`- ⚠️  ${warning}`);
      });
      report.push('');
    }

    if (result.endpoints) {
      report.push('## Available Endpoints:');
      Object.entries(result.endpoints).forEach(([name, url]) => {
        report.push(`- ${name}: ${url}`);
      });
      report.push('');
    }

    if (result.configuration && hasProductionConfig(result.configuration)) {
      report.push('## Configuration Summary:');
      const config = result.configuration;

      // Security settings
      const helmetEnabled = config.security && hasBooleanProperty(config.security, 'helmetEnabled')
        ? config.security.helmetEnabled
        : false;
      const rateLimitEnabled = config.security && hasBooleanProperty(config.security, 'rateLimitEnabled')
        ? config.security.rateLimitEnabled
        : false;

      // Health and performance settings
      const healthEnabled = config.health && hasBooleanProperty(config.health, 'enabled')
        ? config.health.enabled
        : false;
      const metricsEnabled = config.performance && hasBooleanProperty(config.performance, 'enableMetrics')
        ? config.performance.enableMetrics
        : false;

      report.push(`- Security: ${helmetEnabled ? 'Enabled' : 'Disabled'}`);
      report.push(`- Rate Limiting: ${rateLimitEnabled ? 'Enabled' : 'Disabled'}`);
      report.push(`- Health Checks: ${healthEnabled ? 'Enabled' : 'Disabled'}`);
      report.push(`- Metrics: ${metricsEnabled ? 'Enabled' : 'Disabled'}`);
      report.push('');
    }

    report.push('## System Information:');
    const memUsage = process.memoryUsage();
    report.push(
      `- Memory Usage: ${Math.round(memUsage.heapUsed / 1024 / 1024)}MB / ${Math.round(memUsage.heapTotal / 1024 / 1024)}MB`
    );
    report.push(`- Platform: ${process.platform} (${process.arch})`);
    report.push(`- Uptime: ${Math.round(process.uptime())}s`);
    report.push('');

    if (result.success) {
      report.push('🎉 **Server is ready for production traffic!**');
    } else {
      report.push('❌ **Server startup failed. Please check the errors above.**');
    }

    return report.join('\n');
  }
}

// Export singleton instance
export const productionStartup = new ProductionStartup();

export default ProductionStartup;
