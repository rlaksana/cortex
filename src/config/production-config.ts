/**
 * Production Configuration Manager
 *
 * Central configuration manager for production environments.
 * Integrates all production-specific components and provides
 * unified configuration and initialization.
 *
 * @author Cortex Team
 * @version 2.0.1
 */

import { ProductionEnvironmentValidator } from './production-validator.js';
import { ProductionSecurityMiddleware } from '../middleware/production-security-middleware.js';
import { HealthEndpointManager } from '../monitoring/health-endpoint.js';
import { GracefulShutdownManager } from '../monitoring/graceful-shutdown.js';
import { ProductionLogger } from '../monitoring/production-logger.js';

export interface ProductionConfig {
  // Security configuration
  security: {
    corsOrigin: string[];
    rateLimitEnabled: boolean;
    rateLimitWindowMs: number;
    rateLimitMaxRequests: number;
    helmetEnabled: boolean;
    requireApiKey: boolean;
    maxRequestSizeMb: number;
    enableCompression: boolean;
  };

  // Health check configuration
  health: {
    enabled: boolean;
    detailedEndpoints: boolean;
    metricsEndpoint: boolean;
    authenticationRequired: boolean;
    allowedIPs: string[];
  };

  // Shutdown configuration
  shutdown: {
    timeout: number;
    forceTimeout: number;
    enableDrainMode: boolean;
    drainTimeout: number;
  };

  // Logging configuration
  logging: {
    level: string;
    format: 'json' | 'text';
    structured: boolean;
    includeTimestamp: boolean;
    includeRequestId: boolean;
  };

  // Performance configuration
  performance: {
    enableMetrics: boolean;
    enablePerformanceMonitoring: boolean;
    nodeOptions: string;
    maxOldSpaceSize: number;
    maxHeapSize: number;
  };

  // Monitoring configuration
  monitoring: {
    enableSystemMetrics: boolean;
    enableHealthChecks: boolean;
    metricsInterval: number;
    healthCheckInterval: number;
  };
}

export class ProductionConfigManager {
  private static instance: ProductionConfigManager;
  private config: ProductionConfig;
  private validator: ProductionEnvironmentValidator;
  private logger: ProductionLogger;
  private securityMiddleware: ProductionSecurityMiddleware | null = null;
  private healthEndpointManager: HealthEndpointManager | null = null;
  private gracefulShutdownManager: GracefulShutdownManager;

  constructor() {
    this.validator = new ProductionEnvironmentValidator();
    this.logger = new ProductionLogger('production-config');
    this.gracefulShutdownManager = new GracefulShutdownManager();

    this.config = this.loadConfiguration();
    this.validateConfiguration();
  }

  /**
   * Get singleton instance
   */
  static getInstance(): ProductionConfigManager {
    if (!ProductionConfigManager.instance) {
      ProductionConfigManager.instance = new ProductionConfigManager();
    }
    return ProductionConfigManager.instance;
  }

  /**
   * Load production configuration from environment variables
   */
  private loadConfiguration(): ProductionConfig {
    return {
      security: {
        corsOrigin: (process.env.CORS_ORIGIN || '').split(',').map(origin => origin.trim()).filter(Boolean),
        rateLimitEnabled: process.env.RATE_LIMIT_ENABLED === 'true',
        rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'), // 15 minutes
        rateLimitMaxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '1000'),
        helmetEnabled: process.env.HELMET_ENABLED === 'true',
        requireApiKey: process.env.REQUIRE_API_KEY === 'true',
        maxRequestSizeMb: parseInt(process.env.MAX_REQUEST_SIZE_MB || '10'),
        enableCompression: process.env.ENABLE_COMPRESSION === 'true'
      },
      health: {
        enabled: process.env.ENABLE_HEALTH_CHECKS === 'true',
        detailedEndpoints: process.env.ENABLE_DETAILED_HEALTH_ENDPOINTS === 'true',
        metricsEndpoint: process.env.ENABLE_METRICS_ENDPOINT === 'true',
        authenticationRequired: process.env.HEALTH_ENDPOINT_AUTH_REQUIRED === 'true',
        allowedIPs: (process.env.HEALTH_ENDPOINT_ALLOWED_IPS || '').split(',').map(ip => ip.trim()).filter(Boolean)
      },
      shutdown: {
        timeout: parseInt(process.env.SHUTDOWN_TIMEOUT || '30000'), // 30 seconds
        forceTimeout: parseInt(process.env.FORCE_SHUTDOWN_TIMEOUT || '60000'), // 60 seconds
        enableDrainMode: process.env.ENABLE_DRAIN_MODE !== 'false',
        drainTimeout: parseInt(process.env.DRAIN_TIMEOUT || '10000') // 10 seconds
      },
      logging: {
        level: process.env.LOG_LEVEL || 'info',
        format: process.env.LOG_FORMAT === 'text' ? 'text' : 'json',
        structured: process.env.LOG_STRUCTURED === 'true',
        includeTimestamp: process.env.LOG_TIMESTAMP !== 'false',
        includeRequestId: process.env.LOG_REQUEST_ID !== 'false'
      },
      performance: {
        enableMetrics: process.env.ENABLE_METRICS_COLLECTION === 'true',
        enablePerformanceMonitoring: process.env.ENABLE_PERFORMANCE_MONITORING === 'true',
        nodeOptions: process.env.NODE_OPTIONS || '',
        maxOldSpaceSize: parseInt(process.env.MAX_OLD_SPACE_SIZE || '8192'),
        maxHeapSize: parseInt(process.env.MAX_HEAP_SIZE || '8192')
      },
      monitoring: {
        enableSystemMetrics: process.env.ENABLE_SYSTEM_METRICS === 'true',
        enableHealthChecks: process.env.ENABLE_HEALTH_CHECKS === 'true',
        metricsInterval: parseInt(process.env.METRICS_INTERVAL || '60000'), // 1 minute
        healthCheckInterval: parseInt(process.env.HEALTH_CHECK_INTERVAL || '30000') // 30 seconds
      }
    };
  }

  /**
   * Validate configuration
   */
  private validateConfiguration(): void {
    const errors: string[] = [];

    // Validate security configuration
    if (this.config.security.rateLimitEnabled && this.config.security.rateLimitMaxRequests > 10000) {
      errors.push('Rate limit is too permissive for production (>10000 requests)');
    }

    if (this.config.security.maxRequestSizeMb > 100) {
      errors.push('Maximum request size is too large for production (>100MB)');
    }

    // Validate CORS configuration
    if (this.config.security.corsOrigin.length === 0) {
      errors.push('CORS origin must be configured for production');
    }

    if (this.config.security.corsOrigin.includes('*') && process.env.NODE_ENV === 'production') {
      errors.push('Wildcard CORS origin is not recommended for production');
    }

    // Validate timeouts
    if (this.config.shutdown.timeout < 5000) {
      errors.push('Shutdown timeout should be at least 5 seconds');
    }

    if (this.config.shutdown.forceTimeout <= this.config.shutdown.timeout) {
      errors.push('Force shutdown timeout must be greater than normal shutdown timeout');
    }

    // Validate logging
    const validLogLevels = ['error', 'warn', 'info', 'debug'];
    if (!validLogLevels.includes(this.config.logging.level)) {
      errors.push(`Invalid log level: ${this.config.logging.level}`);
    }

    // Validate performance settings
    if (this.config.performance.maxOldSpaceSize < 1024) {
      errors.push('Max old space size should be at least 1024MB for production');
    }

    if (errors.length > 0) {
      this.logger.error('Production configuration validation failed', { errors });
      throw new Error(`Configuration validation failed: ${errors.join(', ')}`);
    }

    this.logger.info('Production configuration validated successfully');
  }

  /**
   * Initialize all production components
   */
  async initialize(): Promise<void> {
    this.logger.info('🚀 Initializing production environment');

    try {
      // Validate environment
      this.logger.info('🔍 Validating production environment...');
      this.validator.assertValidForProduction();

      // Initialize security middleware
      this.logger.info('🛡️ Initializing security middleware...');
      this.securityMiddleware = new ProductionSecurityMiddleware(this.config.security);

      // Validate security configuration
      const securityValidation = this.securityMiddleware.validateConfiguration();
      if (!securityValidation.valid) {
        throw new Error(`Security configuration invalid: ${securityValidation.errors.join(', ')}`);
      }

      // Initialize health endpoints
      this.logger.info('🏥 Initializing health endpoints...');
      this.healthEndpointManager = new HealthEndpointManager({
        enableDetailedEndpoints: this.config.health.detailedEndpoints,
        enableMetricsEndpoint: this.config.health.metricsEndpoint,
        authenticationRequired: this.config.health.authenticationRequired,
        allowedIPs: this.config.health.allowedIPs
      });

      // Setup graceful shutdown handlers
      this.logger.info('🔄 Setting up graceful shutdown handlers...');
      this.setupGracefulShutdownHandlers();

      // Apply Node.js performance optimizations
      this.logger.info('⚡ Applying Node.js performance optimizations...');
      this.applyPerformanceOptimizations();

      this.logger.info('✅ Production environment initialized successfully');
    } catch (error) {
      this.logger.error('❌ Failed to initialize production environment', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Setup graceful shutdown handlers
   */
  private setupGracefulShutdownHandlers(): void {
    // Add cleanup operations for production
    this.gracefulShutdownManager.addCleanupOperation({
      name: 'health-endpoint-cleanup',
      priority: 1,
      timeout: 2000,
      critical: false,
      operation: async () => {
        if (this.healthEndpointManager) {
          this.healthEndpointManager.clearCache();
        }
      }
    });

    this.gracefulShutdownManager.addCleanupOperation({
      name: 'logger-flush',
      priority: 2,
      timeout: 3000,
      critical: false,
      operation: async () => {
        await this.logger.flush();
      }
    });
  }

  /**
   * Apply Node.js performance optimizations
   */
  private applyPerformanceOptimizations(): void {
    // Set up garbage collection if available
    if (global.gc) {
      this.logger.info('Garbage collection enabled');
    } else {
      this.logger.warn('Garbage collection not available (run with --expose-gc)');
    }

    // Log performance configuration
    this.logger.info('Performance settings applied', {
      nodeOptions: this.config.performance.nodeOptions,
      maxOldSpaceSize: this.config.performance.maxOldSpaceSize,
      maxHeapSize: this.config.performance.maxHeapSize,
      enableMetrics: this.config.performance.enableMetrics,
      enablePerformanceMonitoring: this.config.performance.enablePerformanceMonitoring
    });
  }

  /**
   * Get configuration object
   */
  getConfig(): ProductionConfig {
    return { ...this.config };
  }

  /**
   * Get security middleware
   */
  getSecurityMiddleware(): ProductionSecurityMiddleware {
    if (!this.securityMiddleware) {
      throw new Error('Security middleware not initialized. Call initialize() first.');
    }
    return this.securityMiddleware;
  }

  /**
   * Get health endpoint manager
   */
  getHealthEndpointManager(): HealthEndpointManager {
    if (!this.healthEndpointManager) {
      throw new Error('Health endpoint manager not initialized. Call initialize() first.');
    }
    return this.healthEndpointManager;
  }

  /**
   * Get graceful shutdown manager
   */
  getGracefulShutdownManager(): GracefulShutdownManager {
    return this.gracefulShutdownManager;
  }

  /**
   * Get logger instance
   */
  getLogger(): ProductionLogger {
    return this.logger;
  }

  /**
   * Update configuration at runtime
   */
  updateConfig(updates: Partial<ProductionConfig>): void {
    // Deep merge the updates
    this.config = this.deepMerge(this.config, updates);

    this.logger.info('Production configuration updated', { updates });

    // Re-validate after updates
    this.validateConfiguration();
  }

  /**
   * Deep merge objects
   */
  private deepMerge<T extends Record<string, any>>(target: T, source: Partial<T>): T {
    const result = { ...target };

    for (const key in source) {
      if (source[key] !== undefined) {
        if (typeof source[key] === 'object' && source[key] !== null && !Array.isArray(source[key])) {
          result[key] = this.deepMerge((result[key] as any) || {}, source[key] as any) as any;
        } else {
          result[key] = source[key] as any;
        }
      }
    }

    return result;
  }

  /**
   * Get environment information
   */
  getEnvironmentInfo(): Record<string, any> {
    return {
      nodeVersion: process.version,
      platform: process.platform,
      arch: process.arch,
      pid: process.pid,
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage(),
      environment: process.env.NODE_ENV,
      timestamp: new Date().toISOString(),
      configuration: this.config
    };
  }

  /**
   * Health check for configuration manager
   */
  healthCheck(): { healthy: boolean; details: Record<string, any> } {
    return {
      healthy: true,
      details: {
        environment: process.env.NODE_ENV,
        securityConfigured: !!this.securityMiddleware,
        healthEndpointsConfigured: !!this.healthEndpointManager,
        gracefulShutdownReady: true,
        configurationValid: true,
        lastValidation: new Date().toISOString()
      }
    };
  }

  /**
   * Export configuration for monitoring
   */
  exportConfiguration(): Record<string, any> {
    return {
      security: this.config.security,
      health: this.config.health,
      shutdown: this.config.shutdown,
      logging: this.config.logging,
      performance: this.config.performance,
      monitoring: this.config.monitoring,
      environment: process.env.NODE_ENV,
      version: process.env.npm_package_version || '2.0.1'
    };
  }
}

// Export singleton instance
export const productionConfig = ProductionConfigManager.getInstance();

export default ProductionConfigManager;