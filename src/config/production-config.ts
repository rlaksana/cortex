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

import { ProductionLogger } from '@/utils/logger.js';

import { ProductionEnvironmentValidator } from './production-validator.js';
import { ProductionSecurityMiddleware } from '../middleware/production-security-middleware.js';
import { GracefulShutdownManager } from '../monitoring/graceful-shutdown.js';
import { HealthEndpointManager } from '../monitoring/health-endpoint.js';
import type { Dict, JSONValue } from '../types/index.js';
import {
  isProductionConfig,
  safeMergeProductionConfig,
  validateAndCastProductionConfig,
  validateAndConvertHealthConfig,
  validateAndConvertLoggingConfig,
  validateAndConvertMonitoringConfig,
  validateAndConvertPerformanceConfig,
  validateAndConvertSecurityConfig,
  validateAndConvertShutdownConfig,
} from '../utils/configuration-type-guards.js';
import { type SimpleLogger } from '../utils/logger-wrapper.js';

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
  private logger: SimpleLogger;
  private securityMiddleware: ProductionSecurityMiddleware | null = null;
  private healthEndpointManager: HealthEndpointManager | null = null;
  private gracefulShutdownManager: GracefulShutdownManager;

  constructor() {
    this.validator = new ProductionEnvironmentValidator();
    this.logger = ProductionLogger;
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
   * Load production configuration from environment variables with safe parsing
   */
  private loadConfiguration(): ProductionConfig {
    return {
      security: {
        corsOrigin: this.getEnvArray('CORS_ORIGIN', []),
        rateLimitEnabled: this.getEnvBoolean('RATE_LIMIT_ENABLED', false),
        rateLimitWindowMs: this.getEnvNumber('RATE_LIMIT_WINDOW_MS', 900000),
        rateLimitMaxRequests: this.getEnvNumber('RATE_LIMIT_MAX_REQUESTS', 1000),
        helmetEnabled: this.getEnvBoolean('HELMET_ENABLED', false),
        requireApiKey: this.getEnvBoolean('REQUIRE_API_KEY', false),
        maxRequestSizeMb: this.getEnvNumber('MAX_REQUEST_SIZE_MB', 10),
        enableCompression: this.getEnvBoolean('ENABLE_COMPRESSION', false),
      },
      health: {
        enabled: this.getEnvBoolean('ENABLE_HEALTH_CHECKS', false),
        detailedEndpoints: this.getEnvBoolean('ENABLE_DETAILED_HEALTH_ENDPOINTS', false),
        metricsEndpoint: this.getEnvBoolean('ENABLE_METRICS_ENDPOINT', false),
        authenticationRequired: this.getEnvBoolean('HEALTH_ENDPOINT_AUTH_REQUIRED', false),
        allowedIPs: this.getEnvArray('HEALTH_ENDPOINT_ALLOWED_IPS', []),
      },
      shutdown: {
        timeout: this.getEnvNumber('SHUTDOWN_TIMEOUT', 30000),
        forceTimeout: this.getEnvNumber('FORCE_SHUTDOWN_TIMEOUT', 60000),
        enableDrainMode: this.getEnvBoolean('ENABLE_DRAIN_MODE', true),
        drainTimeout: this.getEnvNumber('DRAIN_TIMEOUT', 10000),
      },
      logging: {
        level: this.getEnvString('LOG_LEVEL', 'info'),
        format: (this.getEnvString('LOG_FORMAT', 'json') === 'text' ? 'text' : 'json') as
          | 'json'
          | 'text',
        structured: this.getEnvBoolean('LOG_STRUCTURED', false),
        includeTimestamp: this.getEnvBoolean('LOG_TIMESTAMP', true),
        includeRequestId: this.getEnvBoolean('LOG_REQUEST_ID', true),
      },
      performance: {
        enableMetrics: this.getEnvBoolean('ENABLE_METRICS_COLLECTION', false),
        enablePerformanceMonitoring: this.getEnvBoolean('ENABLE_PERFORMANCE_MONITORING', false),
        nodeOptions: this.getEnvString('NODE_OPTIONS', ''),
        maxOldSpaceSize: this.getEnvNumber('MAX_OLD_SPACE_SIZE', 8192),
        maxHeapSize: this.getEnvNumber('MAX_HEAP_SIZE', 8192),
      },
      monitoring: {
        enableSystemMetrics: this.getEnvBoolean('ENABLE_SYSTEM_METRICS', false),
        enableHealthChecks: this.getEnvBoolean('ENABLE_HEALTH_CHECKS', false),
        metricsInterval: this.getEnvNumber('METRICS_INTERVAL', 60000),
        healthCheckInterval: this.getEnvNumber('HEALTH_CHECK_INTERVAL', 30000),
      },
    };
  }

  // ============================================================================
  // Safe Environment Variable Parsing Utilities
  // ============================================================================

  /**
   * Get environment variable as string with default value
   */
  private getEnvString(key: string, defaultValue: string): string {
    const value = process.env[key];
    if (value === undefined || value === null) {
      return defaultValue;
    }
    return String(value).trim();
  }

  /**
   * Get environment variable as number with default value and validation
   */
  private getEnvNumber(key: string, defaultValue: number): number {
    const value = process.env[key];
    if (value === undefined || value === null) {
      return defaultValue;
    }

    const parsed = Number(value);
    if (isNaN(parsed) || !isFinite(parsed)) {
      this.logger.warn(
        `Invalid number value for environment variable ${key}: "${value}". Using default: ${defaultValue}`
      );
      return defaultValue;
    }

    return parsed;
  }

  /**
   * Get environment variable as boolean with default value
   */
  private getEnvBoolean(key: string, defaultValue: boolean): boolean {
    const value = process.env[key];
    if (value === undefined || value === null) {
      return defaultValue;
    }

    const normalized = String(value).toLowerCase().trim();

    // Explicit true values
    if (['true', '1', 'yes', 'on', 'enabled'].includes(normalized)) {
      return true;
    }

    // Explicit false values
    if (['false', '0', 'no', 'off', 'disabled'].includes(normalized)) {
      return false;
    }

    // Warn for unclear values and return default
    this.logger.warn(
      `Invalid boolean value for environment variable ${key}: "${value}". ` +
        `Expected 'true'/'false', '1'/'0', 'yes'/'no', 'on'/'off', or 'enabled'/'disabled'. Using default: ${defaultValue}`
    );
    return defaultValue;
  }

  /**
   * Get environment variable as array of strings with default value
   */
  private getEnvArray(key: string, defaultValue: string[]): string[] {
    const value = process.env[key];
    if (value === undefined || value === null || value.trim() === '') {
      return defaultValue;
    }

    return value
      .split(',')
      .map((item) => item.trim())
      .filter((item) => item.length > 0);
  }

  /**
   * Validate configuration with comprehensive type safety
   */
  private validateConfiguration(): void {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Validate security configuration
    if (
      this.config.security.rateLimitEnabled &&
      this.config.security.rateLimitMaxRequests > 10000
    ) {
      warnings.push('Rate limit is too permissive for production (>10000 requests)');
    }

    if (this.config.security.maxRequestSizeMb > 100) {
      errors.push('Maximum request size is too large for production (>100MB)');
    }

    // Validate CORS configuration
    if (this.config.security.corsOrigin.length === 0) {
      errors.push('CORS origin must be configured for production');
    }

    if (this.config.security.corsOrigin.includes('*') && process.env.NODE_ENV === 'production') {
      warnings.push('Wildcard CORS origin is not recommended for production');
    }

    // Validate each CORS origin format
    const invalidCorsOrigins = this.config.security.corsOrigin.filter((origin) => {
      if (origin === '*') return false; // Wildcard is handled separately
      if (!origin.startsWith('http://') && !origin.startsWith('https://')) return true;
      try {
        new URL(origin);
        return false;
      } catch {
        return true;
      }
    });

    if (invalidCorsOrigins.length > 0) {
      errors.push(`Invalid CORS origin formats: ${invalidCorsOrigins.join(', ')}`);
    }

    // Validate health configuration
    if (this.config.health.authenticationRequired && this.config.health.allowedIPs.length === 0) {
      warnings.push('Health endpoint authentication enabled but no allowed IPs configured');
    }

    // Validate IP address formats in allowedIPs
    const invalidIPs = this.config.health.allowedIPs.filter((ip) => {
      const ipv4Regex =
        /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
      const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
      return !ipv4Regex.test(ip) && !ipv6Regex.test(ip);
    });

    if (invalidIPs.length > 0) {
      warnings.push(`Invalid IP address formats in health allowed IPs: ${invalidIPs.join(', ')}`);
    }

    // Validate timeouts
    if (this.config.shutdown.timeout < 5000) {
      errors.push('Shutdown timeout should be at least 5 seconds');
    }

    if (this.config.shutdown.forceTimeout <= this.config.shutdown.timeout) {
      errors.push('Force shutdown timeout must be greater than normal shutdown timeout');
    }

    if (this.config.shutdown.drainTimeout >= this.config.shutdown.timeout) {
      warnings.push('Drain timeout should be less than normal shutdown timeout');
    }

    // Validate logging
    const validLogLevels = ['error', 'warn', 'info', 'debug'];
    if (!validLogLevels.includes(this.config.logging.level)) {
      errors.push(
        `Invalid log level: ${this.config.logging.level}. Valid values: ${validLogLevels.join(', ')}`
      );
    }

    // Validate performance settings
    if (this.config.performance.maxOldSpaceSize < 1024) {
      errors.push('Max old space size should be at least 1024MB for production');
    }

    if (this.config.performance.maxHeapSize < 1024) {
      errors.push('Max heap size should be at least 1024MB for production');
    }

    if (this.config.performance.maxOldSpaceSize > 32768) {
      warnings.push(
        'Max old space size is very large (>32GB), ensure sufficient memory is available'
      );
    }

    // Validate monitoring intervals
    if (this.config.monitoring.metricsInterval < 1000) {
      warnings.push('Metrics interval is very frequent (<1s), may impact performance');
    }

    if (this.config.monitoring.healthCheckInterval < 5000) {
      warnings.push('Health check interval is very frequent (<5s), may impact performance');
    }

    // Validate Node.js options format
    if (
      this.config.performance.nodeOptions &&
      !this.isValidNodeOptions(this.config.performance.nodeOptions)
    ) {
      warnings.push('Node.js options format may be invalid');
    }

    // Log validation results
    if (warnings.length > 0) {
      this.logger.warn('Production configuration validation warnings', { warnings });
    }

    if (errors.length > 0) {
      this.logger.error('Production configuration validation failed', { errors });
      throw new Error(`Configuration validation failed: ${errors.join(', ')}`);
    }

    this.logger.info('Production configuration validated successfully', {
      corsOrigins: this.config.security.corsOrigin.length,
      rateLimitEnabled: this.config.security.rateLimitEnabled,
      healthChecksEnabled: this.config.health.enabled,
      metricsEnabled: this.config.performance.enableMetrics,
    });
  }

  /**
   * Validate Node.js options format
   */
  private isValidNodeOptions(options: string): boolean {
    if (!options || typeof options !== 'string') {
      return true; // Empty is valid
    }

    try {
      // Basic validation: check if options look like Node.js CLI flags
      const optionParts = options.split(/\s+/);
      for (const part of optionParts) {
        if (!part) continue; // Skip empty parts

        // Valid Node.js options typically start with --
        if (part.startsWith('--')) {
          continue;
        }

        // Allow some single-dash options
        if (part.startsWith('-') && ['e', 'eval', 'p', 'print'].includes(part.slice(1))) {
          continue;
        }

        // If we reach here, the option format is suspicious
        return false;
      }
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Initialize all production components
   */
  initialize(): void {
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
        allowedIPs: this.config.health.allowedIPs,
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
        error: error instanceof Error ? error.message : 'Unknown error',
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
      },
    });

    this.gracefulShutdownManager.addCleanupOperation({
      name: 'logger-flush',
      priority: 2,
      timeout: 3000,
      critical: false,
      operation: async () => {
        if (this.logger.flush) {
          await this.logger.flush();
        }
      },
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
      enablePerformanceMonitoring: this.config.performance.enablePerformanceMonitoring,
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
  getLogger(): SimpleLogger {
    return this.logger;
  }

  /**
   * Update configuration at runtime with type safety
   */
  updateConfig(updates: Partial<ProductionConfig>): void {
    // Validate updates first
    if (!isProductionConfig(updates)) {
      throw new Error('Invalid configuration updates provided');
    }

    // Convert current config to Dict<JSONValue> for safe merging
    const currentConfigAsDict = this.config as unknown as Dict<JSONValue>;
    const updatesAsDict = updates as unknown as Dict<JSONValue>;

    // Safely merge configurations
    const mergedConfigDict = safeMergeProductionConfig(currentConfigAsDict, updatesAsDict);

    // Validate the merged configuration structure
    const validatedConfig = validateAndCastProductionConfig(mergedConfigDict);

    // Cast back to ProductionConfig with proper type safety
    this.config = this.castToProductionConfig(validatedConfig);

    this.logger.info('Production configuration updated', { updates });

    // Re-validate after updates
    this.validateConfiguration();
  }

  /**
   * Safely cast validated configuration to ProductionConfig using type-safe converters
   */
  private castToProductionConfig(validatedConfig: {
    security: Record<string, unknown>;
    health: Record<string, unknown>;
    shutdown: Record<string, unknown>;
    logging: Record<string, unknown>;
    performance: Record<string, unknown>;
    monitoring: Record<string, unknown>;
  }): ProductionConfig {
    // Use type-safe converters for each configuration section
    return {
      security: validateAndConvertSecurityConfig(validatedConfig.security),
      health: validateAndConvertHealthConfig(validatedConfig.health),
      shutdown: validateAndConvertShutdownConfig(validatedConfig.shutdown),
      logging: validateAndConvertLoggingConfig(validatedConfig.logging),
      performance: validateAndConvertPerformanceConfig(validatedConfig.performance),
      monitoring: validateAndConvertMonitoringConfig(validatedConfig.monitoring),
    };
  }

  /**
   * Deep merge helper for generic Dict<JSONValue>
   */
  private deepMergeDict(source: Dict<JSONValue>, target: Dict<JSONValue>): Dict<JSONValue> {
    const result = { ...target };

    for (const key in source) {
      if (source[key] !== undefined) {
        if (
          typeof source[key] === 'object' &&
          source[key] !== null &&
          !Array.isArray(source[key])
        ) {
          result[key] = this.deepMergeDict(
            source[key] as Dict<JSONValue>,
            (result[key] as Dict<JSONValue>) || {}
          ) as unknown as JSONValue;
        } else {
          result[key] = source[key] as JSONValue;
        }
      }
    }

    return result;
  }

  /**
   * Get environment information
   */
  getEnvironmentInfo(): Dict<JSONValue> {
    return {
      nodeVersion: process.version,
      platform: process.platform,
      arch: process.arch,
      pid: process.pid,
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage() as unknown as JSONValue,
      environment: process.env.NODE_ENV || 'development',
      timestamp: new Date().toISOString(),
      configuration: this.config as unknown as JSONValue,
    };
  }

  /**
   * Health check for configuration manager
   */
  healthCheck(): { healthy: boolean; details: Dict<JSONValue> } {
    return {
      healthy: true,
      details: {
        environment: process.env.NODE_ENV || 'development',
        securityConfigured: !!this.securityMiddleware,
        healthEndpointsConfigured: !!this.healthEndpointManager,
        gracefulShutdownReady: true,
        configurationValid: true,
        lastValidation: new Date().toISOString(),
      },
    };
  }

  /**
   * Export configuration for monitoring
   */
  exportConfiguration(): Dict<JSONValue> {
    return {
      security: this.config.security as unknown as JSONValue,
      health: this.config.health as unknown as JSONValue,
      shutdown: this.config.shutdown as unknown as JSONValue,
      logging: this.config.logging as unknown as JSONValue,
      performance: this.config.performance as unknown as JSONValue,
      monitoring: this.config.monitoring as unknown as JSONValue,
      environment: process.env.NODE_ENV || 'development',
      version: process.env.npm_package_version || '2.0.1',
    };
  }
}

// Export singleton instance
export const productionConfig = ProductionConfigManager.getInstance();

export default ProductionConfigManager;
