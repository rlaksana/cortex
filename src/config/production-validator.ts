/**
 * Production Environment Validator
 *
 * Validates all required environment variables and production-specific configurations.
 * Ensures the application has all necessary security and operational settings
 * before starting in production mode.
 *
 * @author Cortex Team
 * @version 2.0.1
 */

import { logger } from '@/utils/logger.js';

export interface EnvironmentValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
  critical: string[];
}

export interface ProductionEnvironmentConfig {
  // Required secrets
  openaiApiKey: string;
  jwtSecret: string;
  encryptionKey: string;
  mcpApiKey?: string;

  // Required URLs
  qdrantUrl: string;

  // Security settings
  corsOrigin: string[];
  requireApiKey: boolean;
  helmetEnabled: boolean;
  rateLimitEnabled: boolean;

  // Performance settings
  timeouts: {
    qdrant: number;
    api: number;
    connection: number;
  };

  // Monitoring
  enableMetrics: boolean;
  enableHealthChecks: boolean;
  logLevel: string;

  // Scope
  org: string;
  project: string;
  branch: string;
}

export class ProductionEnvironmentValidator {
  private static readonly REQUIRED_SECRETS = ['OPENAI_API_KEY', 'JWT_SECRET', 'ENCRYPTION_KEY'];

  private static readonly MINIMUM_SECRET_LENGTHS = {
    OPENAI_API_KEY: 20,
    JWT_SECRET: 64,
    ENCRYPTION_KEY: 64,
    MCP_API_KEY: 48,
  };

  private static readonly VALID_LOG_LEVELS = ['error', 'warn', 'info', 'debug'];
  private static readonly PRODUCTION_RECOMMENDED_LOG_LEVELS = ['error', 'warn', 'info'];

  constructor() {
    // Use the imported logger instead of creating a new instance
  }

  /**
   * Validate complete production environment
   */
  validateProductionEnvironment(): EnvironmentValidationResult {
    const result: EnvironmentValidationResult = {
      isValid: true,
      errors: [],
      warnings: [],
      critical: [],
    };

    logger.info('Starting production environment validation');

    // Validate critical security settings
    this.validateSecurity(result);

    // Validate required services
    this.validateServices(result);

    // Validate performance configuration
    this.validatePerformance(result);

    // validate monitoring configuration
    this.validateMonitoring(result);

    // Validate scope configuration
    this.validateScope(result);

    // Validate feature flags
    this.validateFeatureFlags(result);

    // Log validation results
    this.logValidationResults(result);

    // Set final validation status
    result.isValid = result.critical.length === 0 && result.errors.length === 0;

    return result;
  }

  /**
   * Validate security configuration
   */
  private validateSecurity(result: EnvironmentValidationResult): void {
    // Check required secrets
    for (const secret of ProductionEnvironmentValidator.REQUIRED_SECRETS) {
      const value = process.env[secret];
      const minLength =
        ProductionEnvironmentValidator.MINIMUM_SECRET_LENGTHS[
          secret as keyof typeof ProductionEnvironmentValidator.MINIMUM_SECRET_LENGTHS
        ];

      if (!value) {
        result.critical.push(`Missing required environment variable: ${secret}`);
      } else if (minLength && value.length < minLength) {
        result.critical.push(
          `${secret} must be at least ${minLength} characters long (current: ${value.length})`
        );
      } else if (this.isDefaultValue(value)) {
        result.critical.push(`${secret} appears to be using a default/placeholder value`);
      }
    }

    // Validate optional API key if required
    if (process.env.REQUIRE_API_KEY === 'true' && !process.env.MCP_API_KEY) {
      result.critical.push('MCP_API_KEY is required when REQUIRE_API_KEY is enabled');
    }

    // Validate JWT secret strength
    const jwtSecret = process.env.JWT_SECRET;
    if (jwtSecret) {
      if (!this.isStrongSecret(jwtSecret)) {
        result.errors.push(
          'JWT_SECRET should contain a mix of letters, numbers, and special characters'
        );
      }
    }

    // Validate encryption key format
    const encryptionKey = process.env.ENCRYPTION_KEY;
    if (encryptionKey && !/^[a-fA-F0-9]+$/.test(encryptionKey)) {
      result.critical.push('ENCRYPTION_KEY must be a valid hexadecimal string');
    }

    // Validate CORS configuration
    const corsOrigin = process.env.CORS_ORIGIN;
    if (!corsOrigin) {
      result.critical.push('CORS_ORIGIN must be configured for production');
    } else if (corsOrigin.includes('*') && corsOrigin.split(',').length === 1) {
      result.warnings.push('Wildcard CORS origin is not recommended for production');
    }

    // Validate security features
    if (process.env.HELMET_ENABLED !== 'true') {
      result.warnings.push('HELMET_ENABLED should be true in production');
    }

    if (process.env.RATE_LIMIT_ENABLED !== 'true') {
      result.warnings.push('RATE_LIMIT_ENABLED should be true in production');
    }
  }

  /**
   * Validate required services
   */
  private validateServices(result: EnvironmentValidationResult): void {
    // Validate OpenAI API key format
    const openaiKey = process.env.OPENAI_API_KEY;
    if (openaiKey) {
      if (!openaiKey.startsWith('sk-')) {
        result.critical.push('OPENAI_API_KEY appears to be invalid (should start with "sk-")');
      }
    }

    // Validate Qdrant configuration
    const qdrantUrl = process.env.QDRANT_URL;
    if (!qdrantUrl) {
      result.critical.push('QDRANT_URL is required');
    } else {
      try {
        new URL(qdrantUrl);
        if (qdrantUrl.includes('localhost') || qdrantUrl.includes('127.0.0.1')) {
          result.warnings.push('QDRANT_URL should point to a production cluster, not localhost');
        }
        if (qdrantUrl.startsWith('http://') && !qdrantUrl.includes('localhost')) {
          result.warnings.push('QDRANT_URL should use HTTPS in production');
        }
      } catch {
        result.critical.push('QDRANT_URL is not a valid URL');
      }
    }

    // Validate database configuration
    const dbType = process.env.DATABASE_TYPE;
    if (dbType !== 'qdrant') {
      result.critical.push('DATABASE_TYPE must be "qdrant" in production');
    }
  }

  /**
   * Validate performance configuration
   */
  private validatePerformance(result: EnvironmentValidationResult): void {
    // Validate timeout values
    const timeouts = {
      qdrant: parseInt(process.env.QDRANT_TIMEOUT || '30000'),
      api: parseInt(process.env.API_TIMEOUT || '30000'),
      connection: parseInt(process.env.DB_CONNECTION_TIMEOUT || '30000'),
    };

    for (const [name, value] of Object.entries(timeouts)) {
      if (isNaN(value) || value < 1000) {
        result.errors.push(`${name.toUpperCase()}_TIMEOUT must be at least 1000ms`);
      } else if (value > 300000) {
        result.warnings.push(
          `${name.toUpperCase()}_TIMEOUT is very high (5+ minutes), consider reducing`
        );
      }
    }

    // Validate connection pool settings
    const maxConnections = parseInt(process.env.QDRANT_MAX_CONNECTIONS || '10');
    if (isNaN(maxConnections) || maxConnections < 5) {
      result.warnings.push('QDRANT_MAX_CONNECTIONS should be at least 5 for production');
    } else if (maxConnections > 100) {
      result.warnings.push(
        'QDRANT_MAX_CONNECTIONS is very high, ensure your Qdrant cluster can handle it'
      );
    }

    // Validate Node.js memory settings
    const nodeOptions = process.env.NODE_OPTIONS;
    if (!nodeOptions || !nodeOptions.includes('--max-old-space-size')) {
      result.warnings.push('NODE_OPTIONS should include --max-old-space-size for production');
    }
  }

  /**
   * Validate monitoring configuration
   */
  private validateMonitoring(result: EnvironmentValidationResult): void {
    // Validate log level
    const logLevel = process.env.LOG_LEVEL?.toLowerCase();
    if (!logLevel) {
      result.errors.push('LOG_LEVEL is required');
    } else if (!ProductionEnvironmentValidator.VALID_LOG_LEVELS.includes(logLevel)) {
      result.errors.push(
        `LOG_LEVEL must be one of: ${ProductionEnvironmentValidator.VALID_LOG_LEVELS.join(', ')}`
      );
    } else if (
      !ProductionEnvironmentValidator.PRODUCTION_RECOMMENDED_LOG_LEVELS.includes(logLevel)
    ) {
      result.warnings.push(
        `LOG_LEVEL "${logLevel}" is verbose for production, consider using "info" or "warn"`
      );
    }

    // Validate monitoring features
    if (process.env.ENABLE_METRICS_COLLECTION !== 'true') {
      result.warnings.push('ENABLE_METRICS_COLLECTION should be true in production');
    }

    if (process.env.ENABLE_HEALTH_CHECKS !== 'true') {
      result.warnings.push('ENABLE_HEALTH_CHECKS should be true in production');
    }
  }

  /**
   * Validate scope configuration
   */
  private validateScope(result: EnvironmentValidationResult): void {
    const requiredScope = ['CORTEX_ORG', 'CORTEX_PROJECT', 'CORTEX_BRANCH'];

    for (const field of requiredScope) {
      const value = process.env[field];
      if (!value) {
        result.critical.push(`${field} is required for production deployment`);
      } else if (this.isDefaultValue(value)) {
        result.critical.push(`${field} appears to be using a default/placeholder value`);
      }
    }
  }

  /**
   * Validate feature flags
   */
  private validateFeatureFlags(result: EnvironmentValidationResult): void {
    // Debug mode should be disabled in production
    if (process.env.ENABLE_DEBUG_MODE === 'true') {
      result.warnings.push('ENABLE_DEBUG_MODE should be false in production');
    }

    // Security features should be enabled
    const securityFeatures = [
      'ENABLE_ENCRYPTION',
      'ENABLE_AUDIT_LOGGING',
      'ENABLE_CIRCUIT_BREAKER',
    ];

    for (const feature of securityFeatures) {
      if (process.env[feature] !== 'true') {
        result.warnings.push(`${feature} should be true in production`);
      }
    }

    // Compression should be enabled
    if (process.env.ENABLE_COMPRESSION !== 'true') {
      result.warnings.push(
        'ENABLE_COMPRESSION should be true in production for better performance'
      );
    }
  }

  /**
   * Check if a value appears to be a default/placeholder
   */
  private isDefaultValue(value: string): boolean {
    const defaultPatterns = [
      /your-.*-here/i,
      /placeholder/i,
      /example/i,
      /test/i,
      /demo/i,
      /change-me/i,
      /replace-with/i,
    ];

    return defaultPatterns.some((pattern) => pattern.test(value));
  }

  /**
   * Check if a secret is strong enough
   */
  private isStrongSecret(secret: string): boolean {
    // Check for minimum entropy (basic heuristic)
    const hasLetters = /[a-zA-Z]/.test(secret);
    const hasNumbers = /[0-9]/.test(secret);
    const hasSpecialChars = /[^a-zA-Z0-9]/.test(secret);

    return hasLetters && hasNumbers && hasSpecialChars && secret.length >= 32;
  }

  /**
   * Log validation results
   */
  private logValidationResults(result: EnvironmentValidationResult): void {
    if (result.critical.length > 0) {
      logger.error('Critical validation errors found', {
        count: result.critical.length,
        errors: result.critical,
      });
    }

    if (result.errors.length > 0) {
      logger.error('Validation errors found', {
        count: result.errors.length,
        errors: result.errors,
      });
    }

    if (result.warnings.length > 0) {
      logger.warn('Validation warnings found', {
        count: result.warnings.length,
        warnings: result.warnings,
      });
    }

    if (result.critical.length === 0 && result.errors.length === 0) {
      logger.info('Production environment validation passed', {
        warningsCount: result.warnings.length,
      });
    }
  }

  /**
   * Get production configuration object
   */
  getProductionConfig(): ProductionEnvironmentConfig {
    const config: ProductionEnvironmentConfig = {
      openaiApiKey: process.env.OPENAI_API_KEY || '',
      jwtSecret: process.env.JWT_SECRET || '',
      encryptionKey: process.env.ENCRYPTION_KEY || '',
      mcpApiKey: process.env.MCP_API_KEY,
      qdrantUrl: process.env.QDRANT_URL || '',
      corsOrigin: (process.env.CORS_ORIGIN || '').split(',').map((o) => o.trim()),
      requireApiKey: process.env.REQUIRE_API_KEY === 'true',
      helmetEnabled: process.env.HELMET_ENABLED === 'true',
      rateLimitEnabled: process.env.RATE_LIMIT_ENABLED === 'true',
      timeouts: {
        qdrant: parseInt(process.env.QDRANT_TIMEOUT || '30000'),
        api: parseInt(process.env.API_TIMEOUT || '30000'),
        connection: parseInt(process.env.DB_CONNECTION_TIMEOUT || '30000'),
      },
      enableMetrics: process.env.ENABLE_METRICS_COLLECTION === 'true',
      enableHealthChecks: process.env.ENABLE_HEALTH_CHECKS === 'true',
      logLevel: process.env.LOG_LEVEL || 'info',
      org: process.env.CORTEX_ORG || '',
      project: process.env.CORTEX_PROJECT || '',
      branch: process.env.CORTEX_BRANCH || '',
    };

    return config;
  }

  /**
   * Abort startup if critical issues are found
   */
  assertValidForProduction(): void {
    const result = this.validateProductionEnvironment();

    if (result.critical.length > 0) {
      logger.error('CRITICAL: Production environment validation failed. Server startup aborted.', {
        critical: result.critical,
        errors: result.errors,
      });

      console.error('\n🚨 CRITICAL VALIDATION FAILURES 🚨');
      console.error('Cannot start in production mode due to critical configuration errors:');
      console.error('');

      result.critical.forEach((error) => {
        console.error(`❌ ${error}`);
      });

      if (result.errors.length > 0) {
        console.error('');
        console.error('Additional errors:');
        result.errors.forEach((error) => {
          console.error(`⚠️  ${error}`);
        });
      }

      console.error('');
      console.error('Please fix these issues before starting the server in production mode.');
      console.error('Refer to the .env.production file for proper configuration examples.');

      process.exit(1);
    }

    if (result.errors.length > 0) {
      logger.warn('Production environment has configuration errors', {
        errors: result.errors,
      });
    }

    if (result.warnings.length > 0) {
      logger.info('Production environment validation completed with warnings', {
        warnings: result.warnings,
      });
    }
  }
}

export default ProductionEnvironmentValidator;
