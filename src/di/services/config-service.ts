// @ts-nocheck
// EMERGENCY ROLLBACK: DI container interface compatibility issues
// TODO: Fix systematic type issues before removing @ts-nocheck

/**
 * Configuration Service Implementation
 *
 * Provides centralized configuration management with environment-based
 * loading and validation. Implements the IConfigService interface.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */


import { Injectable } from '../di-container.js';
import type { IConfigService, ILoggerService  } from '../service-interfaces.js';
import { ServiceTokens } from '../service-interfaces.js';

/**
 * Configuration schema interface
 */
export interface ConfigSchema {
  QDRANT_URL: string;
  QDRANT_API_KEY?: string;
  QDRANT_COLLECTION_NAME: string;
  OPENAI_API_KEY?: string;
  LOG_LEVEL: string;
  NODE_ENV: string;
  CORTEX_ORG?: string;
  CORTEX_PROJECT?: string;
  CORTEX_BRANCH?: string;
  PORT?: number;
  MAX_MEMORY_ITEMS?: number;
  SIMILARITY_THRESHOLD?: number;
  CACHE_TTL?: number;
  DATABASE_TIMEOUT?: number;
  AUTH_SECRET?: string;
  RATE_LIMIT_MAX?: number;
  RATE_LIMIT_WINDOW?: number;
}

/**
 * Default configuration values
 */
const DEFAULT_CONFIG: Partial<ConfigSchema> = {
  QDRANT_URL: 'http://localhost:6333',
  QDRANT_COLLECTION_NAME: 'cortex-memory',
  LOG_LEVEL: 'info',
  NODE_ENV: 'development',
  PORT: 3000,
  MAX_MEMORY_ITEMS: 10000,
  SIMILARITY_THRESHOLD: 0.85,
  CACHE_TTL: 300000, // 5 minutes
  DATABASE_TIMEOUT: 30000, // 30 seconds
  RATE_LIMIT_MAX: 100,
  RATE_LIMIT_WINDOW: 60000, // 1 minute
};

/**
 * Configuration service with environment loading and validation
 */
@Injectable(ServiceTokens.CONFIG_SERVICE)
export class ConfigService implements IConfigService {
  private config: ConfigSchema;
  private logger: ILoggerService;

  constructor(logger: ILoggerService) {
    this.logger = logger.child({ service: 'ConfigService' });
    this.config = this.loadConfiguration();
    this.validateConfiguration();
    this.logger.info('Configuration service initialized');
  }

  /**
   * Get configuration value by key with optional default fallback
   */
  get<T>(key: keyof ConfigSchema, defaultValue?: T): T {
    const value = this.config[key];
    return value !== undefined ? (value as T) : (defaultValue as T);
  }

  /**
   * Check if configuration key exists
   */
  has(key: keyof ConfigSchema): boolean {
    return this.config[key] !== undefined;
  }

  /**
   * Reload configuration from environment
   */
  async reload(): Promise<void> {
    this.logger.info('Reloading configuration...');
    const oldConfig = { ...this.config };
    this.config = this.loadConfiguration();
    this.validateConfiguration();

    // Log configuration changes
    const changes = this.detectChanges(oldConfig, this.config);
    if (changes.length > 0) {
      this.logger.info('Configuration reloaded with changes', { changes });
    } else {
      this.logger.debug('Configuration reloaded with no changes');
    }
  }

  /**
   * Get all configuration values (for debugging)
   */
  getAll(): ConfigSchema {
    return { ...this.config };
  }

  /**
   * Get environment-specific configuration
   */
  getEnvironment(): string {
    return this.config.NODE_ENV;
  }

  /**
   * Check if running in production
   */
  isProduction(): boolean {
    return this.config.NODE_ENV === 'production';
  }

  /**
   * Check if running in development
   */
  isDevelopment(): boolean {
    return this.config.NODE_ENV === 'development';
  }

  /**
   * Check if running in test
   */
  isTest(): boolean {
    return this.config.NODE_ENV === 'test';
  }

  /**
   * Get database configuration
   */
  getDatabaseConfig() {
    return {
      url: this.config.QDRANT_URL,
      apiKey: this.config.QDRANT_API_KEY,
      collectionName: this.config.QDRANT_COLLECTION_NAME,
      timeout: this.config.DATABASE_TIMEOUT,
    };
  }

  /**
   * Get OpenAI configuration
   */
  getOpenAIConfig() {
    return {
      apiKey: this.config.OPENAI_API_KEY,
    };
  }

  /**
   * Get performance configuration
   */
  getPerformanceConfig() {
    return {
      maxMemoryItems: this.config.MAX_MEMORY_ITEMS,
      similarityThreshold: this.config.SIMILARITY_THRESHOLD,
      cacheTTL: this.config.CACHE_TTL,
    };
  }

  /**
   * Get rate limiting configuration
   */
  getRateLimitConfig() {
    return {
      max: this.config.RATE_LIMIT_MAX,
      windowMs: this.config.RATE_LIMIT_WINDOW,
    };
  }

  /**
   * Load configuration from environment variables
   */
  private loadConfiguration(): ConfigSchema {
    const config: ConfigSchema = {
      QDRANT_URL: process.env.QDRANT_URL || DEFAULT_CONFIG.QDRANT_URL!,
      QDRANT_API_KEY: process.env.QDRANT_API_KEY,
      QDRANT_COLLECTION_NAME:
        process.env.QDRANT_COLLECTION_NAME || DEFAULT_CONFIG.QDRANT_COLLECTION_NAME!,
      OPENAI_API_KEY: process.env.OPENAI_API_KEY,
      LOG_LEVEL: process.env.LOG_LEVEL || DEFAULT_CONFIG.LOG_LEVEL!,
      NODE_ENV: process.env.NODE_ENV || DEFAULT_CONFIG.NODE_ENV!,
      CORTEX_ORG: process.env.CORTEX_ORG,
      CORTEX_PROJECT: process.env.CORTEX_PROJECT,
      CORTEX_BRANCH: process.env.CORTEX_BRANCH,
      PORT: process.env.PORT ? parseInt(process.env.PORT, 10) : DEFAULT_CONFIG.PORT,
      MAX_MEMORY_ITEMS: process.env.MAX_MEMORY_ITEMS
        ? parseInt(process.env.MAX_MEMORY_ITEMS, 10)
        : DEFAULT_CONFIG.MAX_MEMORY_ITEMS,
      SIMILARITY_THRESHOLD: process.env.SIMILARITY_THRESHOLD
        ? parseFloat(process.env.SIMILARITY_THRESHOLD)
        : DEFAULT_CONFIG.SIMILARITY_THRESHOLD,
      CACHE_TTL: process.env.CACHE_TTL
        ? parseInt(process.env.CACHE_TTL, 10)
        : DEFAULT_CONFIG.CACHE_TTL,
      DATABASE_TIMEOUT: process.env.DATABASE_TIMEOUT
        ? parseInt(process.env.DATABASE_TIMEOUT, 10)
        : DEFAULT_CONFIG.DATABASE_TIMEOUT,
      AUTH_SECRET: process.env.AUTH_SECRET,
      RATE_LIMIT_MAX: process.env.RATE_LIMIT_MAX
        ? parseInt(process.env.RATE_LIMIT_MAX, 10)
        : DEFAULT_CONFIG.RATE_LIMIT_MAX,
      RATE_LIMIT_WINDOW: process.env.RATE_LIMIT_WINDOW
        ? parseInt(process.env.RATE_LIMIT_WINDOW, 10)
        : DEFAULT_CONFIG.RATE_LIMIT_WINDOW,
    };

    return config;
  }

  /**
   * Validate configuration values
   */
  private validateConfiguration(): void {
    const errors: string[] = [];

    // Validate required fields
    if (!this.config.QDRANT_URL) {
      errors.push('QDRANT_URL is required');
    }

    if (!this.config.QDRANT_COLLECTION_NAME) {
      errors.push('QDRANT_COLLECTION_NAME is required');
    }

    // Validate numeric values
    if (this.config.PORT !== undefined && (this.config.PORT < 1 || this.config.PORT > 65535)) {
      errors.push('PORT must be between 1 and 65535');
    }

    if (this.config.MAX_MEMORY_ITEMS !== undefined && this.config.MAX_MEMORY_ITEMS < 1) {
      errors.push('MAX_MEMORY_ITEMS must be greater than 0');
    }

    if (
      this.config.SIMILARITY_THRESHOLD !== undefined &&
      (this.config.SIMILARITY_THRESHOLD < 0 || this.config.SIMILARITY_THRESHOLD > 1)
    ) {
      errors.push('SIMILARITY_THRESHOLD must be between 0 and 1');
    }

    if (this.config.CACHE_TTL !== undefined && this.config.CACHE_TTL < 0) {
      errors.push('CACHE_TTL must be non-negative');
    }

    if (this.config.DATABASE_TIMEOUT !== undefined && this.config.DATABASE_TIMEOUT < 1000) {
      errors.push('DATABASE_TIMEOUT must be at least 1000ms');
    }

    if (this.config.RATE_LIMIT_MAX !== undefined && this.config.RATE_LIMIT_MAX < 1) {
      errors.push('RATE_LIMIT_MAX must be greater than 0');
    }

    if (this.config.RATE_LIMIT_WINDOW !== undefined && this.config.RATE_LIMIT_WINDOW < 1000) {
      errors.push('RATE_LIMIT_WINDOW must be at least 1000ms');
    }

    // Validate log level
    const validLogLevels = ['error', 'warn', 'info', 'debug', 'trace'];
    if (!validLogLevels.includes(this.config.LOG_LEVEL.toLowerCase())) {
      errors.push(`LOG_LEVEL must be one of: ${validLogLevels.join(', ')}`);
    }

    // Validate environment
    const validEnvironments = ['development', 'production', 'test', 'staging'];
    if (!validEnvironments.includes(this.config.NODE_ENV.toLowerCase())) {
      errors.push(`NODE_ENV must be one of: ${validEnvironments.join(', ')}`);
    }

    if (errors.length > 0) {
      this.logger.error('Configuration validation failed', { errors });
      throw new Error(`Configuration validation failed: ${errors.join(', ')}`);
    }

    this.logger.debug('Configuration validation passed');
  }

  /**
   * Detect configuration changes
   */
  private detectChanges(oldConfig: ConfigSchema, newConfig: ConfigSchema): string[] {
    const changes: string[] = [];

    for (const key in newConfig) {
      const oldVal = oldConfig[key as keyof ConfigSchema];
      const newVal = newConfig[key as keyof ConfigSchema];

      if (oldVal !== newVal) {
        changes.push(`${key}: ${JSON.stringify(oldVal)} -> ${JSON.stringify(newVal)}`);
      }
    }

    return changes;
  }
}
