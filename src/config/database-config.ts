/**
 * Database Configuration Manager
 *
 * Comprehensive database configuration management supporting qdrant,
 * Qdrant, and hybrid deployments with environment-specific optimization.
 *
 * Features:
 * - Environment-specific configuration optimization
 * - Database connection validation
 * - Configuration health monitoring
 * - Dynamic configuration updates
 * - Migration configuration management
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { logger } from '../utils/logger.js';
import { environment } from './environment.js';
import type { DatabaseConfig } from '../db/database-interface.js';

// Polyfill fetch for Node.js compatibility
if (typeof fetch === 'undefined') {
  global.fetch = (await import('node-fetch')).default;
}

export interface DatabaseSelectionConfig {
  type: 'qdrant' | 'hybrid';
  migrationMode: boolean;
  fallbackEnabled: boolean;
}

export interface PostgresConfig {
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
  databaseUrl: string;
  pool: {
    min: number;
    max: number;
    idleTimeout: number;
    connectionTimeout: number;
    retryAttempts: number;
    retryDelay: number;
  };
}

export interface QdrantConfig {
  url?: string;
  apiKey?: string;
  timeout: number;
  collectionPrefix: string;
}

export interface VectorConfig {
  openaiApiKey?: string;
  size: number;
  distance: 'Cosine' | 'Euclidean' | 'DotProduct';
  embeddingModel: string;
  batchSize: number;
}

export interface MigrationConfig {
  mode?: 'pg-to-qdrant' | 'qdrant-to-pg' | 'sync' | 'validate' | 'cleanup';
  batchSize: number;
  concurrency: number;
  dryRun: boolean;
  preservePg: boolean;
  validationEnabled: boolean;
  skipValidation: boolean;
  progressFile: string;
}

export interface FeatureFlags {
  migrationMode: boolean;
  healthChecks: boolean;
  metricsCollection: boolean;
  caching: boolean;
  debugMode: boolean;
}

export interface CompleteDatabaseConfig {
  selection: DatabaseSelectionConfig;
  postgres?: PostgresConfig;
  qdrant: QdrantConfig;
  vector: VectorConfig;
  migration: MigrationConfig;
  features: FeatureFlags;
}

/**
 * Database configuration manager with comprehensive validation and optimization
 */
export class DatabaseConfigManager {
  private static instance: DatabaseConfigManager;
  private config: CompleteDatabaseConfig;
  private validationCache: Map<string, unknown> = new Map();

  private constructor() {
    this.config = this.loadConfiguration();
    this.validateAndOptimize();
  }

  static getInstance(): DatabaseConfigManager {
    if (!DatabaseConfigManager.instance) {
      DatabaseConfigManager.instance = new DatabaseConfigManager();
    }
    return DatabaseConfigManager.instance;
  }

  /**
   * Load and process configuration from environment
   */
  private loadConfiguration(): CompleteDatabaseConfig {
    const rawConfig = environment.getRawConfig();

    return {
      selection: {
        type: (rawConfig.DATABASE_TYPE as 'qdrant' | 'hybrid') || 'qdrant',
        migrationMode: false, // Default to false for now
        fallbackEnabled: true
      },
      qdrant: {
        url: rawConfig.QDRANT_URL || '',
        ...(rawConfig.QDRANT_API_KEY && { apiKey: rawConfig.QDRANT_API_KEY }),
        timeout: parseInt(String(rawConfig.QDRANT_TIMEOUT || '30000')),
        collectionPrefix: rawConfig.QDRANT_COLLECTION_PREFIX || 'cortex'
      },
      vector: {
        ...(rawConfig.OPENAI_API_KEY && { openaiApiKey: rawConfig.OPENAI_API_KEY }),
        size: parseInt(String(rawConfig.VECTOR_SIZE || '1536')),
        distance: rawConfig.VECTOR_DISTANCE as 'Cosine' | 'Euclidean' | 'DotProduct' || 'Cosine',
        embeddingModel: rawConfig.EMBEDDING_MODEL || 'text-embedding-ada-002',
        batchSize: parseInt(String(rawConfig.EMBEDDING_BATCH_SIZE || '10'))
      },
      migration: {
        mode: 'validate',
        batchSize: 100,
        concurrency: 5,
        dryRun: false,
        preservePg: false,
        validationEnabled: true,
        skipValidation: false,
        progressFile: './migration-progress.json'
      },
      features: {
        migrationMode: false,
        healthChecks: true,
        metricsCollection: true,
        caching: true,
        debugMode: rawConfig.NODE_ENV === 'development'
      }
    };
  }

  /**
   * Validate configuration and apply environment-specific optimizations
   */
  private validateAndOptimize(): void {
    const env = environment.getRawConfig().NODE_ENV;

    // Validate based on database type
    this.validateDatabaseType();

    // Apply environment-specific optimizations
    this.applyEnvironmentOptimizations(env);

    // Validate required dependencies
    this.validateDependencies();

    // Log successful configuration
    void logger.info({
      type: this.config.selection.type,
      environment: env,
      migrationMode: this.config.selection.migrationMode,
      features: this.config.features
    }, 'Database configuration validated and optimized');
  }

  /**
   * Validate database type configuration
   */
  private validateDatabaseType(): void {
    const { type } = this.config.selection;

    switch (type) {
      case 'qdrant':
        if (!this.config.qdrant.url) {
          throw new Error('Qdrant configuration is incomplete: missing URL');
        }
        if (!this.config.vector.openaiApiKey) {
          throw new Error('Qdrant configuration is incomplete: missing OpenAI API key');
        }
        break;

      case 'hybrid':
        if (!this.config.qdrant.url) {
          throw new Error('Hybrid mode requires Qdrant configuration');
        }
        if (!this.config.vector.openaiApiKey) {
          throw new Error('Hybrid mode requires OpenAI API key for vectors');
        }
        break;

      default:
        throw new Error(`Unsupported database type: ${type}`);
    }
  }

  /**
   * Apply environment-specific optimizations
   */
  private applyEnvironmentOptimizations(env: string): void {
    switch (env) {
      case 'development':
        // Optimize for development
        this.config.migration.batchSize = Math.min(this.config.migration.batchSize, 100);
        this.config.features.debugMode = true;
        this.config.features.caching = false;
        break;

      case 'production':
        // Optimize for production
        this.config.migration.dryRun = false;
        this.config.features.debugMode = false;
        this.config.features.caching = true;
        this.config.features.metricsCollection = true;
        break;

      case 'test':
        // Optimize for testing
        this.config.migration.batchSize = Math.min(this.config.migration.batchSize, 10);
        this.config.migration.dryRun = true;
        this.config.features.debugMode = false;
        this.config.features.caching = false;
        this.config.features.metricsCollection = false;
        break;
    }
  }

  /**
   * Validate required dependencies and services
   */
  private validateDependencies(): void {
    // Check if required environment variables are set
    const requiredVars: string[] = [];

    if (this.config.selection.type === 'qdrant' || this.config.selection.type === 'hybrid') {
      if (!this.config.vector.openaiApiKey) {
        requiredVars.push('OPENAI_API_KEY');
      }
      if (!this.config.qdrant.url) {
        requiredVars.push('QDRANT_URL');
      }
    }

    if (requiredVars.length > 0) {
      throw new Error(`Missing required environment variables: ${requiredVars.join(', ')}`);
    }
  }

  /**
   * Get complete database configuration
   */
  getConfiguration(): CompleteDatabaseConfig {
    return { ...this.config };
  }

  /**
   * Get configuration for specific database type
   */
  getPostgresConfig(): PostgresConfig | undefined {
    return this.config.postgres ? { ...this.config.postgres } : undefined;
  }

  getQdrantConfig(): QdrantConfig {
    return { ...this.config.qdrant };
  }

  getVectorConfig(): VectorConfig {
    return { ...this.config.vector };
  }

  getMigrationConfig(): MigrationConfig {
    return { ...this.config.migration };
  }

  getFeatureFlags(): FeatureFlags {
    return { ...this.config.features };
  }

  /**
   * Create database configuration for factory
   */
  createFactoryConfig(): DatabaseConfig {
    const baseConfig: DatabaseConfig = {
      type: this.config.selection.type,
      connectionString: this.config.qdrant.url || '',
      url: this.config.qdrant.url,
      ...(this.config.qdrant.apiKey && { apiKey: this.config.qdrant.apiKey }),
      logQueries: this.config.features.debugMode,
      connectionTimeout: this.config.qdrant.timeout,
      maxConnections: 10, // Default value since pool doesn't exist anymore
      vectorSize: this.config.vector.size,
      distance: this.config.vector.distance
    };

    return baseConfig;
  }

  /**
   * Validate all database connections
   */
  async validateConnections(): Promise<{
    qdrant: boolean;
    openai: boolean;
    overall: boolean;
    errors: string[];
  }> {
    const errors: string[] = [];
    let qdrant = false;
    let openai = false;

    try {
      // Basic validation for Qdrant URL
      if (this.config.qdrant.url) {
        qdrant = true;
      } else {
        errors.push('Qdrant URL is not configured');
      }
    } catch (error) {
      errors.push(`Qdrant validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }

    try {
      // Basic validation for OpenAI API key
      if (this.config.vector.openaiApiKey) {
        openai = true;
      } else {
        errors.push('OpenAI API key is not configured');
      }
    } catch (error) {
      errors.push(`OpenAI validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }

    const overall = qdrant && openai && errors.length === 0;

    return {
      qdrant,
      openai,
      overall,
      errors
    };
  }

  /**
   * Update configuration (for dynamic updates)
   */
  updateConfiguration(updates: Partial<CompleteDatabaseConfig>): void {
    // Merge updates with existing configuration
    this.config = this.deepMerge(this.config, updates);

    // Re-validate and optimize
    this.validateAndOptimize();

    // Clear validation cache
    this.validationCache.clear();

    void logger.info({ updates: Object.keys(updates) }, 'Database configuration updated');
  }

  /**
   * Get configuration health status
   */
  async getHealthStatus(): Promise<{
    healthy: boolean;
    configuration: boolean;
    connections: boolean;
    dependencies: boolean;
    issues: string[];
    lastChecked: Date;
  }> {
    const issues: string[] = [];

    // Check configuration validity
    let configurationValid = true;
    try {
      this.validateDatabaseType();
      this.validateDependencies();
    } catch (error) {
      configurationValid = false;
      issues.push(`Configuration error: ${error instanceof Error ? error.message : String(error)}`);
    }

    // Check connection health
    const connectionValidation = await this.validateConnections();
    const connectionsValid = connectionValidation.overall;
    if (!connectionsValid) {
      issues.push(...connectionValidation.errors);
    }

    // Check dependency health (e.g., OpenAI API)
    let dependenciesValid = true;
    if (this.config.selection.type === 'qdrant' || this.config.selection.type === 'hybrid') {
      try {
        // Test OpenAI API connectivity
        const response = await fetch('https://api.openai.com/v1/models', {
          headers: {
            'Authorization': `Bearer ${this.config.vector.openaiApiKey}`
          },
          signal: AbortSignal.timeout(5000)
        });

        if (!response.ok) {
          dependenciesValid = false;
          issues.push(`OpenAI API health check failed: ${response.status}`);
        }
      } catch (error) {
        dependenciesValid = false;
        issues.push(`OpenAI API connectivity failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    }

    const overallHealth = configurationValid && connectionsValid && dependenciesValid;

    return {
      healthy: overallHealth,
      configuration: configurationValid,
      connections: connectionsValid,
      dependencies: dependenciesValid,
      issues,
      lastChecked: new Date()
    };
  }

  /**
   * Export configuration for external systems
   */
  exportForExternal(): Record<string, unknown> {
    return environment.exportForMcp();
  }

  /**
   * Deep merge utility for configuration updates
   */
  private deepMerge(target: Partial<CompleteDatabaseConfig>, source: Partial<CompleteDatabaseConfig>): CompleteDatabaseConfig {
    const result = { ...target };

    for (const key in source) {
      if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
        (result as any)[key] = this.deepMerge((result[key] || {}) as Partial<CompleteDatabaseConfig>, source[key] as Partial<CompleteDatabaseConfig>);
      } else {
        (result as any)[key] = source[key];
      }
    }

    return result as CompleteDatabaseConfig;
  }
}

// Export singleton instance
export const databaseConfig = DatabaseConfigManager.getInstance();