import { z } from 'zod';
import * as dotenv from 'dotenv';
import crypto from 'crypto';
import { logger } from '../utils/logger.js';

// Load environment variables
void dotenv.config();

/**
 * Qdrant-only environment configuration with validation and security
 */

// Database configuration schema (Qdrant-only)
const DatabaseConfigSchema = z.object({
  // Database type selection (Qdrant-only)
  DATABASE_TYPE: z.enum(['qdrant']).default('qdrant'),

  // Qdrant configuration
  QDRANT_URL: z.string().url().default('http://localhost:6333'),
  // DATABASE_URL removed - PostgreSQL no longer supported
  QDRANT_API_KEY: z.string().optional(),
  QDRANT_TIMEOUT: z.string().transform(Number).pipe(z.number().int().min(1000)).default('30000'),
  QDRANT_COLLECTION_PREFIX: z.string().default('cortex'),
  QDRANT_COLLECTION_NAME: z.string().default('cortex-memory'),

  // Database connection pooling (from env.ts for compatibility)
  DB_POOL_MIN: z.string().transform(Number).pipe(z.number().int().min(1)).default('5'),
  DB_POOL_MAX: z.string().transform(Number).pipe(z.number().int().min(2).max(100)).default('20'),
  DB_IDLE_TIMEOUT_MS: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(1000))
    .default('30000'),

  // Vector configuration
  OPENAI_API_KEY: z.string().min(1, 'OPENAI_API_KEY is required for vector operations').optional(),
  VECTOR_SIZE: z
    .string()
    .transform(Number)
    .pipe(z.number().int())
    .refine((n) => [384, 768, 1024, 1536, 2048, 3072].includes(n), {
      message: 'VECTOR_SIZE must be one of: 384, 768, 1024, 1536, 2048, 3072',
    })
    .default('1536'),
  VECTOR_DISTANCE: z.enum(['Cosine', 'Euclidean', 'DotProduct']).default('Cosine'),
  EMBEDDING_MODEL: z.string().default('text-embedding-ada-002'),
  EMBEDDING_BATCH_SIZE: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(1).max(100))
    .default('10'),

  // Connection configuration
  DB_CONNECTION_TIMEOUT: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(1000))
    .default('30000'),
  DB_MAX_CONNECTIONS: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(1).max(100))
    .default('20'),
  DB_RETRY_ATTEMPTS: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(0).max(10))
    .default('3'),
  DB_RETRY_DELAY: z.string().transform(Number).pipe(z.number().int().min(100)).default('1000'),

  // Environment configuration
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'debug', 'trace']).default('info'),

  // Security configuration
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters').optional(),
  ENCRYPTION_KEY: z.string().min(32, 'ENCRYPTION_KEY must be at least 32 characters').optional(),

  // MCP configuration
  MCP_SERVER_NAME: z.string().default('cortex-qdrant'),
  MCP_SERVER_VERSION: z.string().default('2.0.0'),

  // Performance configuration
  CACHE_TTL: z.string().transform(Number).pipe(z.number().int().min(60)).default('3600'),
  CACHE_MAX_SIZE: z.string().transform(Number).pipe(z.number().int().min(10)).default('1000'),

  // Search configuration
  SEARCH_LIMIT: z.string().transform(Number).pipe(z.number().int().min(1).max(100)).default('50'),
  SEARCH_THRESHOLD: z.string().transform(Number).pipe(z.number().min(0).max(1)).default('0.7'),

  // Batch processing configuration
  BATCH_SIZE: z.string().transform(Number).pipe(z.number().int().min(1).max(100)).default('50'),
  BATCH_TIMEOUT: z.string().transform(Number).pipe(z.number().int().min(1000)).default('30000'),

  // Monitoring configuration
  METRICS_ENABLED: z.string().transform(Boolean).pipe(z.boolean()).default('true'),
  HEALTH_CHECK_INTERVAL: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(10000))
    .default('60000'),

  // API configuration
  API_RATE_LIMIT: z.string().transform(Number).pipe(z.number().int().min(1)).default('100'),
  API_TIMEOUT: z.string().transform(Number).pipe(z.number().int().min(1000)).default('30000'),

  // MCP configuration (from env.ts for compatibility)
  MCP_TRANSPORT: z.enum(['stdio', 'http']).default('stdio'),

  // Scope inference (from env.ts for compatibility)
  CORTEX_ORG: z.string().optional(),
  CORTEX_PROJECT: z.string().optional(),
  CORTEX_BRANCH: z.string().optional(),

  // Additional database connection variables (missing from current config)
  DB_HOST: z.string().default('localhost'),
  DB_PORT: z.string().transform(Number).pipe(z.number().int().min(1).max(65535)).default('5433'),
  DB_NAME: z.string().default('cortex_prod'),
  DB_USER: z.string().default('cortex'),
  DB_PASSWORD: z.string().optional(),

  // Database performance and connection variables
  DB_QUERY_TIMEOUT: z.string().transform(Number).pipe(z.number().int().min(1000)).default('30000'),
  DB_STATEMENT_TIMEOUT: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(1000))
    .default('30000'),
  DB_MAX_USES: z.string().transform(Number).pipe(z.number().int().min(1)).default('7500'),
  DB_SSL: z.string().transform(Boolean).pipe(z.boolean()).default('false'),
  DB_CONNECTION_TIMEOUT_MS: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(1000))
    .default('10000'),

  // Testing configuration
  // TEST_DATABASE_URL removed - PostgreSQL no longer supported

  // CI/CD configuration
  CODECOV_TOKEN: z.string().optional(),
  GITHUB_SHA: z.string().optional(),
  GITHUB_REF_NAME: z.string().optional(),
  GITHUB_ACTIONS: z.string().transform(Boolean).pipe(z.boolean()).default('false'),

  // Additional security configuration
  JWT_REFRESH_SECRET: z
    .string()
    .min(32, 'JWT_REFRESH_SECRET must be at least 32 characters')
    .optional(),
});

// Application configuration schema
const AppConfigSchema = z.object({
  // Application metadata
  APP_NAME: z.string().default('Cortex Memory MCP'),
  APP_VERSION: z.string().default('2.0.0'),
  APP_DESCRIPTION: z.string().default('Advanced knowledge management with Qdrant vector database'),

  // Development configuration
  DEV_MODE: z.string().transform(Boolean).pipe(z.boolean()).default('false'),
  DEBUG_MODE: z.string().transform(Boolean).pipe(z.boolean()).default('false'),
  HOT_RELOAD: z.string().transform(Boolean).pipe(z.boolean()).default('false'),

  // Testing configuration
  TEST_MODE: z.string().transform(Boolean).pipe(z.boolean()).default('false'),
  MOCK_EXTERNAL_SERVICES: z.string().transform(Boolean).pipe(z.boolean()).default('false'),

  // Feature flags
  ENABLE_AUTH: z.string().transform(Boolean).pipe(z.boolean()).default('false'),
  ENABLE_CACHING: z.string().transform(Boolean).pipe(z.boolean()).default('true'),
  ENABLE_METRICS: z.string().transform(Boolean).pipe(z.boolean()).default('true'),
  ENABLE_LOGGING: z.string().transform(Boolean).pipe(z.boolean()).default('true'),
});

/**
 * Environment configuration class
 */
export class Environment {
  private static instance: Environment;
  private config: z.infer<typeof DatabaseConfigSchema> & z.infer<typeof AppConfigSchema>;
  private isProduction: boolean;
  private isDevelopment: boolean;
  private isTest: boolean;

  private constructor() {
    // Parse and validate environment configuration
    const dbConfig = DatabaseConfigSchema.parse(process.env);
    const appConfig = AppConfigSchema.parse(process.env);

    this.config = { ...dbConfig, ...appConfig };
    this.isProduction = this.config.NODE_ENV === 'production';
    this.isDevelopment = this.config.NODE_ENV === 'development';
    this.isTest = this.config.NODE_ENV === 'test';

    // Log configuration (without sensitive data)
    this.logConfiguration();
  }

  /**
   * Get singleton instance
   */
  static getInstance(): Environment {
    if (!Environment.instance) {
      Environment.instance = new Environment();
    }
    return Environment.instance;
  }

  /**
   * Get Qdrant database configuration
   */
  getQdrantConfig() {
    // QDRANT URL is required - no PostgreSQL fallback
    if (!this.config.QDRANT_URL) {
      throw new Error('QDRANT_URL is required for Qdrant database configuration');
    }

    return {
      type: 'qdrant' as const,
      url: this.config.QDRANT_URL,
      apiKey: this.config.QDRANT_API_KEY,
      vectorSize: this.config.VECTOR_SIZE,
      distance: this.config.VECTOR_DISTANCE,
      collectionName: this.config.QDRANT_COLLECTION_NAME,
      logQueries: this.isDevelopment,
      connectionTimeout: this.config.DB_CONNECTION_TIMEOUT,
      maxConnections: this.config.DB_MAX_CONNECTIONS,
      poolMin: this.config.DB_POOL_MIN,
      poolMax: this.config.DB_POOL_MAX,
      idleTimeoutMs: this.config.DB_IDLE_TIMEOUT_MS,
    };
  }

  /**
   * Get embedding configuration
   */
  getEmbeddingConfig() {
    return {
      apiKey: this.config.OPENAI_API_KEY,
      model: this.config.EMBEDDING_MODEL,
      batchSize: this.config.EMBEDDING_BATCH_SIZE,
      vectorSize: this.config.VECTOR_SIZE,
    };
  }

  /**
   * Get search configuration
   */
  getSearchConfig() {
    return {
      limit: this.config.SEARCH_LIMIT,
      threshold: this.config.SEARCH_THRESHOLD,
      timeout: this.config.API_TIMEOUT,
    };
  }

  /**
   * Get cache configuration
   */
  getCacheConfig() {
    return {
      enabled: this.config.ENABLE_CACHING,
      ttl: this.config.CACHE_TTL,
      maxSize: this.config.CACHE_MAX_SIZE,
    };
  }

  /**
   * Get monitoring configuration
   */
  getMonitoringConfig() {
    return {
      enabled: this.config.METRICS_ENABLED,
      healthCheckInterval: this.config.HEALTH_CHECK_INTERVAL,
      logLevel: this.config.LOG_LEVEL,
    };
  }

  /**
   * Get API configuration
   */
  getApiConfig() {
    return {
      rateLimit: this.config.API_RATE_LIMIT,
      timeout: this.config.API_TIMEOUT,
      authEnabled: this.config.ENABLE_AUTH,
    };
  }

  /**
   * Get batch processing configuration
   */
  getBatchConfig() {
    return {
      size: this.config.BATCH_SIZE,
      timeout: this.config.BATCH_TIMEOUT,
      retryAttempts: this.config.DB_RETRY_ATTEMPTS,
      retryDelay: this.config.DB_RETRY_DELAY,
    };
  }

  /**
   * Get application metadata
   */
  getAppMetadata() {
    return {
      name: this.config.APP_NAME,
      version: this.config.APP_VERSION,
      description: this.config.APP_DESCRIPTION,
      environment: this.config.NODE_ENV,
      database: 'qdrant',
    };
  }

  /**
   * Check if running in production
   */
  isProductionMode(): boolean {
    return this.isProduction;
  }

  /**
   * Check if running in development
   */
  isDevelopmentMode(): boolean {
    return this.isDevelopment;
  }

  /**
   * Check if running in test mode
   */
  isTestMode(): boolean {
    return this.isTest;
  }

  /**
   * Get feature flag value
   */
  getFeatureFlag(flag: string): boolean {
    switch (flag) {
      case 'auth':
        return this.config.ENABLE_AUTH;
      case 'caching':
        return this.config.ENABLE_CACHING;
      case 'metrics':
        return this.config.ENABLE_METRICS;
      case 'logging':
        return this.config.ENABLE_LOGGING;
      default:
        logger.warn({ flag }, 'Unknown feature flag requested');
        return false;
    }
  }

  /**
   * Validate required configuration
   */
  validateRequiredConfig(): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Validate OpenAI API key for embeddings
    if (!this.config.OPENAI_API_KEY) {
      errors.push('OPENAI_API_KEY is required for vector operations');
    }

    // Validate Qdrant URL
    if (!this.config.QDRANT_URL) {
      errors.push('QDRANT_URL is required');
    }

    // Only Qdrant is supported - PostgreSQL validation removed

    // Validate security configuration in production
    if (this.isProduction) {
      if (!this.config.JWT_SECRET) {
        errors.push('JWT_SECRET is required in production');
      }
      if (!this.config.ENCRYPTION_KEY) {
        errors.push('ENCRYPTION_KEY is required in production');
      }
      if (!this.config.JWT_REFRESH_SECRET) {
        errors.push('JWT_REFRESH_SECRET is required in production');
      }
    }

    // PostgreSQL testing validation removed - only Qdrant is supported

    // Validate vector configuration consistency
    if (
      this.config.EMBEDDING_MODEL === 'text-embedding-ada-002' &&
      this.config.VECTOR_SIZE !== 1536
    ) {
      errors.push('VECTOR_SIZE must be 1536 for text-embedding-ada-002 model');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Generate configuration hash for caching
   */
  generateConfigHash(): string {
    const configString = JSON.stringify({
      database: this.getQdrantConfig(),
      embeddings: this.getEmbeddingConfig(),
      search: this.getSearchConfig(),
      cache: this.getCacheConfig(),
    });

    return crypto.createHash('sha256').update(configString).digest('hex');
  }

  /**
   * Get MCP configuration
   */
  getMcpConfig() {
    return {
      transport: this.config.MCP_TRANSPORT,
      serverName: this.config.MCP_SERVER_NAME,
      serverVersion: this.config.MCP_SERVER_VERSION,
    };
  }

  /**
   * Get scope inference configuration
   */
  getScopeConfig() {
    return {
      org: this.config.CORTEX_ORG,
      project: this.config.CORTEX_PROJECT,
      branch: this.config.CORTEX_BRANCH,
    };
  }

  /**
   * Get database connection configuration
   */
  getDatabaseConnectionConfig() {
    return {
      host: this.config.DB_HOST,
      port: this.config.DB_PORT,
      database: this.config.DB_NAME,
      user: this.config.DB_USER,
      password: this.config.DB_PASSWORD,
      ssl: this.config.DB_SSL,
      queryTimeout: this.config.DB_QUERY_TIMEOUT,
      statementTimeout: this.config.DB_STATEMENT_TIMEOUT,
      maxUses: this.config.DB_MAX_USES,
      connectionTimeoutMs: this.config.DB_CONNECTION_TIMEOUT_MS,
    };
  }

  /**
   * Get testing configuration
   */
  getTestingConfig() {
    return {
      // testDatabaseUrl removed - PostgreSQL no longer supported
      isCiCd: this.config.GITHUB_ACTIONS,
      codecovToken: this.config.CODECOV_TOKEN,
      githubSha: this.config.GITHUB_SHA,
      githubRefName: this.config.GITHUB_REF_NAME,
    };
  }

  /**
   * Get enhanced security configuration
   */
  getSecurityConfig() {
    return {
      jwtSecret: this.config.JWT_SECRET,
      jwtRefreshSecret: this.config.JWT_REFRESH_SECRET,
      encryptionKey: this.config.ENCRYPTION_KEY,
    };
  }

  /**
   * Export configuration for external systems
   */
  exportForMcp() {
    return {
      database: this.getQdrantConfig(),
      application: this.getAppMetadata(),
      features: {
        auth: this.config.ENABLE_AUTH,
        caching: this.config.ENABLE_CACHING,
        metrics: this.config.METRICS_ENABLED,
      },
      environment: this.config.NODE_ENV,
      mcp: this.getMcpConfig(),
      scope: this.getScopeConfig(),
    };
  }

  /**
   * Log configuration (without sensitive data)
   */
  private logConfiguration(): void {
    const safeConfig = {
      database: {
        type: 'qdrant',
        url: this.config.QDRANT_URL,
        vectorSize: this.config.VECTOR_SIZE,
        distance: this.config.VECTOR_DISTANCE,
      },
      application: {
        name: this.config.APP_NAME,
        version: this.config.APP_VERSION,
        environment: this.config.NODE_ENV,
      },
      features: {
        auth: this.config.ENABLE_AUTH,
        caching: this.config.ENABLE_CACHING,
        metrics: this.config.METRICS_ENABLED,
      },
    };

    logger.info(safeConfig, 'Qdrant-only environment configuration loaded');
  }

  /**
   * Get environment-specific defaults
   */
  getEnvironmentSpecificDefaults() {
    const baseDefaults = {
      // Base configuration
      LOG_LEVEL: 'info',
      CACHE_TTL: 3600,
      SEARCH_LIMIT: 50,
    };

    switch (this.config.NODE_ENV) {
      case 'production':
        return {
          ...baseDefaults,
          LOG_LEVEL: 'warn',
          CACHE_TTL: 7200,
          METRICS_ENABLED: true,
          ENABLE_AUTH: true,
          ENABLE_CACHING: true,
          DB_POOL_MIN: 5,
          DB_POOL_MAX: 20,
          BATCH_SIZE: 100,
        };

      case 'test':
        return {
          ...baseDefaults,
          LOG_LEVEL: 'error',
          METRICS_ENABLED: false,
          ENABLE_AUTH: false,
          ENABLE_CACHING: false,
          DB_POOL_MIN: 1,
          DB_POOL_MAX: 5,
          BATCH_SIZE: 10,
          SEARCH_LIMIT: 20,
          MOCK_EXTERNAL_SERVICES: true,
        };

      case 'development':
      default:
        return {
          ...baseDefaults,
          LOG_LEVEL: 'debug',
          METRICS_ENABLED: true,
          ENABLE_AUTH: false,
          ENABLE_CACHING: true,
          DB_POOL_MIN: 2,
          DB_POOL_MAX: 10,
          BATCH_SIZE: 50,
          DEBUG_MODE: true,
          HOT_RELOAD: true,
        };
    }
  }

  /**
   * Get environment-specific configuration
   */
  getEnvironmentSpecificConfig() {
    const defaults = this.getEnvironmentSpecificDefaults();

    return {
      ...defaults,
      database: this.getQdrantConfig(),
      embeddings: this.getEmbeddingConfig(),
      search: this.getSearchConfig(),
      cache: this.getCacheConfig(),
      monitoring: this.getMonitoringConfig(),
      api: this.getApiConfig(),
      batch: this.getBatchConfig(),
      security: this.getSecurityConfig(),
      testing: this.getTestingConfig(),
      databaseConnection: this.getDatabaseConnectionConfig(),
    };
  }

  /**
   * Validate environment-specific requirements
   */
  validateEnvironmentSpecificRequirements(): {
    valid: boolean;
    errors: string[];
    warnings: string[];
  } {
    const errors: string[] = [];
    const warnings: string[] = [];

    switch (this.config.NODE_ENV) {
      case 'production':
        if (!this.config.JWT_SECRET || this.config.JWT_SECRET!.length < 32) {
          errors.push('JWT_SECRET must be at least 32 characters in production');
        }
        if (!this.config.ENCRYPTION_KEY || this.config.ENCRYPTION_KEY!.length < 32) {
          errors.push('ENCRYPTION_KEY must be at least 32 characters in production');
        }
        if (!this.config.JWT_REFRESH_SECRET) {
          errors.push('JWT_REFRESH_SECRET is required in production');
        }
        if (this.config.LOG_LEVEL === 'debug' || this.config.LOG_LEVEL === 'trace') {
          warnings.push(
            'Debug logging enabled in production - consider setting LOG_LEVEL to warn or error'
          );
        }
        break;

      case 'test':
        if (this.config.METRICS_ENABLED) {
          warnings.push('Metrics collection enabled in test mode - may affect test performance');
        }
        // PostgreSQL test validation removed - only Qdrant is supported
        break;

      case 'development':
        if (!this.config.DEBUG_MODE) {
          warnings.push('Consider enabling DEBUG_MODE in development');
        }
        break;
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Get raw configuration values (for internal use)
   */
  getRawConfig() {
    return { ...this.config };
  }
}

/**
 * Export singleton instance
 */
export const environment = Environment.getInstance();

/**
 * Export convenience functions
 */
export function getQdrantConfig() {
  return environment.getQdrantConfig();
}

export function getEmbeddingConfig() {
  return environment.getEmbeddingConfig();
}

export function getSearchConfig() {
  return environment.getSearchConfig();
}

export function isProduction() {
  return environment.isProductionMode();
}

export function isDevelopment() {
  return environment.isDevelopmentMode();
}

export function isTest() {
  return environment.isTestMode();
}

/**
 * Export environment configuration functions for compatibility with env.ts
 */
export function loadEnv() {
  const config = environment.getRawConfig();
  return {
    // DATABASE_URL removed - only QDRANT_URL is supported
    QDRANT_URL: config.QDRANT_URL,
    DB_POOL_MIN: config.DB_POOL_MIN,
    DB_POOL_MAX: config.DB_POOL_MAX,
    DB_IDLE_TIMEOUT_MS: config.DB_IDLE_TIMEOUT_MS,
    LOG_LEVEL: config.LOG_LEVEL,
    NODE_ENV: config.NODE_ENV,
    MCP_TRANSPORT: config.MCP_TRANSPORT,
    CORTEX_ORG: config.CORTEX_ORG,
    CORTEX_PROJECT: config.CORTEX_PROJECT,
    CORTEX_BRANCH: config.CORTEX_BRANCH,
  };
}

export function getMcpConfig() {
  return environment.getMcpConfig();
}

export function getScopeConfig() {
  return environment.getScopeConfig();
}
