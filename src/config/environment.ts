import { z } from 'zod';
import * as dotenv from 'dotenv';
import * as crypto from 'node:crypto';
import { logger } from '../utils/logger.js';
import { DEFAULT_TRUNCATION_CONFIG, type TruncationConfig } from './truncation-config.js';

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

  // Database connection pooling (Qdrant-specific)
  QDRANT_POOL_MIN: z.string().transform(Number).pipe(z.number().int().min(1)).default('5'),
  QDRANT_POOL_MAX: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(2).max(100))
    .default('20'),
  QDRANT_IDLE_TIMEOUT_MS: z
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
  VECTOR_DISTANCE: z.enum(['Cosine', 'Euclid', 'Dot', 'Manhattan']).default('Cosine'),
  EMBEDDING_MODEL: z.string().default('text-embedding-ada-002'),
  EMBEDDING_BATCH_SIZE: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(1).max(100))
    .default('10'),

  // Connection configuration (Qdrant-specific)
  QDRANT_CONNECTION_TIMEOUT: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(1000))
    .default('30000'),
  QDRANT_MAX_CONNECTIONS: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(1).max(100))
    .default('20'),
  QDRANT_RETRY_ATTEMPTS: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(0).max(10))
    .default('3'),
  QDRANT_RETRY_DELAY: z.string().transform(Number).pipe(z.number().int().min(100)).default('1000'),

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

  // P6-T6.1: TTL configuration for knowledge expiry
  TTL_DEFAULT_DAYS: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(1).max(365))
    .default('30'),
  TTL_SHORT_DAYS: z.string().transform(Number).pipe(z.number().int().min(1).max(30)).default('1'),
  TTL_LONG_DAYS: z.string().transform(Number).pipe(z.number().int().min(30).max(365)).default('90'),
  TTL_WORKER_ENABLED: z.string().transform(Boolean).pipe(z.boolean()).default('true'),
  TTL_WORKER_SCHEDULE: z.string().default('0 2 * * *'), // Daily at 2 AM
  TTL_WORKER_BATCH_SIZE: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(1).max(1000))
    .default('100'),
  TTL_WORKER_MAX_BATCHES: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(1).max(100))
    .default('50'),

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

  // Scope inference configuration
  CORTEX_ORG: z.string().optional(),
  CORTEX_PROJECT: z.string().optional(),
  CORTEX_BRANCH: z.string().optional(),

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
  SEMANTIC_CHUNKING_OPTIONAL: z.string().transform(Boolean).pipe(z.boolean()).default('false'),
  DEDUP_ACTION: z.enum(['skip', 'merge']).default('skip'),

  // Chunking and content processing configuration
  MAX_CHARS_PER_CHUNK: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(100).max(10000))
    .default('1200'),
  CHUNK_OVERLAP_SIZE: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(0).max(1000))
    .default('200'),
  CHUNKING_THRESHOLD: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(500).max(10000))
    .default('2400'),
  CONTENT_TRUNCATION_LIMIT: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(1000).max(50000))
    .default('8000'),

  // P1-2: Enhanced truncation configuration
  TRUNCATION_ENABLED: z.string().transform(Boolean).pipe(z.boolean()).default('true'),
  TRUNCATION_MODE: z.enum(['hard', 'soft', 'intelligent']).default('intelligent'),
  TRUNCATION_PRESERVE_STRUCTURE: z.string().transform(Boolean).pipe(z.boolean()).default('true'),
  TRUNCATION_ADD_INDICATORS: z.string().transform(Boolean).pipe(z.boolean()).default('true'),
  TRUNCATION_SAFETY_MARGIN: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(0).max(50))
    .default('5'),
  TRUNCATION_MAX_CHARS_DEFAULT: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(1000).max(100000))
    .default('8000'),
  TRUNCATION_MAX_CHARS_TEXT: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(1000).max(100000))
    .default('10000'),
  TRUNCATION_MAX_CHARS_JSON: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(1000).max(150000))
    .default('15000'),
  TRUNCATION_MAX_CHARS_CODE: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(1000).max(100000))
    .default('8000'),
  TRUNCATION_MAX_CHARS_MARKDOWN: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(1000).max(120000))
    .default('12000'),
  TRUNCATION_MAX_TOKENS_DEFAULT: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(100).max(10000))
    .default('2000'),
  TRUNCATION_MAX_TOKENS_INPUT: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(100).max(20000))
    .default('4000'),
  TRUNCATION_MAX_TOKENS_CONTEXT: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(1000).max(50000))
    .default('8000'),
  TRUNCATION_LOG_WARNINGS: z.string().transform(Boolean).pipe(z.boolean()).default('true'),
  TRUNCATION_INCLUDE_IN_RESPONSE: z.string().transform(Boolean).pipe(z.boolean()).default('true'),
  TRUNCATION_LOG_LEVEL: z.enum(['warn', 'info', 'debug']).default('warn'),
  TRUNCATION_ENFORCE_LIMITS: z.string().transform(Boolean).pipe(z.boolean()).default('true'),
  TRUNCATION_ALLOW_OVERRIDE: z.string().transform(Boolean).pipe(z.boolean()).default('false'),
  TRUNCATION_AUTO_DETECT_TYPE: z.string().transform(Boolean).pipe(z.boolean()).default('true'),
  TRUNCATION_ENABLE_SMART: z.string().transform(Boolean).pipe(z.boolean()).default('true'),

  // P6-1: Insight generation configuration
  INSIGHT_GENERATION_ENABLED: z.string().transform(Boolean).pipe(z.boolean()).default('false'),
  INSIGHT_GENERATION_ENV_ENABLED: z.string().transform(Boolean).pipe(z.boolean()).default('false'),
  INSIGHT_GENERATION_MAX_INSIGHTS_PER_ITEM: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(1).max(10))
    .default('3'),
  INSIGHT_GENERATION_MAX_INSIGHTS_PER_BATCH: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(1).max(50))
    .default('10'),
  INSIGHT_GENERATION_CONFIDENCE_THRESHOLD: z
    .string()
    .transform(Number)
    .pipe(z.number().min(0).max(1))
    .default('0.6'),
  INSIGHT_GENERATION_PROCESSING_TIMEOUT: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(1000).max(30000))
    .default('5000'),
  INSIGHT_GENERATION_PERFORMANCE_THRESHOLD: z
    .string()
    .transform(Number)
    .pipe(z.number().min(1).max(50))
    .default('5'),
  INSIGHT_GENERATION_CACHE_TTL: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(60).max(86400))
    .default('3600'),
  INSIGHT_GENERATION_PATTERNS_ENABLED: z
    .string()
    .transform(Boolean)
    .pipe(z.boolean())
    .default('true'),
  INSIGHT_GENERATION_CONNECTIONS_ENABLED: z
    .string()
    .transform(Boolean)
    .pipe(z.boolean())
    .default('true'),
  INSIGHT_GENERATION_RECOMMENDATIONS_ENABLED: z
    .string()
    .transform(Boolean)
    .pipe(z.boolean())
    .default('true'),
  INSIGHT_GENERATION_ANOMALIES_ENABLED: z
    .string()
    .transform(Boolean)
    .pipe(z.boolean())
    .default('false'),
  INSIGHT_GENERATION_TRENDS_ENABLED: z
    .string()
    .transform(Boolean)
    .pipe(z.boolean())
    .default('false'),
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
      connectionTimeout: this.config.QDRANT_CONNECTION_TIMEOUT,
      maxConnections: this.config.QDRANT_MAX_CONNECTIONS,
      poolMin: this.config.QDRANT_POOL_MIN,
      poolMax: this.config.QDRANT_POOL_MAX,
      idleTimeoutMs: this.config.QDRANT_IDLE_TIMEOUT_MS,
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
      retryAttempts: this.config.QDRANT_RETRY_ATTEMPTS,
      retryDelay: this.config.QDRANT_RETRY_DELAY,
    };
  }

  /**
   * P6-T6.1: Get TTL configuration for knowledge expiry
   */
  getTTLConfig() {
    return {
      default_days: this.config.TTL_DEFAULT_DAYS,
      short_days: this.config.TTL_SHORT_DAYS,
      long_days: this.config.TTL_LONG_DAYS,
      worker: {
        enabled: this.config.TTL_WORKER_ENABLED,
        schedule: this.config.TTL_WORKER_SCHEDULE,
        batch_size: this.config.TTL_WORKER_BATCH_SIZE,
        max_batches: this.config.TTL_WORKER_MAX_BATCHES,
      },
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
        return this.config.METRICS_ENABLED;
      case 'logging':
        return this.config.ENABLE_LOGGING;
      case 'semantic-chunking-optional':
        return this.config.SEMANTIC_CHUNKING_OPTIONAL;
      default:
        logger.warn({ flag }, 'Unknown feature flag requested');
        return false;
    }
  }

  /**
   * Get deduplication action setting
   */
  getDedupAction(): 'skip' | 'merge' {
    return this.config.DEDUP_ACTION;
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
    const _configString = JSON.stringify({
      database: this.getQdrantConfig(),
      embeddings: this.getEmbeddingConfig(),
      search: this.getSearchConfig(),
      cache: this.getCacheConfig(),
    });

    return crypto.createHash('sha256').update(_configString).digest('hex');
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
   * Get chunking configuration
   */
  getChunkingConfig() {
    return {
      semanticChunkingOptional: this.config.SEMANTIC_CHUNKING_OPTIONAL,
      maxCharsPerChunk: this.config.MAX_CHARS_PER_CHUNK,
      chunkOverlapSize: this.config.CHUNK_OVERLAP_SIZE,
      chunkingThreshold: this.config.CHUNKING_THRESHOLD,
      contentTruncationLimit: this.config.CONTENT_TRUNCATION_LIMIT,
    };
  }

  /**
   * P1-2: Get truncation configuration
   */
  getTruncationConfig(): TruncationConfig {
    return {
      maxChars: {
        default: this.config.TRUNCATION_MAX_CHARS_DEFAULT,
        text: this.config.TRUNCATION_MAX_CHARS_TEXT,
        json: this.config.TRUNCATION_MAX_CHARS_JSON,
        code: this.config.TRUNCATION_MAX_CHARS_CODE,
        markdown: this.config.TRUNCATION_MAX_CHARS_MARKDOWN,
        html: this.config.TRUNCATION_MAX_CHARS_JSON, // Use JSON limit for HTML
        xml: this.config.TRUNCATION_MAX_CHARS_JSON, // Use JSON limit for XML
        csv: this.config.TRUNCATION_MAX_CHARS_TEXT, // Use text limit for CSV
        log: this.config.TRUNCATION_MAX_CHARS_DEFAULT * 2, // Double limit for logs
      },
      maxTokens: {
        default: this.config.TRUNCATION_MAX_TOKENS_DEFAULT,
        input: this.config.TRUNCATION_MAX_TOKENS_INPUT,
        output: this.config.TRUNCATION_MAX_TOKENS_DEFAULT,
        context: this.config.TRUNCATION_MAX_TOKENS_CONTEXT,
      },
      behavior: {
        mode: this.config.TRUNCATION_MODE,
        preserveStructure: this.config.TRUNCATION_PRESERVE_STRUCTURE,
        addIndicators: this.config.TRUNCATION_ADD_INDICATORS,
        indicator: DEFAULT_TRUNCATION_CONFIG.behavior.indicator,
        safetyMargin: this.config.TRUNCATION_SAFETY_MARGIN,
      },
      contentTypes: {
        autoDetect: this.config.TRUNCATION_AUTO_DETECT_TYPE,
        preservePriority: DEFAULT_TRUNCATION_CONFIG.contentTypes.preservePriority,
        enableSmart: this.config.TRUNCATION_ENABLE_SMART,
      },
      warnings: {
        logTruncation: this.config.TRUNCATION_LOG_WARNINGS,
        includeInResponse: this.config.TRUNCATION_INCLUDE_IN_RESPONSE,
        logLevel: this.config.TRUNCATION_LOG_LEVEL,
        emitMetrics: true, // Always emit metrics for observability
      },
      enabled: this.config.TRUNCATION_ENABLED,
      enforceLimits: this.config.TRUNCATION_ENFORCE_LIMITS,
      allowOverride: this.config.TRUNCATION_ALLOW_OVERRIDE,
    };
  }

  /**
   * P6-1: Get insight generation configuration
   */
  getInsightConfig() {
    return {
      // Feature toggles
      enabled: this.config.INSIGHT_GENERATION_ENABLED,
      environment_enabled: this.config.INSIGHT_GENERATION_ENV_ENABLED,
      runtime_override: false, // Set via request parameter

      // Generation settings
      max_insights_per_item: this.config.INSIGHT_GENERATION_MAX_INSIGHTS_PER_ITEM,
      max_insights_per_batch: this.config.INSIGHT_GENERATION_MAX_INSIGHTS_PER_BATCH,
      min_confidence_threshold: this.config.INSIGHT_GENERATION_CONFIDENCE_THRESHOLD,
      processing_timeout_ms: this.config.INSIGHT_GENERATION_PROCESSING_TIMEOUT,
      parallel_processing: true,

      // Insight types
      insight_types: {
        patterns: {
          id: 'patterns',
          name: 'Pattern Recognition',
          description: 'Identify recurring patterns in knowledge items',
          enabled: this.config.INSIGHT_GENERATION_PATTERNS_ENABLED,
          confidence_threshold: this.config.INSIGHT_GENERATION_CONFIDENCE_THRESHOLD,
          priority: 1,
          max_insights_per_batch: 3,
        },
        connections: {
          id: 'connections',
          name: 'Connection Analysis',
          description: 'Find relationships and connections between items',
          enabled: this.config.INSIGHT_GENERATION_CONNECTIONS_ENABLED,
          confidence_threshold: this.config.INSIGHT_GENERATION_CONFIDENCE_THRESHOLD,
          priority: 2,
          max_insights_per_batch: 2,
        },
        recommendations: {
          id: 'recommendations',
          name: 'Action Recommendations',
          description: 'Suggest actions based on stored knowledge',
          enabled: this.config.INSIGHT_GENERATION_RECOMMENDATIONS_ENABLED,
          confidence_threshold: this.config.INSIGHT_GENERATION_CONFIDENCE_THRESHOLD,
          priority: 3,
          max_insights_per_batch: 2,
        },
        anomalies: {
          id: 'anomalies',
          name: 'Anomaly Detection',
          description: 'Detect unusual or unexpected patterns',
          enabled: this.config.INSIGHT_GENERATION_ANOMALIES_ENABLED,
          confidence_threshold: 0.9, // Higher threshold for anomalies
          priority: 4,
          max_insights_per_batch: 1,
        },
        trends: {
          id: 'trends',
          name: 'Trend Analysis',
          description: 'Identify trends in knowledge changes over time',
          enabled: this.config.INSIGHT_GENERATION_TRENDS_ENABLED,
          confidence_threshold: this.config.INSIGHT_GENERATION_CONFIDENCE_THRESHOLD,
          priority: 5,
          max_insights_per_batch: 2,
        },
      },

      // Performance settings
      performance_impact_threshold: this.config.INSIGHT_GENERATION_PERFORMANCE_THRESHOLD,
      enable_caching: true,
      cache_ttl_seconds: this.config.INSIGHT_GENERATION_CACHE_TTL,
      enable_metrics: this.config.METRICS_ENABLED,

      // Filtering and prioritization
      max_insight_length: 280,
      include_metadata: true,
      filter_duplicates: true,
      prioritize_by_confidence: true,
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
          QDRANT_POOL_MIN: 5,
          QDRANT_POOL_MAX: 20,
          BATCH_SIZE: 100,
        };

      case 'test':
        return {
          ...baseDefaults,
          LOG_LEVEL: 'error',
          METRICS_ENABLED: false,
          ENABLE_AUTH: false,
          ENABLE_CACHING: false,
          QDRANT_POOL_MIN: 1,
          QDRANT_POOL_MAX: 5,
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
          QDRANT_POOL_MIN: 2,
          QDRANT_POOL_MAX: 10,
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
    const _defaults = this.getEnvironmentSpecificDefaults();

    return {
      ..._defaults,
      database: this.getQdrantConfig(),
      embeddings: this.getEmbeddingConfig(),
      search: this.getSearchConfig(),
      cache: this.getCacheConfig(),
      monitoring: this.getMonitoringConfig(),
      api: this.getApiConfig(),
      batch: this.getBatchConfig(),
      security: this.getSecurityConfig(),
      testing: this.getTestingConfig(),
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
  const _config = environment.getRawConfig();
  return {
    QDRANT_URL: _config.QDRANT_URL,
    QDRANT_POOL_MIN: _config.QDRANT_POOL_MIN,
    QDRANT_POOL_MAX: _config.QDRANT_POOL_MAX,
    QDRANT_IDLE_TIMEOUT_MS: _config.QDRANT_IDLE_TIMEOUT_MS,
    LOG_LEVEL: _config.LOG_LEVEL,
    NODE_ENV: _config.NODE_ENV,
    MCP_TRANSPORT: _config.MCP_TRANSPORT,
    CORTEX_ORG: _config.CORTEX_ORG,
    CORTEX_PROJECT: _config.CORTEX_PROJECT,
    CORTEX_BRANCH: _config.CORTEX_BRANCH,
  };
}

export function getMcpConfig() {
  return environment.getMcpConfig();
}

export function getScopeConfig() {
  return environment.getScopeConfig();
}
