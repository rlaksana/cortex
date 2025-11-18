/**
 * Configuration Types for MCP Cortex
 *
 * This file contains comprehensive type definitions for all configuration objects
 * used throughout the MCP Cortex system, eliminating the need for 'any' types.
 *
 * @author Cortex Team
 * @version 2.0.0
 */

// ============================================================================
// Base Configuration Types
// ============================================================================

export interface BaseConfig {
  environment: 'development' | 'staging' | 'production' | 'test';
  debug: boolean;
  logLevel: 'error' | 'warn' | 'info' | 'debug' | 'trace';
}

// ============================================================================
// Database Configuration Types
// ============================================================================

export interface QdrantConfig {
  host: string;
  port: number;
  apiKey?: string;
  timeout: number;
  maxRetries: number;
  retryDelay: number;
  useHttps: boolean;
  collectionPrefix?: string;
  enableHealthChecks: boolean;
  connectionPoolSize: number;
  requestTimeout: number;
  connectTimeout: number;
}

export interface DatabaseConfig {
  qdrant: QdrantConfig;
  fallbackEnabled: boolean;
  backupEnabled: boolean;
  migrationEnabled: boolean;
}

// ============================================================================
// Authentication Configuration Types
// ============================================================================

export interface JWTConfig {
  secret: string;
  expiresIn: string;
  issuer: string;
  audience: string;
  algorithm: 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512';
}

export interface ApiKeyConfig {
  headerName: string;
  queryParam?: string;
  validationEnabled: boolean;
  rateLimitEnabled: boolean;
}

export interface AuthConfig {
  jwt: JWTConfig;
  apiKey: ApiKeyConfig;
  enabled: boolean;
  sessionTimeout: number;
  refreshTokenEnabled: boolean;
  passwordPolicyEnabled: boolean;
}

// ============================================================================
// API Configuration Types
// ============================================================================

export interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
  skipSuccessfulRequests: boolean;
  skipFailedRequests: boolean;
  enableHeaders: boolean;
}

export interface CorsConfig {
  origin: string | string[] | boolean;
  credentials: boolean;
  methods: string[];
  allowedHeaders: string[];
  exposedHeaders?: string[];
  maxAge?: number;
  preflightContinue?: boolean;
  optionsSuccessStatus?: number;
}

export interface ApiConfig {
  port: number;
  host: string;
  rateLimit: RateLimitConfig;
  cors: CorsConfig;
  compression: boolean;
  helmet: boolean;
  trustProxy: boolean;
  bodyLimit: string;
  timeout: number;
}

// ============================================================================
// Logging Configuration Types
// ============================================================================

export interface LogConfig {
  level: 'error' | 'warn' | 'info' | 'debug' | 'trace';
  format: 'json' | 'pretty' | 'text';
  colorize: boolean;
  timestamp: boolean;
  file: {
    enabled: boolean;
    path: string;
    maxSize: string;
    maxFiles: number;
    rotationInterval?: string;
  };
  console: {
    enabled: boolean;
    level: 'error' | 'warn' | 'info' | 'debug' | 'trace';
  };
}

// ============================================================================
// Monitoring Configuration Types
// ============================================================================

export interface MetricsConfig {
  enabled: boolean;
  interval: number;
  prefix: string;
  labels: Record<string, string>;
  defaultBuckets: number[];
}

export interface HealthCheckConfig {
  enabled: boolean;
  interval: number;
  timeout: number;
  retries: number;
  endpoints: HealthEndpoint[];
}

export interface HealthEndpoint {
  name: string;
  path: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  expectedStatus: number;
  timeout: number;
}

export interface MonitoringConfig {
  metrics: MetricsConfig;
  healthCheck: HealthCheckConfig;
  tracing: {
    enabled: boolean;
    samplingRate: number;
    serviceName: string;
    version: string;
  };
  alerting: {
    enabled: boolean;
    webhookUrl?: string;
    emailSettings?: {
      smtp: {
        host: string;
        port: number;
        secure: boolean;
        auth: {
          user: string;
          pass: string;
        };
      };
      from: string;
      to: string[];
    };
  };
}

// ============================================================================
// Security Configuration Types
// ============================================================================

export interface SecurityConfig {
  encryption: {
    algorithm: string;
    keyLength: number;
    ivLength: number;
  };
  hashing: {
    algorithm: string;
    rounds: number;
    saltLength: number;
  };
  validation: {
    maxFileSize: number;
    allowedMimeTypes: string[];
    allowedExtensions: string[];
  };
  rateLimit: RateLimitConfig;
  cors: CorsConfig;
}

// ============================================================================
// Performance Configuration Types
// ============================================================================

export interface CacheConfig {
  enabled: boolean;
  ttl: number;
  maxSize: number;
  strategy: 'lru' | 'fifo' | 'lfu';
  compressionEnabled: boolean;
}

export interface PerformanceConfig {
  cache: CacheConfig;
  compression: {
    enabled: boolean;
    threshold: number;
    algorithm: 'gzip' | 'deflate' | 'br';
  };
  clustering: {
    enabled: boolean;
    workers: number;
    maxMemory: string;
  };
}

// ============================================================================
// Feature Flag Configuration Types
// ============================================================================

export interface FeatureFlags {
  newSearchAlgorithm: boolean;
  enhancedLogging: boolean;
  betaFeatures: boolean;
  experimentalFeatures: boolean;
  debugMode: boolean;
}

// ============================================================================
// Validation Result Types
// ============================================================================

export interface ValidationError {
  code: string;
  message: string;
  path?: string;
  value?: unknown;
}

export interface ValidationWarning {
  code: string;
  message: string;
  path?: string;
  value?: unknown;
}

export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
  warnings: ValidationWarning[];
  data?: unknown;
}

// ============================================================================
// Complete Configuration Types
// ============================================================================

export interface CompleteConfig extends BaseConfig {
  database: DatabaseConfig;
  auth: AuthConfig;
  api: ApiConfig;
  logging: LogConfig;
  monitoring: MonitoringConfig;
  security: SecurityConfig;
  performance: PerformanceConfig;
  features: FeatureFlags;
}

// ============================================================================
// Migration Types
// ============================================================================

export interface LegacyConfig {
  [key: string]: unknown;
  // Legacy configurations may have arbitrary structure
}

export interface ConfigMigrationOptions {
  dryRun?: boolean;
  validateAfterMigration?: boolean;
  backupOriginal?: boolean;
  migrationVersion?: string;
}

export interface ConfigMigrationResult {
  success: boolean;
  fromVersion: string;
  toVersion: string;
  migratedProperties: string[];
  validationErrors: ValidationError[];
  warnings: ValidationWarning[];
}

// ============================================================================
// Utility Types
// ============================================================================

export type ConfigPath = string;
export type ConfigValue = string | number | boolean | object | unknown;
export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

export type ConfigValidator = (config: unknown) => ValidationResult;
export type ConfigTransformer<TFrom, TTo> = (input: TFrom) => TTo;
