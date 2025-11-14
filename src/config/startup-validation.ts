/**
 * Startup validation for environment variables
 * Validates that all critical environment variables are present and valid
 */

import { ENV_KEYS, CRITICAL_ENV_VARS, getEnvVar, getEnvVarRequired, getEnvVarWithDefault, getEnvVarAsBoolean, getEnvVarAsNumber } from './env-keys.js';

export interface ValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
  missingCritical: string[];
  invalidFormat: string[];
}

export interface StartupConfig {
  // Core Application
  nodeEnv: string;
  port: number;
  host: string;
  debugMode: boolean;

  // External Services
  openaiApiKey: string;
  qdrantUrl: string;
  qdrantApiKey?: string;
  qdrantCollectionName: string;
  qdrantTimeout: number;
  qdrantMaxConnections: number;

  // Security
  jwtSecret?: string;
  requireApiKey: boolean;

  // Logging
  logLevel: string;
  logFormat: string;

  // Health & Metrics
  enableHealthChecks: boolean;
  enableMetricsCollection: boolean;

  // Performance
  maxMemoryMb: number;
  embeddingBatchSize: number;

  // Vector Configuration
  vectorSize: number;
  similarityThreshold: number;

  // Deduplication
  dedupeEnabled: boolean;
}

/**
 * Validates environment variables and returns validation result
 */
export function validateEnvironmentVariables(): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  const missingCritical: string[] = [];
  const invalidFormat: string[] = [];

  // Check critical environment variables
  for (const key of CRITICAL_ENV_VARS) {
    const value = process.env[key];
    if (!value || value.trim() === '') {
      missingCritical.push(key);
      errors.push(`Critical environment variable ${key} is missing or empty`);
    }
  }

  // Validate specific environment variable formats
  try {
    // Node environment
    const nodeEnv = getEnvVarWithDefault(ENV_KEYS.NODE_ENV, 'development');
    if (!['development', 'production', 'test'].includes(nodeEnv)) {
      invalidFormat.push(ENV_KEYS.NODE_ENV);
      warnings.push(`NODE_ENV should be 'development', 'production', or 'test', got: ${nodeEnv}`);
    }

    // Port number
    const port = getEnvVarAsNumber(ENV_KEYS.PORT, 3000);
    if (port < 1 || port > 65535) {
      invalidFormat.push(ENV_KEYS.PORT);
      errors.push(`PORT must be between 1 and 65535, got: ${port}`);
    }

    // Log level
    const logLevel = getEnvVarWithDefault(ENV_KEYS.LOG_LEVEL, 'info');
    const validLogLevels = ['error', 'warn', 'info', 'debug', 'trace'];
    if (!validLogLevels.includes(logLevel.toLowerCase())) {
      invalidFormat.push(ENV_KEYS.LOG_LEVEL);
      warnings.push(`LOG_LEVEL should be one of: ${validLogLevels.join(', ')}, got: ${logLevel}`);
    }

    // Vector size
    const vectorSize = getEnvVarAsNumber(ENV_KEYS.VECTOR_SIZE, 1536);
    if (vectorSize < 1 || vectorSize > 10000) {
      invalidFormat.push(ENV_KEYS.VECTOR_SIZE);
      warnings.push(`VECTOR_SIZE should be between 1 and 10000, got: ${vectorSize}`);
    }

    // Similarity threshold
    const similarityThreshold = getEnvVarAsNumber(ENV_KEYS.SIMILARITY_THRESHOLD, 0.7);
    if (similarityThreshold < 0 || similarityThreshold > 1) {
      invalidFormat.push(ENV_KEYS.SIMILARITY_THRESHOLD);
      warnings.push(`SIMILARITY_THRESHOLD should be between 0 and 1, got: ${similarityThreshold}`);
    }

    // QDRANT timeout
    const qdrantTimeout = getEnvVarAsNumber(ENV_KEYS.QDRANT_TIMEOUT, 30000);
    if (qdrantTimeout < 1000 || qdrantTimeout > 300000) {
      invalidFormat.push(ENV_KEYS.QDRANT_TIMEOUT);
      warnings.push(`QDRANT_TIMEOUT should be between 1000ms and 300000ms, got: ${qdrantTimeout}`);
    }

    // QDRANT max connections
    const qdrantMaxConnections = getEnvVarAsNumber(ENV_KEYS.QDRANT_MAX_CONNECTIONS, 10);
    if (qdrantMaxConnections < 1 || qdrantMaxConnections > 100) {
      invalidFormat.push(ENV_KEYS.QDRANT_MAX_CONNECTIONS);
      warnings.push(`QDRANT_MAX_CONNECTIONS should be between 1 and 100, got: ${qdrantMaxConnections}`);
    }

    // Memory limits
    const maxMemoryMb = getEnvVarAsNumber(ENV_KEYS.MAX_MEMORY_MB, 1024);
    if (maxMemoryMb < 128 || maxMemoryMb > 16384) {
      invalidFormat.push(ENV_KEYS.MAX_MEMORY_MB);
      warnings.push(`MAX_MEMORY_MB should be between 128MB and 16GB, got: ${maxMemoryMb}MB`);
    }

    // Embedding batch size
    const embeddingBatchSize = getEnvVarAsNumber(ENV_KEYS.EMBEDDING_BATCH_SIZE, 10);
    if (embeddingBatchSize < 1 || embeddingBatchSize > 1000) {
      invalidFormat.push(ENV_KEYS.EMBEDDING_BATCH_SIZE);
      warnings.push(`EMBEDDING_BATCH_SIZE should be between 1 and 1000, got: ${embeddingBatchSize}`);
    }

  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    errors.push(`Environment variable validation error: ${message}`);
  }

  // Check for potential security issues
  if (getEnvVarWithDefault(ENV_KEYS.NODE_ENV, 'development') === 'production') {
    const jwtSecret = process.env[ENV_KEYS.JWT_SECRET];
    if (!jwtSecret || jwtSecret.length < 32) {
      warnings.push('JWT_SECRET should be at least 32 characters long in production');
    }

    if (!getEnvVarAsBoolean(ENV_KEYS.REQUIRE_API_KEY, true)) {
      warnings.push('REQUIRE_API_KEY should be true in production for security');
    }
  }

  const isValid = errors.length === 0 && missingCritical.length === 0;

  return {
    isValid,
    errors,
    warnings,
    missingCritical,
    invalidFormat,
  };
}

/**
 * Extracts and validates startup configuration from environment variables
 */
export function getStartupConfig(): StartupConfig {
  const validation = validateEnvironmentVariables();

  if (!validation.isValid) {
    const errorMessage = [
      'Environment variable validation failed:',
      ...validation.errors,
      ...validation.warnings.map(w => `Warning: ${w}`),
    ].join('\n');
    throw new Error(errorMessage);
  }

  return {
    // Core Application
    nodeEnv: getEnvVarWithDefault(ENV_KEYS.NODE_ENV, 'development'),
    port: getEnvVarAsNumber(ENV_KEYS.PORT, 3000),
    host: getEnvVarWithDefault(ENV_KEYS.HOST, '0.0.0.0'),
    debugMode: getEnvVarAsBoolean(ENV_KEYS.DEBUG_MODE, false),

    // External Services
    openaiApiKey: getEnvVarRequired(ENV_KEYS.OPENAI_API_KEY),
    qdrantUrl: getEnvVarRequired(ENV_KEYS.QDRANT_URL),
    qdrantApiKey: getEnvVar(ENV_KEYS.QDRANT_API_KEY),
    qdrantCollectionName: getEnvVarRequired(ENV_KEYS.QDRANT_COLLECTION_NAME),
    qdrantTimeout: getEnvVarAsNumber(ENV_KEYS.QDRANT_TIMEOUT, 30000),
    qdrantMaxConnections: getEnvVarAsNumber(ENV_KEYS.QDRANT_MAX_CONNECTIONS, 10),

    // Security
    jwtSecret: process.env[ENV_KEYS.JWT_SECRET],
    requireApiKey: getEnvVarAsBoolean(ENV_KEYS.REQUIRE_API_KEY, true),

    // Logging
    logLevel: getEnvVarWithDefault(ENV_KEYS.LOG_LEVEL, 'info'),
    logFormat: getEnvVarWithDefault(ENV_KEYS.LOG_FORMAT, 'json'),

    // Health & Metrics
    enableHealthChecks: getEnvVarAsBoolean(ENV_KEYS.ENABLE_HEALTH_CHECKS, true),
    enableMetricsCollection: getEnvVarAsBoolean(ENV_KEYS.ENABLE_METRICS_COLLECTION, true),

    // Performance
    maxMemoryMb: getEnvVarAsNumber(ENV_KEYS.MAX_MEMORY_MB, 1024),
    embeddingBatchSize: getEnvVarAsNumber(ENV_KEYS.EMBEDDING_BATCH_SIZE, 10),

    // Vector Configuration
    vectorSize: getEnvVarAsNumber(ENV_KEYS.VECTOR_SIZE, 1536),
    similarityThreshold: getEnvVarAsNumber(ENV_KEYS.SIMILARITY_THRESHOLD, 0.7),

    // Deduplication
    dedupeEnabled: getEnvVarAsBoolean(ENV_KEYS.DEDUPE_ENABLED, true),
  };
}

/**
 * Validates environment variables and exits process if validation fails
 * Use this for early startup validation
 */
export function validateOrExit(): void {
  const validation = validateEnvironmentVariables();

  if (!validation.isValid) {
    console.error('❌ Environment variable validation failed:');

    if (validation.missingCritical.length > 0) {
      console.error('\n🚨 Missing critical environment variables:');
      validation.missingCritical.forEach(key => {
        console.error(`   - ${key}`);
      });
    }

    if (validation.invalidFormat.length > 0) {
      console.error('\n⚠️  Invalid environment variable formats:');
      validation.invalidFormat.forEach(key => {
        console.error(`   - ${key}`);
      });
    }

    if (validation.errors.length > 0) {
      console.error('\n❌ Errors:');
      validation.errors.forEach(error => {
        console.error(`   - ${error}`);
      });
    }

    if (validation.warnings.length > 0) {
      console.error('\n⚠️  Warnings:');
      validation.warnings.forEach(warning => {
        console.error(`   - ${warning}`);
      });
    }

    console.error('\n💡 To fix these issues, set the required environment variables and restart the application.');
    console.error('   Example: cp .env.example .env && edit .env with your values');

    process.exit(1);
  }

  if (validation.warnings.length > 0) {
    console.warn('⚠️  Environment variable warnings:');
    validation.warnings.forEach(warning => {
      console.warn(`   - ${warning}`);
    });
  }

  console.log('✅ Environment variable validation passed');
}

/**
 * Prints a summary of the current environment configuration
 */
export function printEnvironmentSummary(config: StartupConfig): void {
  console.log('\n📋 Environment Configuration Summary:');
  console.log(`   Node Environment: ${config.nodeEnv}`);
  console.log(`   Server: ${config.host}:${config.port}`);
  console.log(`   Debug Mode: ${config.debugMode}`);
  console.log(`   Log Level: ${config.logLevel}`);
  console.log(`   Qdrant URL: ${config.qdrantUrl}`);
  console.log(`   Qdrant Collection: ${config.qdrantCollectionName}`);
  console.log(`   Vector Size: ${config.vectorSize}`);
  console.log(`   Max Memory: ${config.maxMemoryMb}MB`);
  console.log(`   Health Checks: ${config.enableHealthChecks ? 'Enabled' : 'Disabled'}`);
  console.log(`   Metrics Collection: ${config.enableMetricsCollection ? 'Enabled' : 'Disabled'}`);
  console.log(`   Deduplication: ${config.dedupeEnabled ? 'Enabled' : 'Disabled'}`);
  console.log(`   API Key Required: ${config.requireApiKey ? 'Yes' : 'No'}`);
  console.log('');
}