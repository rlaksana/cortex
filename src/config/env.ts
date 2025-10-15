import { z } from 'zod';
import { logger } from '../utils/logger.js';

/**
 * Environment configuration schema with Zod validation
 *
 * Constitutional Requirement: Type Safety (Principle VII)
 * - Runtime validation of environment variables
 * - Compile-time type inference from schema
 *
 * Required Variables:
 * - DATABASE_URL: PostgreSQL connection string
 * - LOG_LEVEL: Logging verbosity (debug|info|warn|error)
 * - NODE_ENV: Runtime environment (development|production|test)
 *
 * Optional Variables:
 * - CORTEX_ORG, CORTEX_PROJECT, CORTEX_BRANCH: Scope inference overrides
 * - DB_POOL_MIN, DB_POOL_MAX, DB_IDLE_TIMEOUT_MS: Database connection tuning
 */

const envSchema = z.object({
  // Database Configuration
  DATABASE_URL: z.string().url('DATABASE_URL must be a valid PostgreSQL connection string'),
  DB_POOL_MIN: z.coerce.number().int().min(1).default(2),
  DB_POOL_MAX: z.coerce.number().int().min(2).max(100).default(10),
  DB_IDLE_TIMEOUT_MS: z.coerce.number().int().min(1000).default(30000),

  // Logging Configuration
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),

  // MCP Server Configuration
  MCP_TRANSPORT: z.enum(['stdio', 'http']).default('stdio'),

  // Scope Inference (Optional)
  CORTEX_ORG: z.string().optional(),
  CORTEX_PROJECT: z.string().optional(),
  CORTEX_BRANCH: z.string().optional(),
});

export type Env = z.infer<typeof envSchema>;

let cachedEnv: Env | null = null;

/**
 * Load and validate environment configuration
 *
 * @returns Validated environment configuration object
 * @throws {Error} If required environment variables are missing or invalid
 *
 * @example
 * const config = loadEnv();
 * console.log(config.DATABASE_URL); // Type-safe access
 */
export function loadEnv(): Env {
  if (cachedEnv) {
    return cachedEnv;
  }

  try {
    cachedEnv = envSchema.parse(process.env);
    logger.info(
      {
        node_env: cachedEnv.NODE_ENV,
        log_level: cachedEnv.LOG_LEVEL,
        mcp_transport: cachedEnv.MCP_TRANSPORT,
        db_pool_config: {
          min: cachedEnv.DB_POOL_MIN,
          max: cachedEnv.DB_POOL_MAX,
          idle_timeout_ms: cachedEnv.DB_IDLE_TIMEOUT_MS,
        },
      },
      'Environment configuration loaded'
    );
    return cachedEnv;
  } catch (error) {
    if (error instanceof z.ZodError) {
      const errorMessages = error.errors.map((err) => `${err.path.join('.')}: ${err.message}`);
      logger.error(
        {
          validation_errors: errorMessages,
        },
        'Environment configuration validation failed'
      );
      throw new Error(`Environment validation failed:\n${errorMessages.join('\n')}`);
    }
    throw error;
  }
}

/**
 * Check if running in development mode
 */
export function isDevelopment(): boolean {
  return loadEnv().NODE_ENV === 'development';
}

/**
 * Check if running in production mode
 */
export function isProduction(): boolean {
  return loadEnv().NODE_ENV === 'production';
}

/**
 * Check if running in test mode
 */
export function isTest(): boolean {
  return loadEnv().NODE_ENV === 'test';
}
