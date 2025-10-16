import { z } from 'zod';
import dotenv from 'dotenv';
import crypto from 'crypto';
import { logger } from '../utils/logger.js';

// Load environment variables
dotenv.config();

/**
 * Enhanced environment configuration with validation and security
 */

// Database configuration schema
const DatabaseConfigSchema = z.object({
  DB_HOST: z.string().min(1, 'DB_HOST is required').default('localhost'),
  DB_PORT: z.string().transform(Number).pipe(z.number().int().min(1).max(65535)).default('5432'),
  DB_NAME: z.string().min(1, 'DB_NAME is required').default('cortex_prod'),
  DB_USER: z.string().min(1, 'DB_USER is required').default('cortex'),
  DB_PASSWORD: z.string().default(''),
  DATABASE_URL: z.string().url().optional(),
});

// Application configuration schema
const AppConfigSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
  PORT: z.string().transform(Number).pipe(z.number().int().min(1).max(65535)).default('3000'),
});

// Security configuration schema
const SecurityConfigSchema = z.object({
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters').optional(),
  ENCRYPTION_KEY: z.string().min(32, 'ENCRYPTION_KEY must be at least 32 characters').optional(),
  CORS_ORIGIN: z.string().url().optional(),
});

// MCP configuration schema
const McpConfigSchema = z.object({
  MCP_SERVER_NAME: z.string().min(1).default('cortex-memory'),
  MCP_SERVER_VERSION: z.string().min(1).default('1.0.0'),
  MCP_MAX_BATCH_SIZE: z
    .string()
    .transform(Number)
    .pipe(z.number().int().min(1).max(1000))
    .default('100'),
});

// Complete configuration schema
const ConfigSchema = z.object({
  ...DatabaseConfigSchema.shape,
  ...AppConfigSchema.shape,
  ...SecurityConfigSchema.shape,
  ...McpConfigSchema.shape,
});

export type AppConfig = z.infer<typeof ConfigSchema>;

/**
 * Validates and loads configuration
 */
function validateConfig(): AppConfig {
  const result = ConfigSchema.safeParse(process.env);

  if (!result.success) {
    const errors = result.error.errors.map((err) => ({
      field: err.path.join('.'),
      message: err.message,
      received: process.env[err.path[0] as string],
    }));

    logger.error({ errors }, 'Configuration validation failed');

    throw new Error(
      `Configuration validation failed:\n${errors.map((e) => `  ${e.field}: ${e.message} (received: ${e.received || 'undefined'})`).join('\n')}`
    );
  }

  return result.data;
}

/**
 * Secure environment configuration manager
 */
export class EnvironmentConfig {
  private static instance: EnvironmentConfig;
  private config: AppConfig;
  private encryptionKey: Buffer;

  private constructor() {
    this.config = validateConfig();
    this.encryptionKey = this.getOrCreateEncryptionKey();

    // Log configuration (without sensitive data)
    logger.info(
      {
        environment: this.config.NODE_ENV,
        dbHost: this.config.DB_HOST,
        dbPort: this.config.DB_PORT,
        dbName: this.config.DB_NAME,
        dbUser: this.config.DB_USER,
        logLevel: this.config.LOG_LEVEL,
      },
      'Environment configuration loaded successfully'
    );
  }

  public static getInstance(): EnvironmentConfig {
    if (!EnvironmentConfig.instance) {
      EnvironmentConfig.instance = new EnvironmentConfig();
    }
    return EnvironmentConfig.instance;
  }

  public getConfig(): AppConfig {
    return { ...this.config };
  }

  /**
   * Get database configuration with connection string generation
   */
  public getDatabaseConfig() {
    const { DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD, DATABASE_URL } = this.config;

    // Use explicit DATABASE_URL if provided, otherwise construct it
    const databaseUrl =
      DATABASE_URL || `postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}`;

    return {
      host: DB_HOST,
      port: DB_PORT,
      database: DB_NAME,
      user: DB_USER,
      password: DB_PASSWORD,
      databaseUrl,
    };
  }

  /**
   * Encrypt sensitive values
   */
  public encrypt(value: string): string {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', this.encryptionKey, iv);

    let encrypted = cipher.update(value, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    return iv.toString('hex') + ':' + encrypted;
  }

  /**
   * Decrypt sensitive values
   */
  public decrypt(encryptedValue: string): string {
    const parts = encryptedValue.split(':');
    if (parts.length !== 2) {
      throw new Error('Invalid encrypted value format');
    }

    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = parts[1];
    const decipher = crypto.createDecipheriv('aes-256-cbc', this.encryptionKey, iv);

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }

  /**
   * Get or create encryption key
   */
  private getOrCreateEncryptionKey(): Buffer {
    // Try to get encryption key from environment
    if (this.config.ENCRYPTION_KEY) {
      return Buffer.from(this.config.ENCRYPTION_KEY, 'hex');
    }

    // Create a new encryption key for development
    if (this.config.NODE_ENV === 'development') {
      const key = crypto.randomBytes(32).toString('hex');
      logger.warn(
        'Generated new encryption key for development. Set ENCRYPTION_KEY in production for security.'
      );
      return Buffer.from(key, 'hex');
    }

    throw new Error('ENCRYPTION_KEY is required in production environment');
  }

  /**
   * Validate database connection
   */
  public async validateDatabaseConnection(): Promise<boolean> {
    try {
      const { Pool } = await import('pg');
      const dbConfig = this.getDatabaseConfig();

      const pool = new Pool({
        host: dbConfig.host,
        port: dbConfig.port,
        database: dbConfig.database,
        user: dbConfig.user,
        password: dbConfig.password,
        connectionTimeoutMillis: 5000,
      });

      await pool.query('SELECT 1 as health_check');
      await pool.end();

      logger.info('Database connection validation successful');
      return true;
    } catch (error: unknown) {
      logger.error({ error: error instanceof Error ? error.message : String(error) }, 'Database connection validation failed');
      return false;
    }
  }

  /**
   * Export configuration for MCP server
   */
  public exportForMCP() {
    const dbConfig = this.getDatabaseConfig();

    return {
      // Database configuration
      DATABASE_URL: dbConfig.databaseUrl,
      DB_HOST: dbConfig.host,
      DB_PORT: dbConfig.port.toString(),
      DB_NAME: dbConfig.database,
      DB_USER: dbConfig.user,
      DB_PASSWORD: dbConfig.password,

      // Application configuration
      NODE_ENV: this.config.NODE_ENV,
      LOG_LEVEL: this.config.LOG_LEVEL,

      // MCP configuration
      MCP_SERVER_NAME: this.config.MCP_SERVER_NAME,
      MCP_SERVER_VERSION: this.config.MCP_SERVER_VERSION,
      MCP_MAX_BATCH_SIZE: this.config.MCP_MAX_BATCH_SIZE.toString(),
    };
  }
}

// Export singleton instance
export const config = EnvironmentConfig.getInstance();

// Export configuration values for backward compatibility
export const { NODE_ENV, LOG_LEVEL, DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD } =
  config.getConfig();
