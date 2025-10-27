/**
 * Database Factory Interface
 *
 * Defines the contract for creating database adapters
 * based on configuration and runtime requirements.
 */

import { IPostgreSQLAdapter, PostgreSQLConfig } from './postgresql-adapter.interface.js';
import { IVectorAdapter, VectorConfig } from './vector-adapter.interface.js';
import { DatabaseConfig, DatabaseMetrics } from './database-interface.js';

export type DatabaseType = 'postgresql' | 'qdrant' | 'hybrid';

export interface DatabaseFactoryConfig {
  type: DatabaseType;
  postgres?: PostgreSQLConfig;
  qdrant?: VectorConfig;
  fallback?: {
    enabled: boolean;
    retryAttempts: number;
    retryDelay: number;
  };
}

export interface AdapterCapabilities {
  supportsVectors: boolean;
  supportsFullTextSearch: boolean;
  supportsCRUD: boolean;
  supportsTransactions: boolean;
  maxBatchSize: number;
  supportedOperations: string[];
}

/**
 * Factory interface for creating database adapters
 */
export interface IDatabaseFactory {
  /**
   * Create database adapter(s) based on configuration
   */
  create(config: DatabaseFactoryConfig): Promise<DatabaseAdapters>;

  /**
   * Create PostgreSQL adapter only
   */
  createPostgreSQLAdapter(config: PostgreSQLConfig): Promise<IPostgreSQLAdapter>;

  /**
   * Create vector adapter only
   */
  createVectorAdapter(config: VectorConfig): Promise<IVectorAdapter>;

  /**
   * Get supported database types
   */
  getSupportedTypes(): DatabaseType[];

  /**
   * Validate factory configuration
   */
  validateConfig(config: DatabaseFactoryConfig): Promise<{
    valid: boolean;
    errors: string[];
    warnings: string[];
  }>;

  /**
   * Get capabilities for a database type
   */
  getCapabilities(type: DatabaseType): AdapterCapabilities;

  /**
   * Test database connectivity
   */
  testConnection(type: DatabaseType, config: DatabaseConfig): Promise<boolean>;
}

/**
 * Container for created database adapters
 */
export interface DatabaseAdapters {
  postgres?: IPostgreSQLAdapter;
  vector?: IVectorAdapter;
  type: DatabaseType;
  config: DatabaseFactoryConfig;
}

/**
 * Database factory error types
 */
export class DatabaseFactoryError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly type?: DatabaseType,
    public readonly originalError?: Error
  ) {
    super(message);
    this.name = 'DatabaseFactoryError';
  }
}

export class ConfigurationError extends DatabaseFactoryError {
  constructor(message: string, public readonly field?: string) {
    super(message, 'CONFIGURATION_ERROR');
    this.name = 'ConfigurationError';
  }
}

export class AdapterCreationError extends DatabaseFactoryError {
  constructor(type: DatabaseType, originalError?: Error) {
    super(`Failed to create ${type} adapter`, 'ADAPTER_CREATION_ERROR', type, originalError);
    this.name = 'AdapterCreationError';
  }
}

export class UnsupportedDatabaseError extends DatabaseFactoryError {
  constructor(type: DatabaseType) {
    super(`Unsupported database type: ${type}`, 'UNSUPPORTED_DATABASE_TYPE', type);
    this.name = 'UnsupportedDatabaseError';
  }
}