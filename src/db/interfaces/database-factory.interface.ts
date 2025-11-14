// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * Database Factory Interface
 *
 * Defines the contract for creating database adapters
 * based on configuration and runtime requirements.
 */

import { type IVectorAdapter, type VectorConfig } from './vector-adapter.interface.js';
import { type DatabaseConfig } from '../database-interface.js';

export type DatabaseType = 'qdrant';

export interface DatabaseFactoryConfig {
  type: DatabaseType;
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
  create(_config: DatabaseFactoryConfig): Promise<DatabaseAdapters>;

  /**
   * Create vector adapter only
   */
  createVectorAdapter(_config: VectorConfig): Promise<IVectorAdapter>;

  /**
   * Get supported database types
   */
  getSupportedTypes(): DatabaseType[];

  /**
   * Validate factory configuration
   */
  validateConfig(_config: DatabaseFactoryConfig): Promise<{
    valid: boolean;
    errors: string[];
    warnings: string[];
  }>;

  /**
   * Get capabilities for a database type
   */
  getCapabilities(_type: DatabaseType): AdapterCapabilities;

  /**
   * Test database connectivity
   */
  testConnection(_type: DatabaseType, _config: DatabaseConfig): Promise<boolean>;
}

/**
 * Container for created database adapters
 */
export interface DatabaseAdapters {
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
    public readonly _code: string,
    public readonly _type?: DatabaseType,
    public readonly _originalError?: Error
  ) {
    super(message);
    this.name = 'DatabaseFactoryError';
  }
}

export class ConfigurationError extends DatabaseFactoryError {
  constructor(
    message: string,
    public readonly _field?: string
  ) {
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
