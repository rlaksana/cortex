/**
 * Database Factory
 *
 * Creates and manages database adapters based on configuration.
 * Supports Qdrant with proper
 * dependency injection and error handling.
 *
 * Features:
 * - Factory pattern for adapter creation
 * - Configuration validation
 * - Support for Qdrant database
 * - Fallback and error recovery
 * - Type-safe adapter instantiation
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

import { logger } from '@/utils/logger.js';
import { safeGetProperty } from '@/utils/type-fixes.js';

import { Environment } from '../../config/environment.js';
import { QdrantAdapter } from '../adapters/qdrant-adapter.js';
import {
  type AdapterCapabilities,
  AdapterCreationError,
  ConfigurationError,
  type DatabaseAdapters,
  type DatabaseFactoryConfig,
  DatabaseFactoryError,
  type DatabaseType,
  type IDatabaseFactory,
  UnsupportedDatabaseError,
} from '../interfaces/database-factory.interface.js';
import type { IVectorAdapter, VectorConfig } from '../interfaces/vector-adapter.interface.js';
import { createVectorConfig, validateVectorConfig } from '../type-guards.js';

/**
 * Database factory implementation
 */
export class DatabaseFactory implements IDatabaseFactory {
  private supportedTypes: DatabaseType[] = ['qdrant'];
  private capabilities: Map<DatabaseType, AdapterCapabilities>;

  constructor() {
    this.capabilities = new Map();
    this.initializeCapabilities();
  }

  // === Main Factory Methods ===

  async create(config: DatabaseFactoryConfig): Promise<DatabaseAdapters> {
    try {
      logger.debug({ config }, 'Creating database adapters');

      // Validate configuration
      const validation = await this.validateConfig(config);
      if (!validation.valid) {
        throw new ConfigurationError(`Invalid configuration: ${validation.errors.join(', ')}`);
      }

      // Log warnings if any
      if (validation.warnings.length > 0) {
        logger.warn({ warnings: validation.warnings }, 'Database configuration warnings');
      }

      const adapters: DatabaseAdapters = {
        type: config.type,
        config,
      };

      switch (config.type) {
        case 'qdrant':
          if (!config.qdrant) {
            throw new ConfigurationError(
              'Qdrant configuration is required for qdrant type',
              'qdrant'
            );
          }
          adapters.vector = await this.createVectorAdapter(config.qdrant);
          break;

        default:
          throw new UnsupportedDatabaseError(config.type);
      }

      logger.info(
        {
          type: config.type,
          hasVector: !!adapters.vector,
        },
        'Database adapters created successfully'
      );

      return adapters;
    } catch (error) {
      logger.error({ error, config }, 'Failed to create database adapters');
      throw error instanceof DatabaseFactoryError
        ? error
        : new AdapterCreationError(config.type, error as Error);
    }
  }

  async createVectorAdapter(config: VectorConfig): Promise<IVectorAdapter> {
    try {
      logger.debug({ config }, 'Creating vector adapter');

      const adapter = new QdrantAdapter(config);

      // Test connection
      const connected = await this.testConnection('qdrant', config);
      if (!connected) {
        throw new DatabaseFactoryError(
          'Qdrant connection test failed',
          'CONNECTION_TEST_FAILED',
          'qdrant'
        );
      }

      // Initialize adapter
      await adapter.initialize();

      logger.info('Vector adapter created and initialized successfully');
      return adapter;
    } catch (error) {
      logger.error({ error }, 'Failed to create vector adapter');
      throw new AdapterCreationError('qdrant', error as Error);
    }
  }

  // === Configuration and Capabilities ===

  getSupportedTypes(): DatabaseType[] {
    return [...this.supportedTypes];
  }

  async validateConfig(config: DatabaseFactoryConfig): Promise<{
    valid: boolean;
    errors: string[];
    warnings: string[];
  }> {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Validate type
    if (!this.supportedTypes.includes(config.type)) {
      errors.push(
        `Unsupported database type: ${config.type}. Supported types: ${this.supportedTypes.join(', ')}`
      );
    }

    // Validate type-specific configurations
    switch (config.type) {
      case 'qdrant':
        if (!config.qdrant) {
          errors.push('Qdrant configuration is required');
        } else {
          this.validateVectorConfig(config.qdrant, errors, warnings);
        }
        break;

      default:
        errors.push(`Unsupported database type: ${config.type}. Only qdrant is supported.`);
        break;
    }

    // Validate fallback configuration
    if (config.fallback) {
      if (config.fallback.retryAttempts < 0) {
        warnings.push('Retry attempts should be non-negative');
      }
      if (config.fallback.retryDelay < 0) {
        warnings.push('Retry delay should be non-negative');
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  getCapabilities(type: DatabaseType): AdapterCapabilities {
    const capabilities = this.capabilities.get(type);
    if (!capabilities) {
      throw new UnsupportedDatabaseError(type);
    }
    return capabilities;
  }

  async testConnection(_type: DatabaseType, config: VectorConfig): Promise<boolean> {
    try {
      logger.debug({ type: _type }, 'Testing database connection');

      switch (_type) {
        case 'qdrant': {
          const vectorAdapter = new QdrantAdapter(config);
          return await vectorAdapter.healthCheck();
        }

        default:
          throw new UnsupportedDatabaseError(_type);
      }
    } catch (error) {
      logger.error({ error, type: _type }, 'Database connection test failed');
      return false;
    }
  }

  // === Private Helper Methods ===

  private initializeCapabilities(): void {
    // Qdrant capabilities
    this.capabilities.set('qdrant', {
      supportsVectors: true,
      supportsFullTextSearch: true,
      supportsCRUD: false,
      supportsTransactions: false,
      maxBatchSize: 100,
      supportedOperations: [
        'store',
        'update',
        'delete',
        'search',
        'semanticSearch',
        'vectorSearch',
        'hybridSearch',
        'generateEmbedding',
        'findSimilar',
        'checkDuplicates',
        'bulkStore',
        'bulkDelete',
        'bulkSearch',
        'storeWithEmbeddings',
        'vectorSearch',
        'findNearest',
        'backup',
        'restore',
        'optimize',
        'validate',
        'updateCollectionSchema',
        'getCollectionInfo',
      ],
    });
  }

  private validateVectorConfig(config: VectorConfig, _errors: string[], warnings: string[]): void {
    if (!config.url && !process.env.QDRANT_URL) {
      warnings.push('Qdrant URL not specified, using default http://localhost:6333');
    }

    if (config.vectorSize && config.vectorSize <= 0) {
      warnings.push('Vector size should be positive');
    }

    if (config.vectorSize && config.vectorSize > 32768) {
      warnings.push('Vector size is very large, this may impact performance');
    }

    if (config.maxConnections && config.maxConnections <= 0) {
      warnings.push('Max connections should be positive');
    }

    if (config.connectionTimeout && config.connectionTimeout <= 0) {
      warnings.push('Connection timeout should be positive');
    }
  }

  // === Static Factory Methods ===

  /**
   * Get singleton instance of the database factory
   */
  static getInstance(): DatabaseFactory {
    const instance = safeGetProperty(DatabaseFactory, '_instance', null);
    if (!instance) {
      (DatabaseFactory as any)._instance = new DatabaseFactory();
    }
    return (DatabaseFactory as any)._instance;
  }

  /**
   * Create a database factory instance with environment configuration
   */
  static createWithEnvironment(): DatabaseFactory {
    return new DatabaseFactory();
  }

  /**
   * Create adapters using environment configuration
   */
  static async createFromEnvironment(): Promise<DatabaseAdapters> {
    const factory = new DatabaseFactory();
    const env = Environment.getInstance();

    // Create VectorConfig using type-safe factory function
    const qdrantConfig = createVectorConfig({
      type: 'qdrant',
      url: env.getQdrantConfig().url,
      size: env.getQdrantConfig().vectorSize || 1536,
      vectorSize: env.getQdrantConfig().vectorSize || 1536,
      distance: 'Cosine',
      embeddingModel: 'text-embedding-3-small',
      batchSize: 10,
      logQueries: env.isDevelopmentMode(),
      connectionTimeout: env.getQdrantConfig().connectionTimeout,
      maxConnections: env.getQdrantConfig().maxConnections,
      ...(env.getQdrantConfig().apiKey && { apiKey: env.getQdrantConfig().apiKey }),
    });

    const config: DatabaseFactoryConfig = {
      type: 'qdrant',
      qdrant: validateVectorConfig(qdrantConfig),
      fallback: {
        enabled: true,
        retryAttempts: 3,
        retryDelay: 1000,
      },
    };

    return await factory.create(config);
  }
}

// Export factory instance
export const databaseFactory = DatabaseFactory.createWithEnvironment();

// Export convenience function for creating database from VectorConfig
export async function createDatabase(config: VectorConfig): Promise<IVectorAdapter> {
  const factory = DatabaseFactory.createWithEnvironment();
  return await factory.createVectorAdapter(config);
}
