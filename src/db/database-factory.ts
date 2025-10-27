/**
 * Qdrant Database Factory - Vector Database Creation
 *
 * Provides factory methods for creating Qdrant database instances based on
 * configuration, enabling optimized vector database operations for knowledge
 * management and semantic search.
 *
 * Features:
 * - Runtime Qdrant configuration and connection management
 * - Validation of Qdrant database configuration
 * - Connection pooling and optimization
 * - Collection management and schema operations
 * - Health monitoring and error handling
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { logger } from '../utils/logger.js';
import type {
  IDatabase,
  IDatabaseFactory,
  DatabaseConfig
} from './database-interface.js';
import type {
  DatabaseError,
  ValidationError,
  ConnectionError
} from './database-interface.js';
import { QdrantAdapter } from './adapters/qdrant-adapter.js';

/**
 * Factory class for creating Qdrant database instances
 */
export class DatabaseFactory implements IDatabaseFactory {
  private static instance: DatabaseFactory;
  private connections: Map<string, IDatabase> = new Map();
  private defaultType: string = 'qdrant';

  private constructor() {
    // Private constructor for singleton pattern
  }

  /**
   * Get singleton instance
   */
  static getInstance(): DatabaseFactory {
    if (!DatabaseFactory.instance) {
      DatabaseFactory.instance = new DatabaseFactory();
    }
    return DatabaseFactory.instance;
  }

  /**
   * Create a Qdrant database instance based on configuration
   */
  async create(config: DatabaseConfig): Promise<IDatabase> {
    const configKey = this.generateConfigKey(config);

    // Check if we already have a connection for this configuration
    if (this.connections.has(configKey)) {
      const connection = this.connections.get(configKey)!;

      // Validate connection is still healthy
      const healthy = await connection.healthCheck();
      if (healthy) {
        logger.debug({ type: config.type, configKey }, 'Reusing existing Qdrant connection');
        return connection;
      } else {
        // Remove unhealthy connection
        this.connections.delete(configKey);
        logger.warn({ type: config.type, configKey }, 'Removing unhealthy Qdrant connection');
      }
    }

    // Validate configuration
    const validation = await this.validateConfig(config);
    if (!validation.valid) {
      throw new ValidationError(`Invalid Qdrant configuration: ${validation.errors.join(', ')}`);
    }

    // Create new Qdrant database instance
    const database = new QdrantAdapter(config);

    // Initialize the database
    await database.initialize();

    // Cache the connection
    this.connections.set(configKey, database);

    logger.info({
      type: config.type,
      configKey,
      connectionCount: this.connections.size
    }, 'Created new Qdrant database connection');

    return database;
  }

  /**
   * Get Qdrant database instance
   */
  async getByType(type: string, additionalConfig?: Partial<DatabaseConfig>): Promise<IDatabase> {
    if (type !== 'qdrant') {
      throw new ValidationError(`Only 'qdrant' database type is supported. Received: ${type}`);
    }

    const config = this.buildConfig(additionalConfig);
    return await this.create(config);
  }

  /**
   * Get default Qdrant database instance
   */
  async getDefault(additionalConfig?: Partial<DatabaseConfig>): Promise<IDatabase> {
    return await this.getByType(this.defaultType, additionalConfig);
  }

  /**
   * Close specific Qdrant database connection
   */
  async close(type: string, additionalConfig?: Partial<DatabaseConfig> = {}): Promise<void> {
    const config = this.buildConfig(additionalConfig);
    const configKey = this.generateConfigKey(config);

    if (this.connections.has(configKey)) {
      const database = this.connections.get(configKey)!;
      await database.close();
      this.connections.delete(configKey);
      logger.info({ type, configKey }, 'Closed Qdrant database connection');
    } else {
      logger.warn({ type, configKey }, 'No Qdrant database connection found to close');
    }
  }

  /**
   * Close all Qdrant database connections
   */
  async closeAll(): Promise<void> {
    const closePromises = Array.from(this.connections.entries()).map(async ([configKey, database]) => {
      try {
        await database.close();
        logger.debug({ configKey }, 'Closed Qdrant database connection');
      } catch (error) {
        logger.error({ configKey, error }, 'Failed to close Qdrant database connection');
      }
    });

    await Promise.all(closePromises);
    this.connections.clear();
    logger.info('All Qdrant database connections closed');
  }

  /**
   * Get connection statistics
   */
  getConnectionStats(): {
    activeConnections: number;
    connectionsByType: Record<string, number>;
    details: Array<{ type: string; configKey: string; healthy: boolean }>;
  } {
    const connectionsByType: Record<string, number> = {};
    const details: Array<{ type: string; configKey: string; healthy: boolean }> = [];

    for (const [configKey, database] of this.connections.entries()) {
      const type = 'qdrant';
      connectionsByType[type] = (connectionsByType[type] || 0) + 1;

      details.push({
        type,
        configKey,
        healthy: false // Would need health check to determine
      });
    }

    return {
      activeConnections: this.connections.size,
      connectionsByType,
      details
    };
  }

  /**
   * Get supported configuration options
   */
  getSupportedOptions(): string[] {
    return [
      'url',
      'apiKey',
      'logQueries',
      'connectionTimeout',
      'maxConnections',
      'vectorSize',
      'distance',
      'collectionName'
    ];
  }

  /**
   * Validate Qdrant database configuration
   */
  async validateConfig(config: DatabaseConfig): Promise<{ valid: boolean; errors: string[] }> {
    const errors: string[] = [];

    // Validate database type
    if (!config.type) {
      errors.push('Database type is required');
    } else if (config.type !== 'qdrant') {
      errors.push(`Only 'qdrant' database type is supported. Received: ${config.type}`);
    }

    // Validate Qdrant URL
    if (!config.url && !process.env.QDRANT_URL) {
      errors.push('Qdrant URL is required (config.url or QDRANT_URL environment variable)');
    }

    // Validate URL format if provided
    if (config.url && !this.isValidUrl(config.url)) {
      errors.push('Qdrant URL must be a valid HTTP/HTTPS URL');
    }

    // Validate OpenAI configuration (required for embeddings)
    if (!process.env.OPENAI_API_KEY) {
      errors.push('OpenAI API key is required for Qdrant vector operations (OPENAI_API_KEY environment variable)');
    }

    // Validate connection timeout
    if (config.connectionTimeout && (config.connectionTimeout < 1000 || config.connectionTimeout > 300000)) {
      errors.push('Connection timeout must be between 1000ms and 300000ms (5 minutes)');
    }

    // Validate max connections
    if (config.maxConnections && (config.maxConnections < 1 || config.maxConnections > 100)) {
      errors.push('Max connections must be between 1 and 100');
    }

    // Validate vector size
    if (config.vectorSize) {
      const validSizes = [384, 768, 1024, 1536, 2048, 3072]; // Common embedding sizes
      if (!validSizes.includes(config.vectorSize)) {
        errors.push(`Vector size must be one of: ${validSizes.join(', ')}`);
      }
    }

    // Validate distance metric
    if (config.distance) {
      const validDistances = ['Cosine', 'Euclidean', 'DotProduct'];
      if (!validDistances.includes(config.distance)) {
        errors.push(`Distance must be one of: ${validDistances.join(', ')}`);
      }
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * Test Qdrant configuration and connectivity
   */
  async testConfiguration(config: DatabaseConfig): Promise<{
    type: string;
    connected: boolean;
    healthy: boolean;
    latency?: number;
    error?: string;
  }> {
    const startTime = Date.now();

    try {
      const database = await this.create(config);
      const healthy = await database.healthCheck();
      const latency = Date.now() - startTime;

      // Close the test connection immediately
      await this.close(config.type);

      return {
        type: config.type,
        connected: true,
        healthy,
        latency
      };

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      logger.error({ type: config.type, error: errorMessage }, 'Qdrant configuration test failed');

      return {
        type: config.type,
        connected: false,
        healthy: false,
        error: errorMessage
      };
    }
  }

  /**
   * Test Qdrant configuration
   */
  async testAllConfigurations(): Promise<Array<{
    type: string;
    connected: boolean;
    healthy: boolean;
    latency?: number;
    error?: string;
  }>> {
    const results = [];

    try {
      const config = this.buildConfig();
      const result = await this.testConfiguration(config);
      results.push(result);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      results.push({
        type: 'qdrant',
        connected: false,
        healthy: false,
        error: errorMessage
      });
    }

    return results;
  }

  /**
   * Get recommended Qdrant configuration based on use case
   */
  getRecommendation(useCase: {
    requiresVectors?: boolean;
    requiresFullTextSearch?: boolean;
    requiresHighPerformance?: boolean;
    prefersOpenSource?: boolean;
    vectorSize?: number;
  }): {
    recommended: string;
    reason: string;
    configuration: Partial<DatabaseConfig>;
    alternatives: string[];
  } {
    const { requiresVectors, requiresHighPerformance, prefersOpenSource, vectorSize } = useCase;

    // Qdrant is always recommended as it's the only supported database
    const recommendedConfig: Partial<DatabaseConfig> = {
      type: 'qdrant',
      vectorSize: vectorSize || 1536, // Default to OpenAI ada-002 size
      distance: 'Cosine',
      maxConnections: requiresHighPerformance ? 20 : 10,
      connectionTimeout: requiresHighPerformance ? 15000 : 30000
    };

    let reason = 'Qdrant provides optimal vector similarity search and semantic capabilities.';

    if (requiresVectors) {
      reason = 'Qdrant is essential for vector operations and semantic search functionality.';
    }

    if (requiresHighPerformance) {
      reason = 'Qdrant delivers superior performance for vector similarity search with optimized indexing.';
      recommendedConfig.maxConnections = 20;
      recommendedConfig.connectionTimeout = 15000;
    }

    return {
      recommended: 'qdrant',
      reason,
      configuration: recommendedConfig,
      alternatives: [] // No alternatives as Qdrant is the only option
    };
  }

  /**
   * Build Qdrant configuration from environment variables and defaults
   */
  buildConfig(additionalConfig: Partial<DatabaseConfig> = {}): DatabaseConfig {
    const baseConfig: DatabaseConfig = {
      type: 'qdrant',
      url: process.env.QDRANT_URL || 'http://localhost:6333',
      apiKey: process.env.QDRANT_API_KEY,
      logQueries: process.env.NODE_ENV === 'development',
      connectionTimeout: parseInt(process.env.DB_CONNECTION_TIMEOUT || '30000'),
      maxConnections: parseInt(process.env.DB_MAX_CONNECTIONS || '10'),
      vectorSize: parseInt(process.env.VECTOR_SIZE || '1536'),
      distance: process.env.VECTOR_DISTANCE as any || 'Cosine',
      collectionName: process.env.QDRANT_COLLECTION_NAME || 'cortex-memory'
    };

    return { ...baseConfig, ...additionalConfig };
  }

  /**
   * Set default database type (always qdrant)
   */
  setDefaultType(type: string): void {
    if (type !== 'qdrant') {
      throw new ValidationError(`Cannot set default type to unsupported database: ${type}. Only 'qdrant' is supported.`);
    }
    this.defaultType = type;
  }

  /**
   * Get current default database type
   */
  getDefaultType(): string {
    return this.defaultType;
  }

  // === Private Helper Methods ===

  private generateConfigKey(config: DatabaseConfig): string {
    // Create a unique key for the configuration
    const keyParts = [
      config.type,
      config.url || '',
      config.collectionName || '',
      config.maxConnections?.toString() || '10'
    ];

    return crypto.createHash('md5').update(keyParts.join('|')).digest('hex');
  }

  /**
   * Validate URL format
   */
  private isValidUrl(url: string): boolean {
    try {
      const urlObj = new URL(url);
      return urlObj.protocol === 'http:' || urlObj.protocol === 'https:';
    } catch {
      return false;
    }
  }

  /**
   * Get environment-based configuration
   */
  static getEnvironmentConfig(): DatabaseConfig {
    return {
      type: 'qdrant',
      url: process.env.QDRANT_URL || 'http://localhost:6333',
      apiKey: process.env.QDRANT_API_KEY,
      logQueries: process.env.NODE_ENV === 'development',
      connectionTimeout: parseInt(process.env.DB_CONNECTION_TIMEOUT || '30000'),
      maxConnections: parseInt(process.env.DB_MAX_CONNECTIONS || '10'),
      vectorSize: parseInt(process.env.VECTOR_SIZE || '1536'),
      distance: process.env.VECTOR_DISTANCE as any || 'Cosine',
      collectionName: process.env.QDRANT_COLLECTION_NAME || 'cortex-memory'
    };
  }

  /**
   * Create Qdrant database instance from environment configuration
   */
  static async createFromEnvironment(): Promise<IDatabase> {
    const factory = DatabaseFactory.getInstance();
    const config = DatabaseFactory.getEnvironmentConfig();
    return await factory.create(config);
  }

  /**
   * Create default Qdrant database instance
   */
  static async createDefault(): Promise<IDatabase> {
    const factory = DatabaseFactory.getInstance();
    return await factory.getDefault();
  }
}

/**
 * Export convenience functions for Qdrant database creation
 */
export async function createDatabase(config: DatabaseConfig): Promise<IDatabase> {
  const factory = DatabaseFactory.getInstance();
  return await factory.create(config);
}

export async function createQdrantDatabase(additionalConfig?: Partial<DatabaseConfig>): Promise<IDatabase> {
  const factory = DatabaseFactory.getInstance();
  return await factory.getByType('qdrant', additionalConfig);
}

/**
 * Export singleton instance for convenience
 */
export const databaseFactory = DatabaseFactory.getInstance();