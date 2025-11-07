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

import { logger } from '@/utils/logger.js';
import { getKeyVaultService } from '../services/security/key-vault-service.js';
import * as crypto from 'crypto';
import type { IDatabase, IDatabaseFactory, DatabaseConfig } from './database-interface.js';
import type { IVectorAdapter } from './interfaces/vector-adapter.interface.js';
import { ValidationError } from '../utils/error-handler.js';
import { QdrantAdapter } from './adapters/qdrant-adapter.js';
import { createFindObservability } from '../utils/observability-helper.js';

/**
 * Check if a key exists in the key vault
 */
async function checkKeyVaultForKey(keyName: string): Promise<boolean> {
  try {
    const keyVault = getKeyVaultService();
    const key = await keyVault.get_key_by_name(keyName);
    return !!key?.value;
  } catch {
    return false;
  }
}
import type {
  KnowledgeItem,
  StoreError,
  SearchResult,
  SearchQuery,
  MemoryStoreResponse,
  MemoryFindResponse,
} from '../types/core-interfaces.js';

/**
 * Adapter wrapper that converts IVectorAdapter to IDatabase interface
 * This bridges the gap between the vector-specific interface and the generic database interface
 */
class VectorToDatabaseAdapter implements IDatabase {
  private vectorAdapter: IVectorAdapter;

  constructor(vectorAdapter: IVectorAdapter) {
    this.vectorAdapter = vectorAdapter;
  }

  async initialize(): Promise<void> {
    return this.vectorAdapter.initialize();
  }

  async healthCheck(): Promise<boolean> {
    return this.vectorAdapter.healthCheck();
  }

  async getMetrics(): Promise<any> {
    return this.vectorAdapter.getMetrics();
  }

  async close(): Promise<void> {
    return this.vectorAdapter.close();
  }

  async store(items: KnowledgeItem[], options?: any): Promise<MemoryStoreResponse> {
    return this.vectorAdapter.store(items, options);
  }

  async update(items: KnowledgeItem[], options?: any): Promise<MemoryStoreResponse> {
    return this.vectorAdapter.update(items, options);
  }

  async delete(ids: string[], options?: any): Promise<{ deleted: number; errors: StoreError[] }> {
    return this.vectorAdapter.delete(ids, options);
  }

  async findById(ids: string[]): Promise<KnowledgeItem[]> {
    return this.vectorAdapter.findById(ids);
  }

  async search(query: SearchQuery, options?: any): Promise<MemoryFindResponse> {
    return this.vectorAdapter.search(query, options);
  }

  async semanticSearch(query: string, options?: any): Promise<SearchResult[]> {
    return this.vectorAdapter.semanticSearch(query, options);
  }

  async hybridSearch(query: string, options?: any): Promise<MemoryFindResponse> {
    const startTime = Date.now();
    // Convert SearchResult[] to MemoryFindResponse
    const searchResults = await this.vectorAdapter.hybridSearch(query, options);

    // Calculate average confidence from search results
    const confidenceAverage =
      searchResults.length > 0
        ? searchResults.reduce((sum, result) => sum + (result.confidence_score || 0), 0) /
          searchResults.length
        : 0;

    return {
      results: searchResults,
      items: searchResults,
      total_count: searchResults.length,
      autonomous_context: {
        search_mode_used: 'hybrid',
        results_found: searchResults.length,
        confidence_average: confidenceAverage,
        user_message_suggestion: `Found ${searchResults.length} results matching your query`,
      },
      observability: createFindObservability(
        'hybrid',
        true,
        false,
        Date.now() - startTime,
        confidenceAverage
      ),
      meta: {
        strategy: 'hybrid_search',
        vector_used: true,
        degraded: false,
        source: 'database_factory',
        execution_time_ms: Date.now() - startTime,
        confidence_score: confidenceAverage,
        truncated: false,
      },
    };
  }

  // Add other required methods with reasonable implementations or delegations
  async storeByKind(
    kind: string,
    items: KnowledgeItem[],
    options?: any
  ): Promise<MemoryStoreResponse> {
    return this.vectorAdapter.storeByKind(kind, items, options);
  }

  async searchByKind(
    kinds: string[],
    query: SearchQuery,
    options?: any
  ): Promise<MemoryFindResponse> {
    return this.vectorAdapter.searchByKind(kinds, query, options);
  }

  async findByScope(scope: any, options?: any): Promise<KnowledgeItem[]> {
    return this.vectorAdapter.findByScope(scope, options);
  }

  async findSimilar(
    item: KnowledgeItem,
    threshold?: number,
    options?: any
  ): Promise<SearchResult[]> {
    return this.vectorAdapter.findSimilar(item, threshold, options);
  }

  async checkDuplicates(
    items: KnowledgeItem[]
  ): Promise<{ duplicates: KnowledgeItem[]; originals: KnowledgeItem[] }> {
    return this.vectorAdapter.checkDuplicates(items);
  }

  async getStatistics(scope?: any): Promise<any> {
    return this.vectorAdapter.getStatistics(scope);
  }

  async bulkStore(items: KnowledgeItem[], options?: any): Promise<MemoryStoreResponse> {
    return this.vectorAdapter.bulkStore(items, options);
  }

  async bulkDelete(filter: any, options?: any): Promise<{ deleted: number }> {
    return this.vectorAdapter.bulkDelete(filter, options);
  }

  async bulkSearch(queries: SearchQuery[], options?: any): Promise<MemoryFindResponse[]> {
    return this.vectorAdapter.bulkSearch(queries, options);
  }

  async generateEmbedding(content: string): Promise<number[]> {
    return this.vectorAdapter.generateEmbedding(content);
  }

  async storeWithEmbeddings(items: any[], options?: any): Promise<MemoryStoreResponse> {
    return this.vectorAdapter.storeWithEmbeddings(items, options);
  }

  async vectorSearch(embedding: number[], options?: any): Promise<SearchResult[]> {
    return this.vectorAdapter.vectorSearch(embedding, options);
  }

  async findNearest(
    embedding: number[],
    limit?: number,
    threshold?: number
  ): Promise<SearchResult[]> {
    return this.vectorAdapter.findNearest(embedding, limit, threshold);
  }

  async backup(destination?: string): Promise<string> {
    return this.vectorAdapter.backup(destination);
  }

  async restore(source: string): Promise<void> {
    return this.vectorAdapter.restore(source);
  }

  async optimize(): Promise<void> {
    return this.vectorAdapter.optimize();
  }

  async validate(): Promise<{ valid: boolean; issues: string[] }> {
    return this.vectorAdapter.validate();
  }

  async updateCollectionSchema(config: any): Promise<void> {
    return this.vectorAdapter.updateCollectionSchema(config);
  }

  async getCollectionInfo(): Promise<any> {
    return this.vectorAdapter.getCollectionInfo();
  }
}

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
    const vectorAdapter = new QdrantAdapter(config);
    const database = new VectorToDatabaseAdapter(vectorAdapter);

    // Initialize the database
    await database.initialize();

    // Cache the connection
    this.connections.set(configKey, database);

    logger.info(
      {
        type: config.type,
        configKey,
        connectionCount: this.connections.size,
      },
      'Created new Qdrant database connection'
    );

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
  async close(type: string, additionalConfig: Partial<DatabaseConfig> = {}): Promise<void> {
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
    const closePromises = Array.from(this.connections.entries()).map(
      async ([configKey, database]) => {
        try {
          await database.close();
          logger.debug({ configKey }, 'Closed Qdrant database connection');
        } catch (error) {
          logger.error({ configKey, error }, 'Failed to close Qdrant database connection');
        }
      }
    );

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

    for (const [configKey, _database] of this.connections.entries()) {
      const type = 'qdrant';
      connectionsByType[type] = (connectionsByType[type] || 0) + 1;

      details.push({
        type,
        configKey,
        healthy: false, // Would need health check to determine
      });
    }

    return {
      activeConnections: this.connections.size,
      connectionsByType,
      details,
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
      'collectionName',
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
    // Check if OpenAI API key is available in environment or key vault
    const hasOpenAIKey =
      process.env.OPENAI_API_KEY || (await checkKeyVaultForKey('openai_api_key'));
    if (!hasOpenAIKey) {
      errors.push(
        'OpenAI API key is required for Qdrant vector operations (set OPENAI_API_KEY or configure in key vault)'
      );
    }

    // Validate connection timeout
    if (
      config.connectionTimeout &&
      (config.connectionTimeout < 1000 || config.connectionTimeout > 300000)
    ) {
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
      const validDistances = ['Cosine', 'Euclid', 'Dot', 'Manhattan'];
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
        latency,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      logger.error({ type: config.type, error: errorMessage }, 'Qdrant configuration test failed');

      return {
        type: config.type,
        connected: false,
        healthy: false,
        error: errorMessage,
      };
    }
  }

  /**
   * Test Qdrant configuration
   */
  async testAllConfigurations(): Promise<
    Array<{
      type: string;
      connected: boolean;
      healthy: boolean;
      latency?: number;
      error?: string;
    }>
  > {
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
        error: errorMessage,
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
    const { requiresVectors, requiresHighPerformance, vectorSize } = useCase;

    // Qdrant is always recommended as it's the only supported database
    const recommendedConfig: Partial<DatabaseConfig> = {
      type: 'qdrant',
      vectorSize: vectorSize || 1536, // Default to OpenAI ada-002 size
      distance: 'Cosine',
      maxConnections: requiresHighPerformance ? 20 : 10,
      connectionTimeout: requiresHighPerformance ? 15000 : 30000,
    };

    let reason = 'Qdrant provides optimal vector similarity search and semantic capabilities.';

    if (requiresVectors) {
      reason = 'Qdrant is essential for vector operations and semantic search functionality.';
    }

    if (requiresHighPerformance) {
      reason =
        'Qdrant delivers superior performance for vector similarity search with optimized indexing.';
      recommendedConfig.maxConnections = 20;
      recommendedConfig.connectionTimeout = 15000;
    }

    return {
      recommended: 'qdrant',
      reason,
      configuration: recommendedConfig,
      alternatives: [], // No alternatives as Qdrant is the only option
    };
  }

  /**
   * Build Qdrant configuration from environment variables and defaults
   */
  buildConfig(additionalConfig: Partial<DatabaseConfig> = {}): DatabaseConfig {
    const baseConfig: DatabaseConfig = {
      type: 'qdrant',
      url: process.env.QDRANT_URL || 'http://localhost:6333',
      // API key will be resolved by the adapter from key vault or environment
      logQueries: process.env.NODE_ENV === 'development',
      connectionTimeout: parseInt(process.env.DB_CONNECTION_TIMEOUT || '30000'),
      maxConnections: parseInt(process.env.DB_MAX_CONNECTIONS || '10'),
      vectorSize: parseInt(process.env.VECTOR_SIZE || '1536'),
      distance: (process.env.VECTOR_DISTANCE as any) || 'Cosine',
      collectionName: process.env.QDRANT_COLLECTION_NAME || 'cortex-memory',
    };

    return { ...baseConfig, ...additionalConfig };
  }

  /**
   * Set default database type (always qdrant)
   */
  setDefaultType(type: string): void {
    if (type !== 'qdrant') {
      throw new ValidationError(
        `Cannot set default type to unsupported database: ${type}. Only 'qdrant' is supported.`
      );
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
      config.maxConnections?.toString() || '10',
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
      // API key will be resolved by the adapter from key vault or environment
      logQueries: process.env.NODE_ENV === 'development',
      connectionTimeout: parseInt(process.env.DB_CONNECTION_TIMEOUT || '30000'),
      maxConnections: parseInt(process.env.DB_MAX_CONNECTIONS || '10'),
      vectorSize: parseInt(process.env.VECTOR_SIZE || '1536'),
      distance: (process.env.VECTOR_DISTANCE as any) || 'Cosine',
      collectionName: process.env.QDRANT_COLLECTION_NAME || 'cortex-memory',
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

export async function createQdrantDatabase(
  additionalConfig?: Partial<DatabaseConfig>
): Promise<IDatabase> {
  const factory = DatabaseFactory.getInstance();
  return await factory.getByType('qdrant', additionalConfig);
}

/**
 * Export singleton instance for convenience
 */
export const databaseFactory = DatabaseFactory.getInstance();
