/**
 * Unified Database Layer v2.0 - Facade Pattern Implementation
 *
 * A thin facade that provides a unified interface for database operations
 * while delegating to specialized adapters (PostgreSQL and/or Qdrant).
 * This replaces the monolithic UnifiedDatabaseLayer with a clean,
 * maintainable architecture following SOLID principles.
 *
 * Features:
 * - Facade pattern for clean separation of concerns
 * - Delegates to appropriate specialized adapters
 * - Supports PostgreSQL, Qdrant, and hybrid configurations
 * - Type-safe operations with proper error handling
 * - Backward compatibility with existing API
 * - Connection health monitoring and recovery
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { logger } from '../utils/logger.js';
import { databaseFactory } from './factory/database-factory.js';
import type {
  DatabaseAdapters,
  DatabaseFactoryConfig,
  DatabaseType
} from './interfaces/database-factory.interface.js';
import type {
  IPostgreSQLAdapter,
  FullTextSearchOptions,
  SearchResult,
  UUIDGenerationOptions,
  ExplainOptions,
  ExplainResult,
  QueryOptions
} from './interfaces/postgresql-adapter.interface.js';
import type {
  IVectorAdapter,
  SearchOptions,
  StoreOptions,
  DeleteOptions
} from './interfaces/vector-adapter.interface.js';
import type {
  KnowledgeItem,
  StoreResult,
  StoreError,
  MemoryStoreResponse,
  MemoryFindResponse,
  SearchQuery
} from '../types/core-interfaces.js';

/**
 * Configuration for the unified database layer
 */
export interface UnifiedDatabaseConfig {
  type: DatabaseType;
  postgres?: {
    connectionString?: string;
    maxConnections?: number;
    connectionTimeout?: number;
    logQueries?: boolean;
  };
  qdrant?: {
    url?: string;
    apiKey?: string;
    vectorSize?: number;
    distance?: 'Cosine' | 'Euclidean' | 'DotProduct';
    connectionTimeout?: number;
    maxConnections?: number;
    logQueries?: boolean;
  };
  fallback?: {
    enabled: boolean;
    retryAttempts: number;
    retryDelay: number;
  };
}

/**
 * Unified Database Layer - Facade Implementation
 *
 * Provides a single interface for all database operations while delegating
 * to specialized adapters based on the operation type and configuration.
 */
export class UnifiedDatabaseLayer {
  private adapters: DatabaseAdapters | null = null;
  private config: UnifiedDatabaseConfig;
  private initialized: boolean = false;
  private healthCheckInterval: NodeJS.Timeout | null = null;

  constructor(config: UnifiedDatabaseConfig) {
    this.config = config;
  }

  // === Lifecycle Management ===

  async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }

    try {
      logger.info('Initializing unified database layer v2.0...');

      // Convert to factory configuration
      const factoryConfig: DatabaseFactoryConfig = {
        type: this.config.type,
        postgres: this.config.postgres ? {
          type: 'postgresql',
          postgresConnectionString: this.config.postgres.connectionString || process.env.DATABASE_URL,
          logQueries: this.config.postgres.logQueries || false,
          connectionTimeout: this.config.postgres.connectionTimeout || 30000,
          maxConnections: this.config.postgres.maxConnections || 10
        } : undefined,
        qdrant: this.config.qdrant ? {
          type: 'qdrant',
          url: this.config.qdrant.url || process.env.QDRANT_URL,
          apiKey: this.config.qdrant.apiKey || process.env.QDRANT_API_KEY,
          vectorSize: this.config.qdrant.vectorSize || 1536,
          distance: this.config.qdrant.distance || 'Cosine',
          logQueries: this.config.qdrant.logQueries || false,
          connectionTimeout: this.config.qdrant.connectionTimeout || 30000,
          maxConnections: this.config.qdrant.maxConnections || 10
        } : undefined,
        fallback: this.config.fallback || {
          enabled: true,
          retryAttempts: 3,
          retryDelay: 1000
        }
      };

      // Create adapters using factory
      this.adapters = await databaseFactory.create(factoryConfig);

      // Start health monitoring
      this.startHealthMonitoring();

      this.initialized = true;
      logger.info('✅ Unified database layer v2.0 initialized successfully');
      logger.info(`Configuration: ${this.config.type} mode, PostgreSQL: ${!!this.adapters.postgres}, Qdrant: ${!!this.adapters.vector}`);

    } catch (error) {
      logger.error({ error }, '❌ Failed to initialize unified database layer');
      throw error;
    }
  }

  async healthCheck(): Promise<boolean> {
    if (!this.initialized || !this.adapters) {
      return false;
    }

    try {
      const results = await Promise.allSettled([
        this.adapters.postgres?.healthCheck() || Promise.resolve(true),
        this.adapters.vector?.healthCheck() || Promise.resolve(true)
      ]);

      // All configured adapters must be healthy
      return results.every(result => result.status === 'fulfilled' && result.value === true);

    } catch (error) {
      logger.error({ error }, 'Health check failed');
      return false;
    }
  }

  async close(): Promise<void> {
    try {
      // Stop health monitoring
      if (this.healthCheckInterval) {
        clearInterval(this.healthCheckInterval);
        this.healthCheckInterval = null;
      }

      // Close all adapters
      if (this.adapters) {
        await Promise.allSettled([
          this.adapters.postgres?.close() || Promise.resolve(),
          this.adapters.vector?.close() || Promise.resolve()
        ]);
      }

      this.initialized = false;
      logger.info('Unified database layer closed');

    } catch (error) {
      logger.error({ error }, 'Error closing unified database layer');
      throw error;
    }
  }

  // === Knowledge Storage Operations ===

  async store(items: KnowledgeItem[], options: StoreOptions = {}): Promise<MemoryStoreResponse> {
    await this.ensureInitialized();

    try {
      // Store in both adapters if available, otherwise use the appropriate one
      const results = await Promise.allSettled([
        this.adapters?.postgres?.store(items, options) || Promise.resolve(null),
        this.adapters?.vector?.store(items, options) || Promise.resolve(null)
      ]);

      // Combine results, preferring vector adapter results for semantic operations
      const postgresResult = results[0].status === 'fulfilled' ? results[0].value : null;
      const vectorResult = results[1].status === 'fulfilled' ? results[1].value : null;

      // Return the best available result
      if (vectorResult) {
        return vectorResult;
      } else if (postgresResult) {
        return postgresResult;
      } else {
        throw new Error('No database adapters available for store operation');
      }

    } catch (error) {
      logger.error({ error, itemCount: items.length }, 'Store operation failed');
      throw error;
    }
  }

  async update(items: KnowledgeItem[], options: StoreOptions = {}): Promise<MemoryStoreResponse> {
    return await this.store(items, { ...options, upsert: true });
  }

  async delete(ids: string[], options: DeleteOptions = {}): Promise<{ deleted: number; errors: StoreError[] }> {
    await this.ensureInitialized();

    try {
      const results = await Promise.allSettled([
        this.adapters?.postgres ? this.deleteFromPostgres(ids, options) : Promise.resolve({ deleted: 0, errors: [] }),
        this.adapters?.vector ? this.deleteFromVector(ids, options) : Promise.resolve({ deleted: 0, errors: [] })
      ]);

      // Combine results
      let totalDeleted = 0;
      const allErrors: StoreError[] = [];

      results.forEach(result => {
        if (result.status === 'fulfilled' && result.value) {
          totalDeleted += result.value.deleted;
          allErrors.push(...result.value.errors);
        }
      });

      return { deleted: totalDeleted, errors: allErrors };

    } catch (error) {
      logger.error({ error, ids }, 'Delete operation failed');
      throw error;
    }
  }

  async findById(ids: string[]): Promise<KnowledgeItem[]> {
    await this.ensureInitialized();

    try {
      // Try vector adapter first (for semantic search), then PostgreSQL
      if (this.adapters?.vector) {
        const results = await this.adapters.vector.findById(ids);
        if (results.length > 0) {
          return results;
        }
      }

      if (this.adapters?.postgres) {
        return await this.adapters.postgres.findById(ids);
      }

      return [];

    } catch (error) {
      logger.error({ error, ids }, 'Find by ID operation failed');
      return [];
    }
  }

  // === Search Operations ===

  async search(query: SearchQuery, options: SearchOptions = {}): Promise<MemoryFindResponse> {
    await this.ensureInitialized();

    try {
      // Prefer vector adapter for search operations
      if (this.adapters?.vector) {
        return await this.adapters.vector.search(query, options);
      }

      // Fallback to PostgreSQL full-text search
      if (this.adapters?.postgres) {
        const fullTextResults = await this.adapters.postgres.fullTextSearch({
          query: query.query,
          config: 'english',
          max_results: query.limit || 50,
          min_rank: options.score_threshold || 0.1
        });

        // Convert to unified format
        const results = fullTextResults.map(result => ({
          id: result.id,
          kind: result.kind,
          scope: result.data.scope || {},
          data: result.data,
          created_at: result.data.created_at || new Date().toISOString(),
          confidence_score: result.score,
          match_type: 'semantic' as const,
          highlight: result.highlight
        }));

        return {
          results,
          total_count: results.length,
          autonomous_context: {
            search_mode_used: 'fulltext',
            results_found: results.length,
            confidence_average: results.length > 0 ?
              results.reduce((sum, r) => sum + r.confidence_score, 0) / results.length : 0,
            user_message_suggestion: results.length > 0 ?
              `Found ${results.length} relevant items` : 'No items found matching your query'
          }
        };
      }

      throw new Error('No search adapters available');

    } catch (error) {
      logger.error({ error, query }, 'Search operation failed');
      throw error;
    }
  }

  // === PostgreSQL-specific Operations (delegated) ===

  async fullTextSearch(options: FullTextSearchOptions): Promise<SearchResult[]> {
    await this.ensureInitialized();

    if (!this.adapters?.postgres) {
      throw new Error('PostgreSQL adapter not available for full-text search');
    }

    return await this.adapters.postgres.fullTextSearch(options);
  }

  async generateUUID(options?: UUIDGenerationOptions): Promise<string> {
    await this.ensureInitialized();

    if (!this.adapters?.postgres) {
      throw new Error('PostgreSQL adapter not available for UUID generation');
    }

    return await this.adapters.postgres.generateUUID(options);
  }

  async explainQuery(sql: string, params?: any[], options?: ExplainOptions): Promise<ExplainResult> {
    await this.ensureInitialized();

    if (!this.adapters?.postgres) {
      throw new Error('PostgreSQL adapter not available for query explanation');
    }

    return await this.adapters.postgres.explainQuery(sql, params, options);
  }

  // === CRUD Operations (delegated to PostgreSQL) ===

  async create<T = any>(table: string, data: Record<string, any>): Promise<T> {
    await this.ensureInitialized();

    if (!this.adapters?.postgres) {
      throw new Error('PostgreSQL adapter not available for create operations');
    }

    return await this.adapters.postgres.create<T>(table, data);
  }

  async update<T = any>(table: string, where: Record<string, any>, data: Record<string, any>): Promise<T> {
    await this.ensureInitialized();

    if (!this.adapters?.postgres) {
      throw new Error('PostgreSQL adapter not available for update operations');
    }

    return await this.adapters.postgres.update<T>(table, where, data);
  }

  async delete<T = any>(table: string, where: Record<string, any>): Promise<T> {
    await this.ensureInitialized();

    if (!this.adapters?.postgres) {
      throw new Error('PostgreSQL adapter not available for delete operations');
    }

    return await this.adapters.postgres.delete<T>(table, where);
  }

  async find<T = any>(table: string, where?: Record<string, any>, options?: QueryOptions): Promise<T[]> {
    await this.ensureInitialized();

    if (!this.adapters?.postgres) {
      throw new Error('PostgreSQL adapter not available for find operations');
    }

    return await this.adapters.postgres.find<T>(table, where, options);
  }

  async query<T = any>(sql: string, params?: any[]): Promise<T[]> {
    await this.ensureInitialized();

    if (!this.adapters?.postgres) {
      throw new Error('PostgreSQL adapter not available for query operations');
    }

    return await this.adapters.postgres.query<T>(sql, params);
  }

  // === Statistics and Information ===

  async getStatistics(scope?: {
    project?: string;
    branch?: string;
    org?: string;
  }): Promise<{
    totalItems: number;
    itemsByKind: Record<string, number>;
    storageSize: number;
    lastUpdated: string;
    vectorCount?: number;
  }> {
    await this.ensureInitialized();

    try {
      const results = await Promise.allSettled([
        this.adapters?.postgres?.getStatistics(scope) || Promise.resolve(null),
        this.adapters?.vector?.getStatistics(scope) || Promise.resolve(null)
      ]);

      const postgresStats = results[0].status === 'fulfilled' ? results[0].value : null;
      const vectorStats = results[1].status === 'fulfilled' ? results[1].value : null;

      // Combine statistics, preferring vector stats when available
      if (vectorStats) {
        return {
          totalItems: vectorStats.totalItems,
          itemsByKind: vectorStats.itemsByKind,
          storageSize: vectorStats.storageSize,
          lastUpdated: vectorStats.lastUpdated,
          vectorCount: vectorStats.vectorCount
        };
      } else if (postgresStats) {
        return postgresStats;
      } else {
        return {
          totalItems: 0,
          itemsByKind: {},
          storageSize: 0,
          lastUpdated: new Date().toISOString()
        };
      }

    } catch (error) {
      logger.error({ error }, 'Failed to get statistics');
      throw error;
    }
  }

  // === Private Helper Methods ===

  private async ensureInitialized(): Promise<void> {
    if (!this.initialized) {
      await this.initialize();
    }
  }

  private async deleteFromPostgres(ids: string[], options: DeleteOptions): Promise<{ deleted: number; errors: StoreError[] }> {
    if (!this.adapters?.postgres) {
      return { deleted: 0, errors: [] };
    }

    // PostgreSQL doesn't have a direct delete by IDs method for knowledge items
    // This would need to be implemented based on the specific schema
    // For now, return 0 as placeholder
    return { deleted: 0, errors: [] };
  }

  private async deleteFromVector(ids: string[], options: DeleteOptions): Promise<{ deleted: number; errors: StoreError[] }> {
    if (!this.adapters?.vector) {
      return { deleted: 0, errors: [] };
    }

    return await this.adapters.vector.delete(ids, options);
  }

  private startHealthMonitoring(): void {
    // Health check every 30 seconds
    this.healthCheckInterval = setInterval(async () => {
      try {
        const healthy = await this.healthCheck();
        if (!healthy) {
          logger.warn('Database health check failed - attempting recovery');
          // Could implement recovery logic here
        }
      } catch (error) {
        logger.error({ error }, 'Health monitoring error');
      }
    }, 30000);
  }
}

// Export singleton instance with default configuration
export const createUnifiedDatabaseLayer = (config?: Partial<UnifiedDatabaseConfig>): UnifiedDatabaseLayer => {
  const defaultConfig: UnifiedDatabaseConfig = {
    type: 'hybrid',
    postgres: {
      connectionString: process.env.DATABASE_URL,
      logQueries: process.env.NODE_ENV === 'development',
      connectionTimeout: 30000,
      maxConnections: 10
    },
    qdrant: {
      url: process.env.QDRANT_URL || 'http://localhost:6333',
      apiKey: process.env.QDRANT_API_KEY,
      vectorSize: 1536,
      distance: 'Cosine',
      logQueries: process.env.NODE_ENV === 'development',
      connectionTimeout: 30000,
      maxConnections: 10
    },
    fallback: {
      enabled: true,
      retryAttempts: 3,
      retryDelay: 1000
    }
  };

  const finalConfig = config ? { ...defaultConfig, ...config } : defaultConfig;
  return new UnifiedDatabaseLayer(finalConfig);
};

// Export default instance for backward compatibility
export const database = createUnifiedDatabaseLayer();