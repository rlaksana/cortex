/**
 * Qdrant-Only Database Layer v2.0 - Vector-First Architecture
 *
 * A clean, Qdrant-specific database layer for the Cortex Memory MCP server.
 * This implementation follows the Qdrant-only architecture with zero PostgreSQL
 * dependencies, providing optimized vector storage and retrieval operations.
 *
 * Features:
 * - Pure Qdrant vector database operations
 * - High-performance semantic search
 * - Automatic schema management
 * - Type-safe operations with proper error handling
 * - Connection health monitoring and recovery
 * - Optimized for vector embeddings and similarity search
 *
 * @author Cortex Team
 * @version 2.0.0-Qdrant
 * @since 2025
 */

import { logger } from '../utils/logger.js';
import { QdrantAdapter } from './adapters/qdrant-adapter.js';
import type {
  IVectorAdapter,
  SearchOptions,
  StoreOptions,
  DeleteOptions,
} from './interfaces/vector-adapter.interface.js';
import type {
  KnowledgeItem,
  StoreResult,
  StoreError,
  MemoryStoreResponse,
  MemoryFindResponse,
  SearchQuery,
} from '../types/core-interfaces';

/**
 * Configuration for the Qdrant-only database layer
 */
export interface QdrantDatabaseConfig {
  type: 'qdrant';
  qdrant: {
    url: string;
    apiKey?: string;
    collectionName: string;
    timeout: number;
    batchSize?: number;
    maxRetries?: number;
  };
}

/**
 * Qdrant-Only Database Layer Implementation
 *
 * Provides a clean interface for Qdrant vector operations without any
 * PostgreSQL dependencies. Optimized for semantic search and vector operations.
 */
export class QdrantOnlyDatabaseLayer {
  private adapter: IVectorAdapter;
  private config: QdrantDatabaseConfig;
  private isHealthy: boolean = false;

  constructor(config: QdrantDatabaseConfig) {
    this.config = config;
    this.adapter = new QdrantAdapter({
      url: config.qdrant.url,
      apiKey: config.qdrant.apiKey,
      collectionName: config.qdrant.collectionName,
      timeout: config.qdrant.timeout,
      batchSize: config.qdrant.batchSize || 100,
      maxRetries: config.qdrant.maxRetries || 3,
    });

    logger.info(`Qdrant-Only Database Layer initialized: ${config.qdrant.collectionName}`);
  }

  /**
   * Initialize the database connection and verify health
   */
  async initialize(): Promise<void> {
    try {
      await this.adapter.healthCheck();
      this.isHealthy = true;
      logger.info('Qdrant-Only Database Layer: Connection established and healthy');
    } catch (error) {
      this.isHealthy = false;
      logger.error('Qdrant-Only Database Layer: Failed to initialize', error);
      throw error;
    }
  }

  /**
   * Store knowledge items in Qdrant
   */
  async store(items: KnowledgeItem[], options: StoreOptions = {}): Promise<StoreResult> {
    if (!this.isHealthy) {
      await this.initialize();
    }

    try {
      const result = await this.adapter.store(items, options);
      logger.debug(`Stored ${items.length} items in Qdrant`);
      return result;
    } catch (error) {
      logger.error('Failed to store items in Qdrant', error);
      throw error;
    }
  }

  /**
   * Find items by IDs
   */
  async findById(ids: string[]): Promise<MemoryFindResponse> {
    if (!this.isHealthy) {
      await this.initialize();
    }

    try {
      return await this.adapter.findById(ids);
    } catch (error) {
      logger.error('Failed to find items by ID', error);
      throw error;
    }
  }

  /**
   * Semantic search using vector embeddings
   */
  async search(query: SearchQuery, options: SearchOptions = {}): Promise<MemoryFindResponse> {
    if (!this.isHealthy) {
      await this.initialize();
    }

    try {
      const result = await this.adapter.search(query, options);
      logger.debug(`Semantic search returned ${result.items?.length || 0} results`);
      return result;
    } catch (error) {
      logger.error('Semantic search failed', error);
      throw error;
    }
  }

  /**
   * Delete items by IDs
   */
  async delete(
    ids: string[],
    options: DeleteOptions = {}
  ): Promise<{ deleted: number; errors: StoreError[] }> {
    if (!this.isHealthy) {
      await this.initialize();
    }

    try {
      const result = await this.adapter.delete(ids, options);
      logger.debug(`Deleted ${result.deleted} items from Qdrant`);
      return result;
    } catch (error) {
      logger.error('Failed to delete items', error);
      throw error;
    }
  }

  /**
   * Generate unique IDs for new items
   */
  async generateUUID(options: { prefix?: string } = {}): Promise<string> {
    const prefix = options.prefix || 'cortex';
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(2, 8);
    return `${prefix}_${timestamp}_${random}`;
  }

  /**
   * Health check for the database connection
   */
  async healthCheck(): Promise<boolean> {
    try {
      const isHealthy = await this.adapter.healthCheck();
      this.isHealthy = isHealthy;
      return isHealthy;
    } catch (error) {
      this.isHealthy = false;
      logger.warn('Health check failed', error);
      return false;
    }
  }

  /**
   * Get database statistics
   */
  async getStatistics(scope?: any): Promise<any> {
    if (!this.isHealthy) {
      await this.initialize();
    }

    try {
      return await this.adapter.getStatistics(scope);
    } catch (error) {
      logger.error('Failed to get statistics', error);
      throw error;
    }
  }

  /**
   * Close the database connection
   */
  async close(): Promise<void> {
    try {
      await this.adapter.close();
      this.isHealthy = false;
      logger.info('Qdrant-Only Database Layer: Connection closed');
    } catch (error) {
      logger.error('Failed to close database connection', error);
      throw error;
    }
  }

  /**
   * Get current configuration
   */
  getConfig(): QdrantDatabaseConfig {
    return { ...this.config };
  }

  /**
   * Check if the database is healthy
   */
  isConnectionHealthy(): boolean {
    return this.isHealthy;
  }

  // === Compatibility Methods for Audit System ===

  /**
   * Create a record in the specified collection (compatibility method)
   */
  async create(collection: string, data: any): Promise<any> {
    if (!this.isHealthy) {
      await this.initialize();
    }

    try {
      // For audit events, store them as knowledge items
      const knowledgeItem: KnowledgeItem = {
        id: data.id || (await this.generateUUID()),
        kind: collection === 'event_audit' ? 'observation' : 'entity',
        content: JSON.stringify(data),
        metadata: {
          collection,
          ...data,
          timestamp: new Date().toISOString(),
        },
        scope: {
          project: 'cortex-audit',
          branch: 'main',
        },
      };

      const result = await this.store([knowledgeItem]);
      return { id: knowledgeItem.id, ...data };
    } catch (error) {
      logger.error(`Failed to create record in ${collection}`, error);
      throw error;
    }
  }

  /**
   * Find records in a collection (compatibility method)
   */
  async find(collection: string, filter?: any, options?: any): Promise<any[]> {
    if (!this.isHealthy) {
      await this.initialize();
    }

    try {
      // Build search query from filter
      const searchQuery: SearchQuery = {
        query: filter ? JSON.stringify(filter) : '',
        kind: collection === 'event_audit' ? 'observation' : 'entity',
      };

      const searchOptions: SearchOptions = {
        limit: options?.take || 100,
        score_threshold: 0.1,
      };

      const result = await this.search(searchQuery, searchOptions);

      // Transform results back to expected format
      return (result.results || result.items || []).map((item: any) => {
        const metadata = item.metadata || {};
        return {
          id: item.id,
          ...metadata,
          // Map nested fields for audit compatibility
          event_type: metadata.event_type,
          table_name: metadata.table_name,
          record_id: metadata.record_id,
          operation: metadata.operation,
          old_data: metadata.old_data,
          new_data: metadata.new_data,
          changed_by: metadata.changed_by,
          tags: metadata.tags,
          metadata: metadata.metadata,
          changed_at: metadata.changed_at || item.timestamp,
        };
      });
    } catch (error) {
      logger.error(`Failed to find records in ${collection}`, error);
      throw error;
    }
  }

  /**
   * Execute raw query (compatibility method for audit system)
   */
  async query(sql: string, params?: any[]): Promise<{ rows: any[] }> {
    if (!this.isHealthy) {
      await this.initialize();
    }

    try {
      // Handle basic count queries
      if (sql.includes('COUNT(*)')) {
        if (sql.includes('event_audit')) {
          // For audit count, we'll use search to get approximate count
          const searchQuery: SearchQuery = {
            query: '',
            kind: 'observation',
          };

          const result = await this.search(searchQuery, { limit: 10000 });
          const count = (result.results || result.items || []).length;

          return { rows: [{ count: count.toString() }] };
        }
      }

      // Handle UUID generation
      if (sql.includes('gen_random_uuid()')) {
        return { rows: [{ uuid: await this.generateUUID() }] };
      }

      // For other queries, return empty result
      logger.warn(`Unsupported query type in Qdrant-only mode: ${sql}`);
      return { rows: [] };
    } catch (error) {
      logger.error(`Failed to execute query: ${sql}`, error);
      throw error;
    }
  }
}

/**
 * Factory function to create a Qdrant-only database layer
 */
export function createQdrantOnlyDatabase(config: QdrantDatabaseConfig): QdrantOnlyDatabaseLayer {
  if (config.type !== 'qdrant') {
    throw new Error('Only Qdrant database type is supported. PostgreSQL has been removed.');
  }

  return new QdrantOnlyDatabaseLayer(config);
}

// Create a wrapper class that matches the expected interface for tests
export class UnifiedDatabaseLayer extends QdrantOnlyDatabaseLayer {
  constructor(config?: any) {
    if (!config) {
      // Provide default config for backward compatibility with tests
      config = {
        type: 'qdrant' as const,
        qdrant: {
          url: process.env.QDRANT_URL || 'http://localhost:6333',
          apiKey: process.env.QDRANT_API_KEY,
          collectionName: 'knowledge',
          timeout: 30000,
          batchSize: 100,
          maxRetries: 3,
        }
      };
    }
    super(config);
  }

  // Add fullTextSearch method for compatibility with entity service
  async fullTextSearch(collection: string, options: {
    query: string;
    config?: string;
    weighting?: Record<string, number>;
    highlight?: boolean;
    snippet_size?: number;
    max_results?: number;
  }): Promise<any[]> {
    // For now, return empty results - this would need proper implementation
    return [];
  }
}
