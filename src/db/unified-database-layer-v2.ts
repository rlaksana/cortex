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
 * - Key vault integration for secure API key management
 * - Automatic schema management
 * - Type-safe operations with proper error handling
 * - Connection health monitoring and recovery
 * - Optimized for vector embeddings and similarity search
 *
 * @author Cortex Team
 * @version 2.0.0-Qdrant
 * @since 2025
 */

import { QdrantAdapter } from './adapters/qdrant-adapter.js';
import type {
  DeleteOptions,
  IVectorAdapter,
  SearchOptions,
  StoreOptions,
  VectorConfig,
} from './interfaces/vector-adapter.interface.js';
import type {
  KnowledgeItem,
  // MemoryStoreResponse,
  MemoryFindResponse,
  SearchQuery,
  StoreError,
  StoreResult,
} from '../types/core-interfaces.js';
import { unwrapDatabaseResult } from '../utils/database-result-unwrapper.js';
import { logger } from '../utils/logger.js';
import { createFindObservability } from '../utils/observability-helper.js';
import { asPointIdArray } from '../utils/type-conversion.js';

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
  public adapter: IVectorAdapter;
  public config: QdrantDatabaseConfig;
  public isHealthy: boolean = false;

  constructor(config: QdrantDatabaseConfig) {
    this.config = config;

    // Parse URL to get host and port for VectorConfig compatibility
    const url = new URL(config.qdrant.url);

    const qdrantConfig: VectorConfig = {
      // Required DatabaseConfig properties
      type: 'qdrant',
      host: url.hostname,
      port: parseInt(url.port) || 6333,
      database: 'cortex', // Default database name

      // VectorConfig properties
      url: config.qdrant.url,
      collectionName: config.qdrant.collectionName,
      maxRetries: config.qdrant.maxRetries || 3,
      timeout: config.qdrant.timeout,
      vectorSize: 1536, // Default embedding size
      maxConnections: 10, // Default connection pool size

      // Required VectorConfig properties
      size: 1536,
      embeddingModel: 'text-embedding-3-small',
      batchSize: 10,

      // Include API key if present
      ...(config.qdrant.apiKey && { apiKey: config.qdrant.apiKey }),
    };

    this.adapter = new QdrantAdapter(qdrantConfig);

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
      const storeResult = await this.adapter.store(items, options);
      const unwrappedResult = unwrapDatabaseResult(storeResult, {
        operation: 'store',
        itemCount: items.length,
      });
      logger.debug(`Stored ${items.length} items in Qdrant`);

      // Convert MemoryStoreResponse to StoreResult
      return {
        id: `batch_${Date.now()}`,
        status: 'inserted',
        kind: 'batch_store',
        created_at: new Date().toISOString(),
        // count: items.length, // Removed - not in StoreResult
        // items: items.map(item => item.id) // Removed - not in StoreResult
      };
    } catch (error) {
      logger.error('Failed to store items in Qdrant', error);
      throw error;
    }
  }

  /**
   * Find items by IDs
   */
  async findById(ids: string[]): Promise<MemoryFindResponse> {
    const startTime = Date.now();
    if (!this.isHealthy) {
      await this.initialize();
    }

    try {
      const itemsResult = await this.adapter.findById(asPointIdArray(ids));
      const items = unwrapDatabaseResult(itemsResult, { operation: 'findById' });

      // Convert KnowledgeItem[] to MemoryFindResponse with proper SearchResult structure
      const searchResults = items.map((item) => ({
        id: item.id || `unknown_${Date.now()}`,
        kind: item.kind,
        scope: item.scope,
        data: item.data,
        created_at: item.created_at || new Date().toISOString(),
        confidence_score: 1.0,
        match_type: 'exact' as const,
      }));

      return {
        results: searchResults,
        items: searchResults, // Add items property for compatibility
        total_count: items.length,
        total: items.length, // Add total property for compatibility
        autonomous_context: {
          search_mode_used: 'by_ids',
          results_found: items.length,
          confidence_average: 1.0,
          user_message_suggestion: `Found ${items.length} items`,
        },
        observability: createFindObservability('fast', true, false, Date.now() - startTime, 1.0),
        meta: {
          strategy: 'fast',
          vector_used: false,
          degraded: false,
          source: 'cortex_memory',
          execution_time_ms: Date.now() - startTime,
          confidence_score: 1.0,
          truncated: false,
          warnings: [],
        },
      };
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
      const searchResult = await this.adapter.search(query, options);
      const result = unwrapDatabaseResult(searchResult, { operation: 'search', query });
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
      const deleteResult = await this.adapter.delete(asPointIdArray(ids), options);
      const unwrappedResult = unwrapDatabaseResult(deleteResult, { operation: 'delete', ids });
      logger.debug(`Deleted ${unwrappedResult.deletedCount} items from Qdrant`);
      return { deleted: unwrappedResult.deletedCount, errors: [...unwrappedResult.errors] };
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
  async getStatistics(scope?: unknown): Promise<unknown> {
    if (!this.isHealthy) {
      await this.initialize();
    }

    try {
      const statsResult = await this.adapter.getStatistics(scope);
      return unwrapDatabaseResult(statsResult, { operation: 'getStatistics', scope });
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

  /**
   * Bulk delete items based on filter criteria
   */
  async bulkDelete(filter: {
    kind?: string;
    scope?: unknown;
    before?: string;
  }): Promise<{ deleted: number }> {
    if (!this.isHealthy) {
      await this.initialize();
    }

    try {
      const bulkDeleteResult = await this.adapter.bulkDelete(filter);
      const unwrappedResult = unwrapDatabaseResult(bulkDeleteResult, {
        operation: 'bulkDelete',
        filter,
      });
      return { deleted: unwrappedResult.deletedCount };
    } catch (error) {
      logger.error('Failed to bulk delete items', error);
      throw error;
    }
  }

  // === Compatibility Methods for Audit System ===

  /**
   * Create a record in the specified collection (compatibility method)
   */
  async create(collection: string, data: Record<string, unknown>): Promise<unknown> {
    if (!this.isHealthy) {
      await this.initialize();
    }

    try {
      // For audit events, store them as knowledge items
      const knowledgeItem: KnowledgeItem = {
        id: (data.id as string) || (await this.generateUUID()),
        kind: collection === 'event_audit' ? 'observation' : 'entity',
        content: JSON.stringify(data),
        data, // Add required data property
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

      await this.store([knowledgeItem]);
      return { id: knowledgeItem.id, ...data };
    } catch (error) {
      logger.error(`Failed to create record in ${collection}`, error);
      throw error;
    }
  }

  /**
   * Find records in a collection (compatibility method)
   */
  async find(collection: string, filter?: Record<string, unknown>, options?: Record<string, unknown>): Promise<unknown[]> {
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
        limit: (options?.take as number) || 100,
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
   * P6-T6.1: Find expired knowledge items
   * Efficiently finds items that have expired based on expiry_at timestamp
   */
  async findExpiredItems(options: {
    expiry_before?: string;
    limit?: number;
    scope?: unknown;
    kinds?: string[];
  }): Promise<KnowledgeItem[]> {
    if (!this.isHealthy) {
      await this.initialize();
    }

    try {
      logger.debug('Finding expired items using vector adapter', { options });

      // Delegate to the adapter's efficient findExpiredItems method
      const result = await this.adapter.findExpiredItems(options);
      const unwrappedResult = unwrapDatabaseResult(result, { operation: 'findExpired', options });
      // Check if the result is already an array or has items property
      return Array.isArray(unwrappedResult) ? unwrappedResult : (unwrappedResult as any).items || [];
    } catch (error) {
      logger.error('Failed to find expired items', error);
      throw error;
    }
  }

  /**
   * Execute raw query (compatibility method for audit system)
   */
  async query(sql: string, _params?: unknown[]): Promise<{ rows: unknown[] }> {
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
  constructor(config?: QdrantDatabaseConfig) {
    if (!config) {
      // Provide default config for backward compatibility with tests
      config = {
        type: 'qdrant' as const,
        qdrant: {
          url: process.env.QDRANT_URL || 'http://localhost:6333',
          apiKey: undefined, // Will be resolved by the adapter from key vault
          collectionName: 'knowledge',
          timeout: 30000,
          batchSize: 100,
          maxRetries: 3,
        },
      };
    }
    super(config);
  }

  // Add fullTextSearch method for compatibility with entity service
  async fullTextSearch(
    _collection: string,
    _options: {
      query: string;
      config?: string;
      weighting?: Record<string, number>;
      highlight?: boolean;
      snippet_size?: number;
      max_results?: number;
    }
  ): Promise<unknown[]> {
    // For now, return empty results - this would need proper implementation
    return [];
  }

  // Add bulkDelete method for auto-purge service compatibility
  override async bulkDelete(filter: {
    kind?: string;
    scope?: unknown;
    before?: string;
  }): Promise<{ deleted: number }> {
    if (!this.isHealthy) {
      await this.initialize();
    }

    try {
      const bulkDeleteResult = await this.adapter.bulkDelete(filter);
      const unwrappedResult = unwrapDatabaseResult(bulkDeleteResult, {
        operation: 'bulkDelete',
        filter,
      });
      return { deleted: unwrappedResult.deletedCount };
    } catch (error) {
      logger.error('Failed to bulk delete items', error);
      throw error;
    }
  }
}
