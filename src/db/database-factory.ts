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
 * @version 2.1.0
 * @since 2025
 */

import * as crypto from 'crypto';

import { QdrantAdapter } from './adapters/qdrant-adapter.js';
import type { DatabaseMetrics, IDatabase } from './database-interface.js';
import type { IVectorAdapter, VectorConfig } from './interfaces/vector-adapter.interface.js';
import { getKeyVaultService } from '../services/security/key-vault-service.js';
import { isSuccessfulResult } from '../types/database-generics.js';
import {
  convertArrayResponse,
  convertDeleteResponse,
  convertMemoryStoreResponse,
  convertSearchResponse,
  DatabaseResultUnwrapError,
  unwrapDatabaseResult,
} from '../utils/database-result-unwrapper.js';
import { ValidationError } from '../utils/error-handler.js';
import { logger } from '../utils/logger.js';
import { createFindObservability } from '../utils/observability-helper.js';

type SupportedDistanceMetric = 'Cosine' | 'Euclid' | 'Dot' | 'Manhattan';
type SupportedDatabaseType = 'qdrant' | 'hybrid';

/**
 * Unified Database Config for Qdrant Factory
 * Combines the interface requirements with VectorConfig compatibility
 */
interface UnifiedDatabaseConfig {
  // DatabaseInterface requirements
  type: SupportedDatabaseType;
  url?: string;
  apiKey?: string;
  logQueries?: boolean;
  connectionTimeout?: number;
  maxConnections?: number;
  vectorSize?: number;
  distance?: SupportedDistanceMetric;
  distanceMetric?: SupportedDistanceMetric;
  collectionName?: string;

  size?: number;
  embeddingModel?: string;
  batchSize?: number;
  openaiApiKey?: string;
  maxRetries?: number;
  timeout?: number;

  // Additional properties for VectorConfig compatibility
  host?: string;
  port?: number;
  database?: string;
}

interface ConfigurationTestResult {
  type: SupportedDatabaseType;
  connected: boolean;
  healthy: boolean;
  latency?: number;
  error?: string;
}

interface RecommendationUseCase {
  requiresVectors?: boolean;
  requiresFullTextSearch?: boolean;
  requiresHighPerformance?: boolean;
  prefersOpenSource?: boolean;
  vectorSize?: number;
}

interface ConfigurationRecommendation {
  recommended: SupportedDatabaseType;
  reason: string;
  configuration: Partial<UnifiedDatabaseConfig>;
  alternatives: string[];
}

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
  ItemResult,
  KnowledgeItem,
  MemoryFindResponse,
  MemoryStoreResponse,
  SearchQuery,
  SearchResult,
  StoreError,
} from '../types/core-interfaces.js';
import type { KnowledgeEntity, PointId, QueryFilter } from '../types/database-generics.js';

/**
 * Type guard utilities for safe object transformation
 */

/**
 * Check if an object is a valid KnowledgeItem
 */
function isKnowledgeItem(obj: unknown): obj is KnowledgeItem {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const item = obj as Record<string, unknown>;
  return (
    typeof item.kind === 'string' &&
    typeof item.scope === 'object' &&
    item.scope !== null &&
    typeof item.data === 'object' &&
    item.data !== null
  );
}

/**
 * Check if an object is a valid KnowledgeEntity
 */
function isKnowledgeEntity(obj: unknown): obj is KnowledgeEntity {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const entity = obj as Record<string, unknown>;
  return (
    typeof entity.id === 'string' &&
    typeof entity.kind === 'string' &&
    typeof entity.createdAt === 'string' &&
    typeof entity.updatedAt === 'string' &&
    typeof entity.scope === 'object' &&
    entity.scope !== null &&
    typeof entity.data === 'object' &&
    entity.data !== null
  );
}

/**
 * Convert KnowledgeItem to KnowledgeEntity with proper type safety
 */
function knowledgeItemToEntity(item: KnowledgeItem): KnowledgeEntity {
  const now = new Date().toISOString();

  return {
    id: item.id || crypto.randomUUID(),
    kind: item.kind,
    createdAt: item.created_at || now,
    updatedAt: item.updated_at || now,
    scope: {
      project: item.scope?.project,
      branch: item.scope?.branch,
      org: item.scope?.org,
    },
    data: { ...item.data },
    expiryAt: item.expiry_at,
    metadata: item.metadata ? { ...item.metadata } : undefined,
    tags: item.metadata?.tags as readonly string[] | undefined,
  };
}

/**
 * Convert KnowledgeEntity to KnowledgeItem with proper type safety
 */
function knowledgeEntityToItem(entity: KnowledgeEntity): KnowledgeItem {
  return {
    id: entity.id,
    kind: entity.kind,
    content: entity.data.content as string | undefined,
    scope: {
      project: entity.scope.project,
      branch: entity.scope.branch,
      org: entity.scope.org,
    },
    data: { ...entity.data },
    metadata: entity.metadata ? { ...entity.metadata } : undefined,
    created_at: entity.createdAt,
    updated_at: entity.updatedAt,
    expiry_at: entity.expiryAt,
  };
}

/**
 * Convert array of KnowledgeItem to KnowledgeEntity array
 */
function convertKnowledgeItemsToEntities(items: KnowledgeItem[]): KnowledgeEntity[] {
  return items.filter(isKnowledgeItem).map(knowledgeItemToEntity);
}

/**
 * Convert array of KnowledgeEntity to KnowledgeItem array
 */
function convertKnowledgeEntitiesToItems(entities: KnowledgeEntity[]): KnowledgeItem[] {
  return entities.filter(isKnowledgeEntity).map(knowledgeEntityToItem);
}

/**
 * Type guard for QueryFilter compatibility
 */
function isValidQueryFilter(obj: unknown): obj is QueryFilter {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  // Accept any object with filter-like structure for compatibility
  return true; // For now, be permissive to avoid breaking existing code
}

/**
 * Convert string IDs to PointId branded type
 */
function convertToPointIds(ids: string[]): readonly PointId[] {
  return ids.map((id) => id as PointId);
}

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

  async getMetrics(): Promise<DatabaseMetrics> {
    // getMetrics returns DatabaseMetrics directly, not DatabaseResult
    return this.vectorAdapter.getMetrics();
  }

  async close(): Promise<void> {
    return this.vectorAdapter.close();
  }

  async store(items: KnowledgeItem[], options?: unknown): Promise<MemoryStoreResponse> {
    // Convert KnowledgeItem[] to KnowledgeEntity[] for vector adapter compatibility
    const entities = convertKnowledgeItemsToEntities(items);
    const result = await this.vectorAdapter.store(entities, options);
    return convertMemoryStoreResponse(result);
  }

  async update(items: KnowledgeItem[], options?: unknown): Promise<MemoryStoreResponse> {
    // Convert KnowledgeItem[] to KnowledgeEntity[] for vector adapter compatibility
    const entities = convertKnowledgeItemsToEntities(items);
    const result = await this.vectorAdapter.update(entities, options);
    return convertMemoryStoreResponse(result);
  }

  async delete(
    ids: string[],
    options?: unknown
  ): Promise<{ deleted: number; errors: StoreError[] }> {
    const pointIds = convertToPointIds(ids);
    const result = await this.vectorAdapter.delete(pointIds, options);
    return convertDeleteResponse(result);
  }

  async findById(ids: string[]): Promise<KnowledgeItem[]> {
    const pointIds = convertToPointIds(ids);
    const result = await this.vectorAdapter.findById(pointIds);

    // Convert KnowledgeEntity[] to KnowledgeItem[] for interface compatibility
    if (Array.isArray(result)) {
      // If result is already KnowledgeEntity[], convert it
      const entities = result.filter(isKnowledgeEntity);
      return convertKnowledgeEntitiesToItems(entities);
    } else {
      // If result is DatabaseResult<KnowledgeEntity[]>, unwrap and convert
      const unwrapped = unwrapDatabaseResult(result, { operation: 'findById', ids });
      const entities = Array.isArray(unwrapped) ? unwrapped.filter(isKnowledgeEntity) : [];
      return convertKnowledgeEntitiesToItems(entities);
    }
  }

  async search(query: SearchQuery, options?: unknown): Promise<MemoryFindResponse> {
    const result = await this.vectorAdapter.search(query, options);
    return unwrapDatabaseResult(result, { operation: 'search', query });
  }

  async semanticSearch(query: string, options?: unknown): Promise<SearchResult[]> {
    const result = await this.vectorAdapter.semanticSearch(query, options);
    return convertSearchResponse(result);
  }

  async hybridSearch(query: string, options?: unknown): Promise<MemoryFindResponse> {
    const startTime = Date.now();
    // Convert SearchResult[] to MemoryFindResponse
    const searchResults = await this.vectorAdapter.hybridSearch(query, options);

    // Convert DatabaseResult<SearchResult[]> to SearchResult[]
    const results = convertSearchResponse(searchResults);

    // Calculate average confidence from search results
    const confidenceAverage =
      results.length > 0
        ? results.reduce((sum, result) => sum + (result.confidence_score || 0), 0) / results.length
        : 0;

    return {
      results,
      items: results,
      total_count: results.length,
      autonomous_context: {
        search_mode_used: 'hybrid',
        results_found: results.length,
        confidence_average: confidenceAverage,
        user_message_suggestion: `Found ${results.length} results matching your query`,
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
    options?: unknown
  ): Promise<MemoryStoreResponse> {
    // Convert KnowledgeItem[] to KnowledgeEntity[] for vector adapter compatibility
    const entities = convertKnowledgeItemsToEntities(items);
    const result = await this.vectorAdapter.storeByKind(kind, entities, options);
    return convertMemoryStoreResponse(result);
  }

  async searchByKind(
    kinds: string[],
    query: SearchQuery,
    options?: unknown
  ): Promise<MemoryFindResponse> {
    const result = await this.vectorAdapter.searchByKind(kinds, query, options);
    return unwrapDatabaseResult(result, { operation: 'searchByKind', kinds, query });
  }

  async findByScope(scope: unknown, options?: unknown): Promise<KnowledgeItem[]> {
    const result = await this.vectorAdapter.findByScope(scope, options);
    return convertArrayResponse(result);
  }

  async findSimilar(
    item: KnowledgeItem,
    threshold?: number,
    options?: unknown
  ): Promise<SearchResult[]> {
    // Convert KnowledgeItem to KnowledgeEntity for vector adapter compatibility
    const entity = knowledgeItemToEntity(item);
    const result = await this.vectorAdapter.findSimilar(entity, threshold, options);
    return convertSearchResponse(result);
  }

  async checkDuplicates(
    items: KnowledgeItem[]
  ): Promise<{ duplicates: KnowledgeItem[]; originals: KnowledgeItem[] }> {
    // The interface expects KnowledgeItem[] directly, so no conversion needed
    const result = await this.vectorAdapter.checkDuplicates(items);
    const unwrapped = unwrapDatabaseResult(result, { operation: 'checkDuplicates' });

    return {
      duplicates: [...unwrapped.duplicates],
      originals: [...unwrapped.originals],
    };
  }

  async getStatistics(scope?: { project?: string; branch?: string; org?: string }): Promise<{
    totalItems: number;
    itemsByKind: Record<string, number>;
    storageSize: number;
    lastUpdated: string;
    vectorCount: number;
  }> {
    const result = await this.vectorAdapter.getStatistics(scope);
    return unwrapDatabaseResult(result, { operation: 'getStatistics', scope });
  }

  async bulkStore(inputItems: KnowledgeItem[], options?: unknown): Promise<MemoryStoreResponse> {
    // Convert KnowledgeItem[] to KnowledgeEntity[] for vector adapter compatibility
    const entities = convertKnowledgeItemsToEntities(inputItems);
    const result = await this.vectorAdapter.bulkStore(entities, options);
    const unwrapped = unwrapDatabaseResult(result, { operation: 'bulkStore' });
    // Convert BatchResult<KnowledgeItem> to MemoryStoreResponse
    const itemResults: ItemResult[] = [];
    const summary = {
      stored: unwrapped.successCount,
      skipped_dedupe: 0,
      business_rule_blocked: 0,
      validation_error: unwrapped.failureCount || 0,
      total: inputItems.length,
    };

    return {
      items: itemResults,
      summary,
      stored: [], // Legacy compatibility
      errors: unwrapped.errors.map((err: unknown) => ({
        code: 'BULK_STORE_ERROR',
        message:
          err && typeof err === 'object' && 'message' in err
            ? String(err.message)
            : 'Unknown error',
        id: '',
        type: 'bulk_store',
      })),
      autonomous_context: {
        action_performed: 'batch',
        similar_items_checked: 0,
        duplicates_found: 0,
        contradictions_detected: false,
        recommendation: `Bulk stored ${unwrapped.successCount} items`,
        reasoning: 'Bulk operation completed',
        user_message_suggestion: `Successfully stored ${unwrapped.successCount} items`,
      },
      observability: {
        source: 'cortex_memory',
        strategy: 'autonomous_deduplication',
        vector_used: true,
        degraded: false,
        execution_time_ms: 0,
        confidence_score: unwrapped.successCount > 0 ? 1.0 : 0.0,
      },
      meta: {
        strategy: 'bulk_store',
        vector_used: true,
        degraded: false,
        source: 'database_factory',
        execution_time_ms: 0,
        confidence_score: unwrapped.successCount > 0 ? 1.0 : 0.0,
        truncated: false,
      },
    };
  }

  async bulkDelete(filter: unknown, options?: unknown): Promise<{ deleted: number }> {
    // Type guard for QueryFilter compatibility
    if (!isValidQueryFilter(filter)) {
      throw new Error('Invalid filter provided to bulkDelete');
    }

    const result = await this.vectorAdapter.bulkDelete(filter as QueryFilter, options);
    const unwrapped = unwrapDatabaseResult(result, { operation: 'bulkDelete', filter });
    return { deleted: unwrapped.deletedCount };
  }

  async bulkSearch(queries: SearchQuery[], options?: unknown): Promise<MemoryFindResponse[]> {
    const result = await this.vectorAdapter.bulkSearch(queries, options);
    return convertArrayResponse(result);
  }

  async generateEmbedding(content: string): Promise<number[]> {
    const result = await this.vectorAdapter.generateEmbedding(content);
    if (isSuccessfulResult(result)) {
      return Array.isArray(result.data) ? [...result.data] : [];
    } else {
      const errorMessage =
        result.error && typeof result.error === 'object' && 'message' in result.error
          ? String(result.error.message)
          : 'Unknown database error';
      throw new DatabaseResultUnwrapError(
        `Database operation failed: ${errorMessage}`,
        result.error,
        { operation: 'generateEmbedding' }
      );
    }
  }

  async storeWithEmbeddings(items: unknown[], options?: unknown): Promise<MemoryStoreResponse> {
    // Type guard for items with embeddings
    const itemsWithEmbeddings = items.filter((item): item is KnowledgeItem & { embedding: number[] } => {
      if (!item || typeof item !== 'object') {
        return false;
      }
      const record = item as Record<string, unknown>;
      return Array.isArray(record.embedding);
    });

    // Convert KnowledgeItem[] to KnowledgeEntity[] with embeddings for vector adapter compatibility
    const entitiesWithEmbeddings = itemsWithEmbeddings.map((item) => {
      const entity = knowledgeItemToEntity(item);
      return {
        ...entity,
        embedding: item.embedding,
      } as KnowledgeEntity & { readonly embedding: number[] };
    });

    const result = await this.vectorAdapter.storeWithEmbeddings(entitiesWithEmbeddings, options);
    return convertMemoryStoreResponse(result);
  }

  async vectorSearch(embedding: number[], options?: unknown): Promise<SearchResult[]> {
    const result = await this.vectorAdapter.vectorSearch(embedding, options);
    return convertSearchResponse(result);
  }

  async findNearest(
    embedding: number[],
    limit?: number,
    threshold?: number
  ): Promise<SearchResult[]> {
    const result = await this.vectorAdapter.findNearest(embedding, limit, threshold);
    return convertSearchResponse(result);
  }

  async backup(destination?: string): Promise<string> {
    const result = await this.vectorAdapter.backup(destination);
    const unwrapped = unwrapDatabaseResult(result, { operation: 'backup', destination });
    return unwrapped.backupPath || unwrapped.backupId || '';
  }

  async restore(source: string): Promise<void> {
    const result = await this.vectorAdapter.restore(source);
    unwrapDatabaseResult(result, { operation: 'restore', source });
  }

  async optimize(): Promise<void> {
    const result = await this.vectorAdapter.optimize();
    unwrapDatabaseResult(result, { operation: 'optimize' });
  }

  async validate(): Promise<{ valid: boolean; issues: string[] }> {
    const result = await this.vectorAdapter.validate();
    const unwrapped = unwrapDatabaseResult(result, { operation: 'validate' });
    return {
      valid: unwrapped.valid,
      issues: [...unwrapped.issues],
    };
  }

  async updateCollectionSchema(config: unknown): Promise<void> {
    const result = await this.vectorAdapter.updateCollectionSchema(config);
    unwrapDatabaseResult(result, { operation: 'updateCollectionSchema', config });
  }

  async getCollectionInfo(): Promise<Readonly<Record<string, unknown>>> {
    const result = await this.vectorAdapter.getCollectionInfo();
    const unwrapped = unwrapDatabaseResult(result, { operation: 'getCollectionInfo' });

    // Ensure the result is a record-like object
    if (typeof unwrapped === 'object' && unwrapped !== null && !Array.isArray(unwrapped)) {
      return unwrapped as Readonly<Record<string, unknown>>;
    }

    // Return a default record if the result is not object-like
    return { value: unwrapped };
  }
}

/**
 * Factory class for creating Qdrant database instances
 */
export class DatabaseFactory {
  private static instance: DatabaseFactory;
  private connections: Map<string, IDatabase> = new Map();
  private defaultType: SupportedDatabaseType = 'qdrant';

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
  async create(config: UnifiedDatabaseConfig): Promise<IDatabase> {
    // Convert DatabaseConfig to VectorConfig for the adapter
    const vectorConfig = this.convertToVectorConfig(config);
    const configKey = this.generateConfigKey(vectorConfig);

    // Check if we already have a connection for this configuration
    if (this.connections.has(configKey)) {
      const connection = this.connections.get(configKey);

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
    const vectorAdapter = new QdrantAdapter(vectorConfig);
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
  async getByType(
    type: string,
    additionalConfig?: Partial<UnifiedDatabaseConfig>
  ): Promise<IDatabase> {
    if (type !== 'qdrant') {
      throw new ValidationError(`Only 'qdrant' database type is supported. Received: ${type}`);
    }

    const config = this.buildConfig(additionalConfig);
    return await this.create(config);
  }

  /**
   * Get default Qdrant database instance
   */
  async getDefault(additionalConfig?: Partial<UnifiedDatabaseConfig>): Promise<IDatabase> {
    return await this.getByType(this.defaultType, additionalConfig);
  }

  /**
   * Close specific Qdrant database connection
   */
  async close(type: string, additionalConfig: Partial<UnifiedDatabaseConfig> = {}): Promise<void> {
    const config = this.buildConfig(additionalConfig);
    const vectorConfig = this.convertToVectorConfig(config);
    const configKey = this.generateConfigKey(vectorConfig);

    if (this.connections.has(configKey)) {
      const database = this.connections.get(configKey);
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
  async validateConfig(
    config: UnifiedDatabaseConfig
  ): Promise<{ valid: boolean; errors: string[] }> {
    const errors: string[] = [];

    // Validate database type
    if (!config.type) {
      errors.push('Database type is required');
    } else if (config.type !== 'qdrant') {
      errors.push(`Only 'qdrant' database type is supported. Received: ${config.type}`);
    }

    // Validate Qdrant URL or host/port combination
    if (!config.url && !config.host && !process.env.QDRANT_URL) {
      errors.push(
        'Qdrant URL or host is required (config.url/config.host or QDRANT_URL environment variable)'
      );
    }

    // Validate URL format if provided
    if (config.url && !this.isValidUrl(config.url)) {
      errors.push('Qdrant URL must be a valid HTTP/HTTPS URL');
    }

    // Validate host if URL is not provided
    if (!config.url && config.host && !config.port) {
      errors.push('Qdrant port is required when using host configuration');
    }

    // Validate database name
    if (!config.database) {
      errors.push('Database name is required for Qdrant configuration');
    }

    // Validate OpenAI configuration (required for embeddings)
    const hasOpenAIKey =
      Boolean(process.env.OPENAI_API_KEY) || (await checkKeyVaultForKey('openai_api_key'));
    if (!hasOpenAIKey) {
      errors.push(
        'OpenAI API key is required for Qdrant vector operations (set OPENAI_API_KEY or configure in key vault)'
      );
    }

    // Validate connection timeout
    if (
      config.connectionTimeout !== undefined &&
      (config.connectionTimeout < 1000 || config.connectionTimeout > 300000)
    ) {
      errors.push('Connection timeout must be between 1000ms and 300000ms (5 minutes)');
    }

    // Validate max connections
    if (
      config.maxConnections !== undefined &&
      (config.maxConnections < 1 || config.maxConnections > 100)
    ) {
      errors.push('Max connections must be between 1 and 100');
    }

    // Validate vector size (check both possible property names)
    const vectorSize =
      'vectorSize' in config ? config.vectorSize : 'size' in config ? config.size : undefined;
    if (vectorSize !== undefined && ![384, 768, 1024, 1536, 2048, 3072].includes(vectorSize)) {
      errors.push('Vector size must be one of: 384, 768, 1024, 1536, 2048, 3072');
    }

    // Validate distance metric (check both possible property names)
    const distanceMetric = 'distance' in config ? config.distance : config.distanceMetric;
    if (
      distanceMetric !== undefined &&
      !['Cosine', 'Euclid', 'Dot', 'Manhattan'].includes(distanceMetric)
    ) {
      errors.push('Distance metric must be one of: Cosine, Euclid, Dot, Manhattan');
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * Test Qdrant configuration and connectivity
   */
  async testConfiguration(config: UnifiedDatabaseConfig): Promise<ConfigurationTestResult> {
    const startTime = Date.now();

    try {
      const database = await this.create(config);
      const healthy = await database.healthCheck();
      const latency = Date.now() - startTime;

      await this.close(config.type, config);

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
    const results: ConfigurationTestResult[] = [];

    try {
      const config = this.buildConfig();
      const result = await this.testConfiguration(config);
      results.push(result);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      results.push({
        type: this.defaultType,
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
  getRecommendation(useCase: RecommendationUseCase): ConfigurationRecommendation {
    const { requiresVectors = false, requiresHighPerformance = false, vectorSize } = useCase;

    const recommendedConfig: Partial<UnifiedDatabaseConfig> = {
      type: 'qdrant',
      vectorSize: vectorSize ?? 1536,
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
      alternatives: [],
    };
  }

  /**
   * Build Qdrant configuration from environment variables and defaults
   */
  buildConfig(additionalConfig: Partial<UnifiedDatabaseConfig> = {}): UnifiedDatabaseConfig {
    return DatabaseFactory.buildEnvironmentConfig(additionalConfig);
  }

  private static buildEnvironmentConfig(
    overrides: Partial<UnifiedDatabaseConfig> = {}
  ): UnifiedDatabaseConfig {
    const qdrantUrl = process.env.QDRANT_URL ?? 'http://localhost:6333';
    const urlObj = new URL(qdrantUrl);

    const parseEnvNumber = (value: string | undefined, fallback: number): number => {
      if (!value) {
        return fallback;
      }
      const parsed = Number.parseInt(value, 10);
      return Number.isNaN(parsed) ? fallback : parsed;
    };

    const supportedDistances: SupportedDistanceMetric[] = ['Cosine', 'Euclid', 'Dot', 'Manhattan'];
    const vectorDistanceEnv = process.env.VECTOR_DISTANCE;
    const distance =
      vectorDistanceEnv && supportedDistances.includes(vectorDistanceEnv as SupportedDistanceMetric)
        ? (vectorDistanceEnv as SupportedDistanceMetric)
        : 'Cosine';

    const baseConfig: UnifiedDatabaseConfig = {
      type: 'qdrant',
      url: qdrantUrl,
      host: urlObj.hostname,
      port: parseEnvNumber(urlObj.port || '6333', 6333),
      database: 'qdrant',
      apiKey: process.env.QDRANT_API_KEY,
      logQueries: process.env.NODE_ENV === 'development',
      connectionTimeout: parseEnvNumber(process.env.DB_CONNECTION_TIMEOUT, 30000),
      maxConnections: parseEnvNumber(process.env.DB_MAX_CONNECTIONS, 10),
      vectorSize: parseEnvNumber(process.env.VECTOR_SIZE, 1536),
      size: parseEnvNumber(process.env.VECTOR_SIZE, 1536),
      distance,
      distanceMetric: distance,
      collectionName: process.env.QDRANT_COLLECTION_NAME ?? 'cortex-memory',
      embeddingModel: process.env.OPENAI_EMBEDDING_MODEL ?? 'text-embedding-3-small',
      batchSize: parseEnvNumber(process.env.EMBEDDING_BATCH_SIZE, 32),
      openaiApiKey: process.env.OPENAI_API_KEY,
      maxRetries: parseEnvNumber(process.env.DB_MAX_RETRIES, 3),
      timeout: parseEnvNumber(process.env.DB_REQUEST_TIMEOUT, 30000),
    };

    return { ...baseConfig, ...overrides };
  }

  /**
   * Set default database type (always qdrant)
   */
  setDefaultType(type: SupportedDatabaseType): void {
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
  getDefaultType(): SupportedDatabaseType {
    return this.defaultType;
  }

  // === Private Helper Methods ===

  /**
   * Convert UnifiedDatabaseConfig to VectorConfig for adapter compatibility
   */
  private convertToVectorConfig(config: UnifiedDatabaseConfig): VectorConfig {
    let url: string;
    let host: string;
    let port: number;
    let database: string;

    // Handle URL vs host/port/database
    if (config.url) {
      url = config.url;
      const urlObj = new URL(config.url);
      host = urlObj.hostname;
      port = parseInt(urlObj.port || '6333');
      database = 'qdrant'; // Default database name for Qdrant
    } else if (config.host && config.port) {
      host = config.host;
      port = config.port;
      database = config.database || 'qdrant';
      url = `http://${host}:${port}`;
    } else {
      // Fallback to defaults
      url = 'http://localhost:6333';
      host = 'localhost';
      port = 6333;
      database = 'qdrant';
    }

    const vectorConfig: VectorConfig = {
      type: 'qdrant',
      url,
      host,
      port,
      database,
      size: config.size ?? config.vectorSize ?? 1536,
      embeddingModel: config.embeddingModel ?? 'text-embedding-3-small',
      batchSize: config.batchSize ?? 32,
    };

    // Copy common properties
    if (config.apiKey) vectorConfig.apiKey = config.apiKey;
    if (config.logQueries !== undefined) vectorConfig.logQueries = config.logQueries;
    if (config.connectionTimeout !== undefined)
      vectorConfig.connectionTimeout = config.connectionTimeout;
    if (config.maxConnections !== undefined) vectorConfig.maxConnections = config.maxConnections;

    // Copy vector-specific properties from DatabaseConfig interface
    if (config.vectorSize !== undefined) {
      vectorConfig.vectorSize = config.vectorSize;
    }

    const resolvedDistance = config.distance ?? config.distanceMetric;
    if (resolvedDistance) {
      vectorConfig.distanceMetric = resolvedDistance;
    }

    if (config.collectionName !== undefined) {
      vectorConfig.collectionName = config.collectionName;
    }

    if (config.openaiApiKey) {
      vectorConfig.openaiApiKey = config.openaiApiKey;
    }
    if (config.maxRetries !== undefined) {
      vectorConfig.maxRetries = config.maxRetries;
    }
    if (config.timeout !== undefined) {
      vectorConfig.timeout = config.timeout;
    }

    // Set defaults for vector-specific properties if not provided
    if (vectorConfig.vectorSize === undefined) {
      vectorConfig.vectorSize = 1536; // Default OpenAI ada-002 size
    }
    if (vectorConfig.distanceMetric === undefined) {
      vectorConfig.distanceMetric = 'Cosine';
    }
    if (vectorConfig.collectionName === undefined) {
      vectorConfig.collectionName = 'cortex-memory';
    }

    return vectorConfig;
  }

  private generateConfigKey(config: VectorConfig): string {
    // Create a unique key for the configuration
    const keyParts = [
      config.type,
      config.url ?? '',
      config.collectionName ?? '',
      config.maxConnections?.toString() ?? '10',
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
  static getEnvironmentConfig(): UnifiedDatabaseConfig {
    return DatabaseFactory.buildEnvironmentConfig();
  }

  /**
   * Create Qdrant database instance from environment configuration
   */
  static async createFromEnvironment(): Promise<IDatabase> {
    const factory = DatabaseFactory.getInstance();
    const config = DatabaseFactory.getEnvironmentConfig();
    return factory.create(config);
  }

  /**
   * Create default Qdrant database instance
   */
  static async createDefault(): Promise<IDatabase> {
    const factory = DatabaseFactory.getInstance();
    return factory.getDefault();
  }
}

/**
 * Export convenience functions for Qdrant database creation
 */
export async function createDatabase(config: UnifiedDatabaseConfig): Promise<IDatabase> {
  const factory = DatabaseFactory.getInstance();
  return factory.create(config);
}

export async function createQdrantDatabase(
  additionalConfig?: Partial<UnifiedDatabaseConfig>
): Promise<IDatabase> {
  const factory = DatabaseFactory.getInstance();
  return factory.getByType('qdrant', additionalConfig);
}

/**
 * Export singleton instance for convenience
 */
export const databaseFactory = DatabaseFactory.getInstance();
