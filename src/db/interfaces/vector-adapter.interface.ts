// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * Vector Adapter Interface
 *
 * Defines the contract for vector database operations,
 * including semantic search, embedding generation, and
 * vector similarity operations with enhanced type safety.
 */

import {
  type KnowledgeItem,
  type MemoryFindResponse,
  type MemoryStoreResponse,
  type SearchQuery,
  type SearchResult,
  type StoreError,
} from '../../types/core-interfaces.js';
import {
  type BatchResult,
  type CollectionId,
  type DatabaseCapabilities,
  type DatabaseConnection,
  type DatabaseOperation,
  type DatabaseResult,
  type DeleteOptions as TypedDeleteOptions,
  type KnowledgeEntity,
  type MutationBuilder,
  type PointId,
  type QueryBuilder,
  type QueryFilter,
  type QueryOptions,
  type SearchOptions as TypedSearchOptions,
  type StoreOptions as TypedStoreOptions,
  type Transaction,
  type TransactionOptions,
  type VectorDatabaseConfig} from '../../types/database-generics.js';
import {
  type DatabaseMetrics
} from '../database-interface.js';

// Re-export DatabaseMetrics for use in other modules
export type { DatabaseMetrics };

export interface VectorConfig extends VectorDatabaseConfig {
  // Direct properties for compatibility with qdrant-adapter
  url?: string;
  apiKey?: string;
  vectorSize?: number;
  dimensions?: number;
  distanceMetric?: 'Cosine' | 'Euclid' | 'Dot' | 'Manhattan';
  collectionName?: string;
  logQueries?: boolean;
  connectionTimeout?: number;
  maxConnections?: number;
  maxRetries?: number;
  timeout?: number;

  // Legacy nested config for backward compatibility
  qdrant?: {
    url: string;
    apiKey?: string;
    timeout?: number;
  };
}

export interface SearchOptions extends TypedSearchOptions {
  cache?: boolean;
  searchMode?: 'semantic' | 'hybrid' | 'exact';
  keyword_weight?: number;
  semantic_weight?: number;
  score_threshold?: number;
  includeVector?: boolean;
  includeMetadata?: boolean;
  timeout?: number;
  limit?: number;
}

export interface StoreOptions extends TypedStoreOptions {
  validateOnly?: boolean;
  generateEmbeddings?: boolean;
}

// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface DeleteOptions extends TypedDeleteOptions {
  // Additional vector-specific options can be added here
}

/**
 * Enhanced Vector adapter interface for semantic search and vector operations
 * with comprehensive type safety and generic constraints
 */
export interface IVectorAdapter<TClient = unknown, TConfig extends VectorConfig = VectorConfig> {
  // === Lifecycle Management ===

  /**
   * Initialize vector database connection
   */
  initialize(): Promise<void>;

  /**
   * Check vector database health
   */
  healthCheck(): Promise<boolean>;

  /**
   * Get vector database metrics
   */
  getMetrics(): Promise<DatabaseMetrics>;

  /**
   * Close vector database connections
   */
  close(): Promise<void>;

  /**
   * Get database connection information
   */
  getConnection(): DatabaseConnection<TClient>;

  /**
   * Get database capabilities
   */
  getCapabilities(): Promise<DatabaseCapabilities>;

  // === Knowledge Storage Operations ===

  /**
   * Store knowledge items with vector embeddings
   */
  store(items: readonly KnowledgeItem[], options?: StoreOptions): Promise<DatabaseResult<MemoryStoreResponse>>;

  /**
   * Update existing knowledge items
   */
  update(items: readonly KnowledgeItem[], options?: StoreOptions): Promise<DatabaseResult<MemoryStoreResponse>>;

  /**
   * Delete knowledge items by ID
   */
  delete(ids: readonly PointId[], options?: DeleteOptions): Promise<DatabaseResult<{
    deletedCount: number;
    errors: readonly StoreError[];
  }>>;

  /**
   * Find knowledge items by ID
   */
  findById(ids: readonly PointId[]): Promise<DatabaseResult<readonly KnowledgeItem[]>>;

  // === Search Operations ===

  /**
   * Search knowledge items using semantic vector similarity
   */
  search(query: SearchQuery, options?: SearchOptions): Promise<DatabaseResult<MemoryFindResponse>>;

  /**
   * Semantic search using vector embeddings
   */
  semanticSearch(query: string, options?: SearchOptions): Promise<DatabaseResult<readonly SearchResult[]>>;

  /**
   * Hybrid search combining semantic and exact results
   */
  hybridSearch(query: string, options?: SearchOptions): Promise<DatabaseResult<readonly SearchResult[]>>;

  /**
   * Exact search using keyword matching
   */
  exactSearch(query: string, options?: SearchOptions): Promise<DatabaseResult<readonly SearchResult[]>>;

  /**
   * Advanced search with query builder
   */
  createQueryBuilder(): QueryBuilder<Record<string, unknown>>;

  /**
   * Search using query filter
   */
  findByFilter(filter: QueryFilter<Record<string, unknown>>, options?: QueryOptions<Record<string, unknown>>): Promise<DatabaseResult<readonly Record<string, unknown>[]>>;

  // === Knowledge Type Specific Operations ===

  /**
   * Store items of a specific knowledge type
   */
  storeByKind(
    kind: string,
    items: readonly KnowledgeItem[],
    options?: StoreOptions
  ): Promise<DatabaseResult<MemoryStoreResponse>>;

  /**
   * Search within specific knowledge types
   */
  searchByKind(
    kinds: readonly string[],
    query: SearchQuery,
    options?: SearchOptions
  ): Promise<DatabaseResult<MemoryFindResponse>>;

  /**
   * Get items by scope (project, branch, org)
   */
  findByScope(
    scope: {
      readonly project?: string;
      readonly branch?: string;
      readonly org?: string;
    },
    options?: SearchOptions
  ): Promise<DatabaseResult<readonly KnowledgeItem[]>>;

  // === Advanced Operations ===

  /**
   * Find similar items based on vector similarity
   */
  findSimilar(
    item: KnowledgeEntity,
    threshold?: number,
    options?: SearchOptions
  ): Promise<DatabaseResult<readonly SearchResult[]>>;

  /**
   * Check for duplicate items using semantic similarity
   */
  checkDuplicates(items: readonly KnowledgeItem[]): Promise<DatabaseResult<{
    duplicates: readonly KnowledgeItem[];
    originals: readonly KnowledgeItem[];
    similarityThreshold: number;
  }>>;

  /**
   * Get statistics about the knowledge base
   */
  getStatistics(scope?: {
    readonly project?: string;
    readonly branch?: string;
    readonly org?: string;
  }): Promise<DatabaseResult<{
    totalItems: number;
    itemsByKind: Readonly<Record<string, number>>;
    storageSize: number;
    lastUpdated: string;
    vectorCount: number;
    collectionInfo?: {
      readonly name: string;
      readonly vectorsCount: number;
      readonly indexedVectorsCount: number;
      readonly pointsCount: number;
      readonly segmentsCount: number;
      readonly diskDataSize: number;
      readonly ramDataSize: number;
    };
  }>>;

  // === Batch Operations ===

  /**
   * Bulk operations for improved performance
   */
  bulkStore(items: readonly KnowledgeItem[], options?: StoreOptions): Promise<DatabaseResult<BatchResult<KnowledgeItem>>>;

  /**
   * Bulk delete operations
   */
  bulkDelete(
    filter: QueryFilter<Record<string, unknown>>,
    options?: DeleteOptions
  ): Promise<DatabaseResult<{ deletedCount: number }>>;

  /**
   * Bulk search across multiple queries
   */
  bulkSearch(queries: readonly SearchQuery[], options?: SearchOptions): Promise<DatabaseResult<readonly MemoryFindResponse[]>>;

  /**
   * Create mutation builder for batch operations
   */
  createMutationBuilder(): MutationBuilder<Record<string, unknown>>;

  // === Vector Operations ===

  /**
   * Generate embeddings for content
   */
  generateEmbedding(content: string): Promise<DatabaseResult<readonly number[]>>;

  /**
   * Generate multiple embeddings for batch processing
   */
  generateEmbeddingsBatch(contents: readonly string[]): Promise<DatabaseResult<readonly number[][]>>;

  /**
   * Store items with pre-computed embeddings
   */
  storeWithEmbeddings(
    items: readonly (KnowledgeEntity & { readonly embedding: number[] })[],
    options?: StoreOptions
  ): Promise<DatabaseResult<MemoryStoreResponse>>;

  /**
   * Search using vector similarity
   */
  vectorSearch(embedding: readonly number[], options?: SearchOptions): Promise<DatabaseResult<readonly SearchResult[]>>;

  /**
   * Find nearest neighbors for a vector
   */
  findNearest(
    embedding: readonly number[],
    limit?: number,
    threshold?: number
  ): Promise<DatabaseResult<readonly SearchResult[]>>;

  /**
   * Vector similarity search with multiple vectors
   */
  findNearestMultiple(
    embeddings: readonly number[][],
    limit?: number,
    threshold?: number
  ): Promise<DatabaseResult<readonly SearchResult[][]>>;

  // === Administrative Operations ===

  /**
   * Backup vector collection
   */
  backup(destination?: string): Promise<DatabaseResult<{ backupId: string; backupPath: string }>>;

  /**
   * Restore vector collection from backup
   */
  restore(source: string): Promise<DatabaseResult<{ restored: boolean; itemCount: number }>>;

  /**
   * Optimize vector collection performance
   */
  optimize(): Promise<DatabaseResult<{ optimized: boolean; timeMs: number }>>;

  /**
   * Validate data integrity
   */
  validate(): Promise<DatabaseResult<{
    valid: boolean;
    issues: readonly string[];
    warnings?: readonly string[];
    recommendations?: readonly string[];
  }>>;

  /**
   * Create or update collection schema
   */
  updateCollectionSchema(config: Partial<VectorConfig>): Promise<DatabaseResult<{ updated: boolean }>>;

  /**
   * Get collection information
   */
  getCollectionInfo(): Promise<DatabaseResult<{
    name: string;
    config: VectorConfig;
    status: 'healthy' | 'degraded' | 'unhealthy';
    metadata: Readonly<Record<string, unknown>>;
  }>>;

  /**
   * Create a new collection
   */
  createCollection(name: string, config: VectorConfig): Promise<DatabaseResult<{ created: boolean; collectionId: CollectionId }>>;

  /**
   * Delete a collection
   */
  deleteCollection(name: string): Promise<DatabaseResult<{ deleted: boolean }>>;

  /**
   * List all collections
   */
  listCollections(): Promise<DatabaseResult<readonly { name: string; status: string }[]>>;

  /**
   * P6-T6.1: Find expired knowledge items
   * Efficiently finds items that have expired based on expiry_at timestamp
   */
  findExpiredItems(options: {
    readonly expiry_before?: string;
    readonly limit?: number;
    readonly scope?: {
      readonly project?: string;
      readonly branch?: string;
      readonly org?: string;
    };
    readonly kinds?: readonly string[];
  }): Promise<DatabaseResult<readonly KnowledgeItem[]>>;

  // === Transaction Operations ===

  /**
   * Begin a new transaction
   */
  beginTransaction(options?: TransactionOptions): Promise<DatabaseResult<Transaction<TClient>>>;

  /**
   * Execute operations within a transaction
   */
  executeTransaction<T>(
    operations: readonly DatabaseOperation<unknown, T>[],
    options?: TransactionOptions
  ): Promise<DatabaseResult<readonly T[]>>;

  // === Monitoring and Diagnostics ===

  /**
   * Test specific functionality
   */
  testFunctionality(
    operation: string,
    params?: Readonly<Record<string, unknown>>
  ): Promise<DatabaseResult<boolean>>;

  /**
   * Get performance metrics
   */
  getPerformanceMetrics(): Promise<DatabaseResult<{
    queryLatency: number;
    indexingLatency: number;
    throughput: number;
    errorRate: number;
    cacheHitRate?: number;
  }>>;

  /**
   * Health check with detailed status
   */
  detailedHealthCheck(): Promise<DatabaseResult<{
    healthy: boolean;
    connectionStatus: string;
    collectionStatus: string;
    issues: readonly string[];
    recommendations?: readonly string[];
  }>>;

  // === Client Access (for advanced operations) ===

  /**
   * Get the underlying client for advanced operations
   */
  getClient(): TClient;

  /**
   * Get raw access to the database (for migration scripts, etc.)
   */
  getRawClient(): unknown;

  /**
   * Check if specific operation is supported
   */
  supportsOperation(operation: string): boolean;

  /**
   * Get supported operations list
   */
  getSupportedOperations(): readonly string[];
}
