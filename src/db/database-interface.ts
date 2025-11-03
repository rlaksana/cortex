/**
 * Qdrant Database Interface - Vector Database Abstraction Layer
 *
 * Provides a specialized interface for Qdrant vector database operations,
 * focusing on semantic search, vector embeddings, and knowledge management.
 *
 * This interface defines the contract that the Qdrant adapter must implement,
 * ensuring consistent behavior while leveraging Qdrant's unique strengths
 * in vector similarity search and knowledge operations.
 *
 * Features:
 * - Vector-first database interface for knowledge operations
 * - Semantic search with advanced similarity capabilities
 * - Unified error handling and logging
 * - Type-safe operations with full TypeScript support
 * - Connection health monitoring and management
 * - Embedding generation and management
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import {
  KnowledgeItem,
  StoreError,
  SearchResult,
  SearchQuery,
  MemoryStoreResponse,
  MemoryFindResponse,
} from '../types/core-interfaces.js';

export interface DatabaseConfig {
  type: 'qdrant' | 'hybrid';
  url: string;
  apiKey?: string;
  logQueries?: boolean;
  connectionTimeout?: number;
  maxConnections?: number;
  // Qdrant-specific
  vectorSize?: number;
  distance?: 'Cosine' | 'Euclid' | 'Dot' | 'Manhattan';
  collectionName?: string;
}

export interface DatabaseMetrics {
  type: string;
  healthy: boolean;
  connectionCount?: number;
  queryLatency?: number;
  storageSize?: number;
  lastHealthCheck?: string;
  vectorCount?: number;
  collectionInfo?: any;
}

export interface SearchOptions {
  includeVector?: boolean;
  includeMetadata?: boolean;
  cache?: boolean;
  timeout?: number;
  limit?: number;
  score_threshold?: number;
  searchMode?: 'semantic' | 'hybrid' | 'exact';
}

export interface StoreOptions {
  upsert?: boolean;
  validateOnly?: boolean;
  batchSize?: number;
  skipDuplicates?: boolean;
  generateEmbeddings?: boolean;
}

export interface DeleteOptions {
  cascade?: boolean;
  soft?: boolean;
  validate?: boolean;
}

/**
 * Main Qdrant database interface that all operations must implement
 */
export interface IDatabase {
  // === Lifecycle Management ===

  /**
   * Initialize the Qdrant connection and setup
   */
  initialize(): Promise<void>;

  /**
   * Check Qdrant health and connectivity
   */
  healthCheck(): Promise<boolean>;

  /**
   * Get Qdrant metrics and status
   */
  getMetrics(): Promise<DatabaseMetrics>;

  /**
   * Close Qdrant connections and cleanup
   */
  close(): Promise<void>;

  // === Knowledge Storage Operations ===

  /**
   * Store one or more knowledge items with vector embeddings
   */
  store(_items: KnowledgeItem[], _options?: StoreOptions): Promise<MemoryStoreResponse>;

  /**
   * Update existing knowledge items
   */
  update(_items: KnowledgeItem[], _options?: StoreOptions): Promise<MemoryStoreResponse>;

  /**
   * Delete knowledge items by ID
   */
  delete(
    _ids: string[],
    _options?: DeleteOptions
  ): Promise<{ deleted: number; errors: StoreError[] }>;

  /**
   * Find knowledge items by ID
   */
  findById(_ids: string[]): Promise<KnowledgeItem[]>;

  // === Search Operations ===

  /**
   * Search knowledge items using semantic vector similarity
   */
  search(_query: SearchQuery, _options?: SearchOptions): Promise<MemoryFindResponse>;

  /**
   * Semantic search using vector embeddings
   */
  semanticSearch(_query: string, _options?: SearchOptions): Promise<SearchResult[]>;

  /**
   * Hybrid search combining semantic and exact results
   */
  hybridSearch(_query: string, _options?: SearchOptions): Promise<MemoryFindResponse>;

  // === Knowledge Type Specific Operations ===

  /**
   * Store items of a specific knowledge type
   */
  storeByKind(
    _kind: string,
    _items: KnowledgeItem[],
    _options?: StoreOptions
  ): Promise<MemoryStoreResponse>;

  /**
   * Search within specific knowledge types
   */
  searchByKind(
    _kinds: string[],
    _query: SearchQuery,
    _options?: SearchOptions
  ): Promise<MemoryFindResponse>;

  /**
   * Get items by scope (project, branch, org)
   */
  findByScope(
    _scope: { project?: string; branch?: string; org?: string },
    _options?: SearchOptions
  ): Promise<KnowledgeItem[]>;

  // === Advanced Operations ===

  /**
   * Find similar items based on vector similarity
   */
  findSimilar(
    _item: KnowledgeItem,
    _threshold?: number,
    _options?: SearchOptions
  ): Promise<SearchResult[]>;

  /**
   * Check for duplicate items using semantic similarity
   */
  checkDuplicates(
    _items: KnowledgeItem[]
  ): Promise<{ duplicates: KnowledgeItem[]; originals: KnowledgeItem[] }>;

  /**
   * Get statistics about the knowledge base
   */
  getStatistics(_scope?: { project?: string; branch?: string; org?: string }): Promise<{
    totalItems: number;
    itemsByKind: Record<string, number>;
    storageSize: number;
    lastUpdated: string;
    vectorCount: number;
  }>;

  // === Batch Operations ===

  /**
   * Bulk operations for improved performance
   */
  bulkStore(_items: KnowledgeItem[], _options?: StoreOptions): Promise<MemoryStoreResponse>;

  /**
   * Bulk delete operations
   */
  bulkDelete(
    _filter: { kind?: string; scope?: any; before?: string },
    _options?: DeleteOptions
  ): Promise<{ deleted: number }>;

  /**
   * Bulk search across multiple queries
   */
  bulkSearch(_queries: SearchQuery[], _options?: SearchOptions): Promise<MemoryFindResponse[]>;

  // === Vector Operations (Qdrant Core) ===

  /**
   * Generate embeddings for content
   */
  generateEmbedding(_content: string): Promise<number[]>;

  /**
   * Store items with pre-computed embeddings
   */
  storeWithEmbeddings(
    _items: Array<KnowledgeItem & { embedding: number[] }>,
    _options?: StoreOptions
  ): Promise<MemoryStoreResponse>;

  /**
   * Search using vector similarity
   */
  vectorSearch(_embedding: number[], _options?: SearchOptions): Promise<SearchResult[]>;

  /**
   * Find nearest neighbors for a vector
   */
  findNearest(_embedding: number[], _limit?: number, _threshold?: number): Promise<SearchResult[]>;

  // === Administrative Operations ===

  /**
   * Backup Qdrant collection
   */
  backup(_destination?: string): Promise<string>;

  /**
   * Restore Qdrant collection from backup
   */
  restore(_source: string): Promise<void>;

  /**
   * Optimize Qdrant collection performance
   */
  optimize(): Promise<void>;

  /**
   * Validate data integrity
   */
  validate(): Promise<{ valid: boolean; issues: string[] }>;

  /**
   * Create or update collection schema
   */
  updateCollectionSchema(_config: any): Promise<void>;

  /**
   * Get collection information
   */
  getCollectionInfo(): Promise<any>;
}

/**
 * Qdrant database factory interface for creating database instances
 */
export interface IDatabaseFactory {
  /**
   * Create a Qdrant database instance based on configuration
   */
  create(_config: DatabaseConfig): Promise<IDatabase>;

  /**
   * Get supported configuration options
   */
  getSupportedOptions(): string[];

  /**
   * Validate Qdrant configuration
   */
  validateConfig(_config: DatabaseConfig): Promise<{ valid: boolean; errors: string[] }>;
}

/**
 * Qdrant adapter interface for specific implementations
 */
export interface IDatabaseAdapter extends IDatabase {
  /**
   * Get the underlying Qdrant client (for advanced operations)
   */
  getClient(): any;

  /**
   * Get Qdrant-specific capabilities
   */
  getCapabilities(): Promise<{
    supportsVectors: boolean;
    supportsFullTextSearch: boolean;
    supportsPayloadFiltering: boolean;
    maxBatchSize: number;
    supportedDistanceMetrics: string[];
    supportedOperations: string[];
  }>;

  /**
   * Test specific Qdrant functionality
   */
  testFunctionality(_operation: string, _params?: any): Promise<boolean>;

  /**
   * Get collection statistics
   */
  getCollectionStats(): Promise<{
    vectorsCount: number;
    indexedVectorsCount: number;
    pointsCount: number;
    segmentsCount: number;
    diskDataSize: number;
    ramDataSize: number;
  }>;
}

/**
 * Connection pool interface for managing Qdrant connections
 */
export interface IConnectionPool {
  /**
   * Get a connection from the pool
   */
  getConnection(): Promise<any>;

  /**
   * Release a connection back to the pool
   */
  releaseConnection(_connection: any): Promise<void>;

  /**
   * Close all connections in the pool
   */
  close(): Promise<void>;

  /**
   * Get pool statistics
   */
  getStats(): Promise<{
    activeConnections: number;
    idleConnections: number;
    totalConnections: number;
    waitingRequests: number;
  }>;
}

/**
 * Collection management interface for Qdrant operations
 */
export interface ICollectionManager {
  /**
   * Create a new collection
   */
  createCollection(_name: string, _config: any): Promise<void>;

  /**
   * Delete a collection
   */
  deleteCollection(_name: string): Promise<void>;

  /**
   * List all collections
   */
  listCollections(): Promise<string[]>;

  /**
   * Get collection configuration
   */
  getCollectionConfig(_name: string): Promise<any>;

  /**
   * Update collection configuration
   */
  updateCollectionConfig(_name: string, _config: any): Promise<void>;
}

/**
 * Export common error types for Qdrant database operations
 */
export class DatabaseError extends Error {
  constructor(
    _message: string,
    public readonly _code: string,
    public readonly _originalError?: Error,
    public readonly _context?: Record<string, any>
  ) {
    super(_message);
    this.name = 'DatabaseError';
  }
}

export class ConnectionError extends DatabaseError {
  constructor(_message: string, _originalError?: Error) {
    super(_message, 'CONNECTION_ERROR', _originalError);
    this.name = 'ConnectionError';
  }
}

export class ValidationError extends DatabaseError {
  constructor(_message: string, _field?: string) {
    super(_message, 'VALIDATION_ERROR', undefined, { field: _field });
    this.name = 'ValidationError';
  }
}

export class NotFoundError extends DatabaseError {
  constructor(_id: string, _type: string = 'item') {
    super(`${_type} with id '${_id}' not found`, 'NOT_FOUND', undefined, { id: _id, type: _type });
    this.name = 'NotFoundError';
  }
}

export class DuplicateError extends DatabaseError {
  constructor(_id: string, _type: string = 'item') {
    super(`${_type} with id '${_id}' already exists`, 'DUPLICATE_ERROR', undefined, {
      id: _id,
      type: _type,
    });
    this.name = 'DuplicateError';
  }
}

export class EmbeddingError extends DatabaseError {
  constructor(_message: string, _originalError?: Error) {
    super(_message, 'EMBEDDING_ERROR', _originalError);
    this.name = 'EmbeddingError';
  }
}

export class CollectionError extends DatabaseError {
  constructor(_message: string, _collection?: string, _originalError?: Error) {
    super(_message, 'COLLECTION_ERROR', _originalError, { collection: _collection });
    this.name = 'CollectionError';
  }
}

export class VectorError extends DatabaseError {
  constructor(_message: string, _vectorSize?: number, _expectedSize?: number) {
    super(_message, 'VECTOR_ERROR', undefined, {
      vectorSize: _vectorSize,
      expectedSize: _expectedSize,
    });
    this.name = 'VectorError';
  }
}
