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
  StoreResult,
  StoreError,
  SearchResult,
  SearchQuery,
  MemoryStoreResponse,
  MemoryFindResponse,
  AutonomousContext
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
  distance?: 'Cosine' | 'Euclidean' | 'DotProduct';
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
  store(items: KnowledgeItem[], options?: StoreOptions): Promise<MemoryStoreResponse>;

  /**
   * Update existing knowledge items
   */
  update(items: KnowledgeItem[], options?: StoreOptions): Promise<MemoryStoreResponse>;

  /**
   * Delete knowledge items by ID
   */
  delete(ids: string[], options?: DeleteOptions): Promise<{ deleted: number; errors: StoreError[] }>;

  /**
   * Find knowledge items by ID
   */
  findById(ids: string[]): Promise<KnowledgeItem[]>;

  // === Search Operations ===

  /**
   * Search knowledge items using semantic vector similarity
   */
  search(query: SearchQuery, options?: SearchOptions): Promise<MemoryFindResponse>;

  /**
   * Semantic search using vector embeddings
   */
  semanticSearch(query: string, options?: SearchOptions): Promise<SearchResult[]>;

  /**
   * Hybrid search combining semantic and exact results
   */
  hybridSearch(query: string, options?: SearchOptions): Promise<MemoryFindResponse>;

  // === Knowledge Type Specific Operations ===

  /**
   * Store items of a specific knowledge type
   */
  storeByKind(kind: string, items: KnowledgeItem[], options?: StoreOptions): Promise<MemoryStoreResponse>;

  /**
   * Search within specific knowledge types
   */
  searchByKind(kinds: string[], query: SearchQuery, options?: SearchOptions): Promise<MemoryFindResponse>;

  /**
   * Get items by scope (project, branch, org)
   */
  findByScope(scope: { project?: string; branch?: string; org?: string }, options?: SearchOptions): Promise<KnowledgeItem[]>;

  // === Advanced Operations ===

  /**
   * Find similar items based on vector similarity
   */
  findSimilar(item: KnowledgeItem, threshold?: number, options?: SearchOptions): Promise<SearchResult[]>;

  /**
   * Check for duplicate items using semantic similarity
   */
  checkDuplicates(items: KnowledgeItem[]): Promise<{ duplicates: KnowledgeItem[]; originals: KnowledgeItem[] }>;

  /**
   * Get statistics about the knowledge base
   */
  getStatistics(scope?: { project?: string; branch?: string; org?: string }): Promise<{
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
  bulkStore(items: KnowledgeItem[], options?: StoreOptions): Promise<MemoryStoreResponse>;

  /**
   * Bulk delete operations
   */
  bulkDelete(filter: { kind?: string; scope?: any; before?: string }, options?: DeleteOptions): Promise<{ deleted: number }>;

  /**
   * Bulk search across multiple queries
   */
  bulkSearch(queries: SearchQuery[], options?: SearchOptions): Promise<MemoryFindResponse[]>;

  // === Vector Operations (Qdrant Core) ===

  /**
   * Generate embeddings for content
   */
  generateEmbedding(content: string): Promise<number[]>;

  /**
   * Store items with pre-computed embeddings
   */
  storeWithEmbeddings(items: Array<KnowledgeItem & { embedding: number[] }>, options?: StoreOptions): Promise<MemoryStoreResponse>;

  /**
   * Search using vector similarity
   */
  vectorSearch(embedding: number[], options?: SearchOptions): Promise<SearchResult[]>;

  /**
   * Find nearest neighbors for a vector
   */
  findNearest(embedding: number[], limit?: number, threshold?: number): Promise<SearchResult[]>;

  // === Administrative Operations ===

  /**
   * Backup Qdrant collection
   */
  backup(destination?: string): Promise<string>;

  /**
   * Restore Qdrant collection from backup
   */
  restore(source: string): Promise<void>;

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
  updateCollectionSchema(config: any): Promise<void>;

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
  create(config: DatabaseConfig): Promise<IDatabase>;

  /**
   * Get supported configuration options
   */
  getSupportedOptions(): string[];

  /**
   * Validate Qdrant configuration
   */
  validateConfig(config: DatabaseConfig): Promise<{ valid: boolean; errors: string[] }>;
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
  testFunctionality(operation: string, params?: any): Promise<boolean>;

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
  releaseConnection(connection: any): Promise<void>;

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
  createCollection(name: string, config: any): Promise<void>;

  /**
   * Delete a collection
   */
  deleteCollection(name: string): Promise<void>;

  /**
   * List all collections
   */
  listCollections(): Promise<string[]>;

  /**
   * Get collection configuration
   */
  getCollectionConfig(name: string): Promise<any>;

  /**
   * Update collection configuration
   */
  updateCollectionConfig(name: string, config: any): Promise<void>;
}

/**
 * Export common error types for Qdrant database operations
 */
export class DatabaseError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly originalError?: Error,
    public readonly context?: Record<string, any>
  ) {
    super(message);
    this.name = 'DatabaseError';
  }
}

export class ConnectionError extends DatabaseError {
  constructor(message: string, originalError?: Error) {
    super(message, 'CONNECTION_ERROR', originalError);
    this.name = 'ConnectionError';
  }
}

export class ValidationError extends DatabaseError {
  constructor(message: string, field?: string) {
    super(message, 'VALIDATION_ERROR', undefined, { field });
    this.name = 'ValidationError';
  }
}

export class NotFoundError extends DatabaseError {
  constructor(id: string, type: string = 'item') {
    super(`${type} with id '${id}' not found`, 'NOT_FOUND', undefined, { id, type });
    this.name = 'NotFoundError';
  }
}

export class DuplicateError extends DatabaseError {
  constructor(id: string, type: string = 'item') {
    super(`${type} with id '${id}' already exists`, 'DUPLICATE_ERROR', undefined, { id, type });
    this.name = 'DuplicateError';
  }
}

export class EmbeddingError extends DatabaseError {
  constructor(message: string, originalError?: Error) {
    super(message, 'EMBEDDING_ERROR', originalError);
    this.name = 'EmbeddingError';
  }
}

export class CollectionError extends DatabaseError {
  constructor(message: string, collection?: string, originalError?: Error) {
    super(message, 'COLLECTION_ERROR', originalError, { collection });
    this.name = 'CollectionError';
  }
}

export class VectorError extends DatabaseError {
  constructor(message: string, vectorSize?: number, expectedSize?: number) {
    super(message, 'VECTOR_ERROR', undefined, { vectorSize, expectedSize });
    this.name = 'VectorError';
  }
}