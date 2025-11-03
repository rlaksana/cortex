/**
 * Vector Adapter Interface
 *
 * Defines the contract for vector database operations,
 * including semantic search, embedding generation, and
 * vector similarity operations.
 */

import { DatabaseConfig, DatabaseMetrics } from '../database-interface.js';
import {
  KnowledgeItem,
  StoreError,
  SearchResult,
  SearchQuery,
  MemoryStoreResponse,
  MemoryFindResponse,
} from '../../types/core-interfaces.js';

// Re-export DatabaseMetrics for use in other modules
export type { DatabaseMetrics };

export interface VectorConfig extends DatabaseConfig {
  vectorSize?: number;
  dimensions?: number;
  distance?: 'Cosine' | 'Euclid' | 'Dot' | 'Manhattan';
  distanceMetric?: 'Cosine' | 'Euclid' | 'Dot' | 'Manhattan';
  collectionName?: string;
  apiKey?: string;
  logQueries?: boolean;
  connectionTimeout?: number;
  maxConnections?: number;
  maxRetries?: number;
  timeout?: number;
  qdrant?: {
    url: string;
    apiKey?: string;
    timeout?: number;
  };
}

export interface SearchOptions {
  includeVector?: boolean;
  includeMetadata?: boolean;
  cache?: boolean;
  timeout?: number;
  limit?: number;
  score_threshold?: number;
  searchMode?: 'semantic' | 'hybrid' | 'exact';
  keyword_weight?: number;
  semantic_weight?: number;
}

export interface StoreOptions {
  upsert?: boolean;
  validateOnly?: boolean;
  batchSize?: number;
  skipDuplicates?: boolean;
  generateEmbeddings?: boolean;
  timeout?: number;
}

export interface DeleteOptions {
  cascade?: boolean;
  soft?: boolean;
  validate?: boolean;
}

/**
 * Vector adapter interface for semantic search and vector operations
 */
export interface IVectorAdapter {
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

  // === Knowledge Storage Operations ===

  /**
   * Store knowledge items with vector embeddings
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
  ): Promise<{
    deleted: number;
    errors: StoreError[];
  }>;

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
  hybridSearch(_query: string, _options?: SearchOptions): Promise<SearchResult[]>;

  /**
   * Exact search using keyword matching
   */
  exactSearch(_query: string, _options?: SearchOptions): Promise<SearchResult[]>;

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
    _scope: {
      project?: string;
      branch?: string;
      org?: string;
    },
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
  checkDuplicates(_items: KnowledgeItem[]): Promise<{
    duplicates: KnowledgeItem[];
    originals: KnowledgeItem[];
  }>;

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
    _filter: {
      kind?: string;
      scope?: any;
      before?: string;
    },
    _options?: DeleteOptions
  ): Promise<{ deleted: number }>;

  /**
   * Bulk search across multiple queries
   */
  bulkSearch(_queries: SearchQuery[], _options?: SearchOptions): Promise<MemoryFindResponse[]>;

  // === Vector Operations ===

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
   * Backup vector collection
   */
  backup(_destination?: string): Promise<string>;

  /**
   * Restore vector collection from backup
   */
  restore(_source: string): Promise<void>;

  /**
   * Optimize vector collection performance
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

  /**
   * P6-T6.1: Find expired knowledge items
   * Efficiently finds items that have expired based on expiry_at timestamp
   */
  findExpiredItems(options: {
    expiry_before?: string;
    limit?: number;
    scope?: any;
    kinds?: string[];
  }): Promise<KnowledgeItem[]>;

  // === Capability Interface ===

  /**
   * Get vector database capabilities
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
   * Test specific functionality
   */
  testFunctionality(_operation: string, _params?: any): Promise<boolean>;

  /**
   * Get the underlying client for advanced operations
   */
  getClient(): any;
}
