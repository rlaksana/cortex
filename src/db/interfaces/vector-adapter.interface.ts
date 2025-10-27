/**
 * Vector Adapter Interface
 *
 * Defines the contract for vector database operations,
 * including semantic search, embedding generation, and
 * vector similarity operations.
 */

import { DatabaseConfig, DatabaseMetrics } from './database-interface.js';

// Re-export DatabaseMetrics for use in other modules
export type { DatabaseMetrics };
import {
  KnowledgeItem,
  StoreResult,
  StoreError,
  SearchResult,
  SearchQuery,
  MemoryStoreResponse,
  MemoryFindResponse,
} from '../types/core-interfaces.js';

export interface VectorConfig extends DatabaseConfig {
  vectorSize?: number;
  distance?: 'Cosine' | 'Euclidean' | 'DotProduct';
  collectionName?: string;
  url?: string;
  apiKey?: string;
  logQueries?: boolean;
  connectionTimeout?: number;
  maxConnections?: number;
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
  store(items: KnowledgeItem[], options?: StoreOptions): Promise<MemoryStoreResponse>;

  /**
   * Update existing knowledge items
   */
  update(items: KnowledgeItem[], options?: StoreOptions): Promise<MemoryStoreResponse>;

  /**
   * Delete knowledge items by ID
   */
  delete(
    ids: string[],
    options?: DeleteOptions
  ): Promise<{
    deleted: number;
    errors: StoreError[];
  }>;

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
  hybridSearch(query: string, options?: SearchOptions): Promise<SearchResult[]>;

  /**
   * Exact search using keyword matching
   */
  exactSearch(query: string, options?: SearchOptions): Promise<SearchResult[]>;

  // === Knowledge Type Specific Operations ===

  /**
   * Store items of a specific knowledge type
   */
  storeByKind(
    kind: string,
    items: KnowledgeItem[],
    options?: StoreOptions
  ): Promise<MemoryStoreResponse>;

  /**
   * Search within specific knowledge types
   */
  searchByKind(
    kinds: string[],
    query: SearchQuery,
    options?: SearchOptions
  ): Promise<MemoryFindResponse>;

  /**
   * Get items by scope (project, branch, org)
   */
  findByScope(
    scope: {
      project?: string;
      branch?: string;
      org?: string;
    },
    options?: SearchOptions
  ): Promise<KnowledgeItem[]>;

  // === Advanced Operations ===

  /**
   * Find similar items based on vector similarity
   */
  findSimilar(
    item: KnowledgeItem,
    threshold?: number,
    options?: SearchOptions
  ): Promise<SearchResult[]>;

  /**
   * Check for duplicate items using semantic similarity
   */
  checkDuplicates(items: KnowledgeItem[]): Promise<{
    duplicates: KnowledgeItem[];
    originals: KnowledgeItem[];
  }>;

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
  bulkDelete(
    filter: {
      kind?: string;
      scope?: any;
      before?: string;
    },
    options?: DeleteOptions
  ): Promise<{ deleted: number }>;

  /**
   * Bulk search across multiple queries
   */
  bulkSearch(queries: SearchQuery[], options?: SearchOptions): Promise<MemoryFindResponse[]>;

  // === Vector Operations ===

  /**
   * Generate embeddings for content
   */
  generateEmbedding(content: string): Promise<number[]>;

  /**
   * Store items with pre-computed embeddings
   */
  storeWithEmbeddings(
    items: Array<KnowledgeItem & { embedding: number[] }>,
    options?: StoreOptions
  ): Promise<MemoryStoreResponse>;

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
   * Backup vector collection
   */
  backup(destination?: string): Promise<string>;

  /**
   * Restore vector collection from backup
   */
  restore(source: string): Promise<void>;

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
  updateCollectionSchema(config: any): Promise<void>;

  /**
   * Get collection information
   */
  getCollectionInfo(): Promise<any>;

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
  testFunctionality(operation: string, params?: any): Promise<boolean>;

  /**
   * Get the underlying client for advanced operations
   */
  getClient(): any;
}
