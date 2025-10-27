/**
 * ⚠️ DEPRECATED - PostgreSQL Adapter Interface
 *
 * THIS INTERFACE IS DEPRECATED AND WILL BE REMOVED IN A FUTURE RELEASE
 *
 * PostgreSQL is NO LONGER SUPPORTED in Cortex Memory MCP.
 * All database operations now use Qdrant vector database interfaces.
 *
 * Migration completed: 2025-01-27
 * Replacement: src/db/interfaces/vector-adapter.interface.ts
 *
 * If you're seeing this file being imported, please update your code
 * to use the vector adapter interface instead.
 *
 * @deprecated Use VectorAdapter interface instead
 * @remove-version 2.1.0
 */

import { DatabaseConfig, DatabaseMetrics } from './database-interface.js';
import { KnowledgeItem, StoreResult, StoreError, MemoryStoreResponse } from '../types/core-interfaces.js';

export interface PostgreSQLConfig extends DatabaseConfig {
  postgresConnectionString: string;
  maxConnections?: number;
  connectionTimeout?: number;
}

export interface QueryOptions {
  useRaw?: boolean;
  timeout?: number;
  cache?: boolean;
  transaction?: boolean;
  take?: number;
  orderBy?: Record<string, 'asc' | 'desc'>;
}

export interface FullTextSearchOptions {
  query: string;
  config?: string; // ts_config name, e.g., 'english'
  weighting?: Record<string, number>; // D, C, B, A weights
  normalization?: number; // ts_rank_cd normalization
  highlight?: boolean;
  snippet_size?: number;
  max_results?: number;
  min_rank?: number;
}

export interface SearchResult {
  id: string;
  title: string;
  snippet: string;
  score: number;
  kind: string;
  data: Record<string, any>;
  rank?: number;
  highlight?: string[];
}

export interface UUIDGenerationOptions {
  version?: 'v4' | 'v7';
  namespace?: string;
  name?: string;
}

export interface ExplainOptions {
  analyze?: boolean;
  buffers?: boolean;
  timing?: boolean;
  verbose?: boolean;
  costs?: boolean;
  format?: 'text' | 'json' | 'xml' | 'yaml';
}

export interface ExplainResult {
  plan: any;
  execution_time?: number;
  planning_time?: number;
  total_cost?: number;
  rows?: number;
  width?: number;
}

/**
 * PostgreSQL adapter interface for relational database operations
 */
export interface IPostgreSQLAdapter {
  // === Lifecycle Management ===

  /**
   * Initialize PostgreSQL connection pool
   */
  initialize(): Promise<void>;

  /**
   * Check PostgreSQL health and connectivity
   */
  healthCheck(): Promise<boolean>;

  /**
   * Get PostgreSQL metrics and status
   */
  getMetrics(): Promise<DatabaseMetrics>;

  /**
   * Close PostgreSQL connections
   */
  close(): Promise<void>;

  // === CRUD Operations ===

  /**
   * Create a new record
   */
  create<T = any>(table: string, data: Record<string, any>): Promise<T>;

  /**
   * Update existing records
   */
  update<T = any>(table: string, where: Record<string, any>, data: Record<string, any>): Promise<T>;

  /**
   * Delete records
   */
  delete<T = any>(table: string, where: Record<string, any>): Promise<T>;

  /**
   * Find records
   */
  find<T = any>(table: string, where?: Record<string, any>, options?: QueryOptions): Promise<T[]>;

  /**
   * Execute raw SQL queries
   */
  query<T = any>(sql: string, params?: any[]): Promise<T[]>;

  // === PostgreSQL-specific Operations ===

  /**
   * Advanced full-text search using PostgreSQL tsvector features
   */
  fullTextSearch(options: FullTextSearchOptions): Promise<SearchResult[]>;

  /**
   * Generate UUIDs using PostgreSQL functions
   */
  generateUUID(options?: UUIDGenerationOptions): Promise<string>;

  /**
   * Generate multiple UUIDs
   */
  generateMultipleUUIDs(count: number, version?: 'v4' | 'v7'): Promise<string[]>;

  /**
   * Query execution plan analysis
   */
  explainQuery(sql: string, params?: any[], options?: ExplainOptions): Promise<ExplainResult>;

  /**
   * JSON Path Query operations
   */
  jsonPathQuery<T = any>(table: string, jsonbColumn: string, query: {
    path: string;
    filter?: string;
    vars?: Record<string, any>;
  }): Promise<T[]>;

  /**
   * Array operations for PostgreSQL JSON arrays
   */
  arrayQuery<T = any>(table: string, options: {
    column: string;
    operation: 'contains' | 'contained' | 'overlap' | 'any' | 'all' | 'append' | 'prepend' | 'remove';
    values: any[];
    index?: number;
  }): Promise<T[]>;

  // === Knowledge Storage Operations ===

  /**
   * Store knowledge items in PostgreSQL
   */
  store(items: KnowledgeItem[], options?: {
    upsert?: boolean;
    batchSize?: number;
  }): Promise<MemoryStoreResponse>;

  /**
   * Find knowledge items by ID
   */
  findById(ids: string[]): Promise<KnowledgeItem[]>;

  /**
   * Find knowledge items by scope
   */
  findByScope(scope: {
    project?: string;
    branch?: string;
    org?: string;
  }, options?: QueryOptions): Promise<KnowledgeItem[]>;

  /**
   * Get statistics about stored knowledge
   */
  getStatistics(scope?: {
    project?: string;
    branch?: string;
    org?: string;
  }): Promise<{
    totalItems: number;
    itemsByKind: Record<string, number>;
    storageSize: number;
    lastUpdated: string;
  }>;
}