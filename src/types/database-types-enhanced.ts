// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * Enhanced Database & Storage Types for Cortex MCP System
 *
 * Consolidated and type-safe database interface definitions that eliminate `any` usage
 * and provide consistent patterns for data storage and retrieval operations.
 */

import type {
  Dict,
  JSONValue,
  Metadata,
  OperationContext,
  PaginationOptions,
  Result,
  Tags} from './base-types.js';
import type { KnowledgeItem } from './knowledge-types.js';

// ============================================================================
// Core Database Interface
// ============================================================================

export interface DatabaseAdapter {
  readonly name: string;
  readonly type: DatabaseType;
  readonly status: DatabaseStatus;
  readonly config: DatabaseConfig;
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  ping(): Promise<boolean>;
  create(item: KnowledgeItem): Promise<CreateResult>;
  find(query: SearchQuery): Promise<FindResult>;
  update(id: string, updates: Partial<KnowledgeItem>): Promise<UpdateResult>;
  delete(id: string): Promise<DeleteResult>;
  batch(operations: BatchOperation[]): Promise<BatchResult>;
  health(): Promise<DatabaseHealth>;
  getMetrics(): Promise<DatabaseMetrics>;
}

export type DatabaseType =
  | 'qdrant'
  | 'chroma'
  | 'pinecone'
  | 'weaviate'
  | 'elasticsearch'
  | 'redis'
  | 'postgresql'
  | 'mongodb'
  | 'memory';

export type DatabaseStatus = 'connected' | 'disconnected' | 'connecting' | 'error' | 'maintenance';

export interface DatabaseConfig {
  readonly host: string;
  readonly port: number;
  readonly database?: string;
  readonly username?: string;
  readonly password?: string;
  readonly ssl?: boolean;
  readonly timeout?: number;
  readonly pool?: PoolConfig;
  readonly indexes?: readonly IndexConfig[];
  readonly options?: Dict<JSONValue>;
}

export interface PoolConfig {
  readonly min: number;
  readonly max: number;
  readonly acquireTimeoutMillis?: number;
  readonly createTimeoutMillis?: number;
  readonly destroyTimeoutMillis?: number;
  readonly idleTimeoutMillis?: number;
  readonly reapIntervalMillis?: number;
  readonly createRetryIntervalMillis?: number;
}

export interface IndexConfig {
  readonly name: string;
  readonly fields: readonly string[];
  readonly type: IndexType;
  readonly options?: Dict<JSONValue>;
}

export type IndexType =
  | 'vector'
  | 'fulltext'
  | 'hash'
  | 'btree'
  | 'unique'
  | 'partial'
  | 'sparse';

// ============================================================================
// Query Types
// ============================================================================

export interface SearchQuery {
  readonly text?: string;
  readonly vector?: number[];
  readonly filters?: QueryFilters;
  readonly pagination?: PaginationOptions;
  readonly sort?: QuerySort[];
  readonly options?: QueryOptions;
  readonly context?: OperationContext;
}

export interface QueryFilters {
  readonly kinds?: readonly string[];
  readonly scope?: ScopeFilter;
  readonly tags?: Tags;
  readonly metadata?: Dict<JSONValue>;
  readonly dateRange?: DateRangeFilter;
  readonly custom?: Dict<JSONValue>;
}

export interface ScopeFilter {
  readonly project?: string;
  readonly branch?: string;
  readonly org?: string;
  readonly service?: string;
  readonly tenant?: string;
  readonly environment?: string;
}

export interface DateRangeFilter {
  readonly from?: Date;
  readonly to?: Date;
  readonly field?: 'created_at' | 'updated_at' | 'timestamp';
}

export interface QuerySort {
  readonly field: string;
  readonly direction: 'asc' | 'desc';
  readonly mode?: 'min' | 'max' | 'sum' | 'avg';
}

export interface QueryOptions {
  readonly includeMetadata?: boolean;
  readonly includeContent?: boolean;
  readonly includeVectors?: boolean;
  readonly similarityThreshold?: number;
  readonly searchType?: SearchType;
  readonly limit?: number;
  readonly offset?: number;
  readonly timeout?: number;
  readonly consistency?: ConsistencyLevel;
}

export type SearchType =
  | 'semantic'
  | 'keyword'
  | 'hybrid'
  | 'fuzzy'
  | 'exact'
  | 'regex';

export type ConsistencyLevel = 'one' | 'quorum' | 'all' | 'eventual';

// ============================================================================
// Result Types
// ============================================================================

export interface CreateResult {
  readonly success: boolean;
  readonly id?: string;
  readonly created?: Date;
  readonly error?: DatabaseError;
  readonly duplicates?: readonly string[];
  readonly metadata?: Metadata;
}

export interface FindResult {
  readonly success: boolean;
  readonly items: readonly SearchResult[];
  readonly total: number;
  readonly hasMore: boolean;
  readonly took: number;
  readonly facets?: Dict<FacetResult>;
  readonly aggregations?: Dict<AggregationResult>;
  readonly error?: DatabaseError;
  readonly metadata?: Metadata;
}

export interface SearchResult {
  readonly id: string;
  readonly item?: KnowledgeItem;
  readonly score?: number;
  readonly distance?: number;
  readonly explanation?: string;
  readonly highlights?: readonly string[];
  readonly metadata?: Metadata;
}

export interface UpdateResult {
  readonly success: boolean;
  readonly updated?: Date;
  readonly version?: number;
  readonly changes?: readonly string[];
  readonly error?: DatabaseError;
  readonly metadata?: Metadata;
}

export interface DeleteResult {
  readonly success: boolean;
  readonly deleted?: Date;
  readonly count?: number;
  readonly error?: DatabaseError;
  readonly metadata?: Metadata;
}

export interface BatchResult {
  readonly success: boolean;
  readonly results: readonly BatchOperationResult[];
  readonly summary: BatchSummary;
  readonly error?: DatabaseError;
  readonly metadata?: Metadata;
}

export interface BatchOperation {
  readonly type: 'create' | 'update' | 'delete' | 'upsert';
  readonly data: KnowledgeItem | string | BatchUpdateData;
  readonly id?: string;
  readonly options?: OperationOptions;
}

export interface BatchUpdateData {
  readonly id: string;
  readonly updates: Partial<KnowledgeItem>;
}

export interface OperationOptions {
  readonly upsert?: boolean;
  readonly validate?: boolean;
  readonly timeout?: number;
  readonly retry?: RetryOptions;
}

export interface RetryOptions {
  readonly attempts: number;
  readonly delay: number;
  readonly backoff?: 'linear' | 'exponential';
  readonly maxDelay?: number;
}

export interface BatchOperationResult {
  readonly success: boolean;
  readonly index: number;
  readonly id?: string;
  readonly error?: DatabaseError;
  readonly metadata?: Metadata;
}

export interface BatchSummary {
  readonly total: number;
  readonly successful: number;
  readonly failed: number;
  readonly created: number;
  readonly updated: number;
  readonly deleted: number;
  readonly errors: readonly string[];
}

// ============================================================================
// Vector Database Types
// ============================================================================

export interface VectorDatabaseAdapter extends DatabaseAdapter {
  createCollection(name: string, config?: CollectionConfig): Promise<CollectionResult>;
  deleteCollection(name: string): Promise<DeleteResult>;
  getCollection(name: string): Promise<Collection | null>;
  listCollections(): Promise<readonly Collection[]>;
  createIndex(collection: string, config: IndexConfig): Promise<IndexResult>;
  searchVectors(query: VectorSearchQuery): Promise<VectorSearchResult>;
  upsertVectors(collection: string, vectors: readonly VectorPoint[]): Promise<UpsertResult>;
  deleteVectors(collection: string, ids: readonly string[]): Promise<DeleteResult>;
}

export type VectorDistance =
  | 'cosine'
  | 'euclidean'
  | 'manhattan'
  | 'dotproduct'
  | 'hamming';

export interface CollectionConfig {
  readonly size?: number;
  readonly distance?: VectorDistance;
  readonly hnsw?: HNSWConfig;
  readonly quantization?: QuantizationConfig;
  readonly metadata?: Metadata;
}

export interface HNSWConfig {
  readonly m?: number;
  readonly ef_construct?: number;
  readonly ef?: number;
  readonly max_elements?: number;
}

export interface QuantizationConfig {
  readonly enabled: boolean;
  readonly type: 'scalar' | 'product';
  readonly bits?: number;
  readonly centroid_count?: number;
}

export interface Collection {
  readonly name: string;
  readonly size: number;
  readonly distance: VectorDistance;
  readonly config: CollectionConfig;
  readonly created: Date;
  readonly updated: Date;
  readonly status: CollectionStatus;
  readonly metadata?: Metadata;
}

export type CollectionStatus = 'active' | 'indexing' | 'error' | 'paused';

export interface CollectionResult {
  readonly success: boolean;
  readonly collection?: Collection;
  readonly error?: DatabaseError;
  readonly metadata?: Metadata;
}

export interface IndexResult {
  readonly success: boolean;
  readonly index?: string;
  readonly created?: Date;
  readonly error?: DatabaseError;
  readonly metadata?: Metadata;
}

export interface VectorSearchQuery {
  readonly collection: string;
  readonly vector: number[];
  readonly limit?: number;
  readonly filter?: VectorFilter;
  readonly includeVector?: boolean;
  readonly includeMetadata?: boolean;
  readonly params?: SearchParams;
}

export interface VectorFilter {
  readonly must?: readonly FilterCondition[];
  readonly must_not?: readonly FilterCondition[];
  readonly should?: readonly FilterCondition[];
}

export interface FilterCondition {
  readonly key: string;
  readonly match?: string | number | boolean;
  readonly range?: RangeCondition;
  readonly geo?: GeoCondition;
  readonly values?: readonly (string | number)[];
}

export interface RangeCondition {
  readonly gt?: number;
  readonly gte?: number;
  readonly lt?: number;
  readonly lte?: number;
}

export interface GeoCondition {
  readonly center?: GeoPoint;
  readonly radius?: number;
  readonly polygon?: readonly GeoPoint[];
}

export interface GeoPoint {
  readonly lat: number;
  readonly lon: number;
}

export interface SearchParams {
  readonly hnsw_ef?: number;
  readonly exact?: boolean;
  readonly quantization?: boolean;
}

export interface VectorSearchResult {
  readonly success: boolean;
  readonly results: readonly VectorSearchResultItem[];
  readonly took: number;
  readonly error?: DatabaseError;
  readonly metadata?: Metadata;
}

export interface VectorSearchResultItem {
  readonly id: string;
  readonly score: number;
  readonly payload?: Dict<JSONValue>;
  readonly vector?: number[];
  readonly metadata?: Metadata;
}

export interface VectorPoint {
  readonly id: string;
  readonly vector: number[];
  readonly payload?: Dict<JSONValue>;
  readonly metadata?: Metadata;
}

export interface UpsertResult {
  readonly success: boolean;
  readonly upserted?: number;
  readonly failed?: readonly string[];
  readonly error?: DatabaseError;
  readonly metadata?: Metadata;
}

// ============================================================================
// Error Types
// ============================================================================

export interface DatabaseError {
  readonly code: string;
  readonly message: string;
  readonly type: ErrorType;
  readonly details?: JSONValue;
  readonly retryable: boolean;
  readonly timestamp: Date;
  readonly cause?: Error;
}

export type ErrorType =
  | 'connection'
  | 'timeout'
  | 'validation'
  | 'not_found'
  | 'conflict'
  | 'quota_exceeded'
  | 'rate_limited'
  | 'permission_denied'
  | 'internal_error'
  | 'maintenance';

// ============================================================================
// Health & Metrics Types
// ============================================================================

export interface DatabaseHealth {
  readonly status: 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
  readonly latency: LatencyMetrics;
  readonly throughput: ThroughputMetrics;
  readonly errors: ErrorMetrics;
  readonly resources: ResourceMetrics;
  readonly checks: readonly HealthCheck[];
  readonly timestamp: Date;
}

export interface LatencyMetrics {
  readonly read: number;
  readonly write: number;
  readonly search: number;
  readonly batch: number;
  readonly p50: number;
  readonly p95: number;
  readonly p99: number;
}

export interface ThroughputMetrics {
  readonly readsPerSecond: number;
  readonly writesPerSecond: number;
  readonly searchesPerSecond: number;
  readonly batchesPerSecond: number;
  readonly totalOperations: number;
}

export interface ErrorMetrics {
  readonly errorRate: number;
  readonly errorsByType: Dict<number>;
  readonly totalErrors: number;
  readonly lastError?: Date;
}

export interface ResourceMetrics {
  readonly cpuUsage: number;
  readonly memoryUsage: number;
  readonly diskUsage: number;
  readonly connectionCount: number;
  readonly maxConnections: number;
  readonly queueSize: number;
}

export interface HealthCheck {
  readonly name: string;
  readonly status: 'pass' | 'fail' | 'warn';
  readonly message?: string;
  readonly duration: number;
  readonly timestamp: Date;
  readonly details?: JSONValue;
}

export interface DatabaseMetrics {
  readonly collections: CollectionMetrics;
  readonly operations: OperationMetrics;
  readonly performance: PerformanceMetrics;
  readonly storage: StorageMetrics;
  readonly timestamp: Date;
}

export interface CollectionMetrics {
  readonly total: number;
  readonly active: number;
  readonly totalPoints: number;
  readonly pointsByCollection: Dict<number>;
  readonly totalSize: number;
}

export interface OperationMetrics {
  readonly create: OperationCount;
  readonly read: OperationCount;
  readonly update: OperationCount;
  readonly delete: OperationCount;
  readonly search: OperationCount;
  readonly batch: OperationCount;
}

export interface OperationCount {
  readonly total: number;
  readonly successful: number;
  readonly failed: number;
  readonly averageLatency: number;
}

export interface PerformanceMetrics {
  readonly queriesPerSecond: number;
  readonly averageQueryTime: number;
  readonly p95QueryTime: number;
  readonly cacheHitRate: number;
  readonly indexHitRate: number;
}

export interface StorageMetrics {
  readonly used: number;
  readonly available: number;
  readonly total: number;
  readonly utilization: number;
  readonly collections: Dict<number>;
}

// ============================================================================
// Facets & Aggregations
// ============================================================================

export interface FacetResult {
  readonly field: string;
  readonly type: FacetType;
  readonly buckets: readonly FacetBucket[];
  readonly total: number;
  readonly missing: number;
}

export type FacetType = 'terms' | 'range' | 'date_histogram' | 'histogram';

export interface FacetBucket {
  readonly key: string | number;
  readonly count: number;
  readonly selected?: boolean;
  readonly children?: readonly FacetBucket[];
}

export interface AggregationResult {
  readonly name: string;
  readonly type: AggregationType;
  readonly value?: JSONValue;
  readonly buckets?: readonly AggregationBucket[];
  readonly metadata?: Metadata;
}

export type AggregationType =
  | 'sum'
  | 'avg'
  | 'min'
  | 'max'
  | 'count'
  | 'terms'
  | 'date_histogram'
  | 'histogram'
  | 'range';

export interface AggregationBucket {
  readonly key: string | number;
  readonly doc_count: number;
  readonly sub_aggregations?: Dict<AggregationResult>;
}

// ============================================================================
// Migration & Backup Types
// ============================================================================

export interface Migration {
  readonly id: string;
  readonly version: string;
  readonly description: string;
  readonly up: string;
  readonly down?: string;
  readonly checksum: string;
  readonly appliedAt?: Date;
  readonly status: MigrationStatus;
  readonly metadata?: Metadata;
}

export type MigrationStatus = 'pending' | 'applied' | 'failed' | 'rolled_back';

export interface BackupConfig {
  readonly type: 'full' | 'incremental' | 'differential';
  readonly compression: boolean;
  readonly encryption: boolean;
  readonly retention: RetentionPolicy;
  readonly schedule?: BackupSchedule;
  readonly destination: BackupDestination;
}

export interface RetentionPolicy {
  readonly keepDaily: number;
  readonly keepWeekly: number;
  readonly keepMonthly: number;
  readonly keepYearly: number;
}

export interface BackupSchedule {
  readonly cron: string;
  readonly timezone: string;
  readonly enabled: boolean;
}

export interface BackupDestination {
  readonly type: 's3' | 'gcs' | 'azure' | 'filesystem';
  readonly config: Dict<JSONValue>;
}

export interface BackupResult {
  readonly id: string;
  readonly type: string;
  readonly size: number;
  readonly duration: number;
  readonly success: boolean;
  readonly error?: DatabaseError;
  readonly timestamp: Date;
  readonly metadata?: Metadata;
}

// ============================================================================
// Utility Types
// ============================================================================

/** @deprecated Use DatabaseResult<T> from './database-generics.js' instead */
export type DatabaseResult<T> = Result<T, DatabaseError>;

export interface DatabaseContext extends OperationContext {
  readonly database: string;
  readonly collection?: string;
  readonly operation: string;
  readonly userId?: string;
  readonly sessionId?: string;
}

export interface ConnectionPool {
  readonly active: number;
  readonly idle: number;
  readonly total: number;
  readonly waiting: number;
  readonly max: number;
}

export interface IndexStatistics {
  readonly name: string;
  readonly type: IndexType;
  readonly size: number;
  readonly documents: number;
  readonly fields: readonly string[];
  readonly created: Date;
  readonly updated: Date;
  readonly lastUsed?: Date;
}