/**
 * Enhanced Database Generic Types
 *
 * Provides type-safe generic constraints for database operations,
 * eliminating `any` usage while maintaining flexibility and performance.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

// ============================================================================
// Branded Types for Database Identifiers
// ============================================================================

export type DatabaseId<T extends string = string> = T & { __brand: 'DatabaseId' };
export type CollectionId = DatabaseId<'collection'>;
export type PointId = DatabaseId<'point'>;
export type TransactionId = DatabaseId<'transaction'>;
export type SessionId = DatabaseId<'session'>;
export type QueryId = DatabaseId<'query'>;

// ============================================================================
// Base Generic Constraints
// ============================================================================

export interface Identifiable {
  readonly id: string;
}

export interface Timestamped {
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface Versioned {
  readonly version: number;
}

export interface Scopable {
  readonly scope: {
    project?: string;
    branch?: string;
    org?: string;
    environment?: string;
  };
}

export interface Expirable {
  readonly expiryAt?: string;
  readonly ttlPolicy?: string;
}

export interface Tagged {
  readonly tags?: readonly string[];
}

export interface MetadataCarrier {
  readonly metadata?: Readonly<Record<string, unknown>>;
}

// ============================================================================
// Database Entity Base Types
// ============================================================================

export interface DatabaseEntity
  extends Identifiable,
    Timestamped,
    Scopable,
    Record<string, unknown> {}

export interface KnowledgeEntity extends DatabaseEntity {
  readonly kind: string;
  readonly data: Readonly<Record<string, unknown>>;
  readonly expiryAt?: string;
  readonly ttlPolicy?: string;
  readonly tags?: readonly string[];
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface SearchableEntity extends DatabaseEntity {
  readonly content?: string;
  readonly embedding?: readonly number[];
  readonly vectors?: Readonly<Record<string, readonly number[]>>;
}

// ============================================================================
// Generic Operation Types
// ============================================================================

export type DatabaseOperation<TInput, TOutput, TError = DatabaseError> = {
  readonly input: TInput;
  readonly output: Promise<TOutput>;
  readonly error?: TError;
};

export type QueryOperation<TFilter, TResult> = DatabaseOperation<TFilter, TResult, QueryError>;

export type MutationOperation<TData, TResult> = DatabaseOperation<TData, TResult, MutationError>;

export type BatchOperation<TInput, TOutput> = DatabaseOperation<
  readonly TInput[],
  BatchResult<TOutput>,
  BatchError
>;

// ============================================================================
// Enhanced Generic Constraints
// ============================================================================

export type Validated<T> = T & { __validated: true };
export type Sanitized<T> = T & { __sanitized: true };

export type DatabaseRecord<T extends Record<string, unknown> = Record<string, unknown>> =
  Validated<T> & Identifiable & Timestamped;

export type QueryFilter<T = Record<string, unknown>> = {
  readonly [K in keyof T]?: T[K] extends readonly (infer U)[]
    ? readonly U[] | FilterOperator<T[K]>
    : T[K] | FilterOperator<T[K]>;
} & LogicalOperators<T>;

export type FilterOperator<T> =
  | { $eq: T }
  | { $ne: T }
  | { $gt: T }
  | { $gte: T }
  | { $lt: T }
  | { $lte: T }
  | { $in: readonly T[] }
  | { $nin: readonly T[] }
  | { $exists: boolean }
  | { $regex: RegExp }
  | { $like: string };

export type LogicalOperators<T> = {
  readonly $and?: readonly QueryFilter<T>[];
  readonly $or?: readonly QueryFilter<T>[];
  readonly $not?: QueryFilter<T>;
};

export type SortOrder = 'asc' | 'desc';
export type SortDirection<T extends Record<string, unknown> = Record<string, unknown>> = {
  readonly [K in keyof T]?: SortOrder;
};

export type QueryOptions<T extends Record<string, unknown> = Record<string, unknown>> = {
  readonly limit?: number;
  readonly offset?: number;
  readonly sort?: SortDirection<T>;
  readonly projection?: readonly (keyof T)[];
  readonly includeMetadata?: boolean;
  readonly timeout?: number;
  readonly consistency?: ReadConsistency;
};

export type ReadConsistency = 'strong' | 'eventual' | 'session' | { type: 'quorum'; value: number };

// ============================================================================
// Generic Result Types
// ============================================================================

export type DatabaseResult<T, E = DatabaseError> =
  | {
      readonly success: true;
      readonly data: T;
      readonly metadata?: Readonly<Record<string, unknown>>;
    }
  | {
      readonly success: false;
      readonly error: E;
      readonly metadata?: Readonly<Record<string, unknown>>;
    };

export type BatchResult<T> = {
  readonly totalCount: number;
  readonly successCount: number;
  readonly failureCount: number;
  readonly results: readonly DatabaseResult<T>[];
  readonly errors: readonly DatabaseError[];
  readonly executionTimeMs: number;
};

export type PaginatedResult<T> = {
  readonly items: readonly T[];
  readonly totalCount: number;
  readonly currentPage: number;
  readonly totalPages: number;
  readonly hasNext: boolean;
  readonly hasPrevious: boolean;
};

export type SearchResult<T extends SearchableEntity> = {
  readonly item: T;
  readonly score: number;
  readonly matchType: 'exact' | 'fuzzy' | 'semantic';
  readonly highlights?: readonly string[];
  readonly explanation?: string;
};

export type SearchResponse<T extends SearchableEntity> = {
  readonly results: readonly SearchResult<T>[];
  readonly totalCount: number;
  readonly searchTimeMs: number;
  readonly queryId: QueryId;
  readonly metadata?: Readonly<Record<string, unknown>>;
};

// ============================================================================
// Enhanced Error Types
// ============================================================================

export abstract class DatabaseError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly severity: 'low' | 'medium' | 'high' | 'critical',
    public readonly retryable: boolean,
    public readonly context?: Readonly<Record<string, unknown>>,
    public readonly cause?: Error
  ) {
    super(message);
    this.name = this.constructor.name;
  }
}

export class ConnectionError extends DatabaseError {
  constructor(message: string, context?: Readonly<Record<string, unknown>>, cause?: Error) {
    super(message, 'CONNECTION_ERROR', 'high', true, context, cause);
  }
}

export class QueryError extends DatabaseError {
  constructor(
    message: string,
    public readonly query: string,
    public readonly parameters?: Readonly<unknown[]>,
    context?: Readonly<Record<string, unknown>>,
    cause?: Error
  ) {
    super(message, 'QUERY_ERROR', 'medium', false, { query, parameters, ...context }, cause);
  }
}

export class MutationError extends DatabaseError {
  constructor(
    message: string,
    public readonly operation: string,
    public readonly entity?: Readonly<Record<string, unknown>>,
    context?: Readonly<Record<string, unknown>>,
    cause?: Error
  ) {
    super(message, 'MUTATION_ERROR', 'medium', false, { operation, entity, ...context }, cause);
  }
}

export class ValidationError extends DatabaseError {
  constructor(
    message: string,
    public readonly field: string,
    public readonly value: unknown,
    public readonly constraint: string,
    context?: Readonly<Record<string, unknown>>
  ) {
    super(message, 'VALIDATION_ERROR', 'medium', false, { field, value, constraint, ...context });
  }
}

export class ConstraintError extends DatabaseError {
  constructor(
    message: string,
    public readonly constraint: string,
    public readonly entity?: Readonly<Record<string, unknown>>,
    context?: Readonly<Record<string, unknown>>
  ) {
    super(message, 'CONSTRAINT_ERROR', 'medium', false, { constraint, entity, ...context });
  }
}

export class TimeoutError extends DatabaseError {
  constructor(
    message: string,
    public readonly timeout: number,
    public readonly operation: string,
    context?: Readonly<Record<string, unknown>>
  ) {
    super(message, 'TIMEOUT_ERROR', 'high', true, { timeout, operation, ...context });
  }
}

export class TransactionError extends DatabaseError {
  constructor(
    message: string,
    public readonly transactionId: TransactionId,
    public readonly operation: string,
    context?: Readonly<Record<string, unknown>>,
    cause?: Error
  ) {
    super(
      message,
      'TRANSACTION_ERROR',
      'high',
      false,
      { transactionId: transactionId, operation, ...context },
      cause
    );
  }
}

export class BatchError extends DatabaseError {
  constructor(
    message: string,
    public readonly batchSize: number,
    public readonly successCount: number,
    public readonly failureCount: number,
    public readonly errors: readonly DatabaseError[],
    context?: Readonly<Record<string, unknown>>
  ) {
    super(message, 'BATCH_ERROR', 'medium', false, {
      batchSize,
      successCount,
      failureCount,
      ...context,
    });
  }
}

export class ResourceExhaustedError extends DatabaseError {
  constructor(
    message: string,
    public readonly resource: string,
    public readonly limit: number,
    public readonly current: number,
    context?: Readonly<Record<string, unknown>>
  ) {
    super(message, 'RESOURCE_EXHAUSTED', 'high', true, { resource, limit, current, ...context });
  }
}

export class PermissionError extends DatabaseError {
  constructor(
    message: string,
    public readonly operation: string,
    public readonly resource: string,
    public readonly userId?: string,
    context?: Readonly<Record<string, unknown>>
  ) {
    super(message, 'PERMISSION_ERROR', 'medium', false, {
      operation,
      resource,
      userId,
      ...context,
    });
  }
}

export class SystemError extends DatabaseError {
  constructor(message: string, context?: Readonly<Record<string, unknown>>, cause?: Error) {
    super(message, 'SYSTEM_ERROR', 'high', false, context, cause);
  }
}

// ============================================================================
// Generic Database Interface Types
// ============================================================================

export interface DatabaseConnection<TClient = unknown> {
  readonly client: TClient;
  readonly isConnected: boolean;
  readonly lastHealthCheck: Date;
  readonly connectionId: string;
  readonly endpoint: string;
  readonly capabilities: DatabaseCapabilities;
}

export interface DatabaseCapabilities {
  readonly supportsTransactions: boolean;
  readonly supportsVectorSearch: boolean;
  readonly supportsFullTextSearch: boolean;
  readonly supportsBatchOperations: boolean;
  readonly supportsStreaming: boolean;
  readonly maxBatchSize: number;
  readonly maxConnections: number;
  readonly supportedOperations: readonly string[];
  readonly consistencyLevels: readonly ReadConsistency[];
}

export interface TransactionOptions {
  readonly isolation?: 'read_uncommitted' | 'read_committed' | 'repeatable_read' | 'serializable';
  readonly readOnly?: boolean;
  readonly timeout?: number;
  readonly retryCount?: number;
}

export interface Transaction<TClient = unknown> {
  readonly id: TransactionId;
  readonly client: TClient;
  readonly isActive: boolean;
  readonly startTime: Date;
  readonly operations: readonly DatabaseOperation<unknown, unknown>[];

  commit(): Promise<void>;
  rollback(): Promise<void>;
  addOperation<TInput, TOutput>(operation: DatabaseOperation<TInput, TOutput>): void;
}

export interface DatabaseMetrics {
  readonly connectionCount: number;
  readonly queryLatency: number;
  readonly storageSize: number;
  readonly vectorCount?: number;
  readonly lastHealthCheck: Date;
  readonly uptime: number;
  readonly errorRate: number;
  readonly throughput: number;
  readonly cacheHitRate?: number;
}

// ============================================================================
// Generic Query Builder Types
// ============================================================================

export interface QueryBuilder<T extends Record<string, unknown> = Record<string, unknown>> {
  filter(predicate: QueryFilter<T>): QueryBuilder<T>;
  sort(sort: SortDirection<T>): QueryBuilder<T>;
  limit(count: number): QueryBuilder<T>;
  offset(count: number): QueryBuilder<T>;
  project<K extends keyof T>(fields: readonly K[]): QueryBuilder<Pick<T, K>>;
  options(options: QueryOptions<T>): QueryBuilder<T>;
  build(): QueryFilter<T>;
  execute(): Promise<readonly T[]>;
  first(): Promise<T | null>;
  count(): Promise<number>;
  exists(): Promise<boolean>;
}

export interface MutationBuilder<T extends Record<string, unknown> = Record<string, unknown>> {
  insert(data: readonly T[]): MutationBuilder<T>;
  update(filter: QueryFilter<T>, changes: Partial<T>): MutationBuilder<T>;
  upsert(data: readonly T[]): MutationBuilder<T>;
  delete(filter: QueryFilter<T>): MutationBuilder<T>;
  options(options: {
    readonly validate?: boolean;
    readonly batchSize?: number;
  }): MutationBuilder<T>;
  execute(): Promise<BatchResult<T>>;
}

// ============================================================================
// Type Guards and Runtime Validation
// ============================================================================

export function isDatabaseError(error: unknown): error is DatabaseError {
  return error instanceof DatabaseError;
}

export function isConnectionError(error: unknown): error is ConnectionError {
  return error instanceof ConnectionError;
}

export function isQueryError(error: unknown): error is QueryError {
  return error instanceof QueryError;
}

export function isMutationError(error: unknown): error is MutationError {
  return error instanceof MutationError;
}

export function isValidationError(error: unknown): error is ValidationError {
  return error instanceof ValidationError;
}

export function isBatchError(error: unknown): error is BatchError {
  return error instanceof BatchError;
}

export function isDatabaseResult<T>(result: unknown): result is DatabaseResult<T> {
  return typeof result === 'object' && result !== null && 'success' in result;
}

export function isSuccessfulResult<T>(
  result: DatabaseResult<T>
): result is { success: true; data: T } {
  return result.success;
}

export function isFailedResult<T>(
  result: DatabaseResult<T>
): result is { success: false; error: DatabaseError } {
  return !result.success;
}

// ============================================================================
// Utility Types for Database Operations
// ============================================================================

export type DeepReadonly<T> = {
  readonly [P in keyof T]: T[P] extends object ? DeepReadonly<T[P]> : T[P];
};

export type RequiredFields<T, K extends keyof T> = T & Required<Pick<T, K>>;

export type OptionalFields<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;

export type DatabaseEntityWith<
  T extends Record<string, unknown>,
  K extends keyof T,
> = RequiredFields<T, 'id' | 'createdAt' | 'updatedAt'> & K extends string
  ? RequiredFields<T, K>
  : T;

export type SearchQuery = {
  readonly query: string;
  readonly limit?: number;
  readonly offset?: number;
  readonly filter?: QueryFilter<SearchableEntity>;
  readonly options?: QueryOptions<SearchableEntity>;
  readonly scope?: Scopable['scope'];
  readonly types?: readonly string[];
  readonly mode?: 'auto' | 'semantic' | 'exact' | 'hybrid';
};

export type SearchOptions = QueryOptions<SearchableEntity> & {
  readonly includeVector?: boolean;
  readonly includeMetadata?: boolean;
  readonly scoreThreshold?: number;
  readonly searchMode?: 'semantic' | 'hybrid' | 'exact';
  readonly keywordWeight?: number;
  readonly semanticWeight?: number;
};

export type StoreOptions = {
  readonly validate?: boolean;
  readonly batchSize?: number;
  readonly skipDuplicates?: boolean;
  readonly generateEmbeddings?: boolean;
  readonly timeout?: number;
  readonly upsert?: boolean;
};

export type DeleteOptions = {
  readonly cascade?: boolean;
  readonly soft?: boolean;
  readonly validate?: boolean;
  readonly timeout?: number;
};

// ============================================================================
// Type-safe Database Configuration
// ============================================================================

export interface DatabaseConfig {
  readonly type: string;
  readonly host: string;
  readonly port: number;
  readonly database: string;
  readonly credentials?: {
    readonly username?: string;
    readonly password?: string;
    readonly apiKey?: string;
  };
  readonly ssl?: {
    readonly enabled: boolean;
    readonly ca?: string;
    readonly cert?: string;
    readonly key?: string;
  };
  readonly pool?: {
    readonly min: number;
    readonly max: number;
    readonly acquireTimeout: number;
    readonly idleTimeout: number;
  };
  readonly timeout?: number;
  readonly retryAttempts?: number;
  readonly retryDelay?: number;
  readonly logQueries?: boolean;
  readonly logSlowQueries?: number;
}

export interface VectorDatabaseConfig extends DatabaseConfig {
  readonly type: 'qdrant' | 'weaviate' | 'pinecone' | 'milvus';
  readonly vectorSize?: number;
  readonly distance?: 'Cosine' | 'Euclidean' | 'Dot' | 'Manhattan';
  readonly collectionName?: string;
  readonly indexing?: {
    readonly type: 'HNSW' | 'IVF' | 'FLAT';
    readonly parameters?: Readonly<Record<string, unknown>>;
  };
}

export interface RelationalDatabaseConfig extends DatabaseConfig {
  readonly type: 'postgres' | 'mysql' | 'sqlite';
  readonly schema?: string;
  readonly migrations?: {
    readonly enabled: boolean;
    readonly path: string;
    readonly autoRun: boolean;
  };
}

export interface DocumentDatabaseConfig extends DatabaseConfig {
  readonly type: 'mongodb' | 'couchdb';
  readonly collection?: string;
  readonly indexes?: ReadonlyArray<{
    readonly fields: Readonly<Record<string, 1 | -1>>;
    readonly unique?: boolean;
    readonly sparse?: boolean;
  }>;
}

// ============================================================================
// Error Types
// ============================================================================

export class NotFoundError extends Error {
  constructor(
    message: string,
    public readonly code?: string
  ) {
    super(message);
    this.name = 'NotFoundError';
  }
}
