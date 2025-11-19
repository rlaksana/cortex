// EMERGENCY ROLLBACK: Utility type guard compatibility issues

/**
 * Database Operation Type Guards
 *
 * Provides runtime type safety for database operations, query results,
 * and error discrimination with comprehensive validation functions.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import type { MemoryFindResponse, SearchResult } from '../types/core-interfaces.js';
import type {
  BatchError,
  BatchResult,
  CollectionId,
  ConnectionError,
  ConstraintError,
  DatabaseEntity,
  DatabaseError,
  DatabaseResult,
  DeleteOptions,
  DocumentDatabaseConfig,
  FilterOperator,
  KnowledgeEntity,
  LogicalOperators,
  MutationError,
  PermissionError,
  PointId,
  QueryError,
  QueryFilter,
  QueryId,
  RelationalDatabaseConfig,
  ResourceExhaustedError,
  SearchableEntity,
  SearchOptions,
  SearchQuery,
  StoreOptions,
  TimeoutError,
  Transaction,
  TransactionError,
  TransactionId,
  VectorDatabaseConfig,
} from '../types/database-generics.js';
import { ValidationError } from '../types/database-generics.js';

// ============================================================================
// Database Error Type Guards

// Enhanced error interfaces for type safety
type EnhancedQueryError = QueryError & {
  query?: string;
  parameters?: unknown[];
};

type EnhancedValidationError = ValidationError & {
  field?: string;
  value?: unknown;
  constraint?: string;
};

type EnhancedTimeoutError = TimeoutError & {
  timeout?: number;
  operation?: string;
};

type EnhancedBatchError = BatchError & {
  batchSize?: number;
  successCount?: number;
  failureCount?: number;
};
// ============================================================================

/**
 * Type guard for DatabaseError and all its subclasses
 */
export function isDatabaseError(error: unknown): error is DatabaseError {
  return error instanceof Error && 'code' in error && 'severity' in error && 'retryable' in error;
}

/**
 * Type guard for ConnectionError
 */
export function isConnectionError(error: unknown): error is ConnectionError {
  return isDatabaseError(error) && error.code === 'CONNECTION_ERROR';
}

/**
 * Type guard for QueryError
 */
export function isQueryError(error: unknown): error is QueryError {
  return isDatabaseError(error) && error.code === 'QUERY_ERROR' && 'query' in error;
}

/**
 * Type guard for MutationError
 */
export function isMutationError(error: unknown): error is MutationError {
  return isDatabaseError(error) && error.code === 'MUTATION_ERROR' && 'operation' in error;
}

/**
 * Type guard for ValidationError
 */
export function isValidationError(error: unknown): error is ValidationError {
  return (
    isDatabaseError(error) &&
    error.code === 'VALIDATION_ERROR' &&
    'field' in error &&
    'value' in error
  );
}

/**
 * Type guard for ConstraintError
 */
export function isConstraintError(error: unknown): error is ConstraintError {
  return isDatabaseError(error) && error.code === 'CONSTRAINT_ERROR' && 'constraint' in error;
}

/**
 * Type guard for TimeoutError
 */
export function isTimeoutError(error: unknown): error is TimeoutError {
  return (
    isDatabaseError(error) &&
    error.code === 'TIMEOUT_ERROR' &&
    'timeout' in error &&
    'operation' in error
  );
}

/**
 * Type guard for TransactionError
 */
export function isTransactionError(error: unknown): error is TransactionError {
  return isDatabaseError(error) && error.code === 'TRANSACTION_ERROR' && 'transactionId' in error;
}

/**
 * Type guard for BatchError
 */
export function isBatchError(error: unknown): error is BatchError {
  return (
    isDatabaseError(error) &&
    error.code === 'BATCH_ERROR' &&
    'batchSize' in error &&
    'errors' in error
  );
}

/**
 * Type guard for ResourceExhaustedError
 */
export function isResourceExhaustedError(error: unknown): error is ResourceExhaustedError {
  return (
    isDatabaseError(error) &&
    error.code === 'RESOURCE_EXHAUSTED' &&
    'resource' in error &&
    'limit' in error
  );
}

/**
 * Type guard for PermissionError
 */
export function isPermissionError(error: unknown): error is PermissionError {
  return (
    isDatabaseError(error) &&
    error.code === 'PERMISSION_ERROR' &&
    'operation' in error &&
    'resource' in error
  );
}

/**
 * Discriminate database error type with detailed information
 */
export function discriminateDatabaseError(error: unknown): {
  type: string;
  isRetryable: boolean;
  severity: string;
  details?: Record<string, unknown>;
} {
  if (!isDatabaseError(error)) {
    return {
      type: 'UnknownError',
      isRetryable: false,
      severity: 'low',
      details: { originalError: error },
    };
  }

  const baseInfo = {
    type: error.constructor.name,
    isRetryable: error.retryable,
    severity: error.severity,
    details: error.context || {},
  };

  if (isConnectionError(error)) {
    return { ...baseInfo, details: { ...baseInfo.details, endpoint: error.context?.endpoint } };
  }

  if (isQueryError(error)) {
    const queryError = error as EnhancedQueryError;
    return {
      ...baseInfo,
      details: {
        ...baseInfo.details,
        query: queryError.query,
        parameters: queryError.parameters,
      },
    };
  }

  if (isValidationError(error)) {
    const validationError = error as EnhancedValidationError;
    return {
      ...baseInfo,
      details: {
        ...baseInfo.details,
        field: validationError.field,
        value: validationError.value,
        constraint: validationError.constraint,
      },
    };
  }

  if (isTimeoutError(error)) {
    const timeoutError = error as EnhancedTimeoutError;
    return {
      ...baseInfo,
      details: {
        ...baseInfo.details,
        timeout: timeoutError.timeout,
        operation: timeoutError.operation,
      },
    };
  }

  if (isBatchError(error)) {
    const batchError = error as EnhancedBatchError;
    return {
      ...baseInfo,
      details: {
        ...baseInfo.details,
        batchSize: batchError.batchSize,
        successCount: batchError.successCount,
        failureCount: batchError.failureCount,
      },
    };
  }

  return baseInfo;
}

// ============================================================================
// Database Result Type Guards
// ============================================================================

/**
 * Type guard for DatabaseResult
 */
export function isDatabaseResult<T>(result: unknown): result is DatabaseResult<T> {
  return typeof result === 'object' && result !== null && 'success' in result;
}

/**
 * Type guard for successful DatabaseResult
 */
export function isSuccessfulResult<T>(
  result: DatabaseResult<T>
): result is { success: true; data: T } {
  return result.success === true;
}

/**
 * Type guard for failed DatabaseResult
 */
export function isFailedResult<T>(
  result: DatabaseResult<T>
): result is { success: false; error: DatabaseError } {
  return result.success === false;
}

/**
 * Type guard for BatchResult
 */
export function isBatchResult<T>(result: unknown): result is BatchResult<T> {
  return (
    typeof result === 'object' &&
    result !== null &&
    'totalCount' in result &&
    'successCount' in result &&
    'failureCount' in result &&
    'results' in result &&
    Array.isArray(result.results)
  );
}

// ============================================================================
// Query Filter Type Guards
// ============================================================================

/**
 * Type guard for FilterOperator
 */
export function isFilterOperator<T>(obj: unknown): obj is FilterOperator<T> {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const operator = obj as Record<string, unknown>;
  const operatorKeys = [
    '$eq',
    '$ne',
    '$gt',
    '$gte',
    '$lt',
    '$lte',
    '$in',
    '$nin',
    '$exists',
    '$regex',
    '$like',
  ];

  return operatorKeys.some((key) => key in operator);
}

/**
 * Type guard for LogicalOperators
 */
export function isLogicalOperators<T>(obj: unknown): obj is LogicalOperators<T> {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const logical = obj as Record<string, unknown>;
  const logicalKeys = ['$and', '$or', '$not'];

  return logicalKeys.some((key) => key in logical);
}

/**
 * Type guard for QueryFilter
 */
export function isQueryFilter<T extends Record<string, unknown>>(
  obj: unknown
): obj is QueryFilter<T> {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  // Check if it's a valid filter with either direct fields or operators
  const filter = obj as Record<string, unknown>;

  // Check for logical operators
  if (isLogicalOperators<T>(filter)) {
    return true;
  }

  // Check for field-level operators
  for (const [key, value] of Object.entries(filter)) {
    if (key.startsWith('$')) {
      // Skip logical operators as they're already checked
      if (['$and', '$or', '$not'].includes(key)) {
        continue;
      }

      if (!isFilterOperator(value)) {
        return false;
      }
    }
  }

  return true;
}

// ============================================================================
// Entity Type Guards
// ============================================================================

/**
 * Type guard for DatabaseEntity
 */
export function isDatabaseEntity(obj: unknown): obj is DatabaseEntity {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const entity = obj as Record<string, unknown>;

  return (
    typeof entity.id === 'string' &&
    typeof entity.createdAt === 'string' &&
    typeof entity.updatedAt === 'string' &&
    typeof entity.scope === 'object' &&
    entity.scope !== null
  );
}

/**
 * Type guard for KnowledgeEntity
 */
export function isKnowledgeEntity(obj: unknown): obj is KnowledgeEntity {
  if (!isDatabaseEntity(obj)) {
    return false;
  }

  const entity = obj as Record<string, unknown>;

  return typeof entity.kind === 'string' && typeof entity.data === 'object' && entity.data !== null;
}

/**
 * Type guard for SearchableEntity
 */
export function isSearchableEntity(obj: unknown): obj is SearchableEntity {
  if (!isDatabaseEntity(obj)) {
    return false;
  }

  const entity = obj as Record<string, unknown>;

  // Check for at least one searchable property
  return (
    typeof entity.content === 'string' ||
    Array.isArray(entity.embedding) ||
    typeof entity.vectors === 'object'
  );
}

// ============================================================================
// Branded Type Type Guards
// ============================================================================

/**
 * Type guard for PointId
 */
export function isPointId(obj: unknown): obj is PointId {
  return typeof obj === 'string' || typeof obj === 'number';
}

/**
 * Type guard for CollectionId
 */
export function isCollectionId(obj: unknown): obj is CollectionId {
  return typeof obj === 'string';
}

/**
 * Type guard for TransactionId
 */
export function isTransactionId(obj: unknown): obj is TransactionId {
  return typeof obj === 'string';
}

/**
 * Type guard for QueryId
 */
export function isQueryId(obj: unknown): obj is QueryId {
  return typeof obj === 'string';
}

// ============================================================================
// Configuration Type Guards
// ============================================================================

/**
 * Type guard for VectorDatabaseConfig
 */
export function isVectorDatabaseConfig(obj: unknown): obj is VectorDatabaseConfig {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const config = obj as Record<string, unknown>;

  return (
    config.type === 'qdrant' ||
    config.type === 'weaviate' ||
    config.type === 'pinecone' ||
    (config.type === 'milvus' &&
      typeof config.host === 'string' &&
      typeof config.port === 'number' &&
      typeof config.vectorSize === 'number' &&
      ['Cosine', 'Euclidean', 'Dot', 'Manhattan'].includes(config.distance as string))
  );
}

/**
 * Type guard for RelationalDatabaseConfig
 */
export function isRelationalDatabaseConfig(obj: unknown): obj is RelationalDatabaseConfig {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const config = obj as Record<string, unknown>;

  return (
    config.type === 'postgres' ||
    config.type === 'mysql' ||
    (config.type === 'sqlite' && typeof config.host === 'string' && typeof config.port === 'number')
  );
}

/**
 * Type guard for DocumentDatabaseConfig
 */
export function isDocumentDatabaseConfig(obj: unknown): obj is DocumentDatabaseConfig {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const config = obj as Record<string, unknown>;

  return (
    config.type === 'mongodb' ||
    (config.type === 'couchdb' &&
      typeof config.host === 'string' &&
      typeof config.port === 'number')
  );
}

/**
 * Type guard for any database configuration
 */
export function isDatabaseConfig(
  obj: unknown
): obj is VectorDatabaseConfig | RelationalDatabaseConfig | DocumentDatabaseConfig {
  return (
    isVectorDatabaseConfig(obj) || isRelationalDatabaseConfig(obj) || isDocumentDatabaseConfig(obj)
  );
}

// ============================================================================
// Query and Operation Type Guards
// ============================================================================

/**
 * Type guard for SearchQuery
 */
export function isSearchQuery(obj: unknown): obj is SearchQuery {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const query = obj as Record<string, unknown>;

  return (
    typeof query.query === 'string' &&
    (query.limit === undefined || typeof query.limit === 'number') &&
    (query.offset === undefined || typeof query.offset === 'number')
  );
}

/**
 * Type guard for SearchOptions
 */
export function isSearchOptions(obj: unknown): obj is SearchOptions {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const options = obj as Record<string, unknown>;

  return (
    (options.limit === undefined || typeof options.limit === 'number') &&
    (options.timeout === undefined || typeof options.timeout === 'number') &&
    (options.scoreThreshold === undefined || typeof options.scoreThreshold === 'number')
  );
}

/**
 * Type guard for StoreOptions
 */
export function isStoreOptions(obj: unknown): obj is StoreOptions {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const options = obj as Record<string, unknown>;

  return (
    (options.validate === undefined || typeof options.validate === 'boolean') &&
    (options.batchSize === undefined || typeof options.batchSize === 'number') &&
    (options.timeout === undefined || typeof options.timeout === 'number')
  );
}

/**
 * Type guard for DeleteOptions
 */
export function isDeleteOptions(obj: unknown): obj is DeleteOptions {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const options = obj as Record<string, unknown>;

  return (
    (options.cascade === undefined || typeof options.cascade === 'boolean') &&
    (options.soft === undefined || typeof options.soft === 'boolean') &&
    (options.validate === undefined || typeof options.validate === 'boolean')
  );
}

// ============================================================================
// Transaction Type Guards
// ============================================================================

/**
 * Type guard for Transaction
 */
export function isTransaction<T>(obj: unknown): obj is Transaction<T> {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const transaction = obj as Record<string, unknown>;

  return (
    isTransactionId(transaction.id) &&
    typeof transaction.isActive === 'boolean' &&
    transaction.startTime instanceof Date &&
    Array.isArray(transaction.operations) &&
    typeof transaction.commit === 'function' &&
    typeof transaction.rollback === 'function'
  );
}

// ============================================================================
// Validation Utilities
// ============================================================================

/**
 * Validate and normalize a database result
 */
export function validateDatabaseResult<T>(
  result: unknown,
  validator?: (data: unknown) => data is T
): DatabaseResult<T> {
  if (!isDatabaseResult<T>(result)) {
    return {
      success: false,
      error: new ValidationError(
        'Invalid database result format',
        'result',
        result,
        'isValidResult'
      ),
    };
  }

  if (isSuccessfulResult(result)) {
    if (validator && !validator(result.data)) {
      return {
        success: false,
        error: new ValidationError(
          'Result data validation failed',
          'data',
          result.data,
          'customValidator'
        ),
      };
    }
    return result;
  }

  return result;
}

/**
 * Validate query filter with detailed error reporting
 */
export function validateQueryFilter<T extends Record<string, unknown>>(
  filter: unknown
): {
  isValid: boolean;
  errors: string[];
  normalizedFilter?: QueryFilter<T>;
} {
  const errors: string[] = [];

  if (!filter || typeof filter !== 'object') {
    errors.push('Filter must be an object');
    return { isValid: false, errors };
  }

  if (!isQueryFilter<T>(filter)) {
    errors.push('Invalid filter structure');
    return { isValid: false, errors };
  }

  // Additional validation can be added here
  const normalizedFilter = filter as QueryFilter<T>;

  return {
    isValid: errors.length === 0,
    errors,
    normalizedFilter,
  };
}

/**
 * Validate entity with comprehensive checks
 */
export function validateEntity<T extends DatabaseEntity>(
  entity: unknown,
  entityType: 'database' | 'knowledge' | 'searchable' = 'database'
): {
  isValid: boolean;
  errors: string[];
  normalizedEntity?: T;
} {
  const errors: string[] = [];

  if (!entity || typeof entity !== 'object') {
    errors.push('Entity must be an object');
    return { isValid: false, errors };
  }

  // Basic entity validation
  if (!isDatabaseEntity(entity)) {
    errors.push('Invalid entity structure');
    return { isValid: false, errors };
  }

  // Type-specific validation
  switch (entityType) {
    case 'knowledge':
      if (!isKnowledgeEntity(entity)) {
        errors.push('Invalid knowledge entity structure');
      }
      break;
    case 'searchable':
      if (!isSearchableEntity(entity)) {
        errors.push('Invalid searchable entity structure');
      }
      break;
  }

  const normalizedEntity = entity as unknown as T;

  return {
    isValid: errors.length === 0,
    errors,
    normalizedEntity,
  };
}

// ============================================================================
// Runtime Type Conversion Utilities
// ============================================================================

/**
 * Safely convert unknown to branded type
 */
export function toPointId(id: unknown): PointId {
  if (!isPointId(id)) {
    throw new ValidationError('Invalid PointId', 'id', id, 'isPointId');
  }
  return id as PointId;
}

/**
 * Safely convert unknown to collection id
 */
export function toCollectionId(id: unknown): CollectionId {
  if (!isCollectionId(id)) {
    throw new ValidationError('Invalid CollectionId', 'id', id, 'isCollectionId');
  }
  return id as CollectionId;
}

/**
 * Safely convert unknown to transaction id
 */
export function toTransactionId(id: unknown): TransactionId {
  if (!isTransactionId(id)) {
    throw new ValidationError('Invalid TransactionId', 'id', id, 'isTransactionId');
  }
  return id as TransactionId;
}

/**
 * Safely convert unknown to query id
 */
export function toQueryId(id: unknown): QueryId {
  if (!isQueryId(id)) {
    throw new ValidationError('Invalid QueryId', 'id', id, 'isQueryId');
  }
  return id as QueryId;
}

// ============================================================================
// Qdrant Response Type Guards
// ============================================================================

/**
 * Interface for Qdrant search result points
 */
export interface QdrantPoint {
  id: string | number;
  version?: number;
  score: number;
  payload?: Record<string, unknown>;
  vector?: number[];
  shard_key?: string | number | Record<string, unknown> | (string | number)[];
}

/**
 * Interface for Qdrant search response
 */
export interface QdrantSearchResponse {
  result: QdrantPoint[];
  status: 'ok' | 'error';
  time: number;
  error?: {
    status_code: number;
    status: string;
    message: string;
  };
}

/**
 * Interface for Qdrant collection info response
 */
export interface QdrantCollectionInfo {
  result: {
    vectors: {
      size: number;
      distance: string;
    };
    points_count: number;
    segments_count: number;
    disk_data_size: number;
    ram_data_size: number;
    config: {
      params: {
        vector_size: number;
        distance: string;
        hnsw_config?: Record<string, unknown>;
      };
    };
    optimizer_config: Record<string, unknown>;
    payload_schema: Record<string, unknown>;
    status: string;
    optimizer_status: string;
    indexed_vectors_count: number;
  };
  status: 'ok' | 'error';
  time: number;
  error?: {
    status_code: number;
    status: string;
    message: string;
  };
}

/**
 * Interface for Qdrant metrics response
 */
export interface QdrantMetricsResponse {
  averageSearchTime: number;
  averageIndexingTime: number;
  totalOperations: number;
  errorRate: number;
  cacheHitRate: number;
}

/**
 * Guard for Qdrant point objects
 */
export function isQdrantPoint(value: unknown): value is QdrantPoint {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const point = value as Record<string, unknown>;

  // Check required id field (string or number)
  if (
    !('id' in point) ||
    (typeof point.id !== 'string' && typeof point.id !== 'number')
  ) {
    return false;
  }

  // Check required score field
  if (typeof point.score !== 'number' || !isFinite(point.score)) {
    return false;
  }

  // Optional fields validation
  if (point.version !== undefined && typeof point.version !== 'number') {
    return false;
  }

  if (point.payload !== undefined && (!point.payload || typeof point.payload !== 'object' || Array.isArray(point.payload))) {
    return false;
  }

  if (point.vector !== undefined && (!Array.isArray(point.vector) || !point.vector.every(v => typeof v === 'number'))) {
    return false;
  }

  return true;
}

/**
 * Guard for Qdrant search response
 */
export function isQdrantSearchResponse(value: unknown): value is QdrantSearchResponse {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const response = value as Record<string, unknown>;

  // Check required fields
  if (!('result' in response) || !Array.isArray(response.result)) {
    return false;
  }

  if (!response.result.every(isQdrantPoint)) {
    return false;
  }

  if (typeof response.status !== 'string' || !['ok', 'error'].includes(response.status)) {
    return false;
  }

  if (typeof response.time !== 'number' || !isFinite(response.time)) {
    return false;
  }

  // Optional error field
  if (response.error !== undefined && (!response.error || typeof response.error !== 'object' || Array.isArray(response.error))) {
    return false;
  }

  return true;
}

/**
 * Guard for Qdrant collection info response
 */
export function isQdrantCollectionInfo(value: unknown): value is QdrantCollectionInfo {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const response = value as Record<string, unknown>;

  // Check required fields
  if (!('result' in response) || !response.result || typeof response.result !== 'object' || Array.isArray(response.result)) {
    return false;
  }

  if (typeof response.status !== 'string' || !['ok', 'error'].includes(response.status)) {
    return false;
  }

  if (typeof response.time !== 'number' || !isFinite(response.time)) {
    return false;
  }

  const result = response.result as Record<string, unknown>;

  // Validate result structure
  if (!('vectors' in result) || !result.vectors || typeof result.vectors !== 'object' || Array.isArray(result.vectors)) {
    return false;
  }

  if (typeof result.points_count !== 'number' || !isFinite(result.points_count)) {
    return false;
  }

  const vectors = result.vectors as Record<string, unknown>;
  if (
    typeof vectors.size !== 'number' || !isFinite(vectors.size) ||
    typeof vectors.distance !== 'string'
  ) {
    return false;
  }

  return true;
}

/**
 * Guard for Qdrant metrics response
 */
export function isQdrantMetricsResponse(value: unknown): value is QdrantMetricsResponse {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const metrics = value as Record<string, unknown>;

  return (
    typeof metrics.averageSearchTime === 'number' && isFinite(metrics.averageSearchTime) &&
    typeof metrics.averageIndexingTime === 'number' && isFinite(metrics.averageIndexingTime) &&
    typeof metrics.totalOperations === 'number' && isFinite(metrics.totalOperations) &&
    typeof metrics.errorRate === 'number' && isFinite(metrics.errorRate) &&
    typeof metrics.cacheHitRate === 'number' && isFinite(metrics.cacheHitRate)
  );
}

// ============================================================================
// Audit Event Type Guards
// =============================================================================

/**
 * Interface for audit event records
 */
export interface AuditEventRecord {
  id: string;
  eventType: string;
  tableName: string;
  recordId: string;
  operation: 'INSERT' | 'UPDATE' | 'DELETE';
  oldData?: Record<string, unknown>;
  newData?: Record<string, unknown>;
  changedBy?: string;
  tags?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  createdAt: Date | string;
}

/**
 * Guard for audit event records
 */
export function isAuditEventRecord(value: unknown): value is AuditEventRecord {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const record = value as Record<string, unknown>;

  // Check required string fields
  if (
    typeof record.id !== 'string' ||
    typeof record.eventType !== 'string' ||
    typeof record.tableName !== 'string' ||
    typeof record.recordId !== 'string' ||
    typeof record.operation !== 'string'
  ) {
    return false;
  }

  // Validate operation enum
  const validOperations = ['INSERT', 'UPDATE', 'DELETE'];
  if (!validOperations.includes(record.operation)) {
    return false;
  }

  // Validate oldData and newData
  if (record.oldData !== undefined && (!record.oldData || typeof record.oldData !== 'object' || Array.isArray(record.oldData))) {
    return false;
  }

  if (record.newData !== undefined && (!record.newData || typeof record.newData !== 'object' || Array.isArray(record.newData))) {
    return false;
  }

  // Validate optional fields
  if (record.changedBy !== undefined && typeof record.changedBy !== 'string') {
    return false;
  }

  if (record.tags !== undefined && (!record.tags || typeof record.tags !== 'object' || Array.isArray(record.tags))) {
    return false;
  }

  if (record.metadata !== undefined && (!record.metadata || typeof record.metadata !== 'object' || Array.isArray(record.metadata))) {
    return false;
  }

  return true;
}

/**
 * Guard for arrays of audit event records
 */
export function isAuditEventRecords(value: unknown): value is AuditEventRecord[] {
  return Array.isArray(value) && value.every(isAuditEventRecord);
}

// ============================================================================
// Memory Find Response Type Guards
// ============================================================================

/**
 * Guard for SearchResult objects
 */
export function isSearchResult(value: unknown): value is SearchResult {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const result = value as Record<string, unknown>;

  // Basic check - SearchResult should have essential properties
  return (
    (typeof result.id === 'string' || typeof result.id === 'number') &&
    typeof result.confidence_score === 'number' && isFinite(result.confidence_score) &&
    typeof result.match_type === 'string'
  );
}

/**
 * Guard for MemoryFindResponse arrays
 */
export function isMemoryFindResponses(value: unknown): value is MemoryFindResponse[] {
  return Array.isArray(value) && value.every(isMemoryFindResponse);
}

/**
 * Guard for individual MemoryFindResponse objects
 */
export function isMemoryFindResponse(value: unknown): value is MemoryFindResponse {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const response = value as Record<string, unknown>;

  // Check required properties
  if (
    !('results' in response) || !Array.isArray(response.results) ||
    !('total_count' in response) || typeof response.total_count !== 'number'
  ) {
    return false;
  }

  // Validate results array
  if (!response.results.every(isSearchResult)) {
    return false;
  }

  // Check optional properties
  if ('items' in response && response.items !== undefined) {
    if (!Array.isArray(response.items) || !response.items.every(isSearchResult)) {
      return false;
    }
  }

  if ('total' in response && response.total !== undefined) {
    if (typeof response.total !== 'number') {
      return false;
    }
  }

  if ('metadata' in response && response.metadata !== undefined) {
    if (!response.metadata || typeof response.metadata !== 'object' || Array.isArray(response.metadata)) {
      return false;
    }
  }

  return true;
}

// ============================================================================
// Specialized Response Type Guards
// =============================================================================

/**
 * Guard for objects with should property (common in validation/configuration)
 */
export function hasShould(obj: unknown): obj is { should: Record<string, unknown> } {
  return obj != null && typeof obj === 'object' && !Array.isArray(obj) && 'should' in obj &&
         typeof (obj as Record<string, unknown>).should === 'object' && (obj as Record<string, unknown>).should !== null && !Array.isArray((obj as Record<string, unknown>).should);
}

/**
 * Guard for score threshold configuration
 */
export function hasScoreThreshold(obj: unknown): obj is { score_threshold: number } {
  return obj != null && typeof obj === 'object' && !Array.isArray(obj) && 'score_threshold' in obj &&
         typeof (obj as Record<string, unknown>).score_threshold === 'number' && isFinite(Number((obj as Record<string, unknown>).score_threshold));
}

/**
 * Guard for with_vector configuration
 */
export function hasWithVector(obj: unknown): obj is { with_vector: boolean } {
  return obj != null && typeof obj === 'object' && !Array.isArray(obj) && 'with_vector' in obj &&
         typeof (obj as Record<string, unknown>).with_vector === 'boolean';
}

/**
 * Guard for VectorConfig objects
 */
export function isVectorConfig(value: unknown): value is {
  type: string;
  host: string;
  port: number;
  database: string;
  apiKey?: string;
  timeout?: number;
  maxRetries?: number;
} {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const config = value as Record<string, unknown>;

  return (
    typeof config.type === 'string' &&
    typeof config.host === 'string' &&
    typeof config.port === 'number' && isFinite(config.port) && config.port > 0 &&
    typeof config.database === 'string'
  );
}

/**
 * Guard for objects with title and name properties
 */
export function hasTitleAndName(obj: unknown): obj is { title: string; name: string } {
  return obj != null && typeof obj === 'object' && !Array.isArray(obj) &&
         'title' in obj && 'name' in obj &&
         typeof (obj as Record<string, unknown>).title === 'string' &&
         typeof (obj as Record<string, unknown>).name === 'string';
}

/**
 * Guard for objects with description and content properties
 */
export function hasDescriptionAndContent(obj: unknown): obj is {
  description: string;
  content: string;
} {
  return obj != null && typeof obj === 'object' && !Array.isArray(obj) &&
         'description' in obj && 'content' in obj &&
         typeof (obj as Record<string, unknown>).description === 'string' &&
         typeof (obj as Record<string, unknown>).content === 'string';
}

// ============================================================================
// Utility Functions for Safe Database Operations
// =============================================================================

/**
 * Safe property accessor for error objects
 */
export function safeErrorProperty(obj: unknown): { message?: string; code?: string | number } {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    return {};
  }

  const result: { message?: string; code?: string | number } = {};
  const record = obj as Record<string, unknown>;

  if ('message' in record && typeof record.message === 'string') {
    result.message = record.message;
  }

  if ('code' in record && (typeof record.code === 'string' || typeof record.code === 'number')) {
    result.code = record.code;
  }

  return result;
}

/**
 * Safe accessor for Qdrant point properties
 */
export function safeQdrantPointAccess(point: unknown): Partial<QdrantPoint> {
  if (!isQdrantPoint(point)) {
    return {};
  }

  return {
    id: point.id,
    score: point.score,
    payload: point.payload,
    vector: point.vector,
    version: point.version,
    shard_key: point.shard_key,
  };
}

/**
 * Safe accessor for audit event properties
 */
export function safeAuditEventAccess(event: unknown): Partial<AuditEventRecord> {
  if (!isAuditEventRecord(event)) {
    return {};
  }

  return {
    id: event.id,
    eventType: event.eventType,
    tableName: event.tableName,
    recordId: event.recordId,
    operation: event.operation,
    oldData: event.oldData,
    newData: event.newData,
    changedBy: event.changedBy,
    tags: event.tags,
    metadata: event.metadata,
  };
}

/**
 * Type-safe database result unwrapper
 */
export function unwrapDatabaseResult<T>(
  result: unknown,
  dataGuard?: (value: unknown) => value is T
): DatabaseResult<T> {
  if (!result || typeof result !== 'object' || Array.isArray(result)) {
    return {
      success: false,
      error: new ValidationError('Invalid database result format', 'result', result, 'isDatabaseResult'),
    };
  }

  const dbResult = result as Record<string, unknown>;

  if (dbResult.success === true) {
    if (dbResult.data === undefined) {
      return {
        success: false,
        error: new ValidationError('Missing data in successful result', 'data', undefined, 'hasData'),
      };
    }

    if (dataGuard && !dataGuard(dbResult.data)) {
      return {
        success: false,
        error: new ValidationError('Result data validation failed', 'data', dbResult.data, 'dataGuard'),
      };
    }

    return {
      success: true,
      data: dbResult.data as T,
      metadata: dbResult.metadata as Record<string, unknown> | undefined,
    };
  }

  if (dbResult.success === false && dbResult.error !== undefined) {
    // Ensure the error conforms to DatabaseError interface
    const error = dbResult.error as DatabaseError;
    return {
      success: false,
      error: error,
      metadata: dbResult.metadata as Record<string, unknown> | undefined,
    };
  }

  // Default to error case for unknown result structures
  return {
    success: false,
    error: new ValidationError('Invalid database result structure', 'result', result, 'hasSuccessProperty'),
  };
}

/**
 * Type-safe array database result unwrapper
 */
export function unwrapDatabaseResultAsArray<T>(
  result: unknown,
  itemGuard: (value: unknown) => value is T
): DatabaseResult<T[]> {
  const unwrapped = unwrapDatabaseResult(result, (data): data is T[] => {
    return Array.isArray(data) && data.every(itemGuard);
  });

  if (unwrapped.success) {
    return {
      success: true,
      data: unwrapped.data as T[],
      metadata: unwrapped.metadata,
    };
  }

  return unwrapped;
}

// ============================================================================
// Enhanced Database Result Type Guards
// ============================================================================

/**
 * Type guard for successful database results with enhanced validation
 */
export function isSuccessfulDatabaseResult<T>(
  result: unknown,
  dataGuard?: (value: unknown) => value is T
): result is { success: true; data: T; metadata?: Record<string, unknown> } {
  if (!result || typeof result !== 'object' || Array.isArray(result)) {
    return false;
  }

  const databaseResult = result as Record<string, unknown>;

  if (databaseResult.success !== true) {
    return false;
  }

  if (databaseResult.data === undefined) {
    return false;
  }

  return dataGuard ? dataGuard(databaseResult.data) : true;
}

/**
 * Type guard for failed database results with enhanced validation
 */
export function isFailedDatabaseResult(
  result: unknown
): result is { success: false; error: unknown; metadata?: Record<string, unknown> } {
  if (!result || typeof result !== 'object' || Array.isArray(result)) {
    return false;
  }

  const databaseResult = result as Record<string, unknown>;

  return databaseResult.success === false && databaseResult.error !== undefined;
}

/**
 * Enhanced type guard for any database result
 */
export function isEnhancedDatabaseResult<T>(
  value: unknown,
  dataGuard?: (value: unknown) => value is T
): value is DatabaseResult<T> {
  return isSuccessfulDatabaseResult(value, dataGuard) || isFailedDatabaseResult(value);
}

// ============================================================================
// Error Recovery Utilities
// ============================================================================

/**
 * Determine if an error is recoverable and suggest retry strategy
 */
export function getErrorRecoveryStrategy(error: unknown): {
  isRecoverable: boolean;
  retryStrategy: 'immediate' | 'exponential_backoff' | 'linear_backoff' | 'no_retry';
  maxRetries?: number;
  baseDelay?: number;
  message: string;
} {
  const errorInfo = discriminateDatabaseError(error);

  // Connection errors are generally recoverable with exponential backoff
  if (isConnectionError(error)) {
    return {
      isRecoverable: true,
      retryStrategy: 'exponential_backoff',
      maxRetries: 5,
      baseDelay: 1000,
      message: 'Connection error - retrying with exponential backoff',
    };
  }

  // Timeout errors are recoverable with linear backoff
  if (isTimeoutError(error)) {
    return {
      isRecoverable: true,
      retryStrategy: 'linear_backoff',
      maxRetries: 3,
      baseDelay: 500,
      message: 'Timeout error - retrying with linear backoff',
    };
  }

  // Resource exhausted errors need exponential backoff
  if (isResourceExhaustedError(error)) {
    return {
      isRecoverable: true,
      retryStrategy: 'exponential_backoff',
      maxRetries: 3,
      baseDelay: 2000,
      message: 'Resource exhausted - retrying with exponential backoff',
    };
  }

  // Validation and constraint errors are not recoverable
  if (isValidationError(error) || isConstraintError(error)) {
    return {
      isRecoverable: false,
      retryStrategy: 'no_retry',
      message: 'Validation/constraint error - not retryable',
    };
  }

  // Permission errors are not recoverable
  if (isPermissionError(error)) {
    return {
      isRecoverable: false,
      retryStrategy: 'no_retry',
      message: 'Permission error - not retryable',
    };
  }

  // Default strategy based on error properties
  if (errorInfo.isRetryable) {
    return {
      isRecoverable: true,
      retryStrategy: 'exponential_backoff',
      maxRetries: 3,
      baseDelay: 1000,
      message: 'Error marked as retryable - using exponential backoff',
    };
  }

  return {
    isRecoverable: false,
    retryStrategy: 'no_retry',
    message: 'Unknown error - not retryable',
  };
}
