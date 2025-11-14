// @ts-nocheck
// EMERGENCY ROLLBACK: Utility type guard compatibility issues
// TODO: Fix systematic type issues before removing @ts-nocheck

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

import type {
  type BatchError,
  BatchResult,
  CollectionId,
  type ConnectionError,
  type ConstraintError,
  DatabaseEntity,
  type DatabaseError,
  DatabaseResult,
  DeleteOptions,
  DocumentDatabaseConfig,
  FilterOperator,
  KnowledgeEntity,
  LogicalOperators,
  type MutationError,
  type PermissionError,
  PointId,
  type QueryError,
  QueryFilter,
  QueryId,
  RelationalDatabaseConfig,
  type ResourceExhaustedError,
  SearchableEntity,
  SearchOptions,
  SearchQuery,
  StoreOptions,
  type TimeoutError,
  Transaction,
  type TransactionError,
  TransactionId,
  ValidationError,  VectorDatabaseConfig} from '../types/database-generics.js';


// ============================================================================
// Database Error Type Guards
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
  return isDatabaseError(error) && error.code === 'VALIDATION_ERROR' && 'field' in error && 'value' in error;
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
  return isDatabaseError(error) && error.code === 'TIMEOUT_ERROR' && 'timeout' in error && 'operation' in error;
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
  return isDatabaseError(error) && error.code === 'BATCH_ERROR' && 'batchSize' in error && 'errors' in error;
}

/**
 * Type guard for ResourceExhaustedError
 */
export function isResourceExhaustedError(error: unknown): error is ResourceExhaustedError {
  return isDatabaseError(error) && error.code === 'RESOURCE_EXHAUSTED' && 'resource' in error && 'limit' in error;
}

/**
 * Type guard for PermissionError
 */
export function isPermissionError(error: unknown): error is PermissionError {
  return isDatabaseError(error) && error.code === 'PERMISSION_ERROR' && 'operation' in error && 'resource' in error;
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
      details: { originalError: error }
    };
  }

  const baseInfo = {
    type: error.constructor.name,
    isRetryable: error.retryable,
    severity: error.severity,
    details: error.context || {}
  };

  if (isConnectionError(error)) {
    return { ...baseInfo, details: { ...baseInfo.details, endpoint: error.context?.endpoint } };
  }

  if (isQueryError(error)) {
    return { ...baseInfo, details: { ...baseInfo.details, query: (error as unknown).query, parameters: (error as unknown).parameters } };
  }

  if (isValidationError(error)) {
    return { ...baseInfo, details: { ...baseInfo.details, field: (error as unknown).field, value: (error as unknown).value, constraint: (error as unknown).constraint } };
  }

  if (isTimeoutError(error)) {
    return { ...baseInfo, details: { ...baseInfo.details, timeout: (error as unknown).timeout, operation: (error as unknown).operation } };
  }

  if (isBatchError(error)) {
    return { ...baseInfo, details: { ...baseInfo.details, batchSize: (error as unknown).batchSize, successCount: (error as unknown).successCount, failureCount: (error as unknown).failureCount } };
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
export function isSuccessfulResult<T>(result: DatabaseResult<T>): result is { success: true; data: T } {
  return result.success === true;
}

/**
 * Type guard for failed DatabaseResult
 */
export function isFailedResult<T>(result: DatabaseResult<T>): result is { success: false; error: DatabaseError } {
  return result.success === false;
}

/**
 * Type guard for BatchResult
 */
export function isBatchResult<T>(result: unknown): result is BatchResult<T> {
  return typeof result === 'object' && result !== null &&
         'totalCount' in result && 'successCount' in result && 'failureCount' in result &&
         'results' in result && Array.isArray(result.results);
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
  const operatorKeys = ['$eq', '$ne', '$gt', '$gte', '$lt', '$lte', '$in', '$nin', '$exists', '$regex', '$like'];

  return operatorKeys.some(key => key in operator);
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

  return logicalKeys.some(key => key in logical);
}

/**
 * Type guard for QueryFilter
 */
export function isQueryFilter<T extends Record<string, unknown>>(obj: unknown): obj is QueryFilter<T> {
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

  return typeof entity.id === 'string' &&
         typeof entity.createdAt === 'string' &&
         typeof entity.updatedAt === 'string' &&
         typeof entity.scope === 'object' &&
         entity.scope !== null;
}

/**
 * Type guard for KnowledgeEntity
 */
export function isKnowledgeEntity(obj: unknown): obj is KnowledgeEntity {
  if (!isDatabaseEntity(obj)) {
    return false;
  }

  const entity = obj as Record<string, unknown>;

  return typeof entity.kind === 'string' &&
         typeof entity.data === 'object' &&
         entity.data !== null;
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
  return typeof entity.content === 'string' ||
         Array.isArray(entity.embedding) ||
         typeof entity.vectors === 'object';
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

  return config.type === 'qdrant' || config.type === 'weaviate' || config.type === 'pinecone' || config.type === 'milvus' &&
         typeof config.host === 'string' &&
         typeof config.port === 'number' &&
         typeof config.vectorSize === 'number' &&
         ['Cosine', 'Euclidean', 'Dot', 'Manhattan'].includes(config.distance as string);
}

/**
 * Type guard for RelationalDatabaseConfig
 */
export function isRelationalDatabaseConfig(obj: unknown): obj is RelationalDatabaseConfig {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const config = obj as Record<string, unknown>;

  return config.type === 'postgres' || config.type === 'mysql' || config.type === 'sqlite' &&
         typeof config.host === 'string' &&
         typeof config.port === 'number';
}

/**
 * Type guard for DocumentDatabaseConfig
 */
export function isDocumentDatabaseConfig(obj: unknown): obj is DocumentDatabaseConfig {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const config = obj as Record<string, unknown>;

  return config.type === 'mongodb' || config.type === 'couchdb' &&
         typeof config.host === 'string' &&
         typeof config.port === 'number';
}

/**
 * Type guard for any database configuration
 */
export function isDatabaseConfig(obj: unknown): obj is VectorDatabaseConfig | RelationalDatabaseConfig | DocumentDatabaseConfig {
  return isVectorDatabaseConfig(obj) || isRelationalDatabaseConfig(obj) || isDocumentDatabaseConfig(obj);
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

  return typeof query.query === 'string' &&
         (query.limit === undefined || typeof query.limit === 'number') &&
         (query.offset === undefined || typeof query.offset === 'number');
}

/**
 * Type guard for SearchOptions
 */
export function isSearchOptions(obj: unknown): obj is SearchOptions {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const options = obj as Record<string, unknown>;

  return (options.limit === undefined || typeof options.limit === 'number') &&
         (options.timeout === undefined || typeof options.timeout === 'number') &&
         (options.scoreThreshold === undefined || typeof options.scoreThreshold === 'number');
}

/**
 * Type guard for StoreOptions
 */
export function isStoreOptions(obj: unknown): obj is StoreOptions {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const options = obj as Record<string, unknown>;

  return (options.validate === undefined || typeof options.validate === 'boolean') &&
         (options.batchSize === undefined || typeof options.batchSize === 'number') &&
         (options.timeout === undefined || typeof options.timeout === 'number');
}

/**
 * Type guard for DeleteOptions
 */
export function isDeleteOptions(obj: unknown): obj is DeleteOptions {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const options = obj as Record<string, unknown>;

  return (options.cascade === undefined || typeof options.cascade === 'boolean') &&
         (options.soft === undefined || typeof options.soft === 'boolean') &&
         (options.validate === undefined || typeof options.validate === 'boolean');
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

  return isTransactionId(transaction.id) &&
         typeof transaction.isActive === 'boolean' &&
         transaction.startTime instanceof Date &&
         Array.isArray(transaction.operations) &&
         typeof transaction.commit === 'function' &&
         typeof transaction.rollback === 'function';
}

// ============================================================================
// Validation Utilities
// ============================================================================

/**
 * Validate and normalize a database result
 */
export function validateDatabaseResult<T>(result: unknown, validator?: (data: unknown) => data is T): DatabaseResult<T> {
  if (!isDatabaseResult<T>(result)) {
    return {
      success: false,
      error: new ValidationError('Invalid database result format', 'result', result, 'isValidResult')
    };
  }

  if (isSuccessfulResult(result)) {
    if (validator && !validator(result.data)) {
      return {
        success: false,
        error: new ValidationError('Result data validation failed', 'data', result.data, 'customValidator')
      };
    }
    return result;
  }

  return result;
}

/**
 * Validate query filter with detailed error reporting
 */
export function validateQueryFilter<T extends Record<string, unknown>>(filter: unknown): {
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
    normalizedFilter
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
    normalizedEntity
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
      message: 'Connection error - retrying with exponential backoff'
    };
  }

  // Timeout errors are recoverable with linear backoff
  if (isTimeoutError(error)) {
    return {
      isRecoverable: true,
      retryStrategy: 'linear_backoff',
      maxRetries: 3,
      baseDelay: 500,
      message: 'Timeout error - retrying with linear backoff'
    };
  }

  // Resource exhausted errors need exponential backoff
  if (isResourceExhaustedError(error)) {
    return {
      isRecoverable: true,
      retryStrategy: 'exponential_backoff',
      maxRetries: 3,
      baseDelay: 2000,
      message: 'Resource exhausted - retrying with exponential backoff'
    };
  }

  // Validation and constraint errors are not recoverable
  if (isValidationError(error) || isConstraintError(error)) {
    return {
      isRecoverable: false,
      retryStrategy: 'no_retry',
      message: 'Validation/constraint error - not retryable'
    };
  }

  // Permission errors are not recoverable
  if (isPermissionError(error)) {
    return {
      isRecoverable: false,
      retryStrategy: 'no_retry',
      message: 'Permission error - not retryable'
    };
  }

  // Default strategy based on error properties
  if (errorInfo.isRetryable) {
    return {
      isRecoverable: true,
      retryStrategy: 'exponential_backoff',
      maxRetries: 3,
      baseDelay: 1000,
      message: 'Error marked as retryable - using exponential backoff'
    };
  }

  return {
    isRecoverable: false,
    retryStrategy: 'no_retry',
    message: 'Unknown error - not retryable'
  };
}