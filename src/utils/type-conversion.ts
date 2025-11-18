/**
 * Type Conversion Utilities
 *
 * Provides safe conversion functions between different types,
 * particularly for branded types and common type transformations.
 *
 * @author Cortex Team
 * @version 1.0.0
 */

import { PointId, CollectionId, TransactionId, SessionId, QueryId } from '../types/database-generics';
import type { DatabaseConfig } from '../db/database-interface.js';
import type { ConnectionConfig } from '../types/database.js';

// Local type definition for QueuedRequest since it doesn't exist in pool-interfaces
export interface QueuedRequest<T = unknown> {
  readonly id: string;
  readonly operation: string;
  readonly priority: number;
  readonly timeout: number;
  readonly data: T;
  readonly createdAt: Date;
  readonly attempts: number;
  readonly maxAttempts: number;
}

// ============================================================================
// Branded Type Conversions
// ============================================================================

/**
 * Convert string to PointId branded type
 */
export function asPointId(id: string): PointId {
  return id as PointId;
}

/**
 * Convert readonly string array to readonly PointId array
 */
export function asPointIdArray(ids: readonly string[]): readonly PointId[] {
  return ids.map(asPointId);
}

/**
 * Convert mutable string array to PointId array
 */
export function toPointIdArray(ids: string[]): PointId[] {
  return ids.map(asPointId);
}

/**
 * Safe conversion with validation
 */
export function asPointIdSafe(id: unknown): PointId | null {
  if (typeof id === 'string' && id.length > 0) {
    return id as PointId;
  }
  return null;
}

/**
 * Convert string to CollectionId branded type
 */
export function asCollectionId(id: string): CollectionId {
  return id as CollectionId;
}

/**
 * Convert string to TransactionId branded type
 */
export function asTransactionId(id: string): TransactionId {
  return id as TransactionId;
}

/**
 * Convert string to SessionId branded type
 */
export function asSessionId(id: string): SessionId {
  return id as SessionId;
}

/**
 * Convert string to QueryId branded type
 */
export function asQueryId(id: string): QueryId {
  return id as QueryId;
}

// ============================================================================
// Database Type Conversions
// ============================================================================

/**
 * Convert unknown to DatabaseConfig with runtime validation
 */
export function asDatabaseConfig(value: unknown): DatabaseConfig | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return null;
  }

  const config = value as Record<string, unknown>;

  // Required fields validation
  if (
    typeof config.url !== 'string' ||
    typeof config.type !== 'string' ||
    !['qdrant', 'hybrid'].includes(config.type)
  ) {
    return null;
  }

  // Build valid config object
  const result: DatabaseConfig = {
    type: config.type as 'qdrant' | 'hybrid',
    url: config.url,
  };

  // Optional fields
  if (typeof config.apiKey === 'string') {
    result.apiKey = config.apiKey;
  }

  if (typeof config.logQueries === 'boolean') {
    result.logQueries = config.logQueries;
  }

  if (typeof config.connectionTimeout === 'number' && config.connectionTimeout > 0) {
    result.connectionTimeout = config.connectionTimeout;
  }

  if (typeof config.maxConnections === 'number' && config.maxConnections > 0) {
    result.maxConnections = config.maxConnections;
  }

  if (typeof config.vectorSize === 'number' && config.vectorSize > 0) {
    result.vectorSize = config.vectorSize;
  }

  if (typeof config.distance === 'string' && ['Cosine', 'Euclid', 'Dot', 'Manhattan'].includes(config.distance)) {
    result.distance = config.distance as 'Cosine' | 'Euclid' | 'Dot' | 'Manhattan';
  }

  if (typeof config.collectionName === 'string') {
    result.collectionName = config.collectionName;
  }

  return result;
}

/**
 * Convert unknown to ConnectionConfig with runtime validation
 */
export function asConnectionConfig(value: unknown): ConnectionConfig | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return null;
  }

  const config = value as Record<string, unknown>;

  // Required fields validation
  if (
    typeof config.host !== 'string' ||
    typeof config.port !== 'number' ||
    config.port <= 0 ||
    config.port > 65535 ||
    typeof config.timeout !== 'number' ||
    config.timeout <= 0 ||
    typeof config.maxRetries !== 'number' ||
    config.maxRetries < 0 ||
    typeof config.retryDelay !== 'number' ||
    config.retryDelay < 0 ||
    typeof config.useHttps !== 'boolean'
  ) {
    return null;
  }

  // Build valid config object
  const result: ConnectionConfig = {
    host: config.host,
    port: config.port,
    timeout: config.timeout,
    maxRetries: config.maxRetries,
    retryDelay: config.retryDelay,
    useHttps: config.useHttps,
  };

  // Optional field
  if (typeof config.apiKey === 'string') {
    result.apiKey = config.apiKey;
  }

  return result;
}

// ============================================================================
// Performance Metric Conversions
// ============================================================================

/**
 * Convert unknown to PerformanceMetric with runtime validation
 */
export function asPerformanceMetric(value: unknown): {
  readonly timestamp: string;
  readonly operation: string;
  readonly operationType?: string;
  readonly duration: number;
  readonly itemCount: number;
  readonly throughput: number;
  readonly success: boolean;
  readonly resourceUsage?: {
    readonly cpu: number;
    readonly memory: number;
  };
  readonly metadata?: Record<string, unknown>;
} | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return null;
  }

  const metric = value as Record<string, unknown>;

  // Required fields validation
  if (
    typeof metric.timestamp !== 'string' ||
    typeof metric.operation !== 'string' ||
    typeof metric.duration !== 'number' ||
    typeof metric.itemCount !== 'number' ||
    typeof metric.throughput !== 'number' ||
    typeof metric.success !== 'boolean'
  ) {
    return null;
  }

  // Build valid metric object
  const result = {
    timestamp: metric.timestamp,
    operation: metric.operation,
    duration: metric.duration,
    itemCount: metric.itemCount,
    throughput: metric.throughput,
    success: metric.success,
  } as const;

  // Optional fields
  if (typeof metric.operationType === 'string') {
    (result as any).operationType = metric.operationType;
  }

  if (
    metric.resourceUsage &&
    typeof metric.resourceUsage === 'object' &&
    !Array.isArray(metric.resourceUsage) &&
    typeof (metric.resourceUsage as any).cpu === 'number' &&
    typeof (metric.resourceUsage as any).memory === 'number'
  ) {
    (result as any).resourceUsage = metric.resourceUsage;
  }

  if (metric.metadata && typeof metric.metadata === 'object' && !Array.isArray(metric.metadata)) {
    (result as any).metadata = metric.metadata;
  }

  return result;
}

// ============================================================================
// User and Authentication Type Conversions
// ============================================================================

/**
 * Convert unknown to User type with runtime validation
 */
export function asUser(value: unknown): {
  readonly id: string;
  readonly email?: string;
  readonly username?: string;
  readonly roles?: string[];
  readonly permissions?: string[];
  readonly isActive?: boolean;
  readonly createdAt?: string;
  readonly updatedAt?: string;
  readonly metadata?: Record<string, unknown>;
} | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return null;
  }

  const user = value as Record<string, unknown>;

  // Required field validation
  if (typeof user.id !== 'string') {
    return null;
  }

  // Build valid user object
  const result = {
    id: user.id,
  } as const;

  // Optional fields
  const optionalStringFields = ['email', 'username', 'createdAt', 'updatedAt'];
  for (const field of optionalStringFields) {
    if (typeof user[field] === 'string') {
      (result as any)[field] = user[field];
    }
  }

  if (Array.isArray(user.roles) && user.roles.every(role => typeof role === 'string')) {
    (result as any).roles = user.roles;
  }

  if (Array.isArray(user.permissions) && user.permissions.every(perm => typeof perm === 'string')) {
    (result as any).permissions = user.permissions;
  }

  if (typeof user.isActive === 'boolean') {
    (result as any).isActive = user.isActive;
  }

  if (user.metadata && typeof user.metadata === 'object' && !Array.isArray(user.metadata)) {
    (result as any).metadata = user.metadata;
  }

  return result;
}

/**
 * Convert unknown to AuthScope with validation
 */
export function asAuthScope(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

// ============================================================================
// Search Query Conversions
// ============================================================================

/**
 * Convert unknown to SearchQuery with runtime validation
 */
export function asSearchQuery(value: unknown): {
  readonly query: string;
  readonly scope?: { readonly project?: string; readonly branch?: string; readonly org?: string };
  readonly types?: string[];
  readonly kind?: string;
  readonly mode?: 'auto' | 'fast' | 'deep';
  readonly limit?: number;
  readonly top_k?: number;
  readonly expand?: 'relations' | 'parents' | 'children' | 'none';
  readonly text?: unknown;
  readonly filters?: unknown;
} | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return null;
  }

  const query = value as Record<string, unknown>;

  // Required field validation
  if (typeof query.query !== 'string') {
    return null;
  }

  // Build valid query object
  const result = {
    query: query.query,
  } as const;

  // Optional fields with validation
  if (
    query.scope &&
    typeof query.scope === 'object' &&
    !Array.isArray(query.scope)
  ) {
    const scope = query.scope as Record<string, unknown>;
    const validScope: Record<string, string> = {};

    if (typeof scope.project === 'string') {
      validScope.project = scope.project;
    }
    if (typeof scope.branch === 'string') {
      validScope.branch = scope.branch;
    }
    if (typeof scope.org === 'string') {
      validScope.org = scope.org;
    }

    if (Object.keys(validScope).length > 0) {
      (result as any).scope = validScope;
    }
  }

  if (
    Array.isArray(query.types) &&
    query.types.every(type => typeof type === 'string')
  ) {
    (result as any).types = query.types;
  }

  if (typeof query.kind === 'string') {
    (result as any).kind = query.kind;
  }

  if (
    typeof query.mode === 'string' &&
    ['auto', 'fast', 'deep'].includes(query.mode)
  ) {
    (result as any).mode = query.mode;
  }

  if (typeof query.limit === 'number' && query.limit > 0) {
    (result as any).limit = query.limit;
  }

  if (typeof query.top_k === 'number' && query.top_k > 0) {
    (result as any).top_k = query.top_k;
  }

  if (
    typeof query.expand === 'string' &&
    ['relations', 'parents', 'children', 'none'].includes(query.expand)
  ) {
    (result as any).expand = query.expand;
  }

  // These fields can be any type
  if ('text' in query) {
    (result as any).text = query.text;
  }
  if ('filters' in query) {
    (result as any).filters = query.filters;
  }

  return result;
}

// ============================================================================
// Alert Type Conversions
// ============================================================================

/**
 * Convert unknown to Alert (without status, id, timestamp, escalationLevel, channels)
 */
export function asAlertBase(value: unknown): Omit<{
  readonly id: string;
  readonly status: string;
  readonly timestamp: string;
  readonly escalationLevel: number;
  readonly channels: string[];
  readonly title: string;
  readonly description: string;
  readonly severity: 'critical' | 'error' | 'warning' | 'info';
  readonly source: string;
  readonly category: 'backup' | 'restore' | 'validation' | 'performance' | 'capacity' | 'rpo-rto' | 'health';
  readonly details: Record<string, unknown>;
  readonly metrics: Array<{
    name: string;
    value: number;
    unit: string;
    threshold: number;
  }>;
  readonly tags: string[];
}, 'status' | 'id' | 'timestamp' | 'escalationLevel' | 'channels'> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return null;
  }

  const alert = value as Record<string, unknown>;

  // Required fields validation
  if (
    typeof alert.title !== 'string' ||
    typeof alert.description !== 'string' ||
    typeof alert.severity !== 'string' ||
    typeof alert.source !== 'string' ||
    typeof alert.category !== 'string'
  ) {
    return null;
  }

  // Build valid alert base object
  const result = {
    title: alert.title,
    description: alert.description,
    severity: alert.severity as 'critical' | 'error' | 'warning' | 'info',
    source: alert.source,
    category: alert.category as 'backup' | 'restore' | 'validation' | 'performance' | 'capacity' | 'rpo-rto' | 'health',
    details: (typeof alert.details === 'object' && alert.details !== null && !Array.isArray(alert.details))
      ? alert.details as Record<string, unknown>
      : {},
    metrics: Array.isArray(alert.metrics)
      ? alert.metrics as Array<{
          name: string;
          value: number;
          unit: string;
          threshold: number;
        }>
      : [],
    tags: Array.isArray(alert.tags)
      ? alert.tags as string[]
      : [],
  } as const;

  return result;
}

// ============================================================================
// Pool Configuration Conversions
// ============================================================================

/**
 * Convert unknown to PoolConfig with runtime validation
 */
export function asPoolConfig(value: unknown): {
  readonly poolId: string;
  readonly minConnections: number;
  readonly maxConnections: number;
  readonly acquireTimeout: number;
  readonly idleTimeout: number;
  readonly healthCheckInterval: number;
  readonly maxLifetime: number;
  readonly validationInterval: number;
  readonly connectionTimeout: number;
  readonly requestTimeout: number;
  readonly databaseConfig: ConnectionConfig;
} | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return null;
  }

  const config = value as Record<string, unknown>;

  // Required fields validation
  if (
    typeof config.poolId !== 'string' ||
    typeof config.minConnections !== 'number' ||
    typeof config.maxConnections !== 'number' ||
    typeof config.acquireTimeout !== 'number' ||
    typeof config.idleTimeout !== 'number' ||
    typeof config.healthCheckInterval !== 'number' ||
    typeof config.maxLifetime !== 'number' ||
    typeof config.validationInterval !== 'number' ||
    typeof config.connectionTimeout !== 'number' ||
    typeof config.requestTimeout !== 'number'
  ) {
    return null;
  }

  // Validate logical constraints
  if (
    config.minConnections < 0 ||
    config.maxConnections <= 0 ||
    config.minConnections > config.maxConnections ||
    config.acquireTimeout <= 0 ||
    config.idleTimeout <= 0 ||
    config.healthCheckInterval <= 0 ||
    config.maxLifetime <= 0 ||
    config.validationInterval <= 0 ||
    config.connectionTimeout <= 0 ||
    config.requestTimeout <= 0
  ) {
    return null;
  }

  // Validate database config
  const databaseConfig = asConnectionConfig(config.databaseConfig);
  if (!databaseConfig) {
    return null;
  }

  // Build valid pool config object
  return {
    poolId: config.poolId,
    minConnections: config.minConnections,
    maxConnections: config.maxConnections,
    acquireTimeout: config.acquireTimeout,
    idleTimeout: config.idleTimeout,
    healthCheckInterval: config.healthCheckInterval,
    maxLifetime: config.maxLifetime,
    validationInterval: config.validationInterval,
    connectionTimeout: config.connectionTimeout,
    requestTimeout: config.requestTimeout,
    databaseConfig,
  };
}

// ============================================================================
// Queued Request Conversions
// ============================================================================

/**
 * Convert QueuedRequest<T> to QueuedRequest<unknown> for generic compatibility
 */
export function asQueuedRequestUnknown<T>(
  request: QueuedRequest<T>
): QueuedRequest<unknown> {
  return request as QueuedRequest<unknown>;
}

// ============================================================================
// Operation Type Conversions
// ============================================================================

/**
 * Convert unknown to OperationType with validation
 */
export function asOperationType(value: unknown): 'read' | 'write' | 'search' | 'delete' | 'batch' | 'maintenance' | 'health_check' | null {
  if (typeof value !== 'string') {
    return null;
  }

  const validOperations = ['read', 'write', 'search', 'delete', 'batch', 'maintenance', 'health_check'] as const;

  return validOperations.includes(value as any) ? value as any : null;
}

// ============================================================================
// Record and Object Conversions
// ============================================================================

/**
 * Convert unknown to Readonly<Record<string, unknown>> with validation
 */
export function asReadonlyRecord(value: unknown): Readonly<Record<string, unknown>> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return null;
  }

  // Ensure all keys are strings and all values are valid JSON values
  const obj = value as Record<string, unknown>;
  for (const [key, val] of Object.entries(obj)) {
    if (typeof key !== 'string') {
      return null;
    }

    // Check if value is a valid JSON value
    if (
      val !== null &&
      typeof val !== 'string' &&
      typeof val !== 'number' &&
      typeof val !== 'boolean' &&
      typeof val !== 'object'
    ) {
      return null;
    }

    // If it's an object, ensure it's not a function
    if (typeof val === 'object' && Array.isArray(val)) {
      // Arrays are allowed
      continue;
    }

    if (typeof val === 'object' && val !== null) {
      // Check if it's a plain object
      if (Object.prototype.toString.call(val) !== '[object Object]') {
        return null;
      }
    }
  }

  return obj as Readonly<Record<string, unknown>>;
}

// ============================================================================
// Error Handling Conversions
// ============================================================================

/**
 * Convert unknown to Error with validation
 */
export function asError(value: unknown): Error | null {
  if (value instanceof Error) {
    return value;
  }

  if (
    value &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    typeof (value as Record<string, unknown>).message === 'string'
  ) {
    const errorObj = value as Record<string, unknown>;
    const errorMessage = errorObj.message as string;
    const error = new Error(errorMessage);

    // Copy additional properties if they exist
    if (typeof errorObj.name === 'string') {
      error.name = errorObj.name;
    }

    if (typeof errorObj.stack === 'string') {
      error.stack = errorObj.stack;
    }

    return error;
  }

  return null;
}

// ============================================================================
// Auth Middleware Conversions
// ============================================================================

/**
 * Convert unknown to AuthMiddlewareContext with validation
 */
export function asAuthMiddlewareContext(value: unknown): Record<string, unknown> & { auth_token?: string } | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return null;
  }

  const context = value as Record<string, unknown>;

  // Ensure it's a valid record
  if (!asReadonlyRecord(context)) {
    return null;
  }

  // Return as the expected type (auth_token is optional)
  return context as Record<string, unknown> & { auth_token?: string };
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Safe conversion with fallback
 */
export function safeConvert<T>(
  value: unknown,
  converter: (value: unknown) => T | null,
  fallback: T
): T {
  const result = converter(value);
  return result !== null ? result : fallback;
}

/**
 * Batch conversion for arrays
 */
export function batchConvert<T, R>(
  items: T[],
  converter: (item: T) => R | null,
  options: {
    skipInvalid?: boolean;
    fallback?: R;
  } = {}
): R[] {
  const { skipInvalid = true, fallback } = options;

  return items.map((item) => {
    const result = converter(item);
    if (result !== null) {
      return result;
    }

    if (fallback !== undefined) {
      return fallback;
    }

    if (skipInvalid) {
      throw new Error(`Batch conversion failed for item: ${JSON.stringify(item)}`);
    }

    // This should never be reached, but TypeScript needs it
    return undefined as any;
  }).filter(item => item !== undefined) as R[];
}

/**
 * Conditional conversion based on type
 */
export function conditionalConvert<T, R>(
  value: unknown,
  typeGuard: (value: unknown) => value is T,
  converter: (value: T) => R,
  fallback?: R
): R | null {
  if (typeGuard(value)) {
    return converter(value);
  }

  return fallback !== undefined ? fallback : null;
}