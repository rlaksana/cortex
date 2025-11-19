/**
 * Type Assertion Utilities
 *
 * Provides runtime assertion functions for type safety and validation.
 * These functions throw errors when validation fails, making them suitable
 * for use in type narrowing and critical path validation.
 *
 * @author Cortex Team
 * @version 1.0.0
 */

import { assertType, isBoolean, isFunction,isNumber, isObject, isString } from './type-guards';
import { type PointId } from '../types/database-generics';

// ============================================================================
// Basic Type Assertions
// ============================================================================

/**
 * Assert value is a string
 */
export function assertString(value: unknown, message?: string): asserts value is string {
  assertType(value, isString, message || `Expected string, got ${typeof value}`);
}

/**
 * Assert value is a number
 */
export function assertNumber(value: unknown, message?: string): asserts value is number {
  assertType(value, isNumber, message || `Expected number, got ${typeof value}`);
}

/**
 * Assert value is a boolean
 */
export function assertBoolean(value: unknown, message?: string): asserts value is boolean {
  assertType(value, isBoolean, message || `Expected boolean, got ${typeof value}`);
}

/**
 * Assert value is an object (non-null, non-array)
 */
export function assertObject(value: unknown, message?: string): asserts value is Record<string, unknown> {
  assertType(value, isObject, message || `Expected object, got ${typeof value}`);
}

/**
 * Assert value is an array
 */
export function assertArray(value: unknown, message?: string): asserts value is unknown[] {
  assertType(value, (val): val is unknown[] => Array.isArray(val), message || `Expected array, got ${typeof value}`);
}

/**
 * Assert value is a function
 */
export function assertFunction(value: unknown, message?: string): asserts value is Function {
  assertType(value, isFunction, message || `Expected function, got ${typeof value}`);
}

// ============================================================================
// Branded Type Assertions
// ============================================================================

/**
 * Assert value is a valid PointId
 */
export function assertPointId(value: unknown): asserts value is PointId {
  if (typeof value !== 'string') {
    throw new TypeError(`Expected PointId (string), got ${typeof value}`);
  }
  if (value.length === 0) {
    throw new TypeError('PointId cannot be empty');
  }
}

/**
 * Assert all values in array are PointIds
 */
export function assertPointIdArray(value: unknown): asserts value is PointId[] {
  if (!Array.isArray(value)) {
    throw new TypeError(`Expected PointId array, got ${typeof value}`);
  }

  for (let i = 0; i < value.length; i++) {
    if (typeof value[i] !== 'string') {
      throw new TypeError(`Expected PointId at index ${i}, got ${typeof value[i]}`);
    }
    if ((value[i] as string).length === 0) {
      throw new TypeError(`PointId at index ${i} cannot be empty`);
    }
  }
}

/**
 * Assert readonly string array can be converted to PointId array
 */
export function assertStringArrayAsPointIds(value: unknown): asserts value is readonly string[] {
  if (!Array.isArray(value)) {
    throw new TypeError(`Expected string array, got ${typeof value}`);
  }

  for (let i = 0; i < value.length; i++) {
    if (typeof value[i] !== 'string') {
      throw new TypeError(`Expected string at index ${i}, got ${typeof value[i]}`);
    }
  }
}

// ============================================================================
// Configuration Assertions
// ============================================================================

/**
 * Assert value is a valid QdrantDatabaseConfig
 */
export function assertQdrantDatabaseConfig(value: unknown): asserts value is {
  readonly host: string;
  readonly port: number;
  readonly timeout?: number;
  readonly apiKey?: string;
  readonly https?: boolean;
  readonly path?: string;
  readonly collection?: string;
} {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('Expected QdrantDatabaseConfig object');
  }

  const config = value as Record<string, unknown>;

  // Required fields
  if (typeof config.host !== 'string') {
    throw new TypeError('QdrantDatabaseConfig.host must be a string');
  }
  if (typeof config.port !== 'number') {
    throw new TypeError('QdrantDatabaseConfig.port must be a number');
  }
  if (config.port <= 0 || config.port > 65535) {
    throw new TypeError('QdrantDatabaseConfig.port must be between 1 and 65535');
  }

  // Optional fields
  if (config.timeout !== undefined && (typeof config.timeout !== 'number' || config.timeout <= 0)) {
    throw new TypeError('QdrantDatabaseConfig.timeout must be a positive number');
  }
  if (config.apiKey !== undefined && typeof config.apiKey !== 'string') {
    throw new TypeError('QdrantDatabaseConfig.apiKey must be a string');
  }
  if (config.https !== undefined && typeof config.https !== 'boolean') {
    throw new TypeError('QdrantDatabaseConfig.https must be a boolean');
  }
  if (config.path !== undefined && typeof config.path !== 'string') {
    throw new TypeError('QdrantDatabaseConfig.path must be a string');
  }
  if (config.collection !== undefined && typeof config.collection !== 'string') {
    throw new TypeError('QdrantDatabaseConfig.collection must be a string');
  }
}

/**
 * Assert value is a valid DatabaseConnectionConfig
 */
export function assertDatabaseConnectionConfig(value: unknown): asserts value is {
  readonly host: string;
  readonly port: number;
  readonly database?: string;
  readonly username?: string;
  readonly password?: string;
  readonly ssl?: boolean;
  readonly timeout?: number;
} {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('Expected DatabaseConnectionConfig object');
  }

  const config = value as Record<string, unknown>;

  // Required fields
  if (typeof config.host !== 'string') {
    throw new TypeError('DatabaseConnectionConfig.host must be a string');
  }
  if (typeof config.port !== 'number') {
    throw new TypeError('DatabaseConnectionConfig.port must be a number');
  }
  if (config.port <= 0 || config.port > 65535) {
    throw new TypeError('DatabaseConnectionConfig.port must be between 1 and 65535');
  }

  // Optional fields
  if (config.database !== undefined && typeof config.database !== 'string') {
    throw new TypeError('DatabaseConnectionConfig.database must be a string');
  }
  if (config.username !== undefined && typeof config.username !== 'string') {
    throw new TypeError('DatabaseConnectionConfig.username must be a string');
  }
  if (config.password !== undefined && typeof config.password !== 'string') {
    throw new TypeError('DatabaseConnectionConfig.password must be a string');
  }
  if (config.ssl !== undefined && typeof config.ssl !== 'boolean') {
    throw new TypeError('DatabaseConnectionConfig.ssl must be a boolean');
  }
  if (config.timeout !== undefined && (typeof config.timeout !== 'number' || config.timeout <= 0)) {
    throw new TypeError('DatabaseConnectionConfig.timeout must be a positive number');
  }
}

// ============================================================================
// Performance Monitoring Assertions
// ============================================================================

/**
 * Assert value is a valid PerformanceMetric
 */
export function assertPerformanceMetric(value: unknown): asserts value is {
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
} {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('Expected PerformanceMetric object');
  }

  const metric = value as Record<string, unknown>;

  // Required fields
  if (typeof metric.timestamp !== 'string') {
    throw new TypeError('PerformanceMetric.timestamp must be a string');
  }
  if (typeof metric.operation !== 'string') {
    throw new TypeError('PerformanceMetric.operation must be a string');
  }
  if (typeof metric.duration !== 'number') {
    throw new TypeError('PerformanceMetric.duration must be a number');
  }
  if (typeof metric.itemCount !== 'number') {
    throw new TypeError('PerformanceMetric.itemCount must be a number');
  }
  if (typeof metric.throughput !== 'number') {
    throw new TypeError('PerformanceMetric.throughput must be a number');
  }
  if (typeof metric.success !== 'boolean') {
    throw new TypeError('PerformanceMetric.success must be a boolean');
  }

  // Optional operationType
  if (metric.operationType !== undefined && typeof metric.operationType !== 'string') {
    throw new TypeError('PerformanceMetric.operationType must be a string');
  }

  // Optional resourceUsage
  if (metric.resourceUsage !== undefined) {
    if (!metric.resourceUsage || typeof metric.resourceUsage !== 'object' || Array.isArray(metric.resourceUsage)) {
      throw new TypeError('PerformanceMetric.resourceUsage must be an object');
    }
    const resourceUsage = metric.resourceUsage as Record<string, unknown>;
    if (typeof resourceUsage.cpu !== 'number') {
      throw new TypeError('PerformanceMetric.resourceUsage.cpu must be a number');
    }
    if (typeof resourceUsage.memory !== 'number') {
      throw new TypeError('PerformanceMetric.resourceUsage.memory must be a number');
    }
  }

  // Optional metadata
  if (metric.metadata !== undefined && (!metric.metadata || typeof metric.metadata !== 'object' || Array.isArray(metric.metadata))) {
    throw new TypeError('PerformanceMetric.metadata must be an object');
  }
}

// ============================================================================
// User and Authentication Assertions
// ============================================================================

/**
 * Assert value is a valid User object
 */
export function assertUser(value: unknown): asserts value is {
  readonly id: string;
  readonly email?: string;
  readonly username?: string;
  readonly roles?: string[];
  readonly permissions?: string[];
  readonly isActive?: boolean;
  readonly createdAt?: string;
  readonly updatedAt?: string;
  readonly metadata?: Record<string, unknown>;
} {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('Expected User object');
  }

  const user = value as Record<string, unknown>;

  // Required fields
  if (typeof user.id !== 'string') {
    throw new TypeError('User.id must be a string');
  }

  // Optional string fields
  const stringFields = ['email', 'username', 'createdAt', 'updatedAt'];
  for (const field of stringFields) {
    if (user[field] !== undefined && typeof user[field] !== 'string') {
      throw new TypeError(`User.${field} must be a string`);
    }
  }

  // Optional array fields
  if (user.roles !== undefined && (!Array.isArray(user.roles) || !user.roles.every(role => typeof role === 'string'))) {
    throw new TypeError('User.roles must be an array of strings');
  }
  if (user.permissions !== undefined && (!Array.isArray(user.permissions) || !user.permissions.every(perm => typeof perm === 'string'))) {
    throw new TypeError('User.permissions must be an array of strings');
  }

  // Optional boolean fields
  if (user.isActive !== undefined && typeof user.isActive !== 'boolean') {
    throw new TypeError('User.isActive must be a boolean');
  }

  // Optional metadata
  if (user.metadata !== undefined && (!user.metadata || typeof user.metadata !== 'object' || Array.isArray(user.metadata))) {
    throw new TypeError('User.metadata must be an object');
  }
}

/**
 * Assert value is a valid AuthScope
 */
export function assertAuthScope(value: unknown): asserts value is string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError('AuthScope must be a non-empty string');
  }
}

// ============================================================================
// Search Query Assertions
// ============================================================================

/**
 * Assert value is a valid SearchQuery
 */
export function assertSearchQuery(value: unknown): asserts value is {
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
} {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('Expected SearchQuery object');
  }

  const query = value as Record<string, unknown>;

  // Required fields
  if (typeof query.query !== 'string') {
    throw new TypeError('SearchQuery.query must be a string');
  }

  // Optional scope validation
  if (query.scope !== undefined) {
    if (!query.scope || typeof query.scope !== 'object' || Array.isArray(query.scope)) {
      throw new TypeError('SearchQuery.scope must be an object');
    }
    const scope = query.scope as Record<string, unknown>;
    if (scope.project !== undefined && typeof scope.project !== 'string') {
      throw new TypeError('SearchQuery.scope.project must be a string');
    }
    if (scope.branch !== undefined && typeof scope.branch !== 'string') {
      throw new TypeError('SearchQuery.scope.branch must be a string');
    }
    if (scope.org !== undefined && typeof scope.org !== 'string') {
      throw new TypeError('SearchQuery.scope.org must be a string');
    }
  }

  // Optional array fields
  if (query.types !== undefined && (!Array.isArray(query.types) || !query.types.every(type => typeof type === 'string'))) {
    throw new TypeError('SearchQuery.types must be an array of strings');
  }

  // Optional string fields
  const stringFields = ['kind'];
  for (const field of stringFields) {
    if (query[field] !== undefined && typeof query[field] !== 'string') {
      throw new TypeError(`SearchQuery.${field} must be a string`);
    }
  }

  // Optional enum fields
  if (query.mode !== undefined && !['auto', 'fast', 'deep'].includes(query.mode as string)) {
    throw new TypeError("SearchQuery.mode must be one of 'auto', 'fast', 'deep'");
  }
  if (query.expand !== undefined && !['relations', 'parents', 'children', 'none'].includes(query.expand as string)) {
    throw new TypeError("SearchQuery.expand must be one of 'relations', 'parents', 'children', 'none'");
  }

  // Optional number fields
  if (query.limit !== undefined && (typeof query.limit !== 'number' || query.limit <= 0)) {
    throw new TypeError('SearchQuery.limit must be a positive number');
  }
  if (query.top_k !== undefined && (typeof query.top_k !== 'number' || query.top_k <= 0)) {
    throw new TypeError('SearchQuery.top_k must be a positive number');
  }
}

// ============================================================================
// Alert Assertions
// ============================================================================

/**
 * Assert value is a valid Alert base (without status, id, timestamp, escalationLevel, channels)
 */
export function assertAlertBase(value: unknown): asserts value is Omit<{
  readonly id: string;
  readonly status: string;
  readonly timestamp: string;
  readonly escalationLevel: number;
  readonly channels: string[];
  readonly message: string;
  readonly severity: string;
  readonly source: string;
  readonly metadata?: Record<string, unknown>;
}, 'status' | 'id' | 'timestamp' | 'escalationLevel' | 'channels'> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('Expected Alert object');
  }

  const alert = value as Record<string, unknown>;

  // Required fields
  if (typeof alert.message !== 'string') {
    throw new TypeError('Alert.message must be a string');
  }
  if (typeof alert.severity !== 'string') {
    throw new TypeError('Alert.severity must be a string');
  }
  if (typeof alert.source !== 'string') {
    throw new TypeError('Alert.source must be a string');
  }

  // Optional metadata
  if (alert.metadata !== undefined && (!alert.metadata || typeof alert.metadata !== 'object' || Array.isArray(alert.metadata))) {
    throw new TypeError('Alert.metadata must be an object');
  }
}

// ============================================================================
// Pool Configuration Assertions
// ============================================================================

/**
 * Assert value is a valid PoolConfig
 */
export function assertPoolConfig(value: unknown): asserts value is {
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
  readonly databaseConfig: {
    readonly host: string;
    readonly port: number;
    readonly database?: string;
    readonly username?: string;
    readonly password?: string;
    readonly ssl?: boolean;
    readonly timeout?: number;
  };
} {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('Expected PoolConfig object');
  }

  const config = value as Record<string, unknown>;

  // Required string fields
  if (typeof config.poolId !== 'string') {
    throw new TypeError('PoolConfig.poolId must be a string');
  }

  // Required number fields
  const numberFields = [
    'minConnections', 'maxConnections', 'acquireTimeout', 'idleTimeout',
    'healthCheckInterval', 'maxLifetime', 'validationInterval',
    'connectionTimeout', 'requestTimeout'
  ];

  for (const field of numberFields) {
    if (typeof config[field] !== 'number') {
      throw new TypeError(`PoolConfig.${field} must be a number`);
    }
    if ((config[field] as number) <= 0) {
      throw new TypeError(`PoolConfig.${field} must be positive`);
    }
  }

  // Logical constraints
  if (config.minConnections >= config.maxConnections) {
    throw new TypeError('PoolConfig.minConnections must be less than maxConnections');
  }

  // Nested database config validation
  assertDatabaseConnectionConfig(config.databaseConfig);
}

// ============================================================================
// Operation Type Assertions
// ============================================================================

/**
 * Assert value is a valid OperationType
 */
export function assertOperationType(value: unknown): asserts value is 'read' | 'write' | 'search' | 'delete' | 'batch' | 'maintenance' | 'health_check' {
  const validOperations = ['read', 'write', 'search', 'delete', 'batch', 'maintenance', 'health_check'] as const;

  if (typeof value !== 'string') {
    throw new TypeError('OperationType must be a string');
  }

  if (!validOperations.includes(value as any)) {
    throw new TypeError(`Invalid OperationType: ${value}. Must be one of: ${validOperations.join(', ')}`);
  }
}

// ============================================================================
// Record and Object Assertions
// ============================================================================

/**
 * Assert value is a Readonly<Record<string, unknown>>
 */
export function assertReadonlyRecord(value: unknown): asserts value is Readonly<Record<string, unknown>> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('Expected Record<string, unknown>');
  }

  const obj = value as Record<string, unknown>;

  // Ensure all keys are strings and all values are valid
  for (const [key, val] of Object.entries(obj)) {
    if (typeof key !== 'string') {
      throw new TypeError('Record keys must be strings');
    }

    // Validate value types - allow primitives, objects, and arrays
    if (
      val !== null &&
      typeof val !== 'string' &&
      typeof val !== 'number' &&
      typeof val !== 'boolean' &&
      typeof val !== 'object'
    ) {
      throw new TypeError(`Record value for key '${key}' has invalid type: ${typeof val}`);
    }

    // Reject functions
    if (typeof val === 'function') {
      throw new TypeError(`Record value for key '${key}' cannot be a function`);
    }
  }
}

// ============================================================================
// Error Handling Assertions
// ============================================================================

/**
 * Assert value can be converted to Error
 */
export function assertError(value: unknown): asserts value is Error {
  if (value instanceof Error) {
    return; // Already an Error instance
  }

  if (
    value &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    typeof (value as Record<string, unknown>).message === 'string'
  ) {
    return; // Error-like object
  }

  throw new TypeError('Expected Error or Error-like object with message property');
}

// ============================================================================
// Auth Middleware Assertions
// ============================================================================

/**
 * Assert value is a valid AuthMiddlewareContext
 */
export function assertAuthMiddlewareContext(value: unknown): asserts value is Record<string, unknown> & { auth_token?: string } {
  assertReadonlyRecord(value);

  // auth_token is optional, but if present must be a string
  const context = value as Record<string, unknown>;
  if (context.auth_token !== undefined && typeof context.auth_token !== 'string') {
    throw new TypeError('auth_token must be a string');
  }
}

// ============================================================================
// Utility Assertions
// ============================================================================

/**
 * Assert value is not null or undefined
 */
export function assertNotNull<T>(value: T | null | undefined, message?: string): asserts value is T {
  if (value == null) {
    throw new TypeError(message || 'Value cannot be null or undefined');
  }
}

/**
 * Assert value is not null
 */
export function assertNonNull<T>(value: T | null, message?: string): asserts value is T {
  if (value === null) {
    throw new TypeError(message || 'Value cannot be null');
  }
}

/**
 * Assert value is not undefined
 */
export function assertNotUndefined<T>(value: T | undefined, message?: string): asserts value is T {
  if (value === undefined) {
    throw new TypeError(message || 'Value cannot be undefined');
  }
}

/**
 * Assert value is not empty (for strings, arrays, and objects)
 */
export function assertNotEmpty(value: unknown, message?: string): asserts value is (string | unknown[] | Record<string, unknown>) {
  if (value == null) {
    throw new TypeError(message || 'Value cannot be null or undefined');
  }

  if (typeof value === 'string') {
    if (value.length === 0) {
      throw new TypeError(message || 'String cannot be empty');
    }
    return;
  }

  if (Array.isArray(value)) {
    if (value.length === 0) {
      throw new TypeError(message || 'Array cannot be empty');
    }
    return;
  }

  if (typeof value === 'object') {
    if (Object.keys(value as Record<string, unknown>).length === 0) {
      throw new TypeError(message || 'Object cannot be empty');
    }
    return;
  }

  throw new TypeError(message || 'Value must be string, array, or object to check emptiness');
}

/**
 * Assert value matches one of the allowed values
 */
export function assertOneOf<T>(value: unknown, allowedValues: readonly T[], message?: string): asserts value is T {
  if (!allowedValues.includes(value as T)) {
    const allowedList = allowedValues.map(v => typeof v === 'string' ? `'${v}'` : String(v)).join(', ');
    throw new TypeError(message || `Value must be one of: ${allowedList}`);
  }
}

/**
 * Assert value is within numeric range
 */
export function assertInRange(value: unknown, min: number, max: number, inclusive: boolean = true): asserts value is number {
  if (typeof value !== 'number') {
    throw new TypeError(`Expected number, got ${typeof value}`);
  }

  if (inclusive) {
    if (value < min || value > max) {
      throw new TypeError(`Number ${value} must be between ${min} and ${max} (inclusive)`);
    }
  } else {
    if (value <= min || value >= max) {
      throw new TypeError(`Number ${value} must be between ${min} and ${max} (exclusive)`);
    }
  }
}