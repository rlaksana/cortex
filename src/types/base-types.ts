/**
 * Safe Base Types for Cortex MCP System
 *
 * This module provides type-safe alternatives to common `any` usage patterns
 * throughout the codebase. These types should be used instead of `any` to
 * maintain type safety while providing flexibility.
 */

// =============================================================================
// JSON-Safe Types
// =============================================================================

/** Primitive JSON value types */
export type JSONPrimitive = string | number | boolean | null;

/** Any valid JSON value including nested objects and arrays */
export type JSONValue = JSONPrimitive | JSONObject | JSONArray;

/** JSON object with string keys and JSON values */
export interface JSONObject {
  [key: string]: JSONValue;
}

/** JSON array containing JSON values */
export type JSONArray = Array<JSONValue>;

// =============================================================================
// Dictionary Types
// =============================================================================

/** Type-safe dictionary/map replacement for Record<string, T> */
export type Dict<T> = {
  readonly [key: string]: T;
};

/** Mutable dictionary type when updates are needed */
export type MutableDict<T> = {
  [key: string]: T;
};

/** Dictionary with optional values */
export type PartialDict<T> = {
  readonly [key: string]: T | undefined;
};

// =============================================================================
// Metadata and Tagging Types
// =============================================================================

/** Common metadata structure for entities */
export interface Metadata {
  readonly tags?: Tags;
  readonly version?: string;
  readonly source?: string;
  readonly timestamp?: string;
  readonly [key: string]: JSONValue | undefined;
}

/** Tags structure for categorization and filtering */
export type Tags = Dict<string>;

/** Extended tags with optional structured data */
export type ExtendedTags = Dict<string | JSONValue>;

/** Category-based tags with hierarchical organization */
export interface CategorizedTags {
  readonly [category: string]: Tags;
}

// =============================================================================
// Configuration Types
// =============================================================================

/** Safe configuration object type */
export type Config = Dict<JSONValue>;

/** Nested configuration with dot notation support */
export interface NestedConfig {
  readonly [key: string]: JSONValue | NestedConfig;
}

/** Environment-specific configuration */
export interface EnvironmentConfig {
  readonly development?: Config;
  readonly staging?: Config;
  readonly production?: Config;
  readonly test?: Config;
}

// =============================================================================
// Event and Message Types
// =============================================================================

/** Base event structure */
export interface BaseEvent {
  readonly type: string;
  readonly timestamp: string;
  readonly id: string;
  readonly data?: Dict<JSONValue>;
  readonly metadata?: Metadata;
}

/** Message payload structure */
export interface MessagePayload {
  readonly id: string;
  readonly type: string;
  readonly data: JSONValue;
  readonly timestamp: string;
  readonly correlationId?: string;
}

// =============================================================================
// Result Types
// =============================================================================

/** Generic result type for operations that may fail */
export type Result<T, E = Error> =
  | { readonly success: true; readonly data: T }
  | { readonly success: false; readonly error: E };

/** Async result type */
export type AsyncResult<T, E = Error> = Promise<Result<T, E>>;

// =============================================================================
// Collection Types
// =============================================================================

/** Read-only collection */
export type ReadOnlyCollection<T> = readonly T[];

/** Paginated collection */
export interface PaginatedCollection<T> {
  readonly items: readonly T[];
  readonly total: number;
  readonly page: number;
  readonly pageSize: number;
  readonly hasNext: boolean;
  readonly hasPrev: boolean;
}

/** Key-value pair collection */
export interface KeyValuePairs<K extends string, V> {
  readonly key: K;
  readonly value: V;
}

// =============================================================================
// Utility Types for `any` Replacement
// =============================================================================

/** Safe unknown type with JSON serialization guarantee */
export type SafeUnknown = JSONValue;

/** Flexible object type for API responses */
export type ApiResponseData = Dict<JSONValue>;

/** Query parameters type-safe alternative */
export type QueryParams = Dict<string | number | boolean>;

/** Path parameters type */
export type PathParams = Dict<string>;

/** Headers type-safe alternative */
export type Headers = Dict<string>;

/** Context object for operations */
export type OperationContext = Dict<JSONValue>;

/** Generic data container */
export interface DataContainer<T = JSONValue> {
  readonly data: T;
  readonly metadata?: Metadata;
}

// =============================================================================
// Type Guards (Runtime Validation)
// =============================================================================

/** Type guard for JSON primitive values */
export function isJSONPrimitive(value: unknown): value is JSONPrimitive {
  return (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  );
}

/** Type guard for JSON objects */
export function isJSONObject(value: unknown): value is JSONObject {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    Object.keys(value).every(
      (key) => typeof key === 'string' && isJSONValue((value as Record<string, unknown>)[key])
    )
  );
}

/** Type guard for JSON arrays */
export function isJSONArray(value: unknown): value is JSONArray {
  return Array.isArray(value) && value.every(isJSONValue);
}

/** Type guard for any JSON value */
export function isJSONValue(value: unknown): value is JSONValue {
  return isJSONPrimitive(value) || isJSONObject(value) || isJSONArray(value);
}

/** Type guard for Dictionary type */
export function isDict<T>(
  value: unknown,
  itemGuard: (item: unknown) => item is T
): value is Dict<T> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  return Object.entries(value as Record<string, unknown>).every(
    ([key, val]) => typeof key === 'string' && itemGuard(val)
  );
}

/** Type guard for Tags */
export function isTags(value: unknown): value is Tags {
  return isDict(value, (item): item is string => typeof item === 'string');
}

/** Type guard for Metadata */
export function isMetadata(value: unknown): value is Metadata {
  if (value === null || typeof value !== 'object') {
    return false;
  }

  const obj = value as Record<string, unknown>;

  // Check optional fields
  if (obj.tags !== undefined && !isTags(obj.tags)) {
    return false;
  }

  if (obj.version !== undefined && typeof obj.version !== 'string') {
    return false;
  }

  if (obj.source !== undefined && typeof obj.source !== 'string') {
    return false;
  }

  if (obj.timestamp !== undefined && typeof obj.timestamp !== 'string') {
    return false;
  }

  // All other fields must be JSON values
  return Object.entries(obj).every(
    ([key, val]) => ['tags', 'version', 'source', 'timestamp'].includes(key) || isJSONValue(val)
  );
}

// =============================================================================
// Conversion Utilities
// =============================================================================

/** Safely convert unknown to JSONValue with validation */
export function toJSONValue(value: unknown): JSONValue | null {
  if (isJSONValue(value)) {
    return value;
  }

  // Try to serialize common types
  if (typeof value === 'bigint') {
    return value.toString();
  }

  if (typeof value === 'symbol') {
    return value.toString();
  }

  if (typeof value === 'function') {
    return `[Function: ${value.name || 'anonymous'}]`;
  }

  if (value && typeof value === 'object') {
    try {
      return JSON.parse(JSON.stringify(value));
    } catch {
      return null;
    }
  }

  return null;
}

/** Create type-safe Tags from unknown */
export function toTags(value: unknown): Tags | null {
  if (isTags(value)) {
    return value;
  }

  if (value && typeof value === 'object') {
    const tags: MutableDict<string> = {};
    for (const [key, val] of Object.entries(value)) {
      if (typeof key === 'string' && val !== undefined && val !== null) {
        tags[key] = String(val);
      }
    }
    return tags;
  }

  return null;
}

// =============================================================================
// Common Patterns
// =============================================================================

/** Event handler type */
export type EventHandler<T extends BaseEvent = BaseEvent> = (event: T) => void | Promise<void>;

/** Middleware function type */
export type Middleware<T = Dict<JSONValue>, R = void> = (
  data: T,
  next: () => Promise<R>
) => Promise<R>;

/** Transformer function type */
export type Transformer<I, O> = (input: I) => O | Promise<O>;

/** Validator function type */
export type Validator<T> = (value: unknown) => value is T;

/** Equality comparator type */
export type EqualityComparator<T> = (a: T, b: T) => boolean;
