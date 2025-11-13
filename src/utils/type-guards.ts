/**
 * Runtime Type Guards for Safe Base Types
 *
 * This module provides comprehensive runtime type guards for validating
 * data structures and ensuring type safety when working with external data.
 * These guards complement the compile-time types defined in base-types.ts.
 */

import type {
  BaseEvent,
  CategorizedTags,
  Config,
  DataContainer,
  Dict,
  EnvironmentConfig,
  Headers,
  JSONArray,
  JSONObject,
  JSONPrimitive,
  JSONValue,
  MessagePayload,
  Metadata,
  MutableDict,
  OperationContext,
  PaginatedCollection,
  QueryParams,
  Result,
  Tags,
} from '../types/base-types.js';

// =============================================================================
// JSON Type Guards (Enhanced versions)
// =============================================================================

/**
 * Enhanced JSON primitive guard with additional safety checks
 */
export function isJSONPrimitiveStrict(value: unknown): value is JSONPrimitive {
  // Check for NaN and Infinity which are technically numbers but not JSON-safe
  if (typeof value === 'number') {
    return !isNaN(value) && isFinite(value);
  }

  return (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'boolean'
  );
}

/**
 * Check if value is a safe integer for JSON serialization
 */
export function isSafeInteger(value: unknown): value is number {
  return typeof value === 'number' &&
         Number.isSafeInteger(value) &&
         !isNaN(value) &&
         isFinite(value);
}

/**
 * Enhanced JSON object guard with property validation
 */
export function isJSONObjectStrict(
  value: unknown,
  maxDepth = 10,
  currentDepth = 0
): value is JSONObject {
  if (currentDepth > maxDepth) {
    return false; // Prevent infinite recursion
  }

  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    Object.keys(value).every(key =>
      typeof key === 'string' &&
      isJSONValueStrict((value as Record<string, unknown>)[key], maxDepth, currentDepth + 1)
    )
  );
}

/**
 * Enhanced JSON array guard with depth protection
 */
export function isJSONArrayStrict(
  value: unknown,
  maxDepth = 10,
  currentDepth = 0
): value is JSONArray {
  if (currentDepth > maxDepth) {
    return false; // Prevent infinite recursion
  }

  return Array.isArray(value) &&
         value.every(item => isJSONValueStrict(item, maxDepth, currentDepth + 1));
}

/**
 * Comprehensive JSON value validator
 */
export function isJSONValueStrict(
  value: unknown,
  maxDepth = 10,
  currentDepth = 0
): value is JSONValue {
  return isJSONPrimitiveStrict(value) ||
         isJSONObjectStrict(value, maxDepth, currentDepth) ||
         isJSONArrayStrict(value, maxDepth, currentDepth);
}

// =============================================================================
// Dictionary Type Guards
// =============================================================================

/**
 * Check if value is a dictionary with values of a specific type
 */
export function isDictStrict<T>(
  value: unknown,
  itemGuard: (item: unknown) => item is T,
  options: {
    maxKeys?: number;
    allowEmpty?: boolean;
    keyPattern?: RegExp;
  } = {}
): value is Dict<T> {
  const { maxKeys = 1000, allowEmpty = true, keyPattern } = options;

  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj);

  // Check empty constraint
  if (!allowEmpty && keys.length === 0) {
    return false;
  }

  // Check maximum keys constraint
  if (keys.length > maxKeys) {
    return false;
  }

  // Check key pattern if provided
  if (keyPattern && !keys.every(key => keyPattern.test(key))) {
    return false;
  }

  // Validate all values
  return keys.every(key => itemGuard(obj[key]));
}

/**
 * Check if value is a partial dictionary (allowing undefined values)
 */
export function isPartialDict<T>(
  value: unknown,
  itemGuard: (item: unknown) => item is T
): value is Partial<Record<string, T>> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  return Object.entries(value as Record<string, unknown>).every(
    ([key, val]) => typeof key === 'string' && (val === undefined || itemGuard(val))
  );
}

// =============================================================================
// Metadata and Tagging Guards
// =============================================================================

/**
 * Validate Tags structure with enhanced checks
 */
export function isTagsStrict(
  value: unknown,
  options: {
    maxTags?: number;
    maxTagLength?: number;
    allowedTagKeys?: Set<string>;
    tagKeyPattern?: RegExp;
    tagValuePattern?: RegExp;
  } = {}
): value is Tags {
  const {
    maxTags = 100,
    maxTagLength = 200,
    allowedTagKeys,
    tagKeyPattern = /^[a-zA-Z0-9_-]+$/,
    tagValuePattern = /^[a-zA-Z0-9._\s-]+$/
  } = options;

  if (!isDictStrict(value, isString, { maxKeys: maxTags, keyPattern: tagKeyPattern })) {
    return false;
  }

  const tags = value as Tags;

  // Check tag value constraints
  return Object.values(tags).every(val =>
    val.length <= maxTagLength && tagValuePattern.test(val)
  );
}

/**
 * Validate CategorizedTags structure
 */
export function isCategorizedTags(value: unknown): value is CategorizedTags {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  return Object.entries(value as Record<string, unknown>).every(
    ([category, tags]) =>
      typeof category === 'string' &&
      isTagsStrict(tags, { maxTagLength: 100 })
  );
}

/**
 * Comprehensive Metadata validator
 */
export function isMetadataStrict(
  value: unknown,
  options: {
    allowedTopLevelKeys?: Set<string>;
    requireTimestamp?: boolean;
    maxMetadataSize?: number;
  } = {}
): value is Metadata {
  const {
    allowedTopLevelKeys,
    requireTimestamp = false,
    maxMetadataSize = 10240 // 10KB
  } = options;

  if (value === null || typeof value !== 'object') {
    return false;
  }

  const obj = value as Record<string, unknown>;

  // Check size constraint
  const serialized = JSON.stringify(obj);
  if (serialized.length > maxMetadataSize) {
    return false;
  }

  // Check allowed keys if specified
  if (allowedTopLevelKeys && !Object.keys(obj).every(key => allowedTopLevelKeys.has(key))) {
    return false;
  }

  // Validate optional structured fields
  if (obj.tags !== undefined && !isTagsStrict(obj.tags)) {
    return false;
  }

  if (obj.version !== undefined && typeof obj.version !== 'string') {
    return false;
  }

  if (obj.source !== undefined && typeof obj.source !== 'string') {
    return false;
  }

  if (obj.timestamp !== undefined) {
    if (typeof obj.timestamp !== 'string' || !isValidISODate(obj.timestamp)) {
      return false;
    }
  } else if (requireTimestamp) {
    return false;
  }

  // All other fields must be JSON values
  return Object.entries(obj).every(([key, val]) =>
    ['tags', 'version', 'source', 'timestamp'].includes(key) ||
    isJSONValueStrict(val)
  );
}

// =============================================================================
// Configuration Guards
// =============================================================================

/**
 * Validate configuration object
 */
export function isConfig(
  value: unknown,
  options: {
    maxDepth?: number;
    allowFunctions?: boolean;
  } = {}
): value is Config {
  const { maxDepth = 5, allowFunctions = false } = options;

  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  function validateConfig(obj: unknown, currentDepth = 0): boolean {
    if (currentDepth > maxDepth) {
      return false;
    }

    if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
      return false;
    }

    return Object.entries(obj as Record<string, unknown>).every(([key, val]) => {
      if (typeof key !== 'string') {
        return false;
      }

      if (allowFunctions && typeof val === 'function') {
        return true;
      }

      if (isJSONValueStrict(val, maxDepth, currentDepth + 1)) {
        return true;
      }

      if (typeof val === 'object' && val !== null && !Array.isArray(val)) {
        return validateConfig(val, currentDepth + 1);
      }

      return false;
    });
  }

  return validateConfig(value);
}

/**
 * Validate EnvironmentConfig structure
 */
export function isEnvironmentConfig(value: unknown): value is EnvironmentConfig {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const obj = value as Record<string, unknown>;
  const environments = ['development', 'staging', 'production', 'test'];

  return Object.entries(obj).every(([env, config]) =>
    environments.includes(env) && isConfig(config)
  );
}

// =============================================================================
// Event and Message Guards
// =============================================================================

/**
 * Validate BaseEvent structure
 */
export function isBaseEvent(value: unknown): value is BaseEvent {
  if (value === null || typeof value !== 'object') {
    return false;
  }

  const event = value as Record<string, unknown>;

  return (
    typeof event.type === 'string' &&
    typeof event.timestamp === 'string' &&
    isValidISODate(event.timestamp) &&
    typeof event.id === 'string' &&
    (event.data === undefined || isDict(event.data, isJSONValueStrict)) &&
    (event.metadata === undefined || isMetadataStrict(event.metadata))
  );
}

/**
 * Validate MessagePayload structure
 */
export function isMessagePayload(value: unknown): value is MessagePayload {
  if (value === null || typeof value !== 'object') {
    return false;
  }

  const payload = value as Record<string, unknown>;

  return (
    typeof payload.id === 'string' &&
    typeof payload.type === 'string' &&
    isJSONValueStrict(payload.data) &&
    typeof payload.timestamp === 'string' &&
    isValidISODate(payload.timestamp) &&
    (payload.correlationId === undefined || typeof payload.correlationId === 'string')
  );
}

// =============================================================================
// Result and Collection Guards
// =============================================================================

/**
 * Validate Result type
 */
export function isResult<T, E = Error>(
  value: unknown,
  dataGuard: (data: unknown) => data is T,
  errorGuard?: (error: unknown) => error is E
): value is Result<T, E> {
  if (value === null || typeof value !== 'object') {
    return false;
  }

  const result = value as Record<string, unknown>;

  if (result.success === true) {
    return dataGuard(result.data);
  }

  if (result.success === false) {
    return errorGuard ? errorGuard(result.error) : true;
  }

  return false;
}

/**
 * Validate PaginatedCollection structure
 */
export function isPaginatedCollection<T>(
  value: unknown,
  itemGuard: (item: unknown) => item is T
): value is PaginatedCollection<T> {
  if (value === null || typeof value !== 'object') {
    return false;
  }

  const collection = value as Record<string, unknown>;

  return (
    Array.isArray(collection.items) &&
    collection.items.every(itemGuard) &&
    typeof collection.total === 'number' &&
    collection.total >= 0 &&
    typeof collection.page === 'number' &&
    collection.page >= 1 &&
    typeof collection.pageSize === 'number' &&
    collection.pageSize > 0 &&
    typeof collection.hasNext === 'boolean' &&
    typeof collection.hasPrev === 'boolean'
  );
}

// =============================================================================
// Utility Guards
// =============================================================================

/**
 * Check if value is a non-empty string
 */
export function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

/**
 * Check if value is a valid ISO date string
 */
export function isValidISODate(value: unknown): value is string {
  if (typeof value !== 'string') {
    return false;
  }

  const date = new Date(value);
  return !isNaN(date.getTime()) && value === date.toISOString();
}

/**
 * Check if value is a valid UUID
 */
export function isValidUUID(value: unknown): value is string {
  if (typeof value !== 'string') {
    return false;
  }

  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(value);
}

/**
 * Check if value is a valid URL
 */
export function isValidURL(value: unknown): value is string {
  if (typeof value !== 'string') {
    return false;
  }

  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
}

/**
 * Check if value is a valid email address
 */
export function isValidEmail(value: unknown): value is string {
  if (typeof value !== 'string') {
    return false;
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(value);
}

/**
 * Basic dictionary guard (non-strict version)
 */
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

/**
 * Check if value is a string (alias for typeof check)
 */
export function isString(value: unknown): value is string {
  return typeof value === 'string';
}

/**
 * Check if value is a number (excluding NaN and Infinity)
 */
export function isNumber(value: unknown): value is number {
  return typeof value === 'number' && !isNaN(value) && isFinite(value);
}

/**
 * Check if value is a boolean
 */
export function isBoolean(value: unknown): value is boolean {
  return typeof value === 'boolean';
}

/**
 * Check if value is unknown (always true, used for generic typing)
 */
export function isUnknown(value: unknown): value is unknown {
  return true; // Always true, used for type assertion only
}

/**
 * Check if value is an array with items of a specific type
 */
export function isArray<T>(
  value: unknown,
  itemGuard: (item: unknown) => item is T,
  options: {
    maxLength?: number;
    minLength?: number;
    allowNullItems?: boolean;
  } = {}
): value is T[] {
  const { maxLength, minLength, allowNullItems = false } = options;

  if (!Array.isArray(value)) {
    return false;
  }

  if (minLength !== undefined && value.length < minLength) {
    return false;
  }

  if (maxLength !== undefined && value.length > maxLength) {
    return false;
  }

  return value.every(item =>
    allowNullItems && item === null ? true : itemGuard(item)
  );
}

// =============================================================================
// Specialized Guards
// =============================================================================

/**
 * Validate QueryParams structure
 */
export function isQueryParams(value: unknown): value is QueryParams {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  return Object.entries(value as Record<string, unknown>).every(
    ([key, val]) =>
      typeof key === 'string' &&
      (typeof val === 'string' || typeof val === 'number' || typeof val === 'boolean')
  );
}

/**
 * Validate Headers structure
 */
export function isHeaders(value: unknown): value is Headers {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  return Object.entries(value as Record<string, unknown>).every(
    ([key, val]) => typeof key === 'string' && typeof val === 'string'
  );
}

/**
 * Validate OperationContext structure
 */
export function isOperationContext(value: unknown): value is OperationContext {
  return isDict(value, isJSONValueStrict);
}

/**
 * Validate DataContainer structure
 */
export function isDataContainer<T>(
  value: unknown,
  dataGuard: (data: unknown) => data is T
): value is DataContainer<T> {
  if (value === null || typeof value !== 'object') {
    return false;
  }

  const container = value as Record<string, unknown>;

  return (
    dataGuard(container.data) &&
    (container.metadata === undefined || isMetadataStrict(container.metadata))
  );
}

// =============================================================================
// Guard Composition Utilities
// =============================================================================

/**
 * Combine multiple guards with AND logic
 */
export function and<T>(
  ...guards: Array<(value: unknown) => value is T>
): (value: unknown) => value is T {
  return (value: unknown): value is T => {
    return guards.every(guard => guard(value));
  };
}

/**
 * Combine multiple guards with OR logic
 */
export function or<T>(
  ...guards: Array<(value: unknown) => value is T>
): (value: unknown) => value is T {
  return (value: unknown): value is T => {
    return guards.some(guard => guard(value));
  };
}

/**
 * Create a guard that checks for null/undefined before applying another guard
 */
export function optional<T>(
  guard: (value: unknown) => value is T
): (value: unknown) => value is T | null | undefined {
  return (value: unknown): value is T | null | undefined => {
    return value === null || value === undefined || guard(value);
  };
}

/**
 * Create a guard that transforms the value before checking
 */
export function transform<T, U>(
  transformer: (value: unknown) => unknown,
  guard: (value: unknown) => value is U
): (value: unknown) => value is U {
  return (value: unknown): value is U => {
    try {
      const transformed = transformer(value);
      return guard(transformed);
    } catch {
      return false;
    }
  };
}

/**
 * Create a guard that validates an array of items using a provided guard
 */
export function arrayOf<T>(
  itemGuard: (item: unknown) => item is T,
  options: {
    minLength?: number;
    maxLength?: number;
    allowNullItems?: boolean;
    uniqueItems?: boolean;
  } = {}
): (value: unknown) => value is T[] {
  const { minLength, maxLength, allowNullItems = false, uniqueItems = false } = options;

  return (value: unknown): value is T[] => {
    if (!Array.isArray(value)) {
      return false;
    }

    if (minLength !== undefined && value.length < minLength) {
      return false;
    }

    if (maxLength !== undefined && value.length > maxLength) {
      return false;
    }

    // Check each item
    for (const item of value) {
      if (allowNullItems && item === null) {
        continue;
      }
      if (!itemGuard(item)) {
        return false;
      }
    }

    // Check for unique items if required
    if (uniqueItems) {
      const seen = new Set();
      for (const item of value) {
        const key = JSON.stringify(item);
        if (seen.has(key)) {
          return false;
        }
        seen.add(key);
      }
    }

    return true;
  };
}

/**
 * Create a guard that validates an object has a specific property
 */
export function hasProperty<K extends string | number | symbol, T>(
  key: K,
  valueGuard: (value: unknown) => value is T
): (obj: unknown) => obj is { [P in K]: T } {
  return (obj: unknown): obj is { [P in K]: T } => {
    if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
      return false;
    }

    const record = obj as Record<string | number | symbol, unknown>;
    const propertyValue = record[key];

    return valueGuard(propertyValue);
  };
}

/**
 * Create a guard that validates an object has multiple specific properties
 */
export function hasProperties<
  T extends Record<string, (value: unknown) => boolean>
>(
  propertyGuards: T
): (obj: unknown) => obj is Record<string, unknown> {
  return (obj: unknown): obj is Record<string, unknown> => {
    if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
      return false;
    }

    const record = obj as Record<string, unknown>;

    for (const [key, guard] of Object.entries(propertyGuards)) {
      if (!guard(record[key])) {
        return false;
      }
    }

    return true;
  };
}

/**
 * Create a guard that validates an object with partial property matching
 */
export function partialShape<T extends Record<string, (value: unknown) => boolean>>(
  propertyGuards: T
): (obj: unknown) => obj is Partial<Record<string, unknown>> {
  return (obj: unknown): obj is Partial<Record<string, unknown>> => {
    if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
      return false;
    }

    const record = obj as Record<string, unknown>;

    for (const [key, guard] of Object.entries(propertyGuards)) {
      if (key in record && !guard(record[key])) {
        return false;
      }
    }

    return true;
  };
}

/**
 * Create a guard that validates an exact shape (all properties must be present)
 */
export function exactShape<T extends Record<string, (value: unknown) => boolean>>(
  propertyGuards: T
): (obj: unknown) => obj is Record<string, unknown> {
  return (obj: unknown): obj is Record<string, unknown> => {
    if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
      return false;
    }

    const record = obj as Record<string, unknown>;
    const requiredKeys = Object.keys(propertyGuards);
    const actualKeys = Object.keys(record);

    // Check that all required keys are present
    if (requiredKeys.length !== actualKeys.length || !requiredKeys.every(key => key in record)) {
      return false;
    }

    // Check each property
    for (const [key, guard] of Object.entries(propertyGuards)) {
      if (!guard(record[key])) {
        return false;
      }
    }

    return true;
  };
}

/**
 * Create a guard that validates a record (dictionary) with specific key and value types
 */
export function recordOf<K extends string, T>(
  keyGuard: (key: unknown) => key is K,
  valueGuard: (value: unknown) => value is T,
  options: {
    minEntries?: number;
    maxEntries?: number;
  } = {}
): (obj: unknown) => obj is Record<K, T> {
  const { minEntries, maxEntries } = options;

  return (obj: unknown): obj is Record<K, T> => {
    if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
      return false;
    }

    const record = obj as Record<string, unknown>;
    const entries = Object.entries(record);

    if (minEntries !== undefined && entries.length < minEntries) {
      return false;
    }

    if (maxEntries !== undefined && entries.length > maxEntries) {
      return false;
    }

    for (const [key, value] of entries) {
      if (!keyGuard(key) || !valueGuard(value)) {
        return false;
      }
    }

    return true;
  };
}

/**
 * Create a guard that validates a tuple with specific types for each position
 */
export function tuple<T extends readonly unknown[]>(
  ...guards: Array<(value: unknown) => boolean>
): (value: unknown) => value is T {
  return (value: unknown): value is T => {
    if (!Array.isArray(value) || value.length !== guards.length) {
      return false;
    }

    for (let i = 0; i < guards.length; i++) {
      if (!guards[i](value[i])) {
        return false;
      }
    }

    return true;
  };
}

/**
 * Create a guard that validates a discriminated union
 */
export function discriminatedUnion<T extends string, U>(
  discriminator: keyof U,
  discriminatorValue: T,
  shapeGuard: (value: unknown) => value is U
): (value: unknown) => value is U & Record<typeof discriminator, T> {
  return (value: unknown): value is U & Record<typeof discriminator, T> => {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      return false;
    }

    const record = value as Record<string, unknown>;

    if (record[discriminator as string] !== discriminatorValue) {
      return false;
    }

    return shapeGuard(value);
  };
}

/**
 * Create a guard that validates one of several discriminated types
 */
export function oneOf<T extends string, U>(
  discriminator: keyof U,
  cases: Record<T, (value: unknown) => value is U>
): (value: unknown) => value is U {
  return (value: unknown): value is U => {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      return false;
    }

    const record = value as Record<string, unknown>;
    const discriminatorValue = record[discriminator as string] as T;

    if (discriminatorValue === undefined || !cases[discriminatorValue]) {
      return false;
    }

    return cases[discriminatorValue](value);
  };
}

/**
 * Create a guard that validates a value is within a set of allowed values
 */
export function oneOfValues<T extends readonly unknown[]>(
  allowedValues: T
): (value: unknown) => value is T[number] {
  const valueSet = new Set(allowedValues);

  return (value: unknown): value is T[number] => {
    return valueSet.has(value);
  };
}

/**
 * Create a guard that validates a number is within a specific range
 */
export function numberRange(
  min: number,
  max: number,
  options: {
    inclusive?: boolean;
    integer?: boolean;
  } = {}
): (value: unknown) => value is number {
  const { inclusive = true, integer = false } = options;

  return (value: unknown): value is number => {
    if (typeof value !== 'number' || !isFinite(value)) {
      return false;
    }

    if (integer && !Number.isInteger(value)) {
      return false;
    }

    if (inclusive) {
      return value >= min && value <= max;
    } else {
      return value > min && value < max;
    }
  };
}

/**
 * Create a guard that validates a string matches a pattern
 */
export function stringPattern(
  pattern: RegExp,
  options: {
    flags?: string;
  } = {}
): (value: unknown) => value is string {
  const { flags } = options;
  const regex = new RegExp(pattern, flags);

  return (value: unknown): value is string => {
    return typeof value === 'string' && regex.test(value);
  };
}

/**
 * Create a guard that validates a string has a specific length
 */
export function stringLength(
  minLength: number,
  maxLength?: number
): (value: unknown) => value is string {
  return (value: unknown): value is string => {
    if (typeof value !== 'string') {
      return false;
    }

    if (value.length < minLength) {
      return false;
    }

    if (maxLength !== undefined && value.length > maxLength) {
      return false;
    }

    return true;
  };
}

// =============================================================================
// API Response Type Guards
// =============================================================================

/**
 * Check if value is a success response
 */
export function isSuccessResponse<T>(
  value: unknown,
  dataGuard?: (data: unknown) => data is T
): value is { readonly success: true; readonly data: T; readonly message?: string } {
  if (value === null || typeof value !== 'object') {
    return false;
  }

  const response = value as Record<string, unknown>;

  if (response.success !== true) {
    return false;
  }

  if (response.data === undefined) {
    return false;
  }

  return dataGuard ? dataGuard(response.data) : true;
}

/**
 * Check if value is an error response
 */
export function isErrorResponse(
  value: unknown,
  errorCodeGuard?: (code: unknown) => boolean
): value is { readonly success: false; readonly error: { readonly code: string; readonly message: string; readonly details?: unknown } } {
  if (value === null || typeof value !== 'object') {
    return false;
  }

  const response = value as Record<string, unknown>;

  if (response.success !== false) {
    return false;
  }

  const error = response.error;
  if (error === null || typeof error !== 'object') {
    return false;
  }

  const errorObj = error as Record<string, unknown>;

  if (typeof errorObj.code !== 'string' || typeof errorObj.message !== 'string') {
    return false;
  }

  return errorCodeGuard ? errorCodeGuard(errorObj.code) : true;
}

/**
 * Check if value is a standard API response (success or error)
 */
export function isStandardApiResponse<T>(
  value: unknown,
  dataGuard?: (data: unknown) => data is T
): value is ({ readonly success: true; readonly data: T; readonly message?: string } | { readonly success: false; readonly error: { readonly code: string; readonly message: string; readonly details?: unknown } }) {
  return isSuccessResponse(value, dataGuard) || isErrorResponse(value);
}

/**
 * Check if value is an MCP tool response
 */
export function isMCPToolResponse(value: unknown): value is { readonly content: readonly unknown[]; readonly isError?: boolean; readonly _meta?: Record<string, unknown> } {
  if (value === null || typeof value !== 'object') {
    return false;
  }

  const response = value as Record<string, unknown>;

  if (!Array.isArray(response.content)) {
    return false;
  }

  // isError is optional, but if present must be boolean
  if (response.isError !== undefined && typeof response.isError !== 'boolean') {
    return false;
  }

  // _meta is optional, but if present must be object
  if (response._meta !== undefined && (response._meta === null || typeof response._meta !== 'object' || Array.isArray(response._meta))) {
    return false;
  }

  return true;
}

// =============================================================================
// Knowledge Item Type Guards
// =============================================================================

/**
 * Check if value is a KnowledgeItem scope
 */
export function isKnowledgeScope(value: unknown): value is { readonly project?: string; readonly branch?: string; readonly org?: string } {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const scope = value as Record<string, unknown>;

  if (scope.project !== undefined && typeof scope.project !== 'string') {
    return false;
  }

  if (scope.branch !== undefined && typeof scope.branch !== 'string') {
    return false;
  }

  if (scope.org !== undefined && typeof scope.org !== 'string') {
    return false;
  }

  return true;
}

/**
 * Check if value is a KnowledgeItem
 */
export function isKnowledgeItem(value: unknown): value is { readonly id?: string; readonly kind: string; readonly content?: string; readonly scope: { readonly project?: string; readonly branch?: string; readonly org?: string }; readonly data: Record<string, unknown>; readonly metadata?: Record<string, unknown>; readonly created_at?: string; readonly updated_at?: string; readonly expiry_at?: string } {
  if (value === null || typeof value !== 'object') {
    return false;
  }

  const item = value as Record<string, unknown>;

  // Required fields
  if (typeof item.kind !== 'string') {
    return false;
  }

  if (!isKnowledgeScope(item.scope)) {
    return false;
  }

  if (item.data === null || typeof item.data !== 'object' || Array.isArray(item.data)) {
    return false;
  }

  // Optional fields
  if (item.id !== undefined && typeof item.id !== 'string') {
    return false;
  }

  if (item.content !== undefined && typeof item.content !== 'string') {
    return false;
  }

  if (item.metadata !== undefined && (item.metadata === null || typeof item.metadata !== 'object' || Array.isArray(item.metadata))) {
    return false;
  }

  if (item.created_at !== undefined && (typeof item.created_at !== 'string' || !isValidISODate(item.created_at))) {
    return false;
  }

  if (item.updated_at !== undefined && (typeof item.updated_at !== 'string' || !isValidISODate(item.updated_at))) {
    return false;
  }

  if (item.expiry_at !== undefined && (typeof item.expiry_at !== 'string' || !isValidISODate(item.expiry_at))) {
    return false;
  }

  return true;
}

/**
 * Check if value is a SearchQuery
 */
export function isSearchQuery(value: unknown): value is { readonly query: string; readonly scope?: { readonly project?: string; readonly branch?: string; readonly org?: string }; readonly types?: string[]; readonly kind?: string; readonly mode?: 'auto' | 'fast' | 'deep'; readonly limit?: number; readonly top_k?: number; readonly expand?: 'relations' | 'parents' | 'children' | 'none'; readonly text?: unknown; readonly filters?: unknown } {
  if (value === null || typeof value !== 'object') {
    return false;
  }

  const query = value as Record<string, unknown>;

  // Required fields
  if (typeof query.query !== 'string') {
    return false;
  }

  // Optional fields with type checking
  if (query.scope !== undefined && !isKnowledgeScope(query.scope)) {
    return false;
  }

  if (query.types !== undefined && !Array.isArray(query.types)) {
    return false;
  }

  if (query.types !== undefined && !(query.types as unknown[]).every((type) => typeof type === 'string')) {
    return false;
  }

  if (query.kind !== undefined && typeof query.kind !== 'string') {
    return false;
  }

  if (query.mode !== undefined && !['auto', 'fast', 'deep'].includes(query.mode as string)) {
    return false;
  }

  if (query.limit !== undefined && (typeof query.limit !== 'number' || query.limit <= 0)) {
    return false;
  }

  if (query.top_k !== undefined && (typeof query.top_k !== 'number' || query.top_k <= 0)) {
    return false;
  }

  if (query.expand !== undefined && !['relations', 'parents', 'children', 'none'].includes(query.expand as string)) {
    return false;
  }

  return true;
}

/**
 * Check if value is a SearchResult
 */
export function isSearchResult(value: unknown): value is { readonly id: string; readonly kind: string; readonly scope: Record<string, unknown>; readonly data: Record<string, unknown>; readonly created_at: string; readonly confidence_score: number; readonly match_type: 'exact' | 'fuzzy' | 'semantic' | 'keyword' | 'hybrid' | 'expanded' | 'graph'; readonly highlight?: string[] } {
  if (value === null || typeof value !== 'object') {
    return false;
  }

  const result = value as Record<string, unknown>;

  // Required fields
  if (typeof result.id !== 'string') {
    return false;
  }

  if (typeof result.kind !== 'string') {
    return false;
  }

  if (result.scope === null || typeof result.scope !== 'object' || Array.isArray(result.scope)) {
    return false;
  }

  if (result.data === null || typeof result.data !== 'object' || Array.isArray(result.data)) {
    return false;
  }

  if (typeof result.created_at !== 'string' || !isValidISODate(result.created_at)) {
    return false;
  }

  if (typeof result.confidence_score !== 'number' || result.confidence_score < 0 || result.confidence_score > 1) {
    return false;
  }

  if (typeof result.match_type !== 'string' || !['exact', 'fuzzy', 'semantic', 'keyword', 'hybrid', 'expanded', 'graph'].includes(result.match_type as string)) {
    return false;
  }

  // Optional highlight field
  if (result.highlight !== undefined && !Array.isArray(result.highlight)) {
    return false;
  }

  if (result.highlight !== undefined && !(result.highlight as unknown[]).every((highlight) => typeof highlight === 'string')) {
    return false;
  }

  return true;
}

// =============================================================================
// Configuration Type Guards
// =============================================================================

/**
 * Check if value is a Qdrant configuration
 */
export function isQdrantConfig(value: unknown): value is { readonly host: string; readonly port: number; readonly apiKey?: string; readonly timeout: number; readonly maxRetries: number; readonly retryDelay: number; readonly useHttps: boolean; readonly collectionPrefix?: string; readonly enableHealthChecks: boolean; readonly connectionPoolSize: number; readonly requestTimeout: number; readonly connectTimeout: number } {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const config = value as Record<string, unknown>;

  // Required fields
  if (typeof config.host !== 'string') {
    return false;
  }

  if (typeof config.port !== 'number' || config.port <= 0 || config.port > 65535) {
    return false;
  }

  if (typeof config.timeout !== 'number' || config.timeout <= 0) {
    return false;
  }

  if (typeof config.maxRetries !== 'number' || config.maxRetries < 0) {
    return false;
  }

  if (typeof config.retryDelay !== 'number' || config.retryDelay < 0) {
    return false;
  }

  if (typeof config.useHttps !== 'boolean') {
    return false;
  }

  if (typeof config.enableHealthChecks !== 'boolean') {
    return false;
  }

  if (typeof config.connectionPoolSize !== 'number' || config.connectionPoolSize <= 0) {
    return false;
  }

  if (typeof config.requestTimeout !== 'number' || config.requestTimeout <= 0) {
    return false;
  }

  if (typeof config.connectTimeout !== 'number' || config.connectTimeout <= 0) {
    return false;
  }

  // Optional fields
  if (config.apiKey !== undefined && typeof config.apiKey !== 'string') {
    return false;
  }

  if (config.collectionPrefix !== undefined && typeof config.collectionPrefix !== 'string') {
    return false;
  }

  return true;
}

/**
 * Check if value is a Database configuration
 */
export function isDatabaseConfig(value: unknown): value is { readonly qdrant: { readonly host: string; readonly port: number; readonly apiKey?: string; readonly timeout: number; readonly maxRetries: number; readonly retryDelay: number; readonly useHttps: boolean; readonly collectionPrefix?: string; readonly enableHealthChecks: boolean; readonly connectionPoolSize: number; readonly requestTimeout: number; readonly connectTimeout: number }; readonly fallbackEnabled: boolean; readonly backupEnabled: boolean; readonly migrationEnabled: boolean } {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const config = value as Record<string, unknown>;

  if (!isQdrantConfig(config.qdrant)) {
    return false;
  }

  if (typeof config.fallbackEnabled !== 'boolean') {
    return false;
  }

  if (typeof config.backupEnabled !== 'boolean') {
    return false;
  }

  if (typeof config.migrationEnabled !== 'boolean') {
    return false;
  }

  return true;
}

/**
 * Check if value is a JWT configuration
 */
export function isJWTConfig(value: unknown): value is { readonly secret: string; readonly expiresIn: string; readonly issuer: string; readonly audience: string; readonly algorithm: 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512' } {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const config = value as Record<string, unknown>;

  if (typeof config.secret !== 'string') {
    return false;
  }

  if (typeof config.expiresIn !== 'string') {
    return false;
  }

  if (typeof config.issuer !== 'string') {
    return false;
  }

  if (typeof config.audience !== 'string') {
    return false;
  }

  if (typeof config.algorithm !== 'string' || !['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512'].includes(config.algorithm)) {
    return false;
  }

  return true;
}

/**
 * Check if value is an API Key configuration
 */
export function isApiKeyConfig(value: unknown): value is { readonly headerName: string; readonly queryParam?: string; readonly validationEnabled: boolean; readonly rateLimitEnabled: boolean } {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const config = value as Record<string, unknown>;

  if (typeof config.headerName !== 'string') {
    return false;
  }

  if (config.queryParam !== undefined && typeof config.queryParam !== 'string') {
    return false;
  }

  if (typeof config.validationEnabled !== 'boolean') {
    return false;
  }

  if (typeof config.rateLimitEnabled !== 'boolean') {
    return false;
  }

  return true;
}

/**
 * Check if value is an Authentication configuration
 */
export function isAuthConfig(value: unknown): value is { readonly jwt: { readonly secret: string; readonly expiresIn: string; readonly issuer: string; readonly audience: string; readonly algorithm: 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512' }; readonly apiKey: { readonly headerName: string; readonly queryParam?: string; readonly validationEnabled: boolean; readonly rateLimitEnabled: boolean }; readonly enabled: boolean; readonly sessionTimeout: number; readonly refreshTokenEnabled: boolean; readonly passwordPolicyEnabled: boolean } {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const config = value as Record<string, unknown>;

  if (!isJWTConfig(config.jwt)) {
    return false;
  }

  if (!isApiKeyConfig(config.apiKey)) {
    return false;
  }

  if (typeof config.enabled !== 'boolean') {
    return false;
  }

  if (typeof config.sessionTimeout !== 'number' || config.sessionTimeout <= 0) {
    return false;
  }

  if (typeof config.refreshTokenEnabled !== 'boolean') {
    return false;
  }

  if (typeof config.passwordPolicyEnabled !== 'boolean') {
    return false;
  }

  return true;
}

/**
 * Check if value is a Rate Limit configuration
 */
export function isRateLimitConfig(value: unknown): value is { readonly windowMs: number; readonly maxRequests: number; readonly skipSuccessfulRequests: boolean; readonly skipFailedRequests: boolean; readonly enableHeaders: boolean } {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const config = value as Record<string, unknown>;

  if (typeof config.windowMs !== 'number' || config.windowMs <= 0) {
    return false;
  }

  if (typeof config.maxRequests !== 'number' || config.maxRequests <= 0) {
    return false;
  }

  if (typeof config.skipSuccessfulRequests !== 'boolean') {
    return false;
  }

  if (typeof config.skipFailedRequests !== 'boolean') {
    return false;
  }

  if (typeof config.enableHeaders !== 'boolean') {
    return false;
  }

  return true;
}

/**
 * Check if value is a CORS configuration
 */
export function isCorsConfig(value: unknown): value is { readonly origin: string | string[] | boolean; readonly credentials: boolean; readonly methods: string[]; readonly allowedHeaders: string[]; readonly exposedHeaders?: string[]; readonly maxAge?: number; readonly preflightContinue?: boolean; readonly optionsSuccessStatus?: number } {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const config = value as Record<string, unknown>;

  if (typeof config.origin !== 'string' && !Array.isArray(config.origin) && typeof config.origin !== 'boolean') {
    return false;
  }

  if (Array.isArray(config.origin) && !config.origin.every((origin) => typeof origin === 'string')) {
    return false;
  }

  if (typeof config.credentials !== 'boolean') {
    return false;
  }

  if (!Array.isArray(config.methods) || !config.methods.every((method) => typeof method === 'string')) {
    return false;
  }

  if (!Array.isArray(config.allowedHeaders) || !config.allowedHeaders.every((header) => typeof header === 'string')) {
    return false;
  }

  if (config.exposedHeaders !== undefined && (!Array.isArray(config.exposedHeaders) || !config.exposedHeaders.every((header) => typeof header === 'string'))) {
    return false;
  }

  if (config.maxAge !== undefined && (typeof config.maxAge !== 'number' || config.maxAge < 0)) {
    return false;
  }

  if (config.preflightContinue !== undefined && typeof config.preflightContinue !== 'boolean') {
    return false;
  }

  if (config.optionsSuccessStatus !== undefined && (typeof config.optionsSuccessStatus !== 'number' || config.optionsSuccessStatus < 100 || config.optionsSuccessStatus >= 600)) {
    return false;
  }

  return true;
}

/**
 * Check if value is a Service configuration
 */
export function isServiceConfig(value: unknown): value is { readonly timeout?: number; readonly retries?: number; readonly enableLogging?: boolean } {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const config = value as Record<string, unknown>;

  if (config.timeout !== undefined && (typeof config.timeout !== 'number' || config.timeout <= 0)) {
    return false;
  }

  if (config.retries !== undefined && (typeof config.retries !== 'number' || config.retries < 0)) {
    return false;
  }

  if (config.enableLogging !== undefined && typeof config.enableLogging !== 'boolean') {
    return false;
  }

  return true;
}

// =============================================================================
// Error Type Guards
// =============================================================================

/**
 * Check if value is a Validation Error
 */
export function isValidationError(value: unknown): value is { readonly code: string; readonly message: string; readonly path?: string; readonly value?: unknown } {
  if (value === null || typeof value !== 'object') {
    return false;
  }

  const error = value as Record<string, unknown>;

  if (typeof error.code !== 'string') {
    return false;
  }

  if (typeof error.message !== 'string') {
    return false;
  }

  if (error.path !== undefined && typeof error.path !== 'string') {
    return false;
  }

  // value can be any type, so no validation needed

  return true;
}

/**
 * Check if value is a System Error
 */
export function isSystemError(value: unknown): value is { readonly code: string; readonly message: string; readonly category: 'network' | 'database' | 'filesystem' | 'memory' | 'security' | 'performance' | 'configuration' | 'unknown'; readonly severity: 'low' | 'medium' | 'high' | 'critical'; readonly timestamp?: string; readonly retryable: boolean; readonly details?: Record<string, unknown> } {
  if (value === null || typeof value !== 'object') {
    return false;
  }

  const error = value as Record<string, unknown>;

  if (typeof error.code !== 'string') {
    return false;
  }

  if (typeof error.message !== 'string') {
    return false;
  }

  if (typeof error.category !== 'string' || !['network', 'database', 'filesystem', 'memory', 'security', 'performance', 'configuration', 'unknown'].includes(error.category)) {
    return false;
  }

  if (typeof error.severity !== 'string' || !['low', 'medium', 'high', 'critical'].includes(error.severity)) {
    return false;
  }

  if (typeof error.retryable !== 'boolean') {
    return false;
  }

  if (error.timestamp !== undefined && (typeof error.timestamp !== 'string' || !isValidISODate(error.timestamp))) {
    return false;
  }

  if (error.details !== undefined && (error.details === null || typeof error.details !== 'object' || Array.isArray(error.details))) {
    return false;
  }

  return true;
}

/**
 * Check if value is a Database Error
 */
export function isDatabaseError(value: unknown): value is { readonly code: string; readonly message: string; readonly database: string; readonly table?: string; readonly operation?: string; readonly query?: string; readonly retryable: boolean; readonly timeout?: boolean; readonly connectionLost?: boolean } {
  if (value === null || typeof value !== 'object') {
    return false;
  }

  const error = value as Record<string, unknown>;

  if (typeof error.code !== 'string') {
    return false;
  }

  if (typeof error.message !== 'string') {
    return false;
  }

  if (typeof error.database !== 'string') {
    return false;
  }

  if (error.table !== undefined && typeof error.table !== 'string') {
    return false;
  }

  if (error.operation !== undefined && typeof error.operation !== 'string') {
    return false;
  }

  if (error.query !== undefined && typeof error.query !== 'string') {
    return false;
  }

  if (typeof error.retryable !== 'boolean') {
    return false;
  }

  if (error.timeout !== undefined && typeof error.timeout !== 'boolean') {
    return false;
  }

  if (error.connectionLost !== undefined && typeof error.connectionLost !== 'boolean') {
    return false;
  }

  return true;
}

/**
 * Check if value is a Network Error
 */
export function isNetworkError(value: unknown): value is { readonly code: string; readonly message: string; readonly url?: string; readonly method?: string; readonly statusCode?: number; readonly timeout?: boolean; readonly retryable: boolean; readonly headers?: Record<string, string> } {
  if (value === null || typeof value !== 'object') {
    return false;
  }

  const error = value as Record<string, unknown>;

  if (typeof error.code !== 'string') {
    return false;
  }

  if (typeof error.message !== 'string') {
    return false;
  }

  if (error.url !== undefined && !isValidURL(error.url)) {
    return false;
  }

  if (error.method !== undefined && typeof error.method !== 'string') {
    return false;
  }

  if (error.statusCode !== undefined && (typeof error.statusCode !== 'number' || error.statusCode < 100 || error.statusCode >= 600)) {
    return false;
  }

  if (typeof error.retryable !== 'boolean') {
    return false;
  }

  if (error.timeout !== undefined && typeof error.timeout !== 'boolean') {
    return false;
  }

  if (error.headers !== undefined && !isDict(error.headers, isString)) {
    return false;
  }

  return true;
}

/**
 * Check if value is an MCP Error
 */
export function isMCPError(value: unknown): value is { readonly code: number; readonly message: string; readonly data?: unknown } {
  if (value === null || typeof value !== 'object') {
    return false;
  }

  const error = value as Record<string, unknown>;

  if (typeof error.code !== 'number' || error.code < -32768 || error.code > -32000) {
    return false;
  }

  if (typeof error.message !== 'string') {
    return false;
  }

  // data can be any type, so no validation needed

  return true;
}

// =============================================================================
// Schema-Based Guards
// =============================================================================

/**
 * Schema interface for defining complex validation rules
 */
export interface Schema<T = unknown> {
  validate: (value: unknown) => value is T;
  description?: string;
  required?: boolean;
}

/**
 * Create a schema-based guard from a schema definition
 */
export function schema<T>(definition: Schema<T>): (value: unknown) => value is T {
  return definition.validate;
}

/**
 * Create a guard for nested object validation with schema
 */
export function nestedObject<T extends Record<string, Schema | ((value: unknown) => boolean)>>(
  schema: T,
  options: {
    strict?: boolean; // If true, reject extra properties
    allowPartial?: boolean; // If true, allow missing optional properties
  } = {}
): (value: unknown) => value is Record<string, unknown> {
  const { strict = false, allowPartial = false } = options;

  return (value: unknown): value is Record<string, unknown> => {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      return false;
    }

    const obj = value as Record<string, unknown>;
    const schemaKeys = Object.keys(schema);
    const objKeys = Object.keys(obj);

    // In strict mode, object should not have extra properties
    if (strict) {
      for (const key of objKeys) {
        if (!schemaKeys.includes(key)) {
          return false;
        }
      }
    }

    // Validate each property according to schema
    for (const [key, schemaOrGuard] of Object.entries(schema)) {
      const hasProperty = key in obj;

      if (!hasProperty && !allowPartial) {
        return false;
      }

      if (hasProperty) {
        const validator = typeof schemaOrGuard === 'function' && schemaOrGuard.length === 1
          ? schemaOrGuard as (value: unknown) => boolean
          : (schemaOrGuard as Schema).validate;

        if (!validator(obj[key])) {
          return false;
        }
      }
    }

    return true;
  };
}

/**
 * Create a guard for generic collection validation with schema
 */
export function collectionSchema<T>(
  itemSchema: Schema<T> | ((value: unknown) => boolean),
  options: {
    minLength?: number;
    maxLength?: number;
    uniqueKey?: string; // For deduplication based on a key
    sortBy?: string; // For optional sorting validation
  } = {}
): (value: unknown) => value is unknown[] {
  const { minLength, maxLength, uniqueKey, sortBy } = options;
  const itemValidator = typeof itemSchema === 'function' && itemSchema.length === 1
    ? itemSchema as (value: unknown) => boolean
    : (itemSchema as Schema).validate;

  return (value: unknown): value is unknown[] => {
    if (!Array.isArray(value)) {
      return false;
    }

    if (minLength !== undefined && value.length < minLength) {
      return false;
    }

    if (maxLength !== undefined && value.length > maxLength) {
      return false;
    }

    // Validate each item
    for (const item of value) {
      if (!itemValidator(item)) {
        return false;
      }
    }

    // Check for uniqueness based on key if specified
    if (uniqueKey) {
      const seen = new Set();
      for (const item of value) {
        const keyValue = (item as Record<string, unknown>)[uniqueKey];
        if (seen.has(keyValue)) {
          return false;
        }
        seen.add(keyValue);
      }
    }

    // Optional sorting validation
    if (sortBy) {
      for (let i = 1; i < value.length; i++) {
        const prev = (value[i - 1] as Record<string, unknown>)[sortBy];
        const curr = (value[i] as Record<string, unknown>)[sortBy];
          if (typeof prev === 'string' && typeof curr === 'string' && prev > curr) {
          return false;
        } else if (typeof prev === 'number' && typeof curr === 'number' && prev > curr) {
          return false;
        } else if (prev === null || curr === null) {
          // Handle null comparison
          return false;
        }
      }
    }

    return true;
  };
}

/**
 * Create a guard for conditional validation based on other properties
 */
export function conditionalGuard<T>(
  condition: (value: unknown) => boolean,
  trueGuard: (value: unknown) => value is T,
  falseGuard?: (value: unknown) => value is T
): (value: unknown) => value is T {
  return (value: unknown): value is T => {
    if (condition(value)) {
      return trueGuard(value);
    }
    return falseGuard ? falseGuard(value) : false;
  };
}

/**
 * Create a guard that validates data structure with circular reference support
 */
export function circularSchema<T>(
  schemaDefinition: () => (value: unknown) => value is T
): (value: unknown) => value is T {
  // Use WeakSet to track visited objects and prevent infinite recursion
  const visited = new WeakSet();

  return (value: unknown): value is T => {
    if (value === null || typeof value !== 'object') {
      return false;
    }

    if (visited.has(value)) {
      return true; // Already validated this object in current chain
    }

    visited.add(value);
    const result = schemaDefinition()(value);
    visited.delete(value);

    return result;
  };
}

// =============================================================================
// Common API Pattern Guards
// =============================================================================

/**
 * Guard for database query results with created_at timestamp
 */
export function isDatabaseResult(value: unknown): value is Record<string, unknown> & { created_at: Date | string } {
  if (value === null || typeof value !== 'object') {
    return false;
  }

  const result = value as Record<string, unknown>;

  // Check for created_at field
  const createdAt = result.created_at;
  if (!(createdAt instanceof Date) && (typeof createdAt !== 'string' || !isValidISODate(createdAt))) {
    return false;
  }

  return true;
}

/**
 * Guard for Qdrant-style whereClause objects
 */
export function isWhereClause(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const clause = value as Record<string, unknown>;

  // Allow common where clause operators
  const validKeys = ['AND', 'OR', 'NOT', 'kind', 'data', 'tags', 'id', 'created_at', 'updated_at'];

  for (const [key, val] of Object.entries(clause)) {
    if (!validKeys.includes(key)) {
      return false;
    }

    // Validate structure of known operators
    switch (key) {
      case 'AND':
      case 'OR':
        if (!Array.isArray(val)) {
          return false;
        }
        // Each item should be a valid where clause
        if (!val.every(item => isWhereClause(item))) {
          return false;
        }
        break;
      case 'NOT':
        if (!isWhereClause(val)) {
          return false;
        }
        break;
      case 'kind':
        if (typeof val !== 'object' || val === null || Array.isArray(val)) {
          return false;
        }
        // Handle kind operators like { in: ['type1', 'type2'] }
        const kindObj = val as Record<string, unknown>;
        if ('in' in kindObj && !Array.isArray(kindObj.in)) {
          return false;
        }
        break;
      case 'data':
        if (typeof val !== 'object' || val === null || Array.isArray(val)) {
          return false;
        }
        // Handle data operators like { path: ['field'], string_contains: 'value' }
        const dataObj = val as Record<string, unknown>;
        if (dataObj.path && !Array.isArray(dataObj.path)) {
          return false;
        }
        break;
      case 'tags':
        if (typeof val !== 'object' || val === null || Array.isArray(val)) {
          return false;
        }
        // Handle tags operators similar to data
        const tagsObj = val as Record<string, unknown>;
        if (tagsObj.path && !Array.isArray(tagsObj.path)) {
          return false;
        }
        break;
    }
  }

  return true;
}

/**
 * Guard for search results array
 */
export function isSearchResults(value: unknown): value is unknown[] {
  return Array.isArray(value) && value.every(item => isDatabaseResult(item));
}

/**
 * Guard for database row objects
 */
export function isDatabaseRow(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  // Most database rows should have an id field
  const row = value as Record<string, unknown>;
  if (row.id !== undefined && typeof row.id !== 'string' && typeof row.id !== 'number') {
    return false;
  }

  return true;
}

/**
 * Guard for strategy objects with common properties
 */
export function isStrategyObject(value: unknown): value is Record<string, unknown> & { name: string; type?: string } {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const strategy = value as Record<string, unknown>;

  if (typeof strategy.name !== 'string') {
    return false;
  }

  if (strategy.type !== undefined && typeof strategy.type !== 'string') {
    return false;
  }

  return true;
}

/**
 * Guard for metric objects
 */
export function isMetricObject(value: unknown): value is Record<string, unknown> & {
  name?: string;
  value?: number | string;
  timestamp?: string | Date;
  unit?: string;
  tags?: Record<string, string>;
} {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const metric = value as Record<string, unknown>;

  if (metric.name !== undefined && typeof metric.name !== 'string') {
    return false;
  }

  if (metric.value !== undefined && typeof metric.value !== 'number' && typeof metric.value !== 'string') {
    return false;
  }

  if (metric.timestamp !== undefined) {
    if (!(metric.timestamp instanceof Date) && (typeof metric.timestamp !== 'string' || !isValidISODate(metric.timestamp))) {
      return false;
    }
  }

  if (metric.unit !== undefined && typeof metric.unit !== 'string') {
    return false;
  }

  if (metric.tags !== undefined && !isDict(metric.tags, isString)) {
    return false;
  }

  return true;
}

/**
 * Guard for configuration objects
 */
export function isConfigObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  // Basic validation - most config objects have string keys and various value types
  const config = value as Record<string, unknown>;

  for (const [key, val] of Object.entries(config)) {
    if (typeof key !== 'string') {
      return false;
    }

    // Allow common config value types
    if (val !== null &&
        typeof val !== 'string' &&
        typeof val !== 'number' &&
        typeof val !== 'boolean' &&
        typeof val !== 'object') {
      return false;
    }

    // If object, must be plain object or array
    if (typeof val === 'object' && !Array.isArray(val)) {
      if (Object.prototype.toString.call(val) !== '[object Object]') {
        return false;
      }
    }
  }

  return true;
}

/**
 * Guard for issue objects (common in error reporting/monitoring)
 */
export function isIssueObject(value: unknown): value is Record<string, unknown> & {
  id?: string;
  title?: string;
  description?: string;
  severity?: string;
  status?: string;
  created_at?: string | Date;
  updated_at?: string | Date;
} {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const issue = value as Record<string, unknown>;

  if (issue.id !== undefined && typeof issue.id !== 'string') {
    return false;
  }

  if (issue.title !== undefined && typeof issue.title !== 'string') {
    return false;
  }

  if (issue.description !== undefined && typeof issue.description !== 'string') {
    return false;
  }

  if (issue.severity !== undefined && typeof issue.severity !== 'string') {
    return false;
  }

  if (issue.status !== undefined && typeof issue.status !== 'string') {
    return false;
  }

  if (issue.created_at !== undefined) {
    if (!(issue.created_at instanceof Date) && (typeof issue.created_at !== 'string' || !isValidISODate(issue.created_at))) {
      return false;
    }
  }

  if (issue.updated_at !== undefined) {
    if (!(issue.updated_at instanceof Date) && (typeof issue.updated_at !== 'string' || !isValidISODate(issue.updated_at))) {
      return false;
    }
  }

  return true;
}

/**
 * Guard for compliance objects
 */
export function isComplianceObject(value: unknown): value is Record<string, unknown> & {
  status?: string;
  score?: number;
  rules?: Array<{ name: string; passed: boolean; message?: string }>;
  timestamp?: string | Date;
} {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const compliance = value as Record<string, unknown>;

  if (compliance.status !== undefined && typeof compliance.status !== 'string') {
    return false;
  }

  if (compliance.score !== undefined && (typeof compliance.score !== 'number' || compliance.score < 0 || compliance.score > 100)) {
    return false;
  }

  if (compliance.rules !== undefined) {
    if (!Array.isArray(compliance.rules)) {
      return false;
    }

    for (const rule of compliance.rules) {
      if (!rule || typeof rule !== 'object' || Array.isArray(rule)) {
        return false;
      }

      const ruleObj = rule as Record<string, unknown>;
      if (typeof ruleObj.name !== 'string' || typeof ruleObj.passed !== 'boolean') {
        return false;
      }

      if (ruleObj.message !== undefined && typeof ruleObj.message !== 'string') {
        return false;
      }
    }
  }

  if (compliance.timestamp !== undefined) {
    if (!(compliance.timestamp instanceof Date) && (typeof compliance.timestamp !== 'string' || !isValidISODate(compliance.timestamp))) {
      return false;
    }
  }

  return true;
}

/**
 * Safe property accessor with type guard
 */
export function safePropertyAccess<T>(
  obj: unknown,
  property: string,
  typeGuard: (value: unknown) => value is T,
  defaultValue?: T
): T | undefined {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    return defaultValue;
  }

  const value = (obj as Record<string, unknown>)[property];
  return typeGuard(value) ? value : defaultValue;
}

/**
 * Safe array element accessor with type guard
 */
export function safeArrayAccess<T>(
  arr: unknown,
  index: number,
  typeGuard: (value: unknown) => value is T,
  defaultValue?: T
): T | undefined {
  if (!Array.isArray(arr) || index < 0 || index >= arr.length) {
    return defaultValue;
  }

  const value = arr[index];
  return typeGuard(value) ? value : defaultValue;
}

/**
 * Safe nested property accessor with path
 */
export function safeNestedAccess<T>(
  obj: unknown,
  path: string[],
  typeGuard: (value: unknown) => value is T,
  defaultValue?: T
): T | undefined {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    return defaultValue;
  }

  let current: unknown = obj;

  for (const key of path) {
    if (current === null || typeof current !== 'object' || Array.isArray(current)) {
      return defaultValue;
    }

    current = (current as Record<string, unknown>)[key];

    if (current === undefined) {
      return defaultValue;
    }
  }

  return typeGuard(current) ? current : defaultValue;
}

// =============================================================================
// Performance Optimization
// =============================================================================

/**
 * Memoization cache for guard functions
 */
const guardMemoCache = new WeakMap<
  (value: unknown) => boolean,
  Map<unknown, boolean>
>();

/**
 * Create a memoized version of a guard function
 */
export function memoized<T>(
  guard: (value: unknown) => value is T,
  keySelector?: (value: unknown) => unknown
): (value: unknown) => value is T {
  return (value: unknown): value is T => {
    // Don't memoize primitives, they're already fast
    if (value === null || typeof value !== 'object') {
      return guard(value);
    }

    // Get or create cache for this guard
    let cache = guardMemoCache.get(guard);
    if (!cache) {
      cache = new Map();
      guardMemoCache.set(guard, cache);
    }

    // Use key selector or object itself as cache key
    const key = keySelector ? keySelector(value) : value;

    // Check cache
    if (cache.has(key)) {
      return cache.get(key) as boolean;
    }

    // Compute and cache result
    const result = guard(value);
    cache.set(key, result);

    return result;
  };
}

/**
 * Create a guard that fails fast on common invalid types
 */
export function fastFail<T>(
  guard: (value: unknown) => value is T,
  invalidTypes: Array<'null' | 'undefined' | 'string' | 'number' | 'boolean' | 'symbol' | 'function' | 'object' | 'array'>
): (value: unknown) => value is T {
  return (value: unknown): value is T => {
    // Fast fail checks for common invalid types
    for (const invalidType of invalidTypes) {
      switch (invalidType) {
        case 'null':
          if (value === null) return false;
          break;
        case 'undefined':
          if (value === undefined) return false;
          break;
        case 'string':
          if (typeof value === 'string') return false;
          break;
        case 'number':
          if (typeof value === 'number') return false;
          break;
        case 'boolean':
          if (typeof value === 'boolean') return false;
          break;
        case 'symbol':
          if (typeof value === 'symbol') return false;
          break;
        case 'function':
          if (typeof value === 'function') return false;
          break;
        case 'array':
          if (Array.isArray(value)) return false;
          break;
        case 'object':
          if (typeof value === 'object' && !Array.isArray(value)) return false;
          break;
      }
    }

    return guard(value);
  };
}

/**
 * Create a guard that early returns on depth limit to prevent stack overflow
 */
export function depthLimited<T>(
  guard: (value: unknown, depth: number) => value is T,
  maxDepth: number = 10
): (value: unknown) => value is T {
  return (value: unknown): value is T => {
    return guard(value, 0);

    function validateAtDepth(val: unknown, currentDepth: number): val is T {
      if (currentDepth > maxDepth) {
        return false;
      }

      return guard(val, currentDepth);
    }
  };
}

/**
 * Create a guard with timeout protection for expensive validations
 */
export function timeoutGuard<T>(
  guard: (value: unknown) => value is T,
  timeoutMs: number = 100
): (value: unknown) => value is T {
  return (value: unknown): value is T => {
    const startTime = Date.now();

    // Create a timeout checker
    const isTimedOut = () => Date.now() - startTime > timeoutMs;

    // Override time-consuming operations if needed
    const originalJSONStringify = JSON.stringify;
    JSON.stringify = function(this: any, ...args: Parameters<typeof JSON.stringify>) {
      if (isTimedOut()) {
        throw new Error('Guard validation timeout');
      }
      return originalJSONStringify.apply(this, args);
    } as typeof JSON.stringify;

    try {
      return guard(value);
    } finally {
      JSON.stringify = originalJSONStringify;
    }
  };
}

/**
 * Create a guard that samples expensive validations for performance
 */
export function sampled<T>(
  guard: (value: unknown) => value is T,
  sampleRate: number = 0.1 // 10% sample rate by default
): (value: unknown) => value is T {
  if (sampleRate <= 0 || sampleRate >= 1) {
    return guard; // No sampling if rate is 0 or 1
  }

  return (value: unknown): value is T => {
    if (Math.random() < sampleRate) {
      // Perform full validation for sampled items
      return guard(value);
    }

    // For non-sampled items, perform basic type validation only
    // This is a performance optimization for high-volume scenarios
    return value !== null && typeof value === 'object';
  };
}

/**
 * Performance metrics collector for guards
 */
export class GuardPerformance {
  private static metrics = new Map<string, {
    calls: number;
    totalTime: number;
    averageTime: number;
    errors: number;
  }>();

  static wrap<T>(
    name: string,
    guard: (value: unknown) => value is T
  ): (value: unknown) => value is T {
    return (value: unknown): value is T => {
      const startTime = performance.now();
      let result = false;
      let error = false;

      try {
        result = guard(value);
        return result;
      } catch (e) {
        error = true;
        throw e;
      } finally {
        const endTime = performance.now();
        const duration = endTime - startTime;

        const metrics = this.metrics.get(name) || {
          calls: 0,
          totalTime: 0,
          averageTime: 0,
          errors: 0
        };

        metrics.calls++;
        metrics.totalTime += duration;
        metrics.averageTime = metrics.totalTime / metrics.calls;
        if (error) metrics.errors++;

        this.metrics.set(name, metrics);
      }
    };
  }

  static getMetrics(name?: string) {
    if (name) {
      return this.metrics.get(name);
    }
    return Object.fromEntries(this.metrics.entries());
  }

  static resetMetrics(name?: string) {
    if (name) {
      this.metrics.delete(name);
    } else {
      this.metrics.clear();
    }
  }
}