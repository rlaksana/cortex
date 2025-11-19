// EMERGENCY ROLLBACK: Utility type guard compatibility issues

/**
 * Type Safety Layer
 *
 * Provides comprehensive type conversion and validation utilities
 * for bridging different interface layers and ensuring type compatibility.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

/**
 * Safely cast unknown to a specific type with runtime validation
 */
export function safeCast<T>(value: unknown, fallback?: T): T {
  if (value === undefined || value === null) {
    if (fallback !== undefined) return fallback;
    throw new Error(`Cannot cast null/undefined to type`);
  }
  return value as T;
}

/**
 * Convert unknown to StoreOptions or provide default
 */
export function toStoreOptions(options: unknown): Record<string, unknown> {
  return safeCast(options || {}, {});
}

/**
 * Convert string[] to readonly PointId[] for Qdrant compatibility
 */
export function toPointIds(ids: string[]): readonly string[] {
  return ids as readonly string[];
}

/**
 * Safely extract numeric properties with fallback
 */
export function toNumber(value: unknown, fallback = 0): number {
  if (typeof value === 'number') return value;
  if (typeof value === 'string') {
    const parsed = parseInt(value, 10);
    return isNaN(parsed) ? fallback : parsed;
  }
  return fallback;
}

/**
 * Safely extract string properties with fallback
 */
export function toString(value: unknown, fallback = ''): string {
  if (typeof value === 'string') return value;
  if (typeof value === 'number') return value.toString();
  if (typeof value === 'boolean') return value.toString();
  return fallback;
}

/**
 * Convert unknown payload to properly typed object
 */
export function toPayload(payload: unknown): Record<string, unknown> {
  return safeCast(payload || {}, {});
}

/**
 * Safely extract chunk metadata with proper typing
 */
export function toChunkMetadata(metadata: unknown): {
  is_chunk?: boolean;
  chunk_index?: number;
  total_chunks?: number;
  parent_id?: string;
  extracted_title?: string;
} {
  const meta = toPayload(metadata);
  return {
    is_chunk: meta.is_chunk === true,
    chunk_index: toNumber(meta.chunk_index),
    total_chunks: toNumber(meta.total_chunks),
    parent_id: toString(meta.parent_id),
    extracted_title: toString(meta.extracted_title),
  };
}

/**
 * Convert database errors to compatible format
 */
export function toDatabaseError(
  error: Error | string,
  code?: string
): Error & {
  code?: string;
  severity?: string;
  retryable?: boolean;
  originalError?: Error | string;
} {
  const message = typeof error === 'string' ? error : error.message;
  const enhancedError = new Error(message) as Error & {
    code?: string;
    severity?: string;
    retryable?: boolean;
    originalError?: Error | string;
  };
  enhancedError.code = code || 'UNKNOWN_ERROR';
  enhancedError.severity = 'error';
  enhancedError.retryable = false;
  enhancedError.originalError = error;
  return enhancedError;
}

/**
 * Validate and convert point IDs with proper handling of numeric IDs
 */
export function validatePointId(id: string | number | { num?: number; uuid?: string }): string {
  if (typeof id === 'string') return id;
  if (typeof id === 'number') return id.toString();
  if (typeof id === 'object' && id !== null) {
    if (id.uuid) return id.uuid;
    if (id.num !== undefined) return id.num.toString();
  }
  throw new Error(`Invalid point ID format: ${JSON.stringify(id)}`);
}

/**
 * Convert scored points to search results with type safety
 */
export function toSearchResult(point: unknown): {
  id: string;
  score: number;
  payload?: Record<string, unknown>;
  vector?: number[];
} {
  const pointData = point as Record<string, unknown>;
  return {
    id: validatePointId(pointData.id as string | number),
    score: toNumber(pointData.score as number, 0),
    payload: toPayload(pointData.payload as Record<string, unknown>),
    vector: (pointData.vector as number[]) || [],
  };
}

/**
 * Batch convert scored points to search results
 */
export function toSearchResults(points: unknown[]): unknown[] {
  return points.map((point) => toSearchResult(point));
}

/**
 * Create a safe function wrapper that catches and converts errors
 */
export function safeWrapper<T extends unknown[], R>(
  fn: (...args: T) => R,
  errorHandler?: (error: unknown) => R
): (...args: T) => R {
  return (...args: T): R => {
    try {
      return fn(...args);
    } catch (error) {
      if (errorHandler) {
        return errorHandler(error);
      }
      throw toDatabaseError(error instanceof Error ? error : new Error(String(error)));
    }
  };
}

/**
 * Create a safe async function wrapper that catches and converts errors
 */
export function safeAsyncWrapper<T extends unknown[], R>(
  fn: (...args: T) => Promise<R>,
  errorHandler?: (error: unknown) => Promise<R>
): (...args: T) => Promise<R> {
  return async (...args: T): Promise<R> => {
    try {
      return await fn(...args);
    } catch (error) {
      if (errorHandler) {
        return await errorHandler(error);
      }
      throw toDatabaseError(error instanceof Error ? error : new Error(String(error)));
    }
  };
}

/**
 * Type guard to check if a value is a valid object
 */
export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Type guard to check if a value is a valid array
 */
export function isArray(value: unknown): value is unknown[] {
  return Array.isArray(value);
}

/**
 * Safe property access with fallback
 */
export function getProperty<T>(obj: unknown, path: string, fallback?: T): T {
  if (!isObject(obj)) return fallback as T;

  const keys = path.split('.');
  let current: unknown = obj;

  for (const key of keys) {
    if (current === null || current === undefined || typeof current !== 'object' || !(key in current)) {
      return fallback as T;
    }
    current = (current as Record<string, unknown>)[key];
  }

  return current as T;
}

/**
 * Safe property setting with object creation if needed
 */
export function setProperty(obj: unknown, path: string, value: unknown): Record<string, unknown> {
  const target = isObject(obj) ? { ...obj } : {};
  const keys = path.split('.');
  let current: unknown = target;

  for (let i = 0; i < keys.length - 1; i++) {
    const key = keys[i];
    if (typeof current !== 'object' || current === null || !(key in current) || !isObject((current as Record<string, unknown>)[key])) {
      (current as Record<string, unknown>)[key] = {};
    }
    current = (current as Record<string, unknown>)[key];
  }

  current[keys[keys.length - 1]] = value;
  return target;
}
