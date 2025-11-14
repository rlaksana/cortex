// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * Database Result Unwrapper Utilities
 *
 * Provides utilities to safely unwrap DatabaseResult<T> types
 * and convert them to the expected interface types with proper error handling.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import type {
  DatabaseError,
  DatabaseResult} from '../types/database-generics.js';
import {
  isSuccessfulResult} from '../types/database-generics.js';

/**
 * Error thrown when DatabaseResult unwrapping fails
 */
export class DatabaseResultUnwrapError extends Error {
  constructor(
    message: string,
    public readonly originalError?: DatabaseError,
    public readonly context?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'DatabaseResultUnwrapError';
  }
}

/**
 * Safely unwrap a DatabaseResult<T> to get the data or throw an error
 *
 * @param result - The DatabaseResult to unwrap
 * @param context - Optional context for error reporting
 * @returns The unwrapped data
 * @throws DatabaseResultUnwrapError if the result is unsuccessful
 */
export function unwrapDatabaseResult<T>(
  result: DatabaseResult<T>,
  context?: Record<string, unknown>
): T {
  if (isSuccessfulResult(result)) {
    return result.data;
  }

  const errorMessage = result.error?.message || 'Unknown database error';
  throw new DatabaseResultUnwrapError(
    `Database operation failed: ${errorMessage}`,
    result.error,
    context
  );
}

/**
 * Safely unwrap a DatabaseResult<T> with a fallback value
 *
 * @param result - The DatabaseResult to unwrap
 * @param fallback - Fallback value if the result is unsuccessful
 * @returns The unwrapped data or fallback
 */
export function unwrapDatabaseResultWithFallback<T>(
  result: DatabaseResult<T>,
  fallback: T
): T {
  if (isSuccessfulResult(result)) {
    return result.data;
  }

  return fallback;
}

/**
 * Unwrap a DatabaseResult<T> and transform the data if successful
 *
 * @param result - The DatabaseResult to unwrap
 * @param transformer - Function to transform the data if successful
 * @param context - Optional context for error reporting
 * @returns The transformed data
 * @throws DatabaseResultUnwrapError if the result is unsuccessful
 */
export function unwrapAndTransformDatabaseResult<T, R>(
  result: DatabaseResult<T>,
  transformer: (data: T) => R,
  context?: Record<string, unknown>
): R {
  if (isSuccessfulResult(result)) {
    return transformer(result.data);
  }

  const errorMessage = result.error?.message || 'Unknown database error';
  throw new DatabaseResultUnwrapError(
    `Database operation failed: ${errorMessage}`,
    result.error,
    context
  );
}

/**
 * Batch unwrap multiple DatabaseResult<T> values
 *
 * @param results - Array of DatabaseResult values
 * @param context - Optional context for error reporting
 * @returns Array of unwrapped data
 * @throws DatabaseResultUnwrapError if any result is unsuccessful
 */
export function unwrapBatchDatabaseResults<T>(
  results: readonly DatabaseResult<T>[],
  context?: Record<string, unknown>
): T[] {
  const unwrapped: T[] = [];

  for (let i = 0; i < results.length; i++) {
    const result = results[i];
    if (isSuccessfulResult(result)) {
      unwrapped.push(result.data);
    } else {
      const errorMessage = result.error?.message || 'Unknown database error';
      throw new DatabaseResultUnwrapError(
        `Database operation at index ${i} failed: ${errorMessage}`,
        result.error,
        { ...context, index: i }
      );
    }
  }

  return unwrapped;
}

/**
 * Convert DatabaseResult wrapper types to interface-compatible return types
 * Specifically handles the conversion from DatabaseResult<MemoryStoreResponse> to MemoryStoreResponse
 */
export function convertMemoryStoreResponse(result: DatabaseResult<{
  items: unknown[];
  summary: unknown;
  stored: unknown[];
  errors: unknown[];
  autonomous_context: unknown;
  observability: unknown;
  meta: unknown;
}>): {
  items: unknown[];
  summary: unknown;
  stored: unknown[];
  errors: unknown[];
  skipped?: unknown[];
  autonomous_context: unknown;
  observability: unknown;
  meta: unknown;
} {
  return unwrapDatabaseResult(result, { operation: 'convertMemoryStoreResponse' });
}

/**
 * Convert DatabaseResult delete response to interface-compatible format
 */
export function convertDeleteResponse(result: DatabaseResult<{
  deletedCount: number;
  errors: readonly unknown[];
}>): {
  deleted: number;
  errors: unknown[];
} {
  const unwrapped = unwrapDatabaseResult(result, { operation: 'convertDeleteResponse' });
  return {
    deleted: unwrapped.deletedCount,
    errors: [...unwrapped.errors]
  };
}

/**
 * Convert DatabaseResult array response to interface-compatible format
 */
export function convertArrayResponse<T>(result: DatabaseResult<readonly T[]>): T[] {
  const unwrapped = unwrapDatabaseResult(result, { operation: 'convertArrayResponse' });
  return [...unwrapped];
}

/**
 * Convert DatabaseResult search response to interface-compatible format
 */
export function convertSearchResponse<T>(result: DatabaseResult<readonly T[]>): T[] {
  return convertArrayResponse(result);
}

/**
 * Convert DatabaseResult metrics to DatabaseMetrics interface
 */
export function convertMetricsResponse(result: DatabaseResult<{
  type: string;
  healthy: boolean;
  connectionCount?: number;
  queryLatency?: number;
  storageSize?: number;
  lastHealthCheck?: string;
  vectorCount?: number;
  collectionInfo?: Record<string, unknown>;
}>): {
  type: string;
  healthy: boolean;
  connectionCount?: number;
  queryLatency?: number;
  storageSize?: number;
  lastHealthCheck?: string;
  vectorCount?: number;
  collectionInfo?: Record<string, unknown>;
} {
  return unwrapDatabaseResult(result, { operation: 'convertMetricsResponse' });
}

/**
 * Type guard to check if a value is a DatabaseResult
 */
export function isDatabaseResult<T>(value: unknown): value is DatabaseResult<T> {
  return typeof value === 'object' && value !== null && 'success' in value;
}