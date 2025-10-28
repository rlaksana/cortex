import { logger } from '../utils/logger.js';
import { memoryStore } from './memory-store.js';
import type { SearchQuery, MemoryFindResponse, FindHit } from '../types/core-interfaces.js';

/**
 * Core Memory Find Implementation
 *
 * This module contains the actual database query logic without any
 * circular dependencies. It serves as the foundation for both
 * memoryFind and smartMemoryFind wrappers.
 */

export interface CoreFindParams {
  query: string;
  scope?: Record<string, unknown>;
  types?: string[];
  limit?: number;
  mode?: 'auto' | 'fast' | 'deep';
}

/**
 * Direct database query implementation
 */
export async function coreMemoryFind(params: CoreFindParams): Promise<MemoryFindResponse> {
  const startTime = Date.now();

  try {
    logger.info({
      query: params.query,
      mode: params.mode,
      types: params.types,
      limit: params.limit
    }, 'Core memory find operation started');

    // Use memory store directly for database operations
    const result = await memoryStore({
      query: params.query,
      scope: params.scope || {},
      types: params.types || [],
      mode: params.mode || 'auto',
      limit: params.limit || 50
    });

    const duration = Date.now() - startTime;

    logger.info({
      resultCount: result.hits?.length || 0,
      duration,
      mode: params.mode
    }, 'Core memory find operation completed');

    return result;

  } catch (error) {
    const duration = Date.now() - startTime;
    logger.error({
      error: error instanceof Error ? error.message : String(error),
      query: params.query,
      duration
    }, 'Core memory find operation failed');

    throw error;
  }
}