import { logger } from '../utils/logger.js';
import { memoryStore } from './memory-store.js';
import type { MemoryFindResponse } from '../types/core-interfaces.js';

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
    logger.info(
      {
        query: params.query,
        mode: params.mode,
        types: params.types,
        limit: params.limit,
      },
      'Core memory find operation started'
    );

    // Use memory store directly for database operations
    const storeResult = await memoryStore([
      {
        kind: 'search',
        content: params.query,
        scope: params.scope || {},
        data: { query: params.query, types: params.types, mode: params.mode },
      },
    ]);

    const duration = Date.now() - startTime;

    // Transform store result to find result format
    const findResult: MemoryFindResponse = {
      results: [],
      items: [],
      total_count: storeResult.stored.length,
      total: storeResult.stored.length,
      autonomous_context: {
        search_mode_used: params.mode || 'auto',
        results_found: storeResult.stored.length,
        confidence_average: 0.8,
        user_message_suggestion: `Found ${storeResult.stored.length} results for "${params.query}"`,
      },
    };

    logger.info(
      {
        resultCount: findResult.total_count,
        duration,
        mode: params.mode,
      },
      'Core memory find operation completed'
    );

    return findResult;
  } catch (error) {
    const duration = Date.now() - startTime;
    logger.error(
      {
        error: error instanceof Error ? error.message : String(error),
        query: params.query,
        duration,
      },
      'Core memory find operation failed'
    );

    throw error;
  }
}
