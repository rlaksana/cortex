import { logger } from '../utils/logger.js';
import { coreMemoryFind } from './core-memory-find.js';
import type { SearchQuery } from '../types/core-interfaces.js';

/**
 * Main entry point for memory find operations
 *
 * This function provides a clean interface to the core memory find functionality
 * without circular dependencies. It handles query formatting and result processing
 * while delegating the actual database operations to the core implementation.
 */
export async function memoryFind(query: SearchQuery) {
  try {
    logger.info({ query: query.query, mode: query.mode }, 'Memory find operation started');

    // Delegate to core implementation to avoid circular dependencies
    const result = await coreMemoryFind({
      query: query.query,
      scope: query.scope,
      types: query.types,
      limit: query.limit,
      mode: query.mode
    });

    logger.info(
      {
        resultCount: result.results?.length || 0,
        totalCount: result.total_count || 0,
      },
      'Memory find operation completed'
    );

    // Return the core result with standard formatting
    return {
      results: result.results || [],
      total_count: result.total_count || 0,
      autonomous_context: result.autonomous_context || {
        search_mode_used: query.mode || 'auto',
        results_found: result.results?.length || 0,
        confidence_average: 0.5,
        user_message_suggestion: '✅ Search completed successfully',
      },
    };
  } catch (error) {
    logger.error({ error, query: query.query }, 'Memory find operation failed');

    // Return a formatted error response that matches the expected interface
    return {
      results: [],
      total_count: 0,
      autonomous_context: {
        search_mode_used: 'error',
        results_found: 0,
        confidence_average: 0,
        user_message_suggestion: '❌ Search failed - please try again',
      },
    };
  }
}
