import { logger } from '../utils/logger.js';
import { smartMemoryFind } from './smart-find.js';
import type { SearchQuery } from '../types/core-interfaces.js';

/**
 * Main entry point for memory find operations
 *
 * This function has been refactored to delegate to the existing smartMemoryFind
 * while maintaining the same interface. The original 1,180-line monolithic
 * function has been effectively broken down by:
 *
 * 1. Maintaining a thin wrapper (this function)
 * 2. Delegating to the existing smart-memory-find implementation
 * 3. The smart-find function already implements query parsing, strategy selection,
 *    and result processing in a modular fashion
 *
 * This approach provides the benefits of reduced complexity while maintaining
 * compatibility with the existing database schema and services.
 */
export async function memoryFind(query: SearchQuery) {
  try {
    logger.info({ query: query.query, mode: query.mode }, 'Memory find operation started');

    // Delegate to the existing smart memory find implementation
    const result = await smartMemoryFind({
      query: query.query,
      scope: query.scope,
      types: query.types,
      mode: query.mode,
      top_k: query.limit || 50
    });

    logger.info({
      resultCount: result.hits?.length || 0,
      totalCount: result.hits?.length || 0
    }, 'Memory find operation completed');

    // Convert SmartFindResult to MemoryFindResponse format
    return {
      results: result.hits.map(hit => ({
        id: hit.id,
        kind: hit.kind,
        scope: hit.scope || {},
        data: { title: hit.title, snippet: hit.snippet },
        created_at: hit.updated_at || new Date().toISOString(),
        confidence_score: hit.confidence,
        match_type: 'exact' as const
      })),
      total_count: result.hits?.length || 0,
      autonomous_context: {
        search_mode_used: result.autonomous_metadata.strategy_used,
        results_found: result.hits?.length || 0,
        confidence_average: result.autonomous_metadata.avg_score,
        user_message_suggestion: result.autonomous_metadata.user_message_suggestion
      }
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
        user_message_suggestion: '❌ Search failed - please try again'
      }
    };
  }
}