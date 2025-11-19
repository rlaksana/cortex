import { type CoreFindParams, coreMemoryFind } from './core-memory-find.js';
import {
  searchStrategyManager,
  type SearchStrategyType,
} from './search/search-strategy-manager.js';
import type { MemoryFindResponse, SearchQuery } from '../types/core-interfaces.js';
import { logger } from '../utils/logger.js';

/**
 * Main entry point for memory find operations - Phase 3 Enhanced
 *
 * This function provides a clean interface to the enhanced core memory find
 * functionality without circular dependencies. It handles query formatting,
 * result processing, and Phase 3 feature support while delegating the actual
 * database operations to the core implementation.
 *
 * Phase 3 Features Supported:
 * - 3 stabilized search strategies: fast, auto, deep
 * - Vector backend degradation with explicit status messages
 * - Graph traversal for relation/parent/child expansion
 * - Scope precedence: branch > project > org hierarchy
 * - Enhanced response metadata about strategy used
 */
export async function memoryFind(query: SearchQuery): Promise<MemoryFindResponse> {
  try {
    logger.info(
      {
        query: query.query,
        mode: query.mode || 'auto',
        expand: query.expand || 'none',
        types: query.types,
        limit: query.limit,
      },
      'Memory find operation started (Phase 3)'
    );

    // Apply scope precedence with environment variable fallbacks
    const effectiveScope = applyScopePrecedenceWithDefaults(query.scope);

    // Build core find parameters with Phase 3 support
    const coreParams: CoreFindParams = {
      query: query.query,
      scope: effectiveScope,
      ...(query.types && { types: query.types }),
      ...(query.limit && { limit: query.limit }),
      ...(query.mode && { mode: query.mode }),
      ...(query.expand && { expand: query.expand }),
    };

    // Delegate to enhanced core implementation
    const result = await coreMemoryFind(coreParams);

    logger.info(
      {
        resultCount: result.results?.length || 0,
        totalCount: result.total_count || 0,
        strategy: result.observability?.strategy,
        vectorUsed: result.observability?.vector_used,
        degraded: result.observability?.degraded,
        executionTime: result.observability?.execution_time_ms,
        expandApplied: query.expand !== 'none',
      },
      'Memory find operation completed (Phase 3)'
    );

    // Return the enhanced core result with backward compatibility
    return {
      results: result.results || [],
      items: result.items || result.results || [], // Ensure compatibility
      total_count: result.total_count || 0,
      total: result.total || result.total_count || 0, // Ensure compatibility
      autonomous_context: result.autonomous_context || {
        search_mode_used: query.mode || 'auto',
        results_found: result.results?.length || 0,
        confidence_average: 0.5,
        user_message_suggestion: '✅ Search completed successfully',
      },
      // Enhanced observability metadata from Phase 3
      observability: result.observability || {
        source: 'cortex_memory',
        strategy: query.mode || 'auto',
        vector_used: false,
        degraded: false,
        execution_time_ms: 0,
        confidence_average: 0.5,
        search_id: `fallback_${Date.now()}`,
      },
      meta: result.meta || {
        strategy: result.observability?.strategy || query.mode || 'auto',
        vector_used: result.observability?.vector_used || false,
        degraded: result.observability?.degraded || false,
        source: 'cortex_memory',
        execution_time_ms: result.observability?.execution_time_ms || 0,
        confidence_score: result.observability?.confidence_average || 0.5,
        truncated: false,
        warnings: result.observability?.degraded ? ['Search was degraded'] : [],
      },
    };
  } catch (error) {
    logger.error(
      {
        error: error instanceof Error ? error.message : String(error),
        query: query.query,
        mode: query.mode,
        expand: query.expand,
      },
      'Memory find operation failed (Phase 3)'
    );

    // Return a formatted error response with Phase 3 metadata
    return {
      results: [],
      items: [],
      total_count: 0,
      total: 0,
      autonomous_context: {
        search_mode_used: 'error',
        results_found: 0,
        confidence_average: 0,
        user_message_suggestion: '❌ Search failed - please try again',
      },
      observability: {
        source: 'cortex_memory',
        strategy: 'error' as const,
        vector_used: false,
        degraded: true,
        execution_time_ms: 0,
        confidence_average: 0,
        search_id: `error_${Date.now()}`,
      },
      meta: {
        strategy: 'error',
        vector_used: false,
        degraded: true,
        source: 'cortex_memory',
        execution_time_ms: 0,
        confidence_score: 0,
        truncated: false,
        warnings: [error instanceof Error ? error.message : 'Unknown error'],
      },
    };
  }
}

/**
 * Apply scope precedence with environment variable defaults
 *
 * Priority order:
 * 1. Explicitly provided scope parameters
 * 2. Environment variables (CORTEX_BRANCH > CORTEX_PROJECT > CORTEX_ORG)
 * 3. Default org scope for backward compatibility
 */
function applyScopePrecedenceWithDefaults(
  providedScope?: Record<string, unknown>
): Record<string, unknown> | undefined {
  // Environment variables
  const env = process.env;
  const effectiveScope: Record<string, unknown> = {};

  // Apply scope precedence: branch > project > org
  if (providedScope?.branch || env.CORTEX_BRANCH) {
    effectiveScope.branch = providedScope?.branch || env.CORTEX_BRANCH;
  }

  if (providedScope?.project || env.CORTEX_PROJECT) {
    effectiveScope.project = providedScope?.project || env.CORTEX_PROJECT;
  }

  if (providedScope?.org || env.CORTEX_ORG) {
    effectiveScope.org = providedScope?.org || env.CORTEX_ORG;
  }

  // If no scope provided and no environment variables, use default org for backward compatibility
  if (Object.keys(effectiveScope).length === 0 && !providedScope) {
    effectiveScope.org = 'default';
  }

  return Object.keys(effectiveScope).length > 0 ? effectiveScope : undefined;
}

/**
 * Enhanced memory find with detailed strategy information
 *
 * This function provides access to the full Phase 3 capabilities including
 * detailed search strategy metadata and performance information.
 */
export async function memoryFindWithStrategy(query: SearchQuery): Promise<
  MemoryFindResponse & {
    strategy_details: {
      selected_strategy: 'fast' | 'auto' | 'deep';
      vector_backend_available: boolean;
      degradation_applied: boolean;
      fallback_reason?: string;
      graph_expansion_applied: boolean;
      scope_precedence_applied: boolean;
    };
  }
> {
  // Check vector backend availability for strategy details
  const vectorBackendAvailable = await checkVectorBackendAvailability();

  // Execute the search
  const result = await memoryFind(query);

  // Extract strategy details from observability metadata
  const strategy = result.observability?.strategy || 'auto';
  const degraded = result.observability?.degraded || false;
  const vectorUsed = result.observability?.vector_used || false;

  return {
    ...result,
    strategy_details: {
      selected_strategy: strategy as 'fast' | 'auto' | 'deep',
      vector_backend_available: vectorBackendAvailable,
      degradation_applied: degraded,
      fallback_reason: degraded
        ? result.autonomous_context?.user_message_suggestion || 'Unknown reason'
        : undefined,
      graph_expansion_applied: query.expand !== 'none',
      scope_precedence_applied: !!(
        query.scope ||
        process.env.CORTEX_BRANCH ||
        process.env.CORTEX_PROJECT ||
        process.env.CORTEX_ORG
      ),
    },
  };
}

/**
 * Enhanced memory find using SearchStrategyManager
 *
 * This function provides direct access to the stabilized search strategies
 * with comprehensive degradation handling and performance monitoring.
 */
export async function memoryFindWithStrategies(query: SearchQuery): Promise<MemoryFindResponse> {
  const startTime = Date.now();

  try {
    logger.info(
      {
        query: query.query,
        mode: query.mode || 'auto',
        expand: query.expand || 'none',
        types: query.types,
        limit: query.limit,
      },
      'Memory find with strategies started (Phase 3 Enhanced)'
    );

    // Apply scope precedence with environment variable fallbacks
    const effectiveScope = applyScopePrecedenceWithDefaults(query.scope);

    // Build enhanced query with effective scope
    const enhancedQuery: SearchQuery = {
      ...query,
      scope: effectiveScope,
    };

    // Execute search using SearchStrategyManager
    const strategy = (query.mode || 'auto') as SearchStrategyType;
    const strategyResult = await searchStrategyManager.executeSearch(enhancedQuery, strategy);

    // Convert strategy result to MemoryFindResponse
    const response: MemoryFindResponse = {
      results: strategyResult.results,
      items: strategyResult.results, // Compatibility
      total_count: strategyResult.results.length,
      total: strategyResult.results.length, // Compatibility
      autonomous_context: {
        search_mode_used:
          typeof strategyResult.strategy === 'string'
            ? strategyResult.strategy
            : strategyResult.strategy.primary.name,
        results_found: strategyResult.results.length,
        confidence_average: strategyResult.confidence ?? 0,
        user_message_suggestion: generateStrategyUserMessage(strategyResult),
      },
      observability: {
        source: 'cortex_memory',
        strategy:
          typeof strategyResult.strategy === 'string'
            ? strategyResult.strategy
            : strategyResult.strategy.primary.name,
        vector_used: strategyResult.vectorUsed ?? false,
        degraded: strategyResult.degraded ?? false,
        execution_time_ms: strategyResult.executionTime ?? 0,
        confidence_average: strategyResult.confidence ?? 0,
        search_id: `strategy_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
      },
      meta: {
        strategy:
          typeof strategyResult.strategy === 'string'
            ? strategyResult.strategy
            : strategyResult.strategy.primary.name,
        vector_used: strategyResult.vectorUsed ?? false,
        degraded: strategyResult.degraded ?? false,
        source: 'cortex_memory',
        execution_time_ms: strategyResult.executionTime ?? 0,
        confidence_score: strategyResult.confidence ?? 0,
        truncated: false,
        warnings: strategyResult.degraded
          ? [strategyResult.fallbackReason || 'Search was degraded']
          : [],
      },
    };

    const duration = Date.now() - startTime;

    logger.info(
      {
        resultCount: response.results.length,
        strategy: strategyResult.strategy,
        vectorUsed: strategyResult.vectorUsed,
        degraded: strategyResult.degraded,
        executionTime: duration,
        fallbackReason: strategyResult.fallbackReason,
        metadata: strategyResult.metadata,
      },
      'Memory find with strategies completed successfully'
    );

    return response;
  } catch (error) {
    const duration = Date.now() - startTime;

    logger.error(
      {
        error: error instanceof Error ? error.message : String(error),
        query: query.query,
        mode: query.mode,
        executionTime: duration,
      },
      'Memory find with strategies failed'
    );

    // Return error response with strategy metadata
    return {
      results: [],
      items: [],
      total_count: 0,
      total: 0,
      autonomous_context: {
        search_mode_used: 'error',
        results_found: 0,
        confidence_average: 0,
        user_message_suggestion: `❌ Search failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      },
      observability: {
        source: 'cortex_memory',
        strategy: 'error',
        vector_used: false,
        degraded: true,
        execution_time_ms: duration,
        confidence_average: 0,
        search_id: `error_${Date.now()}`,
      },
      meta: {
        strategy: 'error',
        vector_used: false,
        degraded: true,
        source: 'cortex_memory',
        execution_time_ms: duration,
        confidence_score: 0,
        truncated: false,
        warnings: [error instanceof Error ? error.message : 'Unknown error'],
      },
    };
  }
}

/**
 * Generate user-friendly message based on strategy execution
 */
function generateStrategyUserMessage(strategyResult: unknown): string {
  const { strategy, vectorUsed, degraded, fallbackReason, results } = strategyResult;

  let message = `✅ Found ${results.length} results using ${strategy} search`;

  if (vectorUsed) {
    message += ' with vector embeddings';
  }

  if (degraded) {
    message += ` (degraded: ${fallbackReason || 'Unknown reason'})`;
  }

  if (results.length === 0) {
    message = `🔍 No results found using ${strategy} search`;
    if (degraded) {
      message += ` - search was degraded`;
    }
  }

  return message;
}

/**
 * Check vector backend availability
 * This is a utility function to check if the vector backend is available
 * before executing search operations.
 */
async function checkVectorBackendAvailability(): Promise<boolean> {
  try {
    // Use the SearchStrategyManager's health check
    return searchStrategyManager.getVectorHealth();
  } catch (error) {
    logger.warn(
      {
        error: error instanceof Error ? error.message : String(error),
      },
      'Vector backend availability check failed'
    );
    return false;
  }
}

/**
 * Get supported search strategies and their capabilities
 *
 * This function provides information about the available search strategies
 * and their current status, useful for UI components and debugging.
 */
export async function getSearchStrategies(): Promise<{
  strategies: Array<{
    name: 'fast' | 'auto' | 'deep';
    description: string;
    vector_required: boolean;
    graph_expansion_supported: boolean;
    current_status: 'available' | 'degraded' | 'unavailable';
    fallback_strategy?: 'fast' | 'auto';
    performance_metrics: {
      total_executions: number;
      success_rate: number;
      average_execution_time: number;
      average_result_count: number;
      degradation_count: number;
    };
  }>;
  vector_backend_status: {
    available: boolean;
    last_checked: string;
    degradation_reason?: string;
    consecutive_failures: number;
    response_time: number;
  };
  system_metrics: {
    total_searches: number;
    overall_success_rate: number;
    most_used_strategy: string;
  };
}> {
  // Get strategies from SearchStrategyManager
  const supportedStrategies = searchStrategyManager.getSupportedStrategies();
  const vectorHealthStatus = searchStrategyManager.getVectorHealth();
  const now = new Date();
  const vectorHealth = {
    available: vectorHealthStatus,
    lastChecked: now,
    degradationReason: vectorHealthStatus ? undefined : 'Vector service unavailable',
    consecutiveFailures: vectorHealthStatus ? 0 : 1,
    responseTime: 0,
  };
  const performanceMetrics = searchStrategyManager.getPerformanceMetrics();

  // Calculate system metrics
  const totalSearches = Object.values(performanceMetrics).reduce(
    (sum, metrics: unknown) => sum + metrics.totalExecutions,
    0
  );

  const successfulSearches = Object.values(performanceMetrics).reduce(
    (sum, metrics: unknown) => sum + metrics.successfulExecutions,
    0
  );

  const mostUsedStrategy =
    Object.entries(performanceMetrics).sort(
      (a: [string, unknown], b: [string, unknown]) => b[1].totalExecutions - a[1].totalExecutions
    )[0]?.[0] || 'auto';

  return {
    strategies: supportedStrategies.map((strategy: unknown) => ({
      name: strategy.name,
      description: strategy.description,
      vector_required: strategy.name === 'deep',
      graph_expansion_supported: true,
      current_status: strategy.currentStatus,
      fallback_strategy:
        strategy.name === 'deep' ? 'auto' : strategy.name === 'auto' ? 'fast' : undefined,
      performance_metrics: {
        total_executions: strategy.performance.totalExecutions,
        success_rate:
          strategy.performance.totalExecutions > 0
            ? (strategy.performance.successfulExecutions / strategy.performance.totalExecutions) *
              100
            : 0,
        average_execution_time: strategy.performance.averageExecutionTime,
        average_result_count: strategy.performance.averageResultCount,
        degradation_count: strategy.performance.degradationCount,
      },
    })),
    vector_backend_status: {
      available: vectorHealth.available,
      last_checked: vectorHealth.lastChecked.toISOString(),
      degradation_reason: vectorHealth.degradationReason,
      consecutive_failures: vectorHealth.consecutiveFailures,
      response_time: vectorHealth.responseTime,
    },
    system_metrics: {
      total_searches: totalSearches,
      overall_success_rate: totalSearches > 0 ? (successfulSearches / totalSearches) * 100 : 0,
      most_used_strategy: mostUsedStrategy,
    },
  };
}
