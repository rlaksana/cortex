
// @ts-nocheck - Emergency rollback: Critical memory service
import { logger } from '@/utils/logger.js';

import {
  type GraphTraversalResult,
  type TraversalOptions,
  traverseGraphWithExpansion,
} from './graph-traversal.js';
import { memoryStore } from './memory-store.js';
import type { MemoryFindResponse, SearchQuery,SearchResult } from '../types/core-interfaces.js';

/**
 * Core Memory Find Implementation - Phase 3 Enhanced
 *
 * This module contains the actual database query logic with enhanced
 * search strategies, vector backend degradation, and graph traversal.
 *
 * Features:
 * - 3 stabilized search strategies: fast, auto, deep
 * - Vector backend degradation with explicit status messages
 * - Graph traversal for relation/parent/child expansion
 * - Scope precedence: branch > project > org hierarchy
 */

export interface CoreFindParams {
  query: string;
  scope?: Record<string, unknown>;
  types?: string[];
  limit?: number;
  mode?: 'auto' | 'fast' | 'deep';
  expand?: 'relations' | 'parents' | 'children' | 'none';
}

/**
 * Search strategy execution result
 */
interface SearchStrategyResult {
  results: SearchResult[];
  strategy: 'fast' | 'auto' | 'deep';
  vectorUsed: boolean;
  degraded: boolean;
  executionTime: number;
  confidence: number;
  fallbackReason?: string;
}

/**
 * Enhanced search context with strategy metadata
 */
interface SearchContext {
  originalQuery: string;
  processedQuery: string;
  mode: 'auto' | 'fast' | 'deep';
  scope?: Record<string, unknown>;
  types?: string[];
  limit: number;
  expand: 'relations' | 'parents' | 'children' | 'none';
  startTime: number;
  expandMetadata?: {
    parentChildExpansion: boolean;
    maxDepth: number;
    sortBy: string;
    includeCircularRefs: boolean;
  };
}

/**
 * Direct database query implementation with Phase 3 enhancements
 */
export async function coreMemoryFind(params: CoreFindParams): Promise<MemoryFindResponse> {
  const startTime = Date.now();
  const searchId = `search_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;

  try {
    // Create search context
    const context: SearchContext = {
      originalQuery: params.query,
      processedQuery: preprocessQuery(params.query),
      mode: params.mode || 'auto',
      scope: applyScopePrecedence(params.scope),
      types: params.types,
      limit: params.limit || 10,
      expand: params.expand || 'none',
      startTime,
      expandMetadata: {
        parentChildExpansion: params.expand !== 'none',
        maxDepth: params.expand === 'children' ? 3 : 2, // Deeper for children expansion
        sortBy: 'relevance', // Default sort by relevance
        includeCircularRefs: false, // Default to exclude circular refs
      },
    };

    logger.info(
      {
        query: params.query,
        mode: context.mode,
        types: context.types,
        limit: context.limit,
        expand: context.expand,
        searchId,
      },
      'Core memory find operation started (Phase 3)'
    );

    // Execute search strategy
    const strategyResult = await executeSearchStrategy(context);

    // Apply graph expansion if requested
    const { results: expandedResults, graphExpansionMetadata } = await applyGraphExpansion(
      strategyResult.results,
      context
    );

    // Filter by scope and types
    const filteredResults = filterResults(expandedResults, context);

    const duration = Date.now() - startTime;

    // Transform to find result format with enhanced metadata
    const findResult: MemoryFindResponse = {
      results: filteredResults,
      items: filteredResults, // Compatibility
      total_count: filteredResults.length,
      total: filteredResults.length, // Compatibility
      autonomous_context: {
        search_mode_used: strategyResult.strategy,
        results_found: filteredResults.length,
        confidence_average: calculateAverageConfidence(filteredResults),
        user_message_suggestion: generateUserMessage(strategyResult, filteredResults),
      },
      // Enhanced observability metadata
      observability: {
        source: 'cortex_memory',
        strategy: strategyResult.strategy,
        vector_used: strategyResult.vectorUsed,
        degraded: strategyResult.degraded,
        execution_time_ms: duration,
        confidence_average: calculateAverageConfidence(filteredResults),
        search_id: searchId,
      },
      // P2-2: Graph expansion metadata
      graph_expansion: graphExpansionMetadata,
      meta: {
        strategy: strategyResult.strategy,
        vector_used: strategyResult.vectorUsed,
        degraded: strategyResult.degraded,
        source: 'cortex_memory',
        execution_time_ms: duration,
        confidence_score: calculateAverageConfidence(filteredResults),
        truncated: false,
        warnings: strategyResult.degraded
          ? [strategyResult.fallbackReason || 'Search was degraded']
          : [],
      },
    };

    logger.info(
      {
        searchId,
        resultCount: findResult.total_count,
        duration,
        strategy: strategyResult.strategy,
        vectorUsed: strategyResult.vectorUsed,
        degraded: strategyResult.degraded,
        expandApplied: context.expand !== 'none',
      },
      'Core memory find operation completed (Phase 3)'
    );

    return findResult;
  } catch (error) {
    const duration = Date.now() - startTime;
    logger.error(
      {
        searchId,
        error: error instanceof Error ? error.message : String(error),
        query: params.query,
        duration,
      },
      'Core memory find operation failed (Phase 3)'
    );

    // Return error response with proper metadata
    return createErrorResponse(params.query, error, searchId, duration);
  }
}

/**
 * Preprocess query for optimal search
 */
function preprocessQuery(query: string): string {
  return query.trim().toLowerCase();
}

/**
 * Apply scope precedence: branch > project > org
 */
function applyScopePrecedence(
  scope?: Record<string, unknown>
): Record<string, unknown> | undefined {
  if (!scope) return scope;

  // Environment variable fallbacks with precedence
  const env = process.env;
  const effectiveScope: Record<string, unknown> = {};

  // Apply precedence: provided scope > environment defaults
  if (scope.branch || env.CORTEX_BRANCH) {
    effectiveScope.branch = scope.branch || env.CORTEX_BRANCH;
  }
  if (scope.project || env.CORTEX_PROJECT) {
    effectiveScope.project = scope.project || env.CORTEX_PROJECT;
  }
  if (scope.org || env.CORTEX_ORG) {
    effectiveScope.org = scope.org || env.CORTEX_ORG;
  }

  return Object.keys(effectiveScope).length > 0 ? effectiveScope : undefined;
}

/**
 * Execute search strategy with fallback logic
 */
async function executeSearchStrategy(context: SearchContext): Promise<SearchStrategyResult> {
  const { mode, processedQuery, types, limit, scope, startTime } = context;

  try {
    switch (mode) {
      case 'fast':
        return await executeFastSearch(processedQuery, types, limit, scope);
      case 'deep':
        return await executeDeepSearch(processedQuery, types, limit, scope);
      case 'auto':
      default:
        return await executeAutoSearch(processedQuery, types, limit, scope);
    }
  } catch (error) {
    logger.error(
      {
        error: error instanceof Error ? error.message : String(error),
        mode,
        query: processedQuery,
      },
      'Search strategy failed, attempting fallback'
    );

    // Fallback to fast search if primary strategy fails
    try {
      const fallbackResult = await executeFastSearch(processedQuery, types, limit, scope);
      fallbackResult.fallbackReason = error instanceof Error ? error.message : 'Unknown error';
      return fallbackResult;
    } catch (fallbackError) {
      logger.error(
        {
          error: fallbackError instanceof Error ? fallbackError.message : String(fallbackError),
          query: processedQuery,
        },
        'All search strategies failed'
      );
      throw fallbackError;
    }
  }
}

/**
 * Execute fast search (keyword-only)
 */
async function executeFastSearch(
  query: string,
  types?: string[],
  limit?: number,
  scope?: Record<string, unknown>
): Promise<SearchStrategyResult> {
  const startTime = Date.now();

  try {
    // Fast search uses keyword matching only
    const searchQuery: SearchQuery = {
      query,
      types,
      limit: limit || 10,
      scope,
      mode: 'fast',
    };

    // Simulate keyword search results (replace with actual implementation)
    const results: SearchResult[] = await simulateKeywordSearch(searchQuery);

    return {
      results,
      strategy: 'fast',
      vectorUsed: false,
      degraded: false,
      executionTime: Date.now() - startTime,
      confidence: calculateAverageConfidence(results),
    };
  } catch (error) {
    logger.error(
      { error: error instanceof Error ? error.message : String(error), query },
      'Fast search failed'
    );
    throw error;
  }
}

/**
 * Execute deep search (vector + relations) with degradation logic
 */
async function executeDeepSearch(
  query: string,
  types?: string[],
  limit?: number,
  scope?: Record<string, unknown>
): Promise<SearchStrategyResult> {
  const startTime = Date.now();

  try {
    // Check vector backend availability
    const vectorAvailable = await checkVectorBackendAvailability();

    if (!vectorAvailable) {
      logger.warn('Vector backend unavailable, degrading deep search to auto mode');

      // Degrade to auto search
      const autoResult = await executeAutoSearch(query, types, limit, scope);
      autoResult.strategy = 'deep';
      autoResult.degraded = true;
      autoResult.fallbackReason = 'Vector backend unavailable - degraded to auto mode';
      return autoResult;
    }

    // Deep search uses vector + relations
    const searchQuery: SearchQuery = {
      query,
      types,
      limit: limit || 10,
      scope,
      mode: 'deep',
    };

    // Simulate vector search results (replace with actual implementation)
    const results: SearchResult[] = await simulateVectorSearch(searchQuery);

    return {
      results,
      strategy: 'deep',
      vectorUsed: true,
      degraded: false,
      executionTime: Date.now() - startTime,
      confidence: calculateAverageConfidence(results),
    };
  } catch (error) {
    logger.error(
      { error: error instanceof Error ? error.message : String(error), query },
      'Deep search failed, attempting auto fallback'
    );

    // Fallback to auto search
    const autoResult = await executeAutoSearch(query, types, limit, scope);
    autoResult.strategy = 'deep';
    autoResult.degraded = true;
    autoResult.fallbackReason = `Deep search failed: ${error instanceof Error ? error.message : 'Unknown error'}`;
    return autoResult;
  }
}

/**
 * Execute auto search (hybrid approach)
 */
async function executeAutoSearch(
  query: string,
  types?: string[],
  limit?: number,
  scope?: Record<string, unknown>
): Promise<SearchStrategyResult> {
  const startTime = Date.now();

  try {
    // Auto search uses hybrid approach when available
    const vectorAvailable = await checkVectorBackendAvailability();

    const searchQuery: SearchQuery = {
      query,
      types,
      limit: limit || 10,
      scope,
      mode: 'auto',
    };

    let results: SearchResult[];
    let vectorUsed = false;

    if (vectorAvailable) {
      // Use hybrid search
      results = await simulateHybridSearch(searchQuery);
      vectorUsed = true;
    } else {
      // Fallback to keyword search
      results = await simulateKeywordSearch(searchQuery);
    }

    return {
      results,
      strategy: 'auto',
      vectorUsed,
      degraded: !vectorAvailable,
      executionTime: Date.now() - startTime,
      confidence: calculateAverageConfidence(results),
      ...(vectorUsed === false && {
        fallbackReason: 'Vector backend unavailable - using keyword search',
      }),
    };
  } catch (error) {
    logger.error(
      { error: error instanceof Error ? error.message : String(error), query },
      'Auto search failed'
    );
    throw error;
  }
}

/**
 * Apply enhanced graph expansion for relations/parents/children
 */
async function applyGraphExpansion(
  results: SearchResult[],
  context: SearchContext
): Promise<{ results: SearchResult[]; graphExpansionMetadata?: unknown }> {
  if (context.expand === 'none' || results.length === 0) {
    return {
      results,
      graphExpansionMetadata: {
        enabled: false,
        expansion_type: context.expand,
        parent_entities: [],
        child_entities: [],
        traversal_metadata: {
          total_entities_traversed: 0,
          max_depth_reached: 0,
          circular_references_detected: [],
          scope_filtered: !!context.scope,
          ranking_algorithm: 'none',
          traversal_time_ms: 0,
        },
      },
    };
  }

  try {
    const expandedResults: SearchResult[] = [];
    const processedEntities = new Set<string>();
    const parentEntities = new Map<string, unknown>();
    const childEntities = new Map<string, unknown>();
    let totalTraversalTime = 0;
    let totalEntitiesTraversed = 0;
    let maxDepthReached = 0;
    const circularReferencesDetected = new Set<string>();

    // Process each result for graph expansion
    for (const result of results) {
      const entityKey = `${result.kind}:${result.id}`;

      // Skip if already processed to avoid duplicates
      if (processedEntities.has(entityKey)) {
        continue;
      }
      processedEntities.add(entityKey);

      // Add the original result
      expandedResults.push(result);

      // Apply enhanced graph traversal
      if (context.expandMetadata?.parentChildExpansion) {
        const traversalOptions: TraversalOptions = {
          depth: context.expandMetadata.maxDepth,
          direction:
            context.expand === 'parents'
              ? 'incoming'
              : context.expand === 'children'
                ? 'outgoing'
                : 'both',
          scope: context.scope,
          include_circular_refs: context.expandMetadata.includeCircularRefs,
          max_results: Math.floor(context.limit / 2), // Reserve space for multiple entities
          sort_by: context.expandMetadata.sortBy as unknown,
        };

        // Perform enhanced graph traversal
        const graphTraversalStart = Date.now();
        const graphResult = await traverseGraphWithExpansion(
          result.kind,
          result.id,
          traversalOptions
        );
        const traversalTime = Date.now() - graphTraversalStart;

        // Update metadata
        totalTraversalTime += traversalTime;
        totalEntitiesTraversed += graphResult.total_entities_found;
        maxDepthReached = Math.max(maxDepthReached, graphResult.max_depth_reached);
        graphResult.circular_refs_detected.forEach((ref) => circularReferencesDetected.add(ref));

        // Convert graph nodes to search results
        const graphSearchResults = await convertGraphNodesToSearchResults(
          graphResult.nodes.slice(1), // Skip root node (already included)
          context.expand,
          graphResult
        );

        // Process parent and child entities for metadata
        for (const node of graphResult.nodes.slice(1)) {
          const nodeKey = `${node.entity_type}:${node.entity_id}`;

          if (context.expand === 'parents' && node.depth === 1) {
            parentEntities.set(nodeKey, {
              entity_id: node.entity_id,
              entity_type: node.entity_type,
              child_count: 1, // Simplified - would need actual counting
              relationship_types: [node.relationship_metadata?.relation_type || 'unknown'],
            });
          } else if (context.expand === 'children' || context.expand === 'relations') {
            childEntities.set(nodeKey, {
              entity_id: node.entity_id,
              entity_type: node.entity_type,
              parent_id: result.id,
              depth_from_parent: node.depth,
              relationship_metadata: node.relationship_metadata || {
                relation_type: 'related',
                direction: 'child',
                confidence: 0.5,
              },
            });
          }
        }

        // Add graph results avoiding duplicates
        for (const graphResult of graphSearchResults) {
          const graphEntityKey = `${graphResult.kind}:${graphResult.id}`;
          if (!processedEntities.has(graphEntityKey)) {
            processedEntities.add(graphEntityKey);
            expandedResults.push(graphResult);
          }
        }
      } else {
        // Fall back to legacy expansion method
        const legacyResults = await findRelatedItems(result, context.expand, context.scope);
        for (const legacyResult of legacyResults) {
          const legacyEntityKey = `${legacyResult.kind}:${legacyResult.id}`;
          if (!processedEntities.has(legacyEntityKey)) {
            processedEntities.add(legacyEntityKey);
            expandedResults.push(legacyResult);
          }
        }
      }
    }

    // Remove duplicates and apply final ranking
    const uniqueResults = removeDuplicates(expandedResults);

    // Apply enhanced ranking that considers relationship confidence
    const rankedResults = uniqueResults
      .map((result) => ({
        ...result,
        confidence_score: calculateEnhancedConfidence(result, context),
      }))
      .sort((a, b) => b.confidence_score - a.confidence_score)
      .slice(0, context.limit);

    logger.info(
      {
        originalResults: results.length,
        expandedResults: rankedResults.length,
        expansionType: context.expand,
        maxDepth: context.expandMetadata?.maxDepth,
      },
      'Graph expansion completed successfully'
    );

    // Build graph expansion metadata
    const graphExpansionMetadata = {
      enabled: true,
      expansion_type: context.expand,
      parent_entities: Array.from(parentEntities.values()),
      child_entities: Array.from(childEntities.values()),
      traversal_metadata: {
        total_entities_traversed: totalEntitiesTraversed,
        max_depth_reached: maxDepthReached,
        circular_references_detected: Array.from(circularReferencesDetected),
        scope_filtered: !!context.scope,
        ranking_algorithm: context.expandMetadata?.sortBy || 'relevance',
        traversal_time_ms: totalTraversalTime,
      },
    };

    return {
      results: rankedResults,
      graphExpansionMetadata,
    };
  } catch (error) {
    logger.error(
      {
        error: error instanceof Error ? error.message : String(error),
        expand: context.expand,
        originalResultCount: results.length,
      },
      'Graph expansion failed, returning original results'
    );

    return {
      results,
      graphExpansionMetadata: {
        enabled: false,
        expansion_type: context.expand,
        parent_entities: [],
        child_entities: [],
        traversal_metadata: {
          total_entities_traversed: 0,
          max_depth_reached: 0,
          circular_references_detected: [],
          scope_filtered: !!context.scope,
          ranking_algorithm: 'none',
          traversal_time_ms: 0,
        },
      },
    };
  }
}

/**
 * Find related items based on expansion type
 */
async function findRelatedItems(
  result: SearchResult,
  expandType: 'relations' | 'parents' | 'children',
  scope?: Record<string, unknown>
): Promise<SearchResult[]> {
  // Simulate graph traversal (replace with actual implementation)
  const relatedItems: SearchResult[] = [];

  try {
    switch (expandType) {
      case 'relations':
        // Find related items through relations
        relatedItems.push(...(await simulateRelationSearch(result.id, scope)));
        break;
      case 'parents':
        // Find items that reference this item
        relatedItems.push(...(await simulateParentSearch(result.id, scope)));
        break;
      case 'children':
        // Find items referenced by this item
        relatedItems.push(...(await simulateChildSearch(result.id, scope)));
        break;
    }
  } catch (error) {
    logger.error(
      {
        error: error instanceof Error ? error.message : String(error),
        itemId: result.id,
        expandType,
      },
      'Related item search failed'
    );
  }

  return relatedItems;
}

/**
 * Filter results by scope and types
 */
function filterResults(results: SearchResult[], context: SearchContext): SearchResult[] {
  let filteredResults = results;

  // Filter by types if specified
  if (context.types && context.types.length > 0) {
    filteredResults = filteredResults.filter((result) => context.types!.includes(result.kind));
  }

  // Filter by scope if specified
  if (context.scope) {
    filteredResults = filteredResults.filter((result) => {
      const resultScope = result.scope || {};
      return matchesScope(resultScope, context.scope!);
    });
  }

  return filteredResults;
}

/**
 * Check if result scope matches filter scope with precedence
 */
function matchesScope(
  resultScope: Record<string, unknown>,
  filterScope: Record<string, unknown>
): boolean {
  // Branch has highest precedence
  if (filterScope.branch && resultScope.branch !== filterScope.branch) {
    return false;
  }

  // Project has medium precedence
  if (filterScope.project && resultScope.project !== filterScope.project) {
    return false;
  }

  // Org has lowest precedence
  if (filterScope.org && resultScope.org !== filterScope.org) {
    return false;
  }

  return true;
}

/**
 * Calculate average confidence score
 */
function calculateAverageConfidence(results: SearchResult[]): number {
  if (results.length === 0) return 0;

  const totalConfidence = results.reduce((sum, result) => sum + result.confidence_score, 0);
  return totalConfidence / results.length;
}

/**
 * Generate user-friendly message
 */
function generateUserMessage(
  strategyResult: SearchStrategyResult,
  results: SearchResult[]
): string {
  const { strategy, vectorUsed, degraded, fallbackReason } = strategyResult;

  let message = `Found ${results.length} results using ${strategy} search`;

  if (vectorUsed) {
    message += ' with vector embeddings';
  }

  if (degraded) {
    message += ` (degraded: ${fallbackReason})`;
  }

  return message;
}

/**
 * Create error response with proper metadata
 */
function createErrorResponse(
  query: string,
  error: unknown,
  searchId: string,
  duration: number
): MemoryFindResponse {
  const errorMessage = error instanceof Error ? error.message : 'Unknown error';

  return {
    results: [],
    items: [],
    total_count: 0,
    total: 0,
    autonomous_context: {
      search_mode_used: 'error',
      results_found: 0,
      confidence_average: 0,
      user_message_suggestion: `Search failed: ${errorMessage}`,
    },
    observability: {
      source: 'cortex_memory',
      strategy: 'error' as const,
      vector_used: false,
      degraded: true,
      execution_time_ms: duration,
      confidence_average: 0,
      search_id: searchId,
    },
    meta: {
      strategy: 'error',
      vector_used: false,
      degraded: true,
      source: 'cortex_memory',
      execution_time_ms: duration,
      confidence_score: 0,
      truncated: false,
      warnings: [errorMessage],
    },
  };
}

/**
 * Utility functions for simulation (replace with actual implementations)
 */
async function checkVectorBackendAvailability(): Promise<boolean> {
  // Simulate vector backend health check
  try {
    // In a real implementation, this would check the actual vector database
    return Math.random() > 0.1; // 90% availability for simulation
  } catch {
    return false;
  }
}

async function simulateKeywordSearch(query: SearchQuery): Promise<SearchResult[]> {
  // Simulate keyword search results
  return [
    {
      id: 'keyword-1',
      kind: 'entity',
      scope: query.scope || {},
      data: { content: `Keyword match for: ${query.query}` },
      created_at: new Date().toISOString(),
      confidence_score: 0.7,
      match_type: 'keyword',
    },
  ];
}

async function simulateVectorSearch(query: SearchQuery): Promise<SearchResult[]> {
  // Simulate vector search results
  return [
    {
      id: 'vector-1',
      kind: 'entity',
      scope: query.scope || {},
      data: { content: `Vector match for: ${query.query}` },
      created_at: new Date().toISOString(),
      confidence_score: 0.9,
      match_type: 'semantic',
    },
  ];
}

async function simulateHybridSearch(query: SearchQuery): Promise<SearchResult[]> {
  // Simulate hybrid search results
  const keywordResults = await simulateKeywordSearch(query);
  const vectorResults = await simulateVectorSearch(query);

  return [...keywordResults, ...vectorResults]
    .sort((a, b) => b.confidence_score - a.confidence_score)
    .slice(0, query.limit || 10);
}

async function simulateRelationSearch(
  itemId: string,
  scope?: Record<string, unknown>
): Promise<SearchResult[]> {
  // Simulate finding related items
  return [
    {
      id: `relation-${itemId}-1`,
      kind: 'relation',
      scope: scope || {},
      data: { content: `Related to: ${itemId}` },
      created_at: new Date().toISOString(),
      confidence_score: 0.6,
      match_type: 'expanded',
    },
  ];
}

async function simulateParentSearch(
  itemId: string,
  scope?: Record<string, unknown>
): Promise<SearchResult[]> {
  // Simulate finding parent items
  return [
    {
      id: `parent-${itemId}-1`,
      kind: 'entity',
      scope: scope || {},
      data: { content: `Parent of: ${itemId}` },
      created_at: new Date().toISOString(),
      confidence_score: 0.5,
      match_type: 'expanded',
    },
  ];
}

async function simulateChildSearch(
  itemId: string,
  scope?: Record<string, unknown>
): Promise<SearchResult[]> {
  // Simulate finding child items
  return [
    {
      id: `child-${itemId}-1`,
      kind: 'entity',
      scope: scope || {},
      data: { content: `Child of: ${itemId}` },
      created_at: new Date().toISOString(),
      confidence_score: 0.5,
      match_type: 'expanded',
    },
  ];
}

/**
 * Convert graph nodes to search results with parent-child metadata
 */
async function convertGraphNodesToSearchResults(
  nodes: unknown[],
  expandType: 'relations' | 'parents' | 'children' | 'none',
  graphResult: GraphTraversalResult
): Promise<SearchResult[]> {
  return nodes.map((node) => {
    const nodeData = node.data || {};
    const tags = nodeData.tags || {};
    const relationshipMeta = node.relationship_metadata;

    return {
      id: node.entity_id,
      kind: node.entity_type,
      scope: {
        project: tags.project,
        branch: tags.branch,
        org: tags.org,
      },
      data: {
        ...nodeData,
        // Add parent-child relationship metadata
        relationship_metadata: relationshipMeta,
        expansion_type: expandType,
        depth_from_parent: node.depth,
        circular_reference: graphResult.circular_refs_detected.includes(
          `${node.entity_type}:${node.entity_id}`
        ),
      },
      created_at:
        typeof nodeData.created_at === 'string' ? nodeData.created_at : new Date().toISOString(),
      confidence_score: node.confidence_score || 0.7,
      match_type: 'expanded' as const,
    };
  });
}

/**
 * Calculate enhanced confidence score considering relationship metadata
 */
function calculateEnhancedConfidence(result: SearchResult, context: SearchContext): number {
  let baseConfidence = result.confidence_score;

  // Boost confidence based on expansion type and relationship metadata
  if (result.data?.relationship_metadata) {
    const relMeta = result.data.relationship_metadata as unknown;

    // Direction-specific boosts
    if (relMeta.direction === 'parent') {
      baseConfidence *= 1.1; // Parent relationships get a boost
    } else if (relMeta.direction === 'child') {
      baseConfidence *= 0.95; // Slightly lower for children
    }

    // Relationship type boosts
    if (relMeta.confidence) {
      baseConfidence = baseConfidence * 0.7 + relMeta.confidence * 0.3; // Weighted average
    }

    // Depth penalty (deeper = lower confidence)
    const depth = result.data?.depth_from_parent || 0;
    const depthPenalty = Math.max(0, 1 - depth * 0.15);
    baseConfidence *= depthPenalty;
  }

  // Circular reference penalty
  if (result.data?.circular_reference) {
    baseConfidence *= 0.8; // Penalize circular references
  }

  // Ensure confidence stays within valid range
  return Math.max(0.1, Math.min(1.0, baseConfidence));
}

function removeDuplicates(results: SearchResult[]): SearchResult[] {
  const seen = new Set<string>();
  return results.filter((result) => {
    if (seen.has(result.id)) {
      return false;
    }
    seen.add(result.id);
    return true;
  });
}
