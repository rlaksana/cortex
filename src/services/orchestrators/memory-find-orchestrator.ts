import { logger } from '../../utils/logger.js';
import { prisma } from '../../db/prisma-client.js';
import { traverseGraph, enrichGraphNodes, type TraversalOptions } from '../graph-traversal.js';
import type { SearchQuery, SearchResult, MemoryFindResponse } from '../../types/core-interfaces.js';
import { queryParser, type ParsedQuery } from '../search/query-parser.js';
import { searchStrategySelector, type StrategySelection } from '../search/search-strategy.js';
import { resultRanker, type ResultRanker } from '../ranking/result-ranker.js';
import { auditService } from '../audit/audit-service.js';

/**
 * Search execution context
 */
interface SearchContext {
  originalQuery: SearchQuery;
  parsed: ParsedQuery;
  strategy: StrategySelection;
  startTime: number;
}

/**
 * Search execution result
 */
interface SearchExecutionResult {
  results: SearchResult[];
  totalCount: number;
  strategy: StrategySelection;
  executionTime: number;
  fallbackUsed: boolean;
}

/**
 * Orchestrator for memory find operations
 * Coordinates query parsing, strategy selection, search execution, and result ranking
 */
export class MemoryFindOrchestrator {
  constructor(
    private ranker: ResultRanker = resultRanker
  ) {}

  /**
   * Map knowledge kinds to their corresponding Prisma table names
   */
  private getTableNameForKind(kind: string): string | null {
    const kindToTableMap: Record<string, string> = {
      'section': 'section',
      'decision': 'adrDecision',
      'issue': 'issueLog',
      'todo': 'todoLog',
      'runbook': 'runbook',
      'change': 'changeLog',
      'release_note': 'releaseNote',
      'ddl': 'ddlHistory',
      'pr_context': 'prContext',
      'entity': 'knowledgeEntity',
      'relation': 'knowledgeRelation',
      'observation': 'knowledgeObservation',
      'incident': 'incidentLog',
      'release': 'releaseLog',
      'risk': 'riskLog',
      'assumption': 'assumptionLog'
    };

    return kindToTableMap[kind] || null;
  }

  /**
   * Query multiple knowledge tables based on types filter
   */
  private async queryMultipleTables(types: string[], whereClause: any, select: any, orderBy?: any, take?: number) {
    const results: any[] = [];
    let totalCount = 0;

    for (const kind of types) {
      const tableName = this.getTableNameForKind(kind);
      if (!tableName) continue;

      try {
        const tableResults = await (prisma as any)[tableName].findMany({
          where: whereClause,
          select,
          orderBy,
          take
        });

        const tableCount = await (prisma as any)[tableName].count({
          where: whereClause
        });

        results.push(...tableResults.map((result: any) => ({
          ...result,
          kind,
          created_at: result.created_at.toISOString()
        })));

        totalCount += tableCount;
      } catch (error) {
        logger.warn({ kind, error }, 'Failed to query table, skipping');
      }
    }

    return { results, totalCount };
  }

  /**
   * Main entry point for memory find operations
   */
  async findItems(query: SearchQuery): Promise<MemoryFindResponse> {
    const startTime = Date.now();

    try {
      logger.info({ query: query.query, mode: query.mode }, 'Memory find operation started');

      // Step 1: Parse and validate query
      const { parsed, validation } = queryParser.parseQuery(query);
      if (!validation.valid) {
        return this.createValidationErrorResponse(validation.errors);
      }

      const context: SearchContext = {
        originalQuery: query,
        parsed,
        strategy: searchStrategySelector.selectStrategy(query, parsed),
        startTime
      };

      // Step 2: Execute search strategy
      const searchResult = await this.executeSearch(context);

      // Step 3: Rank results
      const rankedResults = this.ranker.rankResults(
        searchResult.results,
        query,
        parsed
      );

      // Step 4: Build response
      const response = this.buildResponse(rankedResults, searchResult);

      // Step 5: Log operation
      await this.logSearchOperation(query, response, Date.now() - startTime);

      logger.info({
        resultCount: response.results.length,
        executionTime: Date.now() - startTime,
        strategy: searchResult.strategy.primary.name
      }, 'Memory find operation completed');

      return response;

    } catch (error) {
      logger.error({ error, query }, 'Memory find operation failed');

      // Log error
      await auditService.logError(error instanceof Error ? error : new Error('Unknown error'), {
        operation: 'memory_find',
        query: query.query
      });

      return this.createErrorResponse(error);
    }
  }

  /**
   * Execute the selected search strategy
   */
  private async executeSearch(context: SearchContext): Promise<SearchExecutionResult> {
    const { parsed, originalQuery, strategy } = context;

    try {
      // Execute primary strategy
      const primaryResults = await this.executeStrategy(
        strategy.primary,
        parsed,
        originalQuery
      );

      if (primaryResults.results.length > 0 || !strategy.fallback) {
        return {
          results: primaryResults.results,
          totalCount: primaryResults.totalCount,
          strategy,
          executionTime: Date.now() - context.startTime,
          fallbackUsed: false
        };
      }

      // Try fallback strategy if primary returned no results
      logger.warn({
        primaryStrategy: strategy.primary.name,
        fallbackStrategy: strategy.fallback?.name
      }, 'Primary strategy returned no results, trying fallback');

      if (strategy.fallback) {
        const fallbackResults = await this.executeStrategy(
          strategy.fallback,
          parsed,
          originalQuery
        );

        return {
          results: fallbackResults.results,
          totalCount: fallbackResults.totalCount,
          strategy,
          executionTime: Date.now() - context.startTime,
          fallbackUsed: true
        };
      }

      return {
        results: [],
        totalCount: 0,
        strategy,
        executionTime: Date.now() - context.startTime,
        fallbackUsed: false
      };

    } catch (error) {
      logger.error({ error, strategy: strategy.primary.name }, 'Primary strategy failed');

      // Try fallback if primary failed
      if (strategy.fallback) {
        try {
          const fallbackResults = await this.executeStrategy(
            strategy.fallback,
            parsed,
            originalQuery
          );

          return {
            results: fallbackResults.results,
            totalCount: fallbackResults.totalCount,
            strategy,
            executionTime: Date.now() - context.startTime,
            fallbackUsed: true
          };
        } catch (fallbackError) {
          logger.error({ fallbackError, strategy: strategy.fallback.name }, 'Fallback strategy also failed');
          throw fallbackError;
        }
      }

      throw error;
    }
  }

  /**
   * Execute a specific search strategy
   */
  private async executeStrategy(
    strategy: any,
    parsed: ParsedQuery,
    query: SearchQuery
  ): Promise<{ results: SearchResult[]; totalCount: number }> {
    switch (strategy.name) {
      case 'fulltext':
        return await this.executeFulltextSearch(parsed, query);

      case 'semantic':
        return await this.executeSemanticSearch(parsed, query);

      case 'hybrid':
        return await this.executeHybridSearch(parsed, query);

      case 'graph':
        return await this.executeGraphSearch(parsed, query);

      case 'fallback':
        return await this.executeFallbackSearch(parsed, query);

      default:
        throw new Error(`Unknown search strategy: ${strategy.name}`);
    }
  }

  /**
   * Execute full-text search
   */
  private async executeFulltextSearch(
    parsed: ParsedQuery,
    query: SearchQuery
  ): Promise<{ results: SearchResult[]; totalCount: number }> {
    // Build search query for PostgreSQL FTS
    // const searchVector = this.buildSearchVector(parsed); // Unused for now

    const whereClause: any = {
      OR: [
        { data: { path: ['title'], string_contains: parsed.terms[0] } },
        { data: { path: ['description'], string_contains: parsed.terms[0] } },
        { data: { path: ['content'], string_contains: parsed.terms[0] } }
      ]
    };

    // Add type filters
    if (query.types && query.types.length > 0) {
      whereClause.kind = { in: query.types };
    }

    // Add scope filters
    if (query.scope) {
      if (query.scope.project) {
        whereClause.scope_project = query.scope.project;
      }
      if (query.scope.branch) {
        whereClause.scope_branch = query.scope.branch;
      }
      if (query.scope.org) {
        whereClause.scope_org = query.scope.org;
      }
    }

    const types = query.types && query.types.length > 0 ? query.types : Object.keys({
      'section': 'section',
      'decision': 'adrDecision',
      'issue': 'issueLog',
      'todo': 'todoLog',
      'runbook': 'runbook',
      'change': 'changeLog',
      'release_note': 'releaseNote',
      'ddl': 'ddlHistory',
      'pr_context': 'prContext',
      'entity': 'knowledgeEntity',
      'relation': 'knowledgeRelation',
      'observation': 'knowledgeObservation',
      'incident': 'incidentLog',
      'release': 'releaseLog',
      'risk': 'riskLog',
      'assumption': 'assumptionLog'
    });

    const selectFields = {
      id: true,
      scope_project: true,
      scope_branch: true,
      scope_org: true,
      data: true,
      created_at: true,
      updated_at: true
    };

    const { results, totalCount } = await this.queryMultipleTables(
      types,
      whereClause,
      selectFields,
      { updated_at: 'desc' },
      query.limit || 50
    );

    return {
      results: results.map(row => this.mapRowToSearchResult(row, 0.8)), // Base confidence score
      totalCount
    };
  }

  /**
   * Execute semantic search (placeholder)
   */
  private async executeSemanticSearch(
    parsed: ParsedQuery,
    query: SearchQuery
  ): Promise<{ results: SearchResult[]; totalCount: number }> {
    // This is a placeholder for semantic search
    // In a full implementation, you would use vector embeddings or similar

    logger.warn('Semantic search not fully implemented, falling back to fulltext');

    // For now, delegate to fulltext search
    return this.executeFulltextSearch(parsed, query);
  }

  /**
   * Execute hybrid search
   */
  private async executeHybridSearch(
    parsed: ParsedQuery,
    query: SearchQuery
  ): Promise<{ results: SearchResult[]; totalCount: number }> {
    // Execute both fulltext and semantic searches
    const [fulltextResults, semanticResults] = await Promise.all([
      this.executeFulltextSearch(parsed, query),
      this.executeSemanticSearch(parsed, query)
    ]);

    // Merge and deduplicate results
    const mergedResults = this.mergeResults(
      fulltextResults.results,
      semanticResults.results
    );

    return {
      results: mergedResults,
      totalCount: Math.max(fulltextResults.totalCount, semanticResults.totalCount)
    };
  }

  /**
   * Execute graph-based search
   */
  private async executeGraphSearch(
    parsed: ParsedQuery,
    query: SearchQuery
  ): Promise<{ results: SearchResult[]; totalCount: number }> {
    // Find entities that match the query
    const entityMatches = await this.findEntityMatches(parsed, query);

    if (entityMatches.length === 0) {
      return { results: [], totalCount: 0 };
    }

    // Traverse graph from matching entities
    const allResults: SearchResult[] = [];
    let totalCount = 0;

    for (const entity of entityMatches.slice(0, 5)) { // Limit to prevent explosion
      const traversalOptions: TraversalOptions = {
        depth: 2,
        direction: 'both'
      };

      const graphResult = await traverseGraph(
        entity.kind,
        entity.id,
        traversalOptions
      );

      // Enrich graph nodes with data
      const enrichedNodes = await enrichGraphNodes(graphResult.nodes);

      // Convert to search results
      const searchResults = enrichedNodes.map(node => ({
        id: node.entity_id,
        kind: node.entity_type,
        scope: {
          project: node.data?.scope_project,
          branch: node.data?.scope_branch,
          org: node.data?.scope_org
        },
        data: node.data || {},
        created_at: (typeof node.data?.created_at === 'string' ? node.data.created_at : new Date().toISOString()),
        confidence_score: 0.7, // Base confidence for graph traversal
        match_type: 'semantic' as const
      }));

      allResults.push(...searchResults);
      totalCount += searchResults.length;
    }

    return {
      results: allResults,
      totalCount
    };
  }

  /**
   * Execute fallback search
   */
  private async executeFallbackSearch(
    _parsed: ParsedQuery,
    query: SearchQuery
  ): Promise<{ results: SearchResult[]; totalCount: number }> {
    // For now, return empty results as fallback
    // TODO: Implement proper fallback search using service layer instead of direct prisma calls
    logger.warn({ query: query.query }, 'Fallback search not implemented, returning empty results');

    return {
      results: [],
      totalCount: 0
    };
  }

  
  /**
   * Find entities matching the query terms
   */
  private async findEntityMatches(
    _parsed: ParsedQuery,
    query: SearchQuery
  ): Promise<{ id: string; kind: string }[]> {
    const whereClause: any = {
      kind: { in: ['entity', 'decision', 'issue'] }
    };

    if (query.types && query.types.length > 0) {
      whereClause.kind = { in: query.types };
    }

    // TODO: Implement proper entity matching using service layer instead of direct prisma calls
    // For now, return empty results
    logger.warn({ query: query.query }, 'Entity matching not implemented, returning empty results');

    return [];
  }

  /**
   * Merge and deduplicate results from multiple searches
   */
  private mergeResults(
    results1: SearchResult[],
    results2: SearchResult[]
  ): SearchResult[] {
    const seen = new Set<string>();
    const merged: SearchResult[] = [];

    for (const result of [...results1, ...results2]) {
      if (!seen.has(result.id)) {
        seen.add(result.id);
        merged.push(result);
      }
    }

    return merged;
  }

  /**
   * Map database row to SearchResult
   */
  private mapRowToSearchResult(row: any, baseConfidence: number): SearchResult {
    return {
      id: row.id,
      kind: row.kind,
      scope: {
        project: row.scope_project,
        branch: row.scope_branch,
        org: row.scope_org
      },
      data: row.data,
      created_at: row.created_at?.toISOString() || new Date().toISOString(),
      confidence_score: baseConfidence,
      match_type: 'exact' as const
    };
  }

  /**
   * Build final response
   */
  private buildResponse(
    rankedResults: any[],
    searchResult: SearchExecutionResult
  ): MemoryFindResponse {
    // Convert ranked results back to SearchResult format
    const results = rankedResults.map(rr => ({
      id: rr.id,
      kind: rr.kind,
      scope: rr.scope,
      data: rr.data,
      created_at: rr.created_at,
      confidence_score: rr.boostedScore,
      match_type: rr.match_type
    }));

    return {
      results,
      total_count: searchResult.totalCount,
      autonomous_context: {
        search_mode_used: searchResult.strategy.primary.name,
        results_found: results.length,
        confidence_average: results.length > 0
          ? results.reduce((sum, r) => sum + r.confidence_score, 0) / results.length
          : 0,
        user_message_suggestion: this.generateUserMessage(results, searchResult)
      }
    };
  }

  /**
   * Generate user-friendly message
   */
  private generateUserMessage(
    results: SearchResult[],
    searchResult: SearchExecutionResult
  ): string {
    const count = results.length;
    const fallbackUsed = searchResult.fallbackUsed;

    if (count === 0) {
      return '🔍 No results found - try different search terms';
    }

    let message = `✅ Found ${count} result${count > 1 ? 's' : ''}`;

    if (fallbackUsed) {
      message += ` (used fallback search)`;
    }

    return message;
  }

  /**
   * Log search operation to audit
   */
  private async logSearchOperation(
    query: SearchQuery,
    response: MemoryFindResponse,
    duration: number
  ): Promise<void> {
    await auditService.logSearchOperation(
      query.query,
      response.results.length,
      response.autonomous_context.search_mode_used,
      query.scope,
      undefined,
      duration
    );
  }

  /**
   * Create validation error response
   */
  private createValidationErrorResponse(errors: string[]): MemoryFindResponse {
    return {
      results: [],
      total_count: 0,
      autonomous_context: {
        search_mode_used: 'validation_failed',
        results_found: 0,
        confidence_average: 0,
        user_message_suggestion: `❌ Invalid query: ${errors.join(', ')}`
      }
    };
  }

  /**
   * Create error response
   */
  private createErrorResponse(_error: any): MemoryFindResponse {
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

// Export singleton instance
export const memoryFindOrchestrator = new MemoryFindOrchestrator();