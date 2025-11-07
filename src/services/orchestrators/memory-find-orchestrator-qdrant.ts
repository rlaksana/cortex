// @ts-nocheck
/**
 * Memory Find Orchestrator - Qdrant Implementation
 *
 * Enhanced orchestrator that leverages Qdrant's vector capabilities for sophisticated
 * semantic search with multiple strategies and autonomous context generation while
 * maintaining compatibility with the unified database abstraction layer.
 *
 * Features:
 * - Vector embeddings for semantic search
 * - Multi-strategy search: semantic, keyword, hybrid, fallback
 * - Confidence scoring and intelligent result ranking
 * - Scope-based isolation (org/project/branch)
 * - Autonomous context generation with search insights
 * - Query parsing and optimization
 * - Performance monitoring and optimization
 * - Integration with unified database abstraction layer
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { logger } from '@/utils/logger.js';
// import { auditService } from '../audit/audit-service.js'; // REMOVED: Service file deleted
import type {
  SearchResult,
  SearchQuery,
  MemoryFindResponse,
  SmartFindRequest,
  SmartFindResult,
} from '../../types/core-interfaces.js';
import {
  ConnectionError,
  type IDatabase,
  type SearchOptions,
} from '../../db/database-interface.js';
import { ResultGroupingService } from '../search/result-grouping-service.js';
import { createFindObservability } from '../../utils/observability-helper.js';

/**
 * Search strategy configuration
 */
interface SearchStrategy {
  name: string;
  type: 'semantic' | 'keyword' | 'hybrid' | 'fallback';
  priority: number;
  threshold?: number;
  limit?: number;
}

/**
 * Search execution context
 */
interface SearchContext {
  originalQuery: SmartFindRequest;
  parsed: ParsedQuery;
  strategy: SearchStrategySet;
  startTime: number;
}

/**
 * Search strategy set with primary and fallback options
 */
interface SearchStrategySet {
  primary: SearchStrategy;
  fallback?: SearchStrategy;
  alternatives: SearchStrategy[];
}

/**
 * Parsed query components
 */
interface ParsedQuery {
  original: string;
  cleaned: string;
  entities: Array<{ text: string; type: string; position: number }>;
  keywords: string[];
  scope?: Record<string, any>;
  filters: Record<string, any>;
  intent: 'search' | 'lookup' | 'browse' | 'unknown';
}

/**
 * Search execution result
 */
interface SearchResultData {
  results: SearchResult[];
  totalCount: number;
  strategy: SearchStrategySet;
  executionTime: number;
  fallbackUsed: boolean;
  confidence: number;
  metadata: Record<string, any>;
}

/**
 * Orchestrator for memory find operations using Qdrant with enhanced multi-strategy search
 */
export class MemoryFindOrchestratorQdrant {
  private database: IDatabase;
  private resultGroupingService: ResultGroupingService;

  // Search strategies ordered by effectiveness
  private readonly SEARCH_STRATEGIES: SearchStrategy[] = [
    {
      name: 'hybrid',
      type: 'hybrid',
      priority: 1,
      threshold: 0.7,
      limit: 50,
    },
    {
      name: 'semantic',
      type: 'semantic',
      priority: 2,
      threshold: 0.6,
      limit: 50,
    },
    {
      name: 'keyword',
      type: 'keyword',
      priority: 3,
      threshold: 0.4,
      limit: 50,
    },
    {
      name: 'fallback',
      type: 'fallback',
      priority: 4,
      limit: 25,
    },
  ];

  constructor(database: IDatabase) {
    this.database = database;
    this.resultGroupingService = new ResultGroupingService();
  }

  /**
   * Main entry point for memory find operations
   */
  async findItems(query: SmartFindRequest): Promise<SmartFindResult> {
    const startTime = Date.now();

    try {
      // Initialize database if needed
      await this.ensureDatabaseInitialized();

      logger.info(
        {
          query: query.query,
          mode: query.mode,
          maxAttempts: query.max_attempts || 3,
        },
        'Memory find operation started (Qdrant)'
      );

      // Step 1: Parse and validate query
      const { parsed, validation } = this.parseQuery(query);
      if (!validation.valid) {
        return this.createValidationErrorResponse(validation.errors);
      }

      const context: SearchContext = {
        originalQuery: query,
        parsed,
        strategy: this.selectSearchStrategy(query, parsed),
        startTime,
      };

      // Step 2: Execute search strategy
      const searchResult = await this.executeSearch(context);

      // Step 3: Rank and enhance results
      const rankedResults = this.rankResults(searchResult.results, query, parsed);

      // Step 4: Build response
      const response = this.buildSmartResponse(rankedResults, searchResult, query);

      // Step 5: Log operation
      await this.logSearchOperation(query, response, Date.now() - startTime);

      logger.info(
        {
          resultCount: response.hits.length,
          executionTime: Date.now() - startTime,
          strategy: searchResult.strategy.primary.name,
          fallbackUsed: searchResult.fallbackUsed,
        },
        'Memory find operation completed (Qdrant)'
      );

      return response;
    } catch (error) {
      logger.error({ error, query }, 'Memory find operation failed (Qdrant)');

      // Log error
      // await auditService.logError(error instanceof Error ? error : new Error('Unknown error'), {
      //   operation: 'memory_find_qdrant',
      //   query: query.query,
      // }); // REMOVED: audit-service deleted
      logger.error({ error, query: query.query }, 'Memory find error (logging disabled)');

      return this.createErrorResponse(error);
    }
  }

  /**
   * Legacy find operation for backward compatibility
   */
  async findItemsLegacy(query: SearchQuery): Promise<MemoryFindResponse> {
    const startTime = Date.now();
    // Convert legacy query to smart find format
    const smartQuery: SmartFindRequest = {
      query: query.query,
      ...(query.scope && { scope: query.scope }),
      ...(query.types && { types: query.types }),
      top_k: query.limit || 50,
      mode: query.mode || 'auto',
      enable_auto_fix: true,
      return_corrections: true,
      max_attempts: 3,
      timeout_per_attempt_ms: 10000,
    };

    const result = await this.findItems(smartQuery);

    // Convert back to legacy format
    const searchResults = result.hits.map((hit) => ({
      id: hit.id,
      kind: hit.kind,
      scope: hit.scope || {},
      data: this.extractDataFromHit(hit),
      created_at: hit.updated_at || new Date().toISOString(),
      confidence_score: hit.confidence,
      match_type: (hit.confidence > 0.8 ? 'exact' : hit.confidence > 0.6 ? 'fuzzy' : 'semantic') as
        | 'exact'
        | 'fuzzy'
        | 'semantic',
    }));

    return {
      results: searchResults,
      items: searchResults, // Add items property for compatibility
      total_count: result.hits.length,
      autonomous_context: {
        search_mode_used: result.autonomous_metadata.strategy_used,
        results_found: result.hits.length,
        confidence_average: Number(result.autonomous_metadata.confidence) || 0,
        user_message_suggestion: result.autonomous_metadata.recommendation,
      },
      observability: createFindObservability(
        result.autonomous_metadata.strategy_used as any,
        true, // vector_used - Qdrant always uses vectors
        false, // degraded - assume not degraded unless error occurs
        Date.now() - startTime,
        Number(result.autonomous_metadata.confidence) || 0
      ),
      meta: {
        strategy: result.autonomous_metadata.strategy_used,
        vector_used: true,
        degraded: false,
        source: 'memory-find-orchestrator-qdrant',
        execution_time_ms: Date.now() - startTime,
        confidence_score: Number(result.autonomous_metadata.confidence) || 0,
        truncated: false,
      },
    };
  }

  /**
   * Parse and analyze query for optimal search strategy
   */
  private parseQuery(query: SmartFindRequest): {
    parsed: ParsedQuery;
    validation: { valid: boolean; errors: string[] };
  } {
    const errors: string[] = [];

    // Basic validation
    if (!query.query || query.query.trim().length === 0) {
      errors.push('Query cannot be empty');
      return {
        parsed: {} as ParsedQuery,
        validation: { valid: false, errors },
      };
    }

    const cleaned = query.query.trim().toLowerCase();
    const keywords = this.extractKeywords(cleaned);
    const entities = this.extractEntities(cleaned);
    const intent = this.detectIntent(cleaned, keywords);

    const parsed: ParsedQuery = {
      original: query.query,
      cleaned,
      keywords,
      entities,
      ...(query.scope && { scope: query.scope }),
      filters: this.extractFilters(query),
      intent,
    };

    return {
      parsed,
      validation: { valid: errors.length === 0, errors },
    };
  }

  /**
   * Select optimal search strategy based on query and context
   */
  private selectSearchStrategy(query: SmartFindRequest, parsed: ParsedQuery): SearchStrategySet {
    const mode = query.mode || 'auto';
    let primaryStrategy: SearchStrategy;
    let fallbackStrategy: SearchStrategy | undefined;

    // Determine primary strategy based on mode and query characteristics
    switch (mode) {
      case 'deep':
        primaryStrategy = this.SEARCH_STRATEGIES.find((s) => s.type === 'semantic')!;
        break;
      case 'fast':
        primaryStrategy = this.SEARCH_STRATEGIES.find((s) => s.type === 'keyword')!;
        break;
      case 'auto':
      default:
        // Auto-select based on query characteristics
        if (parsed.entities.length > 0 && parsed.keywords.length > 3) {
          primaryStrategy = this.SEARCH_STRATEGIES.find((s) => s.type === 'hybrid')!;
        } else if (parsed.entities.length > 0) {
          primaryStrategy = this.SEARCH_STRATEGIES.find((s) => s.type === 'semantic')!;
        } else {
          primaryStrategy = this.SEARCH_STRATEGIES.find((s) => s.type === 'keyword')!;
        }
        break;
    }

    // Determine fallback strategy
    if (primaryStrategy.type !== 'hybrid') {
      fallbackStrategy = this.SEARCH_STRATEGIES.find((s) => s.type === 'hybrid');
    } else {
      fallbackStrategy = this.SEARCH_STRATEGIES.find((s) => s.type === 'semantic');
    }

    return {
      primary: primaryStrategy,
      ...(fallbackStrategy && { fallback: fallbackStrategy }),
      alternatives: this.SEARCH_STRATEGIES.filter((s) => s !== primaryStrategy),
    };
  }

  /**
   * Execute the selected search strategy
   */
  private async executeSearch(context: SearchContext): Promise<SearchResultData> {
    const { parsed, originalQuery, strategy, startTime } = context;

    try {
      // Execute primary strategy
      const primaryResults = await this.executeStrategy(strategy.primary, parsed, originalQuery);

      if (primaryResults.results.length > 0 || !strategy.fallback) {
        return {
          results: primaryResults.results,
          totalCount: primaryResults.totalCount,
          strategy,
          executionTime: Date.now() - startTime,
          fallbackUsed: false,
          confidence: this.calculateConfidence(primaryResults.results, strategy.primary),
          metadata: {
            strategyUsed: strategy.primary.name,
            queryProcessed: parsed.cleaned,
            resultCount: primaryResults.results.length,
          },
        };
      }

      // Try fallback strategy if primary returned no results
      logger.warn(
        {
          primaryStrategy: strategy.primary.name,
          fallbackStrategy: strategy.fallback?.name,
          query: originalQuery.query,
        },
        'Primary strategy returned no results, trying fallback'
      );

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
          executionTime: Date.now() - startTime,
          fallbackUsed: true,
          confidence: this.calculateConfidence(fallbackResults.results, strategy.fallback),
          metadata: {
            strategyUsed: `${strategy.primary.name} -> ${strategy.fallback.name}`,
            queryProcessed: parsed.cleaned,
            resultCount: fallbackResults.results.length,
          },
        };
      }

      // No results from any strategy
      return {
        results: [],
        totalCount: 0,
        strategy,
        executionTime: Date.now() - startTime,
        fallbackUsed: true,
        confidence: 0,
        metadata: {
          strategyUsed: 'none',
          queryProcessed: parsed.cleaned,
          resultCount: 0,
        },
      };
    } catch (error) {
      logger.error({ error, strategy: strategy.primary.name }, 'Search strategy execution failed');
      throw error;
    }
  }

  /**
   * Execute a specific search strategy
   */
  private async executeStrategy(
    strategy: SearchStrategy,
    parsed: ParsedQuery,
    query: SmartFindRequest
  ): Promise<{ results: SearchResult[]; totalCount: number }> {
    const searchQuery: SearchQuery = {
      query: parsed.cleaned,
      ...(query.scope && { scope: query.scope }),
      ...(query.types && { types: query.types }),
      mode: 'auto',
      limit: strategy.limit || query.top_k || 50,
    };

    const options: SearchOptions = {
      includeMetadata: true,
      cache: true,
      ...(query.timeout_per_attempt_ms && { timeout: query.timeout_per_attempt_ms }),
    };

    switch (strategy.type) {
      case 'semantic':
        return await this.executeSemanticSearch(searchQuery, options, strategy.threshold);
      case 'keyword':
        return await this.executeKeywordSearch(searchQuery, options, strategy.threshold);
      case 'hybrid':
        return await this.executeHybridSearch(searchQuery, options, strategy.threshold);
      case 'fallback':
        return await this.executeFallbackSearch(searchQuery, options);
      default:
        throw new Error(`Unknown search strategy: ${strategy.type}`);
    }
  }

  /**
   * Execute semantic search using vector embeddings
   */
  private async executeSemanticSearch(
    query: SearchQuery,
    options: SearchOptions,
    threshold?: number
  ): Promise<{ results: SearchResult[]; totalCount: number }> {
    try {
      const response = await this.database.search(query, options);

      // Filter by confidence threshold
      const filteredResults = threshold
        ? response.results.filter((r) => r.confidence_score >= threshold!)
        : response.results;

      return {
        results: filteredResults,
        totalCount: filteredResults.length,
      };
    } catch (error) {
      logger.error({ error, query: query.query }, 'Semantic search failed');
      throw error;
    }
  }

  /**
   * Execute keyword search using traditional methods
   */
  private async executeKeywordSearch(
    query: SearchQuery,
    options: SearchOptions,
    threshold?: number
  ): Promise<{ results: SearchResult[]; totalCount: number }> {
    try {
      const response = await this.database.search(query, options);

      // Filter by confidence threshold
      const filteredResults = threshold
        ? response.results.filter((r) => r.confidence_score >= threshold!)
        : response.results;

      return {
        results: filteredResults,
        totalCount: filteredResults.length,
      };
    } catch (error) {
      logger.error({ error, query: query.query }, 'Keyword search failed');
      throw error;
    }
  }

  /**
   * Execute hybrid search combining vector and keyword search
   */
  private async executeHybridSearch(
    query: SearchQuery,
    options: SearchOptions,
    threshold?: number
  ): Promise<{ results: SearchResult[]; totalCount: number }> {
    try {
      // Use database's built-in hybrid search capabilities
      const response = await this.database.search(query, options);

      // Filter by confidence threshold
      const filteredResults = threshold
        ? response.results.filter((r) => r.confidence_score >= threshold!)
        : response.results;

      return {
        results: filteredResults,
        totalCount: filteredResults.length,
      };
    } catch (error) {
      logger.error({ error, query: query.query }, 'Hybrid search failed');
      throw error;
    }
  }

  /**
   * Execute fallback search with broadened criteria
   */
  private async executeFallbackSearch(
    query: SearchQuery,
    options: SearchOptions
  ): Promise<{ results: SearchResult[]; totalCount: number }> {
    try {
      // Broaden search criteria for fallback
      const broadenedQuery = {
        ...query,
        query: this.broadenQuery(query.query),
        limit: Math.min(query.limit || 25, 25), // Lower limit for fallback
      };

      const response = await this.database.search(broadenedQuery, options);

      return {
        results: response.results,
        totalCount: response.results.length,
      };
    } catch (error) {
      logger.error({ error, query: query.query }, 'Fallback search failed');
      throw error;
    }
  }

  /**
   * Rank and enhance search results
   */
  private rankResults(
    results: SearchResult[],
    query: SmartFindRequest,
    parsed: ParsedQuery
  ): SearchResult[] {
    // Step 1: Group chunked results by parent_id
    const groupedResults = this.resultGroupingService.groupAndSortResults(results);

    // Step 2: Process groups to create flattened results
    const processedResults: SearchResult[] = [];

    for (const group of groupedResults) {
      if (group.is_single_item) {
        // Single item - add as-is
        const originalResult = results.find((r) => r.id === group.parent_id);
        if (originalResult) {
          processedResults.push({
            ...originalResult,
            confidence_score: this.adjustConfidence(
              originalResult,
              query,
              parsed,
              processedResults.length
            ),
          });
        }
      } else {
        // Grouped chunks - create representative result
        const reconstructed = this.resultGroupingService.reconstructGroupedContent(group);

        // Use the highest scoring chunk as the representative, or create a synthetic result
        const representativeChunk = group.chunks.reduce((best, chunk) =>
          chunk.confidence_score > best.confidence_score ? chunk : best
        );

        // Create a reconstructed result
        const reconstructedResult: SearchResult = {
          ...representativeChunk,
          id: group.parent_id,
          data: {
            ...representativeChunk.data,
            content: reconstructed.content,
            is_reconstructed: true,
            original_chunks: group.chunks.length,
            completeness_ratio: reconstructed.completeness_ratio,
            parent_score: reconstructed.parent_score,
          },
          confidence_score: reconstructed.confidence_score,
        };

        processedResults.push({
          ...reconstructedResult,
          confidence_score: this.adjustConfidence(
            reconstructedResult,
            query,
            parsed,
            processedResults.length
          ),
        });
      }
    }

    return processedResults;
  }

  /**
   * Adjust confidence scores based on additional factors
   */
  private adjustConfidence(
    result: SearchResult,
    _query: SmartFindRequest,
    _parsed: ParsedQuery,
    index: number
  ): number {
    let adjustedScore = result.confidence_score;

    // Boost scores for exact matches
    if (result.match_type === 'exact') {
      adjustedScore += 0.1;
    }

    // Boost scores for recent items
    const itemDate = new Date(result.created_at);
    const daysSinceCreation = (Date.now() - itemDate.getTime()) / (1000 * 60 * 60 * 24);
    if (daysSinceCreation < 7) {
      adjustedScore += 0.05;
    }

    // Apply position-based adjustment
    if (index < 5) {
      adjustedScore += 0.02;
    }

    return Math.min(adjustedScore, 1.0);
  }

  /**
   * Build smart response with autonomous metadata
   */
  private buildSmartResponse(
    results: SearchResult[],
    searchResult: SearchResultData,
    query: SmartFindRequest
  ): SmartFindResult {
    const hits = results.map((result) => this.searchResultToHit(result));

    const _autonomousMetadata = {
      strategy_used: searchResult.metadata.strategyUsed,
      mode_requested: query.mode || 'auto',
      mode_executed: query.mode || 'auto',
      confidence: this.calculateOverallConfidence(hits),
      total_results: hits.length,
      avg_score: this.calculateAverageScore(hits),
      fallback_attempted: searchResult.fallbackUsed,
      recommendation: this.generateRecommendation(hits, searchResult),
      user_message_suggestion: this.generateUserMessage(hits, searchResult),
    };

    return {
      hits,
      suggestions: this.generateSuggestions(hits, query),
      autonomous_metadata: _autonomousMetadata,
      debug: {
        executionTime: searchResult.executionTime,
        strategyDetails: searchResult.strategy,
        queryProcessed: searchResult.metadata.queryProcessed,
      },
    };
  }

  /**
   * Convert search result to hit format
   */
  private searchResultToHit(result: SearchResult): any {
    return {
      kind: result.kind,
      id: result.id,
      title: this.extractTitle(result),
      snippet: this.extractSnippet(result),
      score: result.confidence_score,
      scope: result.scope,
      updated_at: result.created_at,
      route_used: 'qdrant_vector_search',
      confidence: result.confidence_score,
    };
  }

  /**
   * Extract title from search result
   */
  private extractTitle(result: SearchResult): string {
    const data = result.data;
    return data.title || data.name || `${result.kind} ${result.id.substring(0, 8)}`;
  }

  /**
   * Extract snippet from search result
   */
  private extractSnippet(result: SearchResult): string {
    const data = result.data;
    const content = data.content || data.description || data.rationale || '';
    return content.length > 200 ? `${content.substring(0, 200)}...` : content;
  }

  /**
   * Extract data from hit for legacy format
   */
  private extractDataFromHit(hit: any): Record<string, any> {
    return {
      title: hit.title,
      content: hit.snippet,
      kind: hit.kind,
      score: hit.score,
      confidence: hit.confidence,
    };
  }

  /**
   * Generate search suggestions
   */
  private generateSuggestions(hits: any[], _query: SmartFindRequest): string[] {
    const suggestions: string[] = [];

    if (hits.length === 0) {
      // Suggest alternative queries
      const baseSuggestions = [
        'Try different keywords',
        'Use broader search terms',
        'Check spelling',
      ];
      suggestions.push(...baseSuggestions);
    } else if (hits.length < 5) {
      suggestions.push('Try broader search terms for more results');
    }

    // Add kind-specific suggestions
    const kinds = [...new Set(hits.map((h) => h.kind))];
    if (kinds.length > 1) {
      suggestions.push(`Filter by specific type: ${kinds.join(', ')}`);
    }

    return suggestions;
  }

  /**
   * Calculate overall confidence
   */
  private calculateOverallConfidence(hits: any[]): 'high' | 'medium' | 'low' {
    if (hits.length === 0) return 'low';

    const avgConfidence = this.calculateAverageScore(hits);
    if (avgConfidence > 0.8) return 'high';
    if (avgConfidence > 0.6) return 'medium';
    return 'low';
  }

  /**
   * Calculate average score
   */
  private calculateAverageScore(hits: any[]): number {
    if (hits.length === 0) return 0;

    const totalScore = hits.reduce((sum, hit) => sum + hit.confidence, 0);
    return totalScore / hits.length;
  }

  /**
   * Generate recommendation
   */
  private generateRecommendation(hits: any[], searchResult: SearchResultData): string {
    if (hits.length === 0) {
      return searchResult.fallbackUsed
        ? 'Try different keywords or broader search terms'
        : 'No relevant items found - try refining your query';
    }

    const confidence = this.calculateOverallConfidence(hits);

    if (confidence === 'high' && hits.length >= 5) {
      return 'Good match! Found relevant items with high confidence';
    } else if (confidence === 'high') {
      return 'Found highly relevant items - consider broader terms for more results';
    } else if (confidence === 'medium') {
      return 'Found related items - try specific keywords for better matches';
    } else {
      return 'Limited matches found - try alternative search terms';
    }
  }

  /**
   * Generate user-friendly message
   */
  private generateUserMessage(hits: any[], searchResult: SearchResultData): string {
    if (hits.length === 0) {
      return `No results found using ${searchResult.metadata.strategyUsed} search strategy`;
    }

    const strategy = searchResult.metadata.strategyUsed;
    const confidence = this.calculateOverallConfidence(hits);

    let message = `Found ${hits.length} relevant items using ${strategy} search`;

    if (searchResult.fallbackUsed) {
      message += ' (with fallback strategy)';
    }

    if (confidence === 'high') {
      message += ' with high confidence';
    }

    return message;
  }

  /**
   * Extract keywords from query
   */
  private extractKeywords(query: string): string[] {
    // Simple keyword extraction - can be enhanced with NLP
    return query
      .split(/\s+/)
      .filter((word) => word.length > 2)
      .filter((word) => !this.isStopWord(word));
  }

  /**
   * Extract entities from query
   */
  private extractEntities(query: string): Array<{ text: string; type: string; position: number }> {
    // Simple entity extraction - can be enhanced with NLP
    const entities: Array<{ text: string; type: string; position: number }> = [];

    // Look for quoted phrases
    const quotedPhrases = query.match(/"([^"]+)"/g);
    if (quotedPhrases) {
      quotedPhrases.forEach((phrase, _index) => {
        const cleanPhrase = phrase.replace(/"/g, '');
        const position = query.indexOf(phrase);
        entities.push({
          text: cleanPhrase,
          type: 'phrase',
          position,
        });
      });
    }

    return entities;
  }

  /**
   * Detect search intent
   */
  private detectIntent(
    query: string,
    keywords: string[]
  ): 'search' | 'lookup' | 'browse' | 'unknown' {
    if (keywords.length === 1 && keywords[0].length < 10) {
      return 'lookup';
    }

    if (query.includes('list') || query.includes('show') || query.includes('all')) {
      return 'browse';
    }

    return 'search';
  }

  /**
   * Extract filters from query
   */
  private extractFilters(query: SmartFindRequest): Record<string, any> {
    const filters: Record<string, any> = {};

    if (query.types && query.types.length > 0) {
      filters.types = query.types;
    }

    if (query.scope) {
      filters.scope = query.scope;
    }

    return filters;
  }

  /**
   * Broaden query for fallback search
   */
  private broadenQuery(query: string): string {
    // Remove quotes, expand abbreviations, etc.
    return query
      .replace(/"/g, '')
      .replace(/\b(adr)\b/gi, 'architecture decision')
      .replace(/\b(pr)\b/gi, 'pull request');
  }

  /**
   * Check if word is a stop word
   */
  private isStopWord(word: string): boolean {
    const stopWords = [
      'the',
      'is',
      'at',
      'which',
      'on',
      'and',
      'or',
      'but',
      'in',
      'with',
      'for',
      'of',
      'to',
      'a',
      'an',
    ];
    return stopWords.includes(word.toLowerCase());
  }

  /**
   * Calculate confidence for search results
   */
  private calculateConfidence(results: SearchResult[], strategy: SearchStrategy): number {
    if (results.length === 0) return 0;

    const avgScore = results.reduce((sum, r) => sum + r.confidence_score, 0) / results.length;

    // Adjust based on strategy effectiveness
    const strategyMultiplier = {
      hybrid: 1.0,
      semantic: 0.95,
      keyword: 0.9,
      fallback: 0.8,
    };

    return avgScore * (strategyMultiplier[strategy.type] || 0.8);
  }

  /**
   * Create validation error response
   */
  private createValidationErrorResponse(errors: string[]): SmartFindResult {
    return {
      hits: [],
      suggestions: ['Check query format and try again'],
      autonomous_metadata: {
        strategy_used: 'fast',
        mode_requested: 'none',
        mode_executed: 'none',
        confidence: 'low',
        total_results: 0,
        avg_score: 0,
        fallback_attempted: false,
        recommendation: 'Fix query validation errors',
        user_message_suggestion: `Query validation failed: ${errors.join(', ')}`,
      },
      debug: {
        validationErrors: errors,
      },
    };
  }

  /**
   * Create error response
   */
  private createErrorResponse(error: any): SmartFindResult {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';

    return {
      hits: [],
      suggestions: ['Try again with different query'],
      autonomous_metadata: {
        strategy_used: 'deep',
        mode_requested: 'none',
        mode_executed: 'none',
        confidence: 'low',
        total_results: 0,
        avg_score: 0,
        fallback_attempted: false,
        recommendation: 'Check query format and system status',
        user_message_suggestion: `Search failed: ${errorMessage}`,
      },
      debug: {
        error: errorMessage,
        stack: error instanceof Error ? error.stack : undefined,
      },
    };
  }

  /**
   * Log search operation
   */
  private async logSearchOperation(
    query: SmartFindRequest,
    response: SmartFindResult,
    _executionTime: number
  ): Promise<void> {
    // await auditService.logSearchOperation(
    //   query.query,
    //   response.hits.length,
    //   response.autonomous_metadata.strategy_used,
    //   {
    //     strategy: response.autonomous_metadata.strategy_used,
    //     confidence: response.autonomous_metadata.confidence,
    //     fallback: response.autonomous_metadata.fallback_attempted,
    //   }
    // ); // REMOVED: audit-service deleted
    logger.debug(
      {
        query: query.query,
        resultsFound: response.hits.length,
        strategy: response.autonomous_metadata.strategy_used,
      },
      'Search operation (logging disabled)'
    );
  }

  /**
   * Ensure database is initialized
   */
  private async ensureDatabaseInitialized(): Promise<void> {
    try {
      const healthy = await this.database.healthCheck();
      if (!healthy) {
        throw new Error('Database health check failed');
      }
    } catch (error) {
      logger.error({ error }, 'Database initialization failed');
      throw new ConnectionError('Failed to initialize database', error as Error);
    }
  }

  /**
   * Get orchestrator statistics and capabilities
   */
  async getOrchestratorStats(): Promise<{
    supportedStrategies: string[];
    capabilities: string[];
    averageResponseTime: number;
  }> {
    return {
      supportedStrategies: this.SEARCH_STRATEGIES.map((s) => s.name),
      capabilities: [
        'semantic_vector_search',
        'keyword_search',
        'hybrid_search',
        'fallback_mechanism',
        'multi_strategy_selection',
        'confidence_scoring',
        'result_ranking',
        'autonomous_context_generation',
        'query_parsing',
        'scope_isolation',
        'result_grouping',
      ],
      averageResponseTime: 0, // Would need to track actual response times
    };
  }

  /**
   * Get access to the result grouping service (useful for testing and analysis)
   */
  getResultGroupingService(): ResultGroupingService {
    return this.resultGroupingService;
  }
}
