// @ts-nocheck
// @ts-ignore next import
import { logger } from '@/utils/logger.js';
import { qdrant } from '../../db/qdrant-client.js';
import { traverseGraph, enrichGraphNodes, type TraversalOptions } from '../graph-traversal.js';
import type { SearchQuery, SearchResult, MemoryFindResponse } from '../../types/core-interfaces.js';
import { queryParser, type ParsedQuery } from '../search/query-parser.js';
import { searchStrategySelector, type StrategySelection } from '../search/search-strategy.js';
import { searchService } from '../search/search-service.js';
import { entityMatchingService } from '../search/entity-matching-service.js';
import { resultRanker, type ResultRanker } from '../ranking/result-ranker.js';
import { auditService } from '../audit/audit-service.js';
import { structuredLogger } from '@/utils/logger.js';
import { SearchStrategy } from '@/types/core-interfaces.js'; // wherever the enum lives
import { OperationType } from '../../monitoring/operation-types.js';
import { generateCorrelationId } from '../../utils/correlation-id.js';
import { rateLimitMiddleware } from '../../middleware/rate-limit-middleware.js';
import type { AuthContext } from '../../types/auth-types.js';
import { createFindObservability } from '../../utils/observability-helper.js';

// Types are now imported from the actual service files

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
  private rateLimiter = rateLimitMiddleware.memoryFind();

  constructor(private _ranker: ResultRanker = resultRanker) {}

  /**
   * Map knowledge kinds to their corresponding Qdrant table names
   */
  private getTableNameForKind(kind: string): string | null {
    const kindToTableMap: Record<string, string> = {
      section: 'section',
      decision: 'adrDecision',
      issue: 'issueLog',
      todo: 'todoLog',
      runbook: 'runbook',
      change: 'changeLog',
      release_note: 'releaseNote',
      ddl: 'ddlHistory',
      pr_context: 'prContext',
      entity: 'knowledgeEntity',
      relation: 'knowledgeRelation',
      observation: 'knowledgeObservation',
      incident: 'incidentLog',
      release: 'releaseLog',
      risk: 'riskLog',
      assumption: 'assumptionLog',
    };

    return kindToTableMap[kind] || null;
  }

  /**
   * Query multiple knowledge tables based on types filter
   * Uses table-specific field mapping instead of universal data field
   */
  private async queryMultipleTables(
    types: string[],
    whereClause: any,
    select: any,
    orderBy?: any,
    take?: number
  ) {
    const results: any[] = [];
    let totalCount = 0;

    for (const kind of types) {
      const tableName = this.getTableNameForKind(kind);
      if (!tableName) continue;

      try {
        // Create table-specific where clause and select fields
        const tableSpecificWhere = this.buildTableSpecificWhereClause(tableName, whereClause, kind);
        const tableSpecificSelect = this.buildTableSpecificSelect(tableName, select, kind);

        const tableResults = await (qdrant as any)[tableName].findMany({
          where: tableSpecificWhere,
          select: tableSpecificSelect,
          orderBy: orderBy || { updated_at: 'desc' },
          take: take || 50,
        });

        const tableCount = await (qdrant as any)[tableName].count({
          where: tableSpecificWhere,
        });

        results.push(
          ...tableResults.map((result: any) => ({
            ...result,
            kind,
            created_at: result.created_at.toISOString(),
          }))
        );

        totalCount += tableCount;
      } catch (error) {
        logger.warn({ kind, tableName, error }, 'Failed to query table, skipping');
      }
    }

    return { results, totalCount };
  }

  /**
   * Build table-specific WHERE clause based on table structure
   */
  private buildTableSpecificWhereClause(
    tableName: string,
    baseWhereClause: any,
    _kind: string
  ): any {
    const whereClause = { ...baseWhereClause };

    // Convert universal data field searches to table-specific field searches
    if (whereClause.OR && Array.isArray(whereClause.OR)) {
      const searchFields = this.getSearchableFields(tableName);
      const tableSpecificOR = [];

      for (const orCondition of whereClause.OR) {
        if (orCondition.data && orCondition.data.path && orCondition.data.string_contains) {
          const searchTerm = orCondition.data.string_contains;

          // Create OR conditions for all searchable fields in this table
          const fieldConditions = searchFields.map((field) => ({
            [field]: { contains: searchTerm, mode: 'insensitive' },
          }));

          tableSpecificOR.push(...fieldConditions);
        } else {
          // Keep non-data OR conditions as-is
          tableSpecificOR.push(orCondition);
        }
      }

      if (tableSpecificOR.length > 0) {
        whereClause.OR = tableSpecificOR;
      } else {
        delete whereClause.OR;
      }
    }

    // Remove the data field references that don't exist in the schema
    delete whereClause.data;

    return whereClause;
  }

  /**
   * Build table-specific SELECT fields based on table structure
   */
  private buildTableSpecificSelect(tableName: string, _baseSelect: any, _kind: string): any {
    // For tables with knowledge structure, use tags and metadata
    if (
      [
        'section',
        'adrDecision',
        'issueLog',
        'todoLog',
        'runbook',
        'changeLog',
        'releaseNote',
        'ddlHistory',
        'prContext',
        'incidentLog',
        'releaseLog',
        'riskLog',
        'assumptionLog',
      ].includes(tableName)
    ) {
      return {
        id: true,
        tags: true, // Scope data is stored in tags field
        created_at: true,
        updated_at: true,
        // Add table-specific fields
        ...this.getTableSpecificFields(tableName),
      };
    }

    // For knowledge entity tables
    if (tableName === 'knowledgeEntity') {
      return {
        id: true,
        entity_type: true,
        name: true,
        tags: true,
        created_at: true,
        updated_at: true,
      };
    }

    // For knowledge relation tables
    if (tableName === 'knowledgeRelation') {
      return {
        id: true,
        from_entity_type: true,
        from_entity_id: true,
        to_entity_type: true,
        to_entity_id: true,
        relation_type: true,
        tags: true,
        created_at: true,
        updated_at: true,
      };
    }

    // Default select
    return {
      id: true,
      tags: true,
      created_at: true,
      updated_at: true,
    };
  }

  /**
   * Get searchable fields for each table type
   */
  private getSearchableFields(tableName: string): string[] {
    const fieldMap: Record<string, string[]> = {
      section: ['title', 'content', 'heading', 'body_md', 'body_text'],
      adrDecision: ['title', 'rationale', 'component'],
      issueLog: ['title', 'description', 'status', 'tracker'],
      todoLog: ['title', 'description', 'status', 'text'],
      runbook: ['title', 'description', 'service'],
      changeLog: ['change_type', 'subject_ref', 'summary', 'author'],
      releaseNote: ['version', 'summary'],
      ddlHistory: ['migration_id', 'description', 'status'],
      prContext: ['title', 'description', 'author', 'status'],
      incidentLog: ['title', 'severity', 'impact', 'resolution_status'],
      releaseLog: ['version', 'release_type', 'scope', 'status'],
      riskLog: ['title', 'category', 'risk_level', 'impact_description'],
      assumptionLog: ['title', 'description', 'category', 'validation_status'],
      knowledgeEntity: ['name', 'entity_type'],
      knowledgeRelation: ['relation_type'],
    };

    return fieldMap[tableName] || ['title', 'description'];
  }

  /**
   * Get table-specific fields for SELECT
   */
  private getTableSpecificFields(tableName: string): any {
    const fieldMap: Record<string, any> = {
      section: { title: true, content: true, heading: true },
      adrDecision: { title: true, rationale: true, component: true },
      issueLog: { title: true, description: true, status: true },
      todoLog: { title: true, description: true, status: true },
      runbook: { title: true, description: true, service: true },
      changeLog: { change_type: true, summary: true, author: true },
      releaseNote: { version: true, summary: true },
      ddlHistory: { migration_id: true, description: true },
      prContext: { title: true, description: true, author: true },
      incidentLog: { title: true, severity: true, impact: true },
      releaseLog: { version: true, release_type: true, scope: true },
      riskLog: { title: true, category: true, risk_level: true },
      assumptionLog: { title: true, description: true, category: true },
    };

    return fieldMap[tableName] || {};
  }

  /**
   * Main entry point for memory find operations
   */
  async findItems(query: SearchQuery, authContext?: AuthContext): Promise<MemoryFindResponse> {
    const startTime = Date.now();
    const correlationId = generateCorrelationId();

    try {
      // Check rate limits
      const rateLimitResult = await this.rateLimiter.checkOrchestratorRateLimit(
        authContext,
        OperationType.MEMORY_FIND,
        1 // Each search counts as one token
      );

      if (!rateLimitResult.allowed) {
        const latency = Date.now() - startTime;

        // Log rate limit violation
        structuredLogger.logRateLimit(
          correlationId,
          latency,
          false,
          authContext?.apiKeyId || 'anonymous',
          'api_key',
          OperationType.MEMORY_FIND,
          1,
          rateLimitResult.error?.error || 'rate_limit_exceeded'
        );

        return {
          results: [],
          total_count: 0,
          items: [],
          autonomous_context: {
            search_mode_used: 'rate_limited',
            results_found: 0,
            confidence_average: 0,
            user_message_suggestion: 'Rate limit exceeded. Please try again later.',
          },
          observability: createFindObservability(
            'fallback',
            false, // vector_used - no vectors used in rate limit error
            true, // degraded - rate limit is degraded state
            Date.now() - startTime,
            0
          ),
          meta: {
            strategy: 'rate_limited',
            vector_used: false,
            degraded: true,
            source: 'memory-find-orchestrator',
            execution_time_ms: Date.now() - startTime,
            confidence_score: 0,
            truncated: false,
          },
        };
      }

      logger.info({ query: query.query, mode: query.mode }, 'Memory find operation started');

      // Step 1: Parse and validate query
      const parsedResult = queryParser.parseQuery(query);
      const parsed = (parsedResult as any).parsed ?? parsedResult;
      const validation = (parsedResult as any).validation;
      if (!validation.valid) {
        return this.createValidationErrorResponse(validation.errors);
      }

      const context: SearchContext = {
        originalQuery: query,
        parsed,
        strategy: (searchStrategySelector as any).selectStrategy(query, parsed),
        startTime,
      };

      // Step 2: Execute search strategy
      const searchResult = await this.executeSearch(context);

      // Step 3: Rank results
      const rankedResults = this._ranker.rankResults(searchResult.results, query, parsed);

      // Step 4: Build response
      const response = this.buildResponse(rankedResults, searchResult);

      // Step 5: Log operation
      await this.logSearchOperation(query, response, Date.now() - startTime);

      // Log successful operation with structured logger
      const latencyMs = Date.now() - startTime;
      const strategyName = searchResult.strategy.primary.name as SearchStrategy;

      structuredLogger.logMemoryFind(
        correlationId,
        latencyMs,
        true,
        strategyName,
        response.results.length,
        response.total_count,
        undefined,
        {
          query: query.query,
          mode: query.mode,
          limit: query.limit,
          types: query.types,
          scope: query.scope,
          expand: query.expand,
        }
      );

      logger.info(
        {
          resultCount: response.results.length,
          executionTime: latencyMs,
          strategy: searchResult.strategy.primary.name,
        },
        'Memory find operation completed'
      );

      return response;
    } catch (error) {
      const latencyMs = Date.now() - startTime;

      // Log operation failure
      structuredLogger.logMemoryFind(
        correlationId,
        latencyMs,
        false,
        SearchStrategy.ERROR,
        0,
        0,
        undefined,
        {
          query: query.query,
          mode: query.mode,
          limit: query.limit,
          types: query.types,
          scope: query.scope,
          expand: query.expand,
        },
        error instanceof Error ? error : new Error('Unknown search error')
      );

      logger.error({ error, query }, 'Memory find operation failed');

      // Log error
      await auditService.logError(error instanceof Error ? error : new Error('Unknown error'), {
        operation: 'memory_find',
        query: query.query,
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
      const primaryResults = await this.executeStrategy(strategy.primary, parsed, originalQuery);

      if (primaryResults.results.length > 0 || !strategy.fallback) {
        return {
          results: primaryResults.results,
          totalCount: primaryResults.totalCount,
          strategy,
          executionTime: Date.now() - context.startTime,
          fallbackUsed: false,
        };
      }

      // Try fallback strategy if primary returned no results
      logger.warn(
        {
          primaryStrategy: strategy.primary.name,
          fallbackStrategy: strategy.fallback?.name,
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
          executionTime: Date.now() - context.startTime,
          fallbackUsed: true,
        };
      }

      return {
        results: [],
        totalCount: 0,
        strategy,
        executionTime: Date.now() - context.startTime,
        fallbackUsed: false,
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
            fallbackUsed: true,
          };
        } catch (fallbackError) {
          logger.error(
            { fallbackError, strategy: strategy.fallback.name },
            'Fallback strategy also failed'
          );
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
    // Build search query for table-specific fields
    const whereClause: any = {
      OR: [],
    };

    // Add search conditions for each term
    for (const term of parsed.terms) {
      if (term.length > 2) {
        // Skip very short terms
        whereClause.OR.push(
          { data: { path: ['title'], string_contains: term } },
          { data: { path: ['name'], string_contains: term } },
          { data: { path: ['description'], string_contains: term } },
          { data: { path: ['content'], string_contains: term } },
          { data: { path: ['summary'], string_contains: term } }
        );
      }
    }

    // Add type filters
    if (query.types && query.types.length > 0) {
      whereClause.kind = { in: query.types };
    }

    // Add scope filters using tags field (since scope_* columns don't exist)
    if (query.scope) {
      const scopeConditions = [];
      if (query.scope.project) {
        scopeConditions.push({
          tags: { path: ['project'], equals: query.scope.project },
        });
      }
      if (query.scope.branch) {
        scopeConditions.push({
          tags: { path: ['branch'], equals: query.scope.branch },
        });
      }
      if (query.scope.org) {
        scopeConditions.push({
          tags: { path: ['org'], equals: query.scope.org },
        });
      }

      if (scopeConditions.length > 0) {
        whereClause.AND = whereClause.AND || [];
        whereClause.AND.push({ AND: scopeConditions });
      }
    }

    const types =
      query.types && query.types.length > 0
        ? query.types
        : Object.keys({
            section: 'section',
            decision: 'adrDecision',
            issue: 'issueLog',
            todo: 'todoLog',
            runbook: 'runbook',
            change: 'changeLog',
            release_note: 'releaseNote',
            ddl: 'ddlHistory',
            pr_context: 'prContext',
            entity: 'knowledgeEntity',
            relation: 'knowledgeRelation',
            observation: 'knowledgeObservation',
            incident: 'incidentLog',
            release: 'releaseLog',
            risk: 'riskLog',
            assumption: 'assumptionLog',
          });

    const selectFields = {
      id: true,
      tags: true, // Scope data is stored in tags field
      created_at: true,
      updated_at: true,
    };

    const { results, totalCount } = await this.queryMultipleTables(
      types,
      whereClause,
      selectFields,
      { updated_at: 'desc' },
      query.limit || 50
    );

    return {
      results: results.map((row) => this.mapRowToSearchResult(row, 0.8)), // Base confidence score
      totalCount,
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
      this.executeSemanticSearch(parsed, query),
    ]);

    // Merge and deduplicate results
    const mergedResults = this.mergeResults(fulltextResults.results, semanticResults.results);

    return {
      results: mergedResults,
      totalCount: Math.max(fulltextResults.totalCount, semanticResults.totalCount),
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

    for (const entity of entityMatches.slice(0, 5)) {
      // Limit to prevent explosion
      const traversalOptions: TraversalOptions = {
        depth: 2,
        direction: 'both',
      };

      const graphResult = await traverseGraph(entity.kind, entity.id, traversalOptions);

      // Enrich graph nodes with data
      const enrichedNodes = await enrichGraphNodes(graphResult.nodes);

      // Convert to search results
      const searchResults = enrichedNodes.map((node) => {
        const nodeData = node.data as any;
        const tags = nodeData?.tags || {};
        return {
          id: node.entity_id,
          kind: node.entity_type,
          scope: {
            project: tags.project,
            branch: tags.branch,
            org: tags.org,
          },
          data: nodeData || {},
          created_at:
            typeof nodeData?.created_at === 'string'
              ? nodeData.created_at
              : new Date().toISOString(),
          confidence_score: 0.7, // Base confidence for graph traversal
          match_type: 'semantic' as const,
        };
      });

      allResults.push(...searchResults);
      totalCount += searchResults.length;
    }

    return {
      results: allResults,
      totalCount,
    };
  }

  /**
   * Execute fallback search using enhanced service layer with hybrid degrade
   */
  private async executeFallbackSearch(
    parsed: ParsedQuery,
    query: SearchQuery
  ): Promise<{ results: SearchResult[]; totalCount: number }> {
    logger.info(
      { query: query.query },
      'Executing hybrid degrade search using enhanced service layer'
    );

    try {
      // Use the enhanced search service for hybrid degrade search
      const searchResult = await searchService.performFallbackSearch(parsed, query);

      // Log quality metrics for monitoring
      const p95Metrics = searchService.getP95QualityMetrics();
      logger.info(
        {
          query: query.query,
          resultsCount: searchResult.results.length,
          strategy: 'hybrid_degrade',
          qualityMetrics: p95Metrics,
        },
        'Hybrid degrade search completed with quality metrics'
      );

      return {
        results: searchResult.results,
        totalCount: searchResult.totalCount,
      };
    } catch (error) {
      logger.error({ error, query: query.query }, 'Hybrid degrade search service failed');

      // Final fallback to basic keyword search
      logger.info({ query: query.query }, 'Attempting final fallback to basic keyword search');
      return await this.executeFulltextSearch(parsed, query);
    }
  }

  /**
   * Find entities matching the query terms using service layer
   */
  private async findEntityMatches(
    parsed: ParsedQuery,
    query: SearchQuery
  ): Promise<{ id: string; kind: string }[]> {
    logger.info({ query: query.query }, 'Finding entity matches using service layer');

    try {
      // Use the entity matching service for entity resolution
      return await entityMatchingService.findEntityMatches(parsed, query);
    } catch (error) {
      logger.error({ error, query: query.query }, 'Entity matching service failed');
      return [];
    }
  }

  /**
   * Merge and deduplicate results from multiple searches
   */
  private mergeResults(results1: SearchResult[], results2: SearchResult[]): SearchResult[] {
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
   * Normalizes table-specific fields to a consistent data structure
   */
  private mapRowToSearchResult(row: any, baseConfidence: number): SearchResult {
    // Extract scope data from tags field (where it's actually stored)
    const tags = row.tags || {};

    // Normalize table-specific fields to a consistent data structure
    const normalizedData = this.normalizeTableData(row);

    return {
      id: row.id,
      kind: row.kind,
      scope: {
        project: tags.project,
        branch: tags.branch,
        org: tags.org,
      },
      data: normalizedData,
      created_at: row.created_at?.toISOString() || new Date().toISOString(),
      confidence_score: baseConfidence,
      match_type: 'exact' as const,
    };
  }

  /**
   * Normalize table-specific data to consistent structure
   */
  private normalizeTableData(row: any): any {
    const tableName = this.getTableNameForKind(row.kind);

    switch (tableName) {
      case 'section':
        return {
          title: row.title,
          content: row.content,
          heading: row.heading,
          body_md: row.body_md,
          body_text: row.body_text,
        };

      case 'adrDecision':
        return {
          title: row.title,
          rationale: row.rationale,
          component: row.component,
          status: row.status,
        };

      case 'issueLog':
        return {
          title: row.title,
          description: row.description,
          status: row.status,
          severity: row.severity,
        };

      case 'todoLog':
        return {
          title: row.title,
          description: row.description,
          status: row.status,
          priority: row.priority,
        };

      case 'runbook':
        return {
          title: row.title,
          description: row.description,
          service: row.service,
        };

      case 'changeLog':
        return {
          title: row.subject_ref,
          description: row.summary,
          change_type: row.change_type,
          author: row.author,
        };

      case 'releaseNote':
        return {
          title: row.version,
          description: row.summary,
        };

      case 'ddlHistory':
        return {
          title: row.migration_id,
          description: row.description,
          status: row.status,
        };

      case 'prContext':
        return {
          title: row.title,
          description: row.description,
          author: row.author,
          status: row.status,
        };

      case 'incidentLog':
        return {
          title: row.title,
          description: row.impact,
          severity: row.severity,
          status: row.resolution_status,
        };

      case 'releaseLog':
        return {
          title: row.version,
          description: row.scope,
          release_type: row.release_type,
          status: row.status,
        };

      case 'riskLog':
        return {
          title: row.title,
          description: row.impact_description,
          category: row.category,
          risk_level: row.risk_level,
        };

      case 'assumptionLog':
        return {
          title: row.title,
          description: row.description,
          category: row.category,
          validation_status: row.validation_status,
        };

      case 'knowledgeEntity':
        return {
          name: row.name,
          entity_type: row.entity_type,
        };

      case 'knowledgeRelation':
        return {
          relation_type: row.relation_type,
          from_entity_type: row.from_entity_type,
          to_entity_type: row.to_entity_type,
        };

      default:
        return {
          title: row.title || row.name || 'Unknown',
          description: row.description || row.content || '',
        };
    }
  }

  /**
   * Build final response with enhanced metadata
   */
  private buildResponse(
    rankedResults: any[],
    searchResult: SearchExecutionResult
  ): MemoryFindResponse {
    const startTime = Date.now();
    // Convert ranked results back to SearchResult format
    const results = rankedResults.map((rr) => ({
      id: rr.id,
      kind: rr.kind,
      scope: rr.scope,
      data: rr.data,
      created_at: rr.created_at,
      confidence_score: rr.boostedScore,
      match_type: rr.match_type,
    }));

    const averageConfidence =
      results.length > 0
        ? results.reduce((sum, r) => sum + r.confidence_score, 0) / results.length
        : 0;

    const strategyUsed = searchResult.strategy.primary?.name || searchResult.strategy;
    const fallbackUsed = searchResult.fallbackUsed;
    const degraded = fallbackUsed || searchResult.executionTime > 3000; // Consider slow responses as degraded

    return {
      results,
      items: results,
      total_count: searchResult.totalCount,
      autonomous_context: {
        search_mode_used: String(strategyUsed),
        results_found: results.length,
        confidence_average: averageConfidence,
        user_message_suggestion: this.generateUserMessage(results, searchResult),
      },
      observability: createFindObservability(
        strategyUsed as any,
        String(strategyUsed).includes('semantic') || String(strategyUsed).includes('hybrid'),
        degraded,
        Date.now() - startTime,
        averageConfidence
      ),
      meta: {
        strategy: String(strategyUsed),
        vector_used:
          String(strategyUsed).includes('semantic') || String(strategyUsed).includes('hybrid'),
        degraded,
        source: 'memory-find-orchestrator',
        execution_time_ms: Date.now() - startTime,
        confidence_score: averageConfidence,
        truncated: false,
      },
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
    const startTime = Date.now();
    return {
      results: [],
      items: [],
      total_count: 0,
      autonomous_context: {
        search_mode_used: 'validation_failed',
        results_found: 0,
        confidence_average: 0,
        user_message_suggestion: `❌ Invalid query: ${errors.join(', ')}`,
      },
      observability: createFindObservability('error', false, true, Date.now() - startTime, 0),
      meta: {
        strategy: 'validation_failed',
        vector_used: false,
        degraded: true,
        source: 'memory-find-orchestrator',
        execution_time_ms: Date.now() - startTime,
        confidence_score: 0,
        truncated: false,
      },
    };
  }

  /**
   * Create error response
   */
  private createErrorResponse(_error: any): MemoryFindResponse {
    const startTime = Date.now();
    return {
      results: [],
      items: [],
      total_count: 0,
      autonomous_context: {
        search_mode_used: 'validation_failed',
        results_found: 0,
        confidence_average: 0,
        user_message_suggestion: `❌ Search error: ${_error?.message || 'Unknown error'}`,
      },
      observability: createFindObservability(
        'error',
        false, // vector_used - no vectors used in validation error
        true, // degraded - validation error is degraded state
        Date.now() - startTime,
        0
      ),
      meta: {
        strategy: 'validation_failed',
        vector_used: false,
        degraded: true,
        source: 'memory-find-orchestrator',
        execution_time_ms: Date.now() - startTime,
        confidence_score: 0,
        truncated: false,
      },
    };
  }
}

// Export singleton instance
export const memoryFindOrchestrator = new MemoryFindOrchestrator();
