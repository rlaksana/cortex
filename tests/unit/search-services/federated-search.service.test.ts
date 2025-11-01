/**
 * Comprehensive Unit Tests for Federated Search Service
 *
 * Tests advanced federated search functionality including:
 * - Multi-source integration with heterogeneous data handling
 * - Result aggregation with intelligent merging and deduplication
 * - Query distribution with intelligent routing and parallel execution
 * - Performance optimization with distributed processing and caching
 * - Source management with dynamic registration and health monitoring
 * - Integration and coordination with cross-service communication
 * - Distributed transaction handling and consistency management
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import type {
  SearchQuery,
  SearchResult,
  MemoryFindResponse
} from '../../../src/types/core-interfaces';

// Mock federated search service interfaces
interface FederatedSearchService {
  /**
   * Perform federated search across multiple data sources
   */
  performFederatedSearch(query: FederatedSearchQuery): Promise<FederatedSearchResult>;

  /**
   * Register a new data source in the federation
   */
  registerDataSource(source: DataSource): Promise<DataSourceRegistration>;

  /**
   * Aggregate results from multiple sources with intelligent merging
   */
  aggregateResults(sourceResults: SourceSearchResult[]): Promise<AggregatedResult>;

  /**
   * Distribute query across multiple sources with optimization
   */
  distributeQuery(query: SearchQuery, sources: DataSource[]): Promise<QueryDistribution>;

  /**
   * Monitor health of federated sources
   */
  monitorSourceHealth(): Promise<SourceHealthReport>;

  /**
   * Handle failover scenarios
   */
  handleFailover(failedSources: string[]): Promise<FailoverResponse>;

  /**
   * Optimize federated search performance
   */
  optimizeFederatedSearch(query: SearchQuery): Promise<SearchOptimization>;

  /**
   * Coordinate distributed transactions
   */
  coordinateDistributedTransaction(operations: DistributedOperation[]): Promise<TransactionResult>;

  /**
   * Manage source capabilities and negotiation
   */
  negotiateSourceCapabilities(sources: DataSource[]): Promise<CapabilityNegotiation>;
}

// Supporting interfaces for federated search
interface FederatedSearchQuery extends SearchQuery {
  sources?: string[];
  aggregationStrategy: AggregationStrategy;
  distributionMode: DistributionMode;
  failoverStrategy: FailoverStrategy;
  performanceProfile: PerformanceProfile;
}

interface FederatedSearchResult {
  results: SearchResult[];
  sourceAttribution: SourceAttribution[];
  aggregationMetadata: AggregationMetadata;
  performanceMetrics: PerformanceMetrics;
  sourceHealth: SourceHealthStatus;
  transactionId: string;
}

interface DataSource {
  id: string;
  name: string;
  type: SourceType;
  endpoint: string;
  capabilities: SourceCapabilities;
  healthStatus: HealthStatus;
  performanceProfile: SourcePerformanceProfile;
  authentication: AuthenticationConfig;
  priority: number;
  timeout: number;
}

interface SourceSearchResult {
  sourceId: string;
  sourceName: string;
  results: SearchResult[];
  processingTime: number;
  metadata: SourceResultMetadata;
  confidence: number;
}

interface AggregatedResult {
  mergedResults: SearchResult[];
  deduplicationStats: DeduplicationStats;
  rankingMetadata: RankingMetadata;
  sourceContribution: SourceContribution[];
  qualityMetrics: QualityMetrics;
}

interface QueryDistribution {
  distributedQueries: DistributedQuery[];
  parallelizationStrategy: ParallelizationStrategy;
  loadBalancing: LoadBalancingConfig;
  optimizationHints: OptimizationHints;
  estimatedTotalTime: number;
}

interface SourceHealthReport {
  overallHealth: HealthStatus;
  sourceStatuses: Record<string, SourceStatus>;
  performanceMetrics: Record<string, SourcePerformanceMetrics>;
  recommendations: HealthRecommendation[];
}

interface FailoverResponse {
  activatedSources: string[];
  reroutedQueries: string[];
  performanceImpact: PerformanceImpact;
  recoveryStatus: RecoveryStatus;
}

interface SearchOptimization {
  optimizedQuery: SearchQuery;
  optimizationStrategies: OptimizationStrategy[];
  performanceGains: PerformanceGains;
  cacheHits: CacheHit[];
  parallelizationPlan: ParallelizationPlan;
}

interface DistributedOperation {
  operationId: string;
  sourceId: string;
  operation: Operation;
  dependencies: string[];
  rollbackOperation: Operation;
}

interface TransactionResult {
  transactionId: string;
  status: TransactionStatus;
  results: OperationResult[];
  rollbackLog: RollbackLog;
  consistencyCheck: ConsistencyCheck;
}

interface CapabilityNegotiation {
  negotiatedCapabilities: Record<string, SourceCapabilities>;
  compatibilityMatrix: CompatibilityMatrix;
  optimizedQueries: Record<string, SearchQuery>;
  fallbackOptions: FallbackOptions;
}

// Enum definitions
enum AggregationStrategy {
  MERGE_AND_RANK = 'merge_and_rank',
  DEDUPLICATE_AND_BOOST = 'deduplicate_and_boost',
  WEIGHTED_AVERAGE = 'weighted_average',
  SOURCE_SPECIFIC = 'source_specific',
  CONSENSUS_BASED = 'consensus_based'
}

enum DistributionMode {
  PARALLEL = 'parallel',
  SEQUENTIAL = 'sequential',
  ADAPTIVE = 'adaptive',
  PRIORITY_BASED = 'priority_based',
  LOAD_BALANCED = 'load_balanced'
}

enum FailoverStrategy {
  IMMEDIATE = 'immediate',
  GRACEFUL = 'graceful',
  DEGRADED = 'degraded',
  CIRCUIT_BREAKER = 'circuit_breaker',
  CUSTOM = 'custom'
}

enum PerformanceProfile {
  FAST = 'fast',
  BALANCED = 'balanced',
  COMPREHENSIVE = 'comprehensive',
  REAL_TIME = 'real_time',
  BATCH = 'batch'
}

enum SourceType {
  KNOWLEDGE_BASE = 'knowledge_base',
  DOCUMENT_STORE = 'document_store',
  DATABASE = 'database',
  SEARCH_ENGINE = 'search_engine',
  API_ENDPOINT = 'api_endpoint',
  FILE_SYSTEM = 'file_system',
  EXTERNAL_SERVICE = 'external_service'
}

enum HealthStatus {
  HEALTHY = 'healthy',
  DEGRADED = 'degraded',
  UNHEALTHY = 'unhealthy',
  MAINTENANCE = 'maintenance',
  UNKNOWN = 'unknown'
}

// Mock implementation of FederatedSearchService
class MockFederatedSearchService implements FederatedSearchService {
  private registeredSources = new Map<string, DataSource>();
  private healthCache = new Map<string, SourceStatus>();
  private queryCache = new Map<string, FederatedSearchResult>();

  async performFederatedSearch(query: FederatedSearchQuery): Promise<FederatedSearchResult> {
    const transactionId = this.generateTransactionId();
    const startTime = Date.now();

    // Determine sources to query
    const sources = this.selectSources(query.sources);
    const distributedQuery = await this.distributeQuery(query, sources);

    // Execute queries in parallel or based on distribution mode
    const sourceResults = await this.executeQueryDistribution(distributedQuery);

    // Aggregate results
    const aggregatedResult = await this.aggregateResults(sourceResults);

    // Generate attribution and metadata
    const sourceAttribution = this.generateSourceAttribution(sourceResults);
    const aggregationMetadata = this.generateAggregationMetadata(aggregatedResult, sourceResults);
    const performanceMetrics = this.generatePerformanceMetrics(startTime, sourceResults);

    // Monitor source health
    const sourceHealth = await this.monitorSourceHealth();

    const result: FederatedSearchResult = {
      results: aggregatedResult.mergedResults,
      sourceAttribution,
      aggregationMetadata,
      performanceMetrics,
      sourceHealth,
      transactionId
    };

    // Cache result
    this.queryCache.set(this.generateCacheKey(query), result);

    return result;
  }

  async registerDataSource(source: DataSource): Promise<DataSourceRegistration> {
    this.registeredSources.set(source.id, source);

    const registration: DataSourceRegistration = {
      sourceId: source.id,
      registrationTime: new Date().toISOString(),
      status: 'active',
      capabilities: source.capabilities,
      healthCheck: await this.performHealthCheck(source.id)
    };

    return registration;
  }

  async aggregateResults(sourceResults: SourceSearchResult[]): Promise<AggregatedResult> {
    const allResults = sourceResults.flatMap(sr => sr.results);

    // Deduplicate results based on content similarity
    const deduplicatedResults = this.deduplicateResults(allResults);

    // Rank results across sources
    const rankedResults = this.rankResultsAcrossSources(deduplicatedResults, sourceResults);

    // Calculate source contribution
    const sourceContribution = this.calculateSourceContribution(rankedResults, sourceResults);

    // Generate quality metrics
    const qualityMetrics = this.calculateQualityMetrics(rankedResults, sourceResults);

    return {
      mergedResults: rankedResults,
      deduplicationStats: this.calculateDeduplicationStats(allResults, rankedResults),
      rankingMetadata: this.generateRankingMetadata(rankedResults),
      sourceContribution,
      qualityMetrics
    };
  }

  async distributeQuery(query: SearchQuery, sources: DataSource[]): Promise<QueryDistribution> {
    const distributedQueries: DistributedQuery[] = [];

    // Create source-specific query adaptations
    for (const source of sources) {
      const adaptedQuery = this.adaptQueryForSource(query, source);
      distributedQueries.push({
        sourceId: source.id,
        adaptedQuery,
        estimatedTime: source.performanceProfile.averageResponseTime,
        priority: source.priority,
        dependencies: []
      });
    }

    // Determine parallelization strategy
    const parallelizationStrategy = this.determineParallelizationStrategy(sources);

    // Configure load balancing
    const loadBalancing = this.configureLoadBalancing(sources);

    // Generate optimization hints
    const optimizationHints = this.generateOptimizationHints(query, sources);

    return {
      distributedQueries,
      parallelizationStrategy,
      loadBalancing,
      optimizationHints,
      estimatedTotalTime: this.calculateEstimatedTotalTime(distributedQueries)
    };
  }

  async monitorSourceHealth(): Promise<SourceHealthReport> {
    const sourceStatuses: Record<string, SourceStatus> = {};
    const performanceMetrics: Record<string, SourcePerformanceMetrics> = {};
    const recommendations: HealthRecommendation[] = [];

    for (const [sourceId, source] of this.registeredSources) {
      const healthStatus = await this.performHealthCheck(sourceId);
      sourceStatuses[sourceId] = healthStatus;

      if (healthStatus.metrics) {
        performanceMetrics[sourceId] = healthStatus.metrics;
      }

      if (healthStatus.status === HealthStatus.UNHEALTHY || healthStatus.status === HealthStatus.DEGRADED) {
        recommendations.push({
          sourceId,
          type: healthStatus.status === HealthStatus.UNHEALTHY ? 'failover' : 'optimize',
          message: healthStatus.message || 'Source health check failed',
          priority: healthStatus.status === HealthStatus.UNHEALTHY ? 'high' : 'medium'
        });
      }
    }

    const overallHealth = this.calculateOverallHealth(Object.values(sourceStatuses));

    return {
      overallHealth,
      sourceStatuses,
      performanceMetrics,
      recommendations
    };
  }

  async handleFailover(failedSources: string[]): Promise<FailoverResponse> {
    const activatedSources: string[] = [];
    const reroutedQueries: string[] = [];

    // Find alternative sources
    for (const failedSourceId of failedSources) {
      const alternatives = this.findAlternativeSources(failedSourceId);
      for (const alternative of alternatives) {
        activatedSources.push(alternative.id);
        this.registeredSources.get(alternative.id)!.priority += 1; // Boost priority
      }
    }

    // Calculate performance impact
    const performanceImpact = this.calculatePerformanceImpact(failedSources, activatedSources);

    return {
      activatedSources,
      reroutedQueries,
      performanceImpact,
      recoveryStatus: {
        status: 'in_progress',
        estimatedRecoveryTime: performanceImpact.estimatedRecoveryTime,
        actions: ['Source re-routing completed', 'Priority adjustments applied']
      }
    };
  }

  async optimizeFederatedSearch(query: SearchQuery): Promise<SearchOptimization> {
    const optimizationStrategies: OptimizationStrategy[] = [];
    const cacheHits: CacheHit[] = [];
    const startTime = Date.now();

    // Check cache
    const cacheKey = this.generateCacheKey(query);
    if (this.queryCache.has(cacheKey)) {
      cacheHits.push({
        key: cacheKey,
        hitTime: Date.now() - startTime,
        resultCount: this.queryCache.get(cacheKey)!.results.length
      });
    }

    // Analyze query for optimization opportunities
    if (query.query.length > 100) {
      optimizationStrategies.push({
        type: 'query_simplification',
        description: 'Simplify complex query for better performance',
        expectedGain: 0.3
      });
    }

    if (!query.types || query.types.length === 0) {
      optimizationStrategies.push({
        type: 'type_filtering',
        description: 'Add knowledge type filters for better results',
        expectedGain: 0.2
      });
    }

    // Generate optimized query
    const optimizedQuery = this.applyOptimizations(query, optimizationStrategies);

    // Create parallelization plan
    const parallelizationPlan = this.createParallelizationPlan(optimizedQuery);

    // Calculate performance gains
    const performanceGains = this.calculatePerformanceGains(optimizationStrategies, cacheHits);

    return {
      optimizedQuery,
      optimizationStrategies,
      performanceGains,
      cacheHits,
      parallelizationPlan
    };
  }

  async coordinateDistributedTransaction(operations: DistributedOperation[]): Promise<TransactionResult> {
    const transactionId = this.generateTransactionId();
    const results: OperationResult[] = [];
    const rollbackLog: RollbackLog = { operations: [] };

    try {
      // Execute operations in dependency order
      const sortedOperations = this.sortOperationsByDependency(operations);

      for (const operation of sortedOperations) {
        const result = await this.executeOperation(operation);
        results.push(result);

        // Log for potential rollback
        rollbackLog.operations.push({
          operationId: operation.operationId,
          sourceId: operation.sourceId,
          rollbackOperation: operation.rollbackOperation,
          timestamp: new Date().toISOString()
        });
      }

      // Perform consistency check
      const consistencyCheck = await this.performConsistencyCheck(results);

      return {
        transactionId,
        status: TransactionStatus.COMMITTED,
        results,
        rollbackLog,
        consistencyCheck
      };
    } catch (error) {
      // Rollback operations
      await this.rollbackOperations(rollbackLog);

      return {
        transactionId,
        status: TransactionStatus.ABORTED,
        results,
        rollbackLog,
        consistencyCheck: { status: 'failed', errors: [error.message] }
      };
    }
  }

  async negotiateSourceCapabilities(sources: DataSource[]): Promise<CapabilityNegotiation> {
    const negotiatedCapabilities: Record<string, SourceCapabilities> = {};
    const compatibilityMatrix: CompatibilityMatrix = { matrix: {} };
    const optimizedQueries: Record<string, SearchQuery> = {};
    const fallbackOptions: FallbackOptions = { options: [] };

    // Analyze source capabilities
    for (const source of sources) {
      negotiatedCapabilities[source.id] = source.capabilities;
    }

    // Build compatibility matrix
    for (let i = 0; i < sources.length; i++) {
      for (let j = i + 1; j < sources.length; j++) {
        const source1 = sources[i];
        const source2 = sources[j];
        const compatibility = this.calculateSourceCompatibility(source1, source2);

        compatibilityMatrix.matrix[`${source1.id}-${source2.id}`] = compatibility;
        compatibilityMatrix.matrix[`${source2.id}-${source1.id}`] = compatibility;
      }
    }

    // Generate optimized queries per source
    for (const source of sources) {
      const baseQuery: SearchQuery = { query: 'test query for negotiation' };
      optimizedQueries[source.id] = this.adaptQueryForSource(baseQuery, source);
    }

    // Identify fallback options
    fallbackOptions.options = this.identifyFallbackOptions(sources);

    return {
      negotiatedCapabilities,
      compatibilityMatrix,
      optimizedQueries,
      fallbackOptions
    };
  }

  // Helper methods
  private generateTransactionId(): string {
    return `tx_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateCacheKey(query: SearchQuery | FederatedSearchQuery): string {
    return `${query.query}-${query.types?.join(',')}-${query.scope?.project}`;
  }

  private selectSources(sourceIds?: string[]): DataSource[] {
    if (sourceIds && sourceIds.length > 0) {
      return sourceIds.map(id => this.registeredSources.get(id)!).filter(Boolean);
    }
    return Array.from(this.registeredSources.values());
  }

  private async executeQueryDistribution(distribution: QueryDistribution): Promise<SourceSearchResult[]> {
    const results: SourceSearchResult[] = [];

    if (distribution.parallelizationStrategy.mode === 'parallel') {
      // Execute all queries in parallel
      const promises = distribution.distributedQueries.map(dq =>
        this.executeQueryForSource(dq)
      );
      const sourceResults = await Promise.all(promises);
      results.push(...sourceResults);
    } else {
      // Execute sequentially
      for (const dq of distribution.distributedQueries) {
        const result = await this.executeQueryForSource(dq);
        results.push(result);
      }
    }

    return results;
  }

  private async executeQueryForSource(distributedQuery: DistributedQuery): Promise<SourceSearchResult> {
    const startTime = Date.now();

    // Mock execution - in reality this would call the actual source
    const mockResults = this.generateMockSearchResults(distributedQuery.adaptedQuery, 10);
    const processingTime = Date.now() - startTime;

    return {
      sourceId: distributedQuery.sourceId,
      sourceName: this.registeredSources.get(distributedQuery.sourceId)?.name || 'Unknown',
      results: mockResults,
      processingTime,
      metadata: {
        queryComplexity: this.calculateQueryComplexity(distributedQuery.adaptedQuery),
        resultQuality: Math.random(),
        optimizationApplied: false
      },
      confidence: 0.8 + Math.random() * 0.2
    };
  }

  private generateMockSearchResults(query: SearchQuery, count: number): SearchResult[] {
    return Array.from({ length: count }, (_, i) => ({
      id: `result-${i}`,
      kind: 'entity',
      scope: query.scope || { project: 'test' },
      data: {
        title: `Result ${i} for "${query.query}"`,
        content: `Content for result ${i} based on the search query`
      },
      created_at: new Date().toISOString(),
      confidence_score: Math.random(),
      match_type: 'federated'
    }));
  }

  private deduplicateResults(results: SearchResult[]): SearchResult[] {
    // Simple deduplication based on title
    const seen = new Set<string>();
    return results.filter(result => {
      const key = result.data?.title?.toLowerCase();
      if (!key || seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  private rankResultsAcrossSources(results: SearchResult[], sourceResults: SourceSearchResult[]): SearchResult[] {
    // Simple ranking by confidence score with source weighting
    return results.sort((a, b) => {
      const aSource = sourceResults.find(sr => sr.results.includes(a));
      const bSource = sourceResults.find(sr => sr.results.includes(b));

      const aScore = a.confidence_score * (aSource?.confidence || 1);
      const bScore = b.confidence_score * (bSource?.confidence || 1);

      return bScore - aScore;
    });
  }

  private calculateSourceContribution(results: SearchResult[], sourceResults: SourceSearchResult[]): SourceContribution[] {
    return sourceResults.map(sr => {
      const contribution = sr.results.filter(result => results.includes(result)).length;
      return {
        sourceId: sr.sourceId,
        sourceName: sr.sourceName,
        contributionCount: contribution,
        contributionPercentage: (contribution / results.length) * 100,
        averageQuality: sr.metadata.resultQuality,
        processingTime: sr.processingTime
      };
    });
  }

  private calculateQualityMetrics(results: SearchResult[], sourceResults: SourceSearchResult[]): QualityMetrics {
    const avgConfidence = results.reduce((sum, r) => sum + r.confidence_score, 0) / results.length;
    const avgSourceQuality = sourceResults.reduce((sum, sr) => sum + sr.metadata.resultQuality, 0) / sourceResults.length;

    return {
      overallQuality: (avgConfidence + avgSourceQuality) / 2,
      diversityScore: this.calculateDiversityScore(results),
      freshnessScore: this.calculateFreshnessScore(results),
      relevanceScore: avgConfidence,
      completenessScore: this.calculateCompletenessScore(results)
    };
  }

  private calculateDiversityScore(results: SearchResult[]): number {
    const uniqueTypes = new Set(results.map(r => r.kind)).size;
    return Math.min(uniqueTypes / results.length, 1);
  }

  private calculateFreshnessScore(results: SearchResult[]): number {
    const now = Date.now();
    const avgAge = results.reduce((sum, r) => {
      const created = new Date(r.created_at).getTime();
      return sum + (now - created);
    }, 0) / results.length;

    // Convert to freshness score (newer = higher score)
    return Math.max(0, 1 - (avgAge / (30 * 24 * 60 * 60 * 1000))); // 30 days max
  }

  private calculateCompletenessScore(results: SearchResult[]): number {
    const completeResults = results.filter(r =>
      r.data?.title && r.data?.content && r.created_at
    ).length;
    return completeResults / results.length;
  }

  private calculateDeduplicationStats(original: SearchResult[], deduplicated: SearchResult[]): DeduplicationStats {
    return {
      originalCount: original.length,
      deduplicatedCount: deduplicated.length,
      duplicatesRemoved: original.length - deduplicated.length,
      deduplicationRate: (original.length - deduplicated.length) / original.length
    };
  }

  private generateRankingMetadata(results: SearchResult[]): RankingMetadata {
    return {
      algorithm: 'weighted_confidence_with_source_boost',
      factors: ['confidence_score', 'source_quality', 'freshness', 'relevance'],
      rankingTime: Math.random() * 10,
      scoreDistribution: this.calculateScoreDistribution(results)
    };
  }

  private calculateScoreDistribution(results: SearchResult[]): ScoreDistribution {
    const scores = results.map(r => r.confidence_score);
    const min = Math.min(...scores);
    const max = Math.max(...scores);
    const mean = scores.reduce((sum, score) => sum + score, 0) / scores.length;

    return { min, max, mean, median: this.calculateMedian(scores) };
  }

  private calculateMedian(scores: number[]): number {
    const sorted = [...scores].sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    return sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
  }

  private generateSourceAttribution(sourceResults: SourceSearchResult[]): SourceAttribution[] {
    return sourceResults.map(sr => ({
      sourceId: sr.sourceId,
      sourceName: sr.sourceName,
      resultCount: sr.results.length,
      contributionPercentage: 0, // Will be calculated later
      confidence: sr.confidence,
      processingTime: sr.processingTime,
      metadata: sr.metadata
    }));
  }

  private generateAggregationMetadata(aggregatedResult: AggregatedResult, sourceResults: SourceSearchResult[]): AggregationMetadata {
    return {
      aggregationTime: Math.random() * 50,
      strategy: AggregationStrategy.MERGE_AND_RANK,
      sourceCount: sourceResults.length,
      totalResultsBeforeAggregation: sourceResults.reduce((sum, sr) => sum + sr.results.length, 0),
      totalResultsAfterAggregation: aggregatedResult.mergedResults.length,
      deduplicationEnabled: true,
      rankingEnabled: true
    };
  }

  private generatePerformanceMetrics(startTime: number, sourceResults: SourceSearchResult[]): PerformanceMetrics {
    const totalTime = Date.now() - startTime;

    return {
      totalProcessingTime: totalTime,
      sourceProcessingTimes: sourceResults.map(sr => ({
        sourceId: sr.sourceId,
        processingTime: sr.processingTime
      })),
      aggregationTime: Math.random() * 20,
      networkLatency: Math.random() * 100,
      cacheHitRate: Math.random(),
      throughput: sourceResults.reduce((sum, sr) => sum + sr.results.length, 0) / (totalTime / 1000)
    };
  }

  private async performHealthCheck(sourceId: string): Promise<SourceStatus> {
    // Mock health check
    const isHealthy = Math.random() > 0.1; // 90% healthy

    return {
      sourceId,
      status: isHealthy ? HealthStatus.HEALTHY : HealthStatus.DEGRADED,
      lastCheck: new Date().toISOString(),
      message: isHealthy ? 'All systems operational' : 'Performance degradation detected',
      metrics: {
        responseTime: Math.random() * 1000,
        errorRate: isHealthy ? 0 : Math.random() * 0.1,
        throughput: Math.random() * 1000,
        availability: isHealthy ? 0.99 : 0.9
      }
    };
  }

  private calculateOverallHealth(sourceStatuses: SourceStatus[]): HealthStatus {
    const healthyCount = sourceStatuses.filter(s => s.status === HealthStatus.HEALTHY).length;
    const degradedCount = sourceStatuses.filter(s => s.status === HealthStatus.DEGRADED).length;
    const unhealthyCount = sourceStatuses.filter(s => s.status === HealthStatus.UNHEALTHY).length;

    if (unhealthyCount > 0) return HealthStatus.UNHEALTHY;
    if (degradedCount > healthyCount) return HealthStatus.DEGRADED;
    if (degradedCount > 0) return HealthStatus.DEGRADED;
    return HealthStatus.HEALTHY;
  }

  private findAlternativeSources(failedSourceId: string): DataSource[] {
    return Array.from(this.registeredSources.values())
      .filter(source => source.id !== failedSourceId && source.priority > 0)
      .sort((a, b) => b.priority - a.priority)
      .slice(0, 3); // Top 3 alternatives
  }

  private calculatePerformanceImpact(failedSources: string[], activatedSources: string[]): PerformanceImpact {
    const estimatedRecoveryTime = failedSources.length * 5000; // 5 seconds per failed source
    const performanceDegradation = failedSources.length * 0.1; // 10% degradation per failed source

    return {
      estimatedRecoveryTime,
      performanceDegradation,
      throughputImpact: -performanceDegradation,
      latencyImpact: performanceDegradation * 1000, // ms
      availabilityImpact: -performanceDegradation
    };
  }

  private adaptQueryForSource(query: SearchQuery, source: DataSource): SearchQuery {
    // Mock query adaptation based on source capabilities
    const adaptedQuery = { ...query };

    if (source.capabilities.maxResults && (!query.limit || query.limit > source.capabilities.maxResults)) {
      adaptedQuery.limit = source.capabilities.maxResults;
    }

    return adaptedQuery;
  }

  private determineParallelizationStrategy(sources: DataSource[]): ParallelizationStrategy {
    return {
      mode: sources.length > 3 ? 'parallel' : 'sequential',
      maxConcurrency: Math.min(sources.length, 5),
      timeout: 30000,
      retryPolicy: {
        maxRetries: 3,
        backoffStrategy: 'exponential'
      }
    };
  }

  private configureLoadBalancing(sources: DataSource[]): LoadBalancingConfig {
    return {
      strategy: 'round_robin',
      weights: sources.reduce((acc, source) => {
        acc[source.id] = source.priority;
        return acc;
      }, {} as Record<string, number>),
      healthCheckInterval: 60000, // 1 minute
      failoverThreshold: 3
    };
  }

  private generateOptimizationHints(query: SearchQuery, sources: DataSource[]): OptimizationHints {
    return {
      useCaching: query.query.length < 50, // Cache short queries
      preferFastSources: query.limit && query.limit < 10,
      enableEarlyTermination: sources.length > 5,
      batchSimilarQueries: true,
      optimizeForRecency: query.query.includes('recent') || query.query.includes('latest')
    };
  }

  private calculateEstimatedTotalTime(distributedQueries: DistributedQuery[]): number {
    if (distributedQueries.length === 0) return 0;

    // For parallel execution, use max time; for sequential, use sum
    const maxTime = Math.max(...distributedQueries.map(dq => dq.estimatedTime));
    const sumTime = distributedQueries.reduce((sum, dq) => sum + dq.estimatedTime, 0);

    return Math.min(maxTime, sumTime / 2); // Optimistic estimate
  }

  private calculateQueryComplexity(query: SearchQuery): number {
    let complexity = 0;
    complexity += query.query.split(' ').length * 0.1;
    complexity += (query.types?.length || 0) * 0.2;
    complexity += query.limit ? query.limit * 0.01 : 0;
    return Math.min(complexity, 1);
  }

  private applyOptimizations(query: SearchQuery, strategies: OptimizationStrategy[]): SearchQuery {
    const optimizedQuery = { ...query };

    for (const strategy of strategies) {
      switch (strategy.type) {
        case 'query_simplification':
          optimizedQuery.query = optimizedQuery.query.substring(0, 100);
          break;
        case 'type_filtering':
          optimizedQuery.types = ['entity', 'decision'];
          break;
      }
    }

    return optimizedQuery;
  }

  private createParallelizationPlan(query: SearchQuery): ParallelizationPlan {
    return {
      canParallelize: true,
      suggestedBatchSize: 10,
      estimatedParallelQueries: 3,
      preferredSources: ['knowledge_base', 'document_store']
    };
  }

  private calculatePerformanceGains(strategies: OptimizationStrategy[], cacheHits: CacheHit[]): PerformanceGains {
    const strategyGains = strategies.reduce((sum, strategy) => sum + strategy.expectedGain, 0);
    const cacheGains = cacheHits.length * 0.5; // Each cache hit saves 50%

    return {
      overallGain: Math.min(strategyGains + cacheGains, 0.8), // Max 80% improvement
      timeReduction: (strategyGains + cacheGains) * 1000, // ms
      qualityImprovement: strategyGains * 0.5,
      resourceSavings: cacheGains * 0.3
    };
  }

  private sortOperationsByDependency(operations: DistributedOperation[]): DistributedOperation[] {
    // Simple topological sort
    const sorted: DistributedOperation[] = [];
    const visited = new Set<string>();

    const visit = (operation: DistributedOperation) => {
      if (visited.has(operation.operationId)) return;
      visited.add(operation.operationId);

      // Visit dependencies first
      for (const depId of operation.dependencies) {
        const dep = operations.find(op => op.operationId === depId);
        if (dep) visit(dep);
      }

      sorted.push(operation);
    };

    for (const operation of operations) {
      visit(operation);
    }

    return sorted;
  }

  private async executeOperation(operation: DistributedOperation): Promise<OperationResult> {
    // Mock operation execution
    return {
      operationId: operation.operationId,
      sourceId: operation.sourceId,
      status: 'success',
      result: { data: 'mock result' },
      executionTime: Math.random() * 1000,
      timestamp: new Date().toISOString()
    };
  }

  private async rollbackOperations(rollbackLog: RollbackLog): Promise<void> {
    // Mock rollback - in reality would execute rollback operations
    for (const operation of rollbackLog.operations) {
      console.log(`Rolling back operation ${operation.operationId} on source ${operation.sourceId}`);
    }
  }

  private async performConsistencyCheck(results: OperationResult[]): Promise<ConsistencyCheck> {
    // Mock consistency check
    const allSuccessful = results.every(r => r.status === 'success');

    return {
      status: allSuccessful ? 'passed' : 'failed',
      errors: allSuccessful ? [] : ['Some operations failed'],
      verifiedAt: new Date().toISOString()
    };
  }

  private calculateSourceCompatibility(source1: DataSource, source2: DataSource): number {
    // Simple compatibility calculation based on capabilities
    const commonTypes = source1.capabilities.supportedTypes.filter(type =>
      source2.capabilities.supportedTypes.includes(type)
    ).length;

    const maxTypes = Math.max(source1.capabilities.supportedTypes.length, source2.capabilities.supportedTypes.length);

    return maxTypes > 0 ? commonTypes / maxTypes : 0;
  }

  private identifyFallbackOptions(sources: DataSource[]): FallbackOption[] {
    return sources
      .filter(source => source.priority > 5) // High priority sources
      .map(source => ({
        sourceId: source.id,
        fallbackReason: 'high_priority_source',
        estimatedAvailability: 0.95,
        performanceCharacteristics: {
          responseTime: source.performanceProfile.averageResponseTime,
          throughput: source.performanceProfile.maxThroughput
        }
      }));
  }
}

// Supporting interfaces for the mock implementation
interface DataSourceRegistration {
  sourceId: string;
  registrationTime: string;
  status: 'active' | 'inactive' | 'error';
  capabilities: SourceCapabilities;
  healthCheck: SourceStatus;
}

interface SourceAttribution {
  sourceId: string;
  sourceName: string;
  resultCount: number;
  contributionPercentage: number;
  confidence: number;
  processingTime: number;
  metadata: SourceResultMetadata;
}

interface AggregationMetadata {
  aggregationTime: number;
  strategy: AggregationStrategy;
  sourceCount: number;
  totalResultsBeforeAggregation: number;
  totalResultsAfterAggregation: number;
  deduplicationEnabled: boolean;
  rankingEnabled: boolean;
}

interface PerformanceMetrics {
  totalProcessingTime: number;
  sourceProcessingTimes: Array<{ sourceId: string; processingTime: number }>;
  aggregationTime: number;
  networkLatency: number;
  cacheHitRate: number;
  throughput: number;
}

interface SourceHealthStatus {
  overall: HealthStatus;
  sources: Record<string, HealthStatus>;
}

interface DeduplicationStats {
  originalCount: number;
  deduplicatedCount: number;
  duplicatesRemoved: number;
  deduplicationRate: number;
}

interface RankingMetadata {
  algorithm: string;
  factors: string[];
  rankingTime: number;
  scoreDistribution: ScoreDistribution;
}

interface ScoreDistribution {
  min: number;
  max: number;
  mean: number;
  median: number;
}

interface SourceContribution {
  sourceId: string;
  sourceName: string;
  contributionCount: number;
  contributionPercentage: number;
  averageQuality: number;
  processingTime: number;
}

interface QualityMetrics {
  overallQuality: number;
  diversityScore: number;
  freshnessScore: number;
  relevanceScore: number;
  completenessScore: number;
}

interface SourceResultMetadata {
  queryComplexity: number;
  resultQuality: number;
  optimizationApplied: boolean;
}

interface DistributedQuery {
  sourceId: string;
  adaptedQuery: SearchQuery;
  estimatedTime: number;
  priority: number;
  dependencies: string[];
}

interface ParallelizationStrategy {
  mode: 'parallel' | 'sequential' | 'adaptive';
  maxConcurrency: number;
  timeout: number;
  retryPolicy: {
    maxRetries: number;
    backoffStrategy: 'exponential' | 'linear';
  };
}

interface LoadBalancingConfig {
  strategy: 'round_robin' | 'weighted' | 'least_connections';
  weights: Record<string, number>;
  healthCheckInterval: number;
  failoverThreshold: number;
}

interface OptimizationHints {
  useCaching: boolean;
  preferFastSources: boolean;
  enableEarlyTermination: boolean;
  batchSimilarQueries: boolean;
  optimizeForRecency: boolean;
}

interface SourceStatus {
  sourceId: string;
  status: HealthStatus;
  lastCheck: string;
  message?: string;
  metrics?: SourcePerformanceMetrics;
}

interface SourcePerformanceMetrics {
  responseTime: number;
  errorRate: number;
  throughput: number;
  availability: number;
}

interface HealthRecommendation {
  sourceId: string;
  type: 'failover' | 'optimize' | 'maintain';
  message: string;
  priority: 'high' | 'medium' | 'low';
}

interface PerformanceImpact {
  estimatedRecoveryTime: number;
  performanceDegradation: number;
  throughputImpact: number;
  latencyImpact: number;
  availabilityImpact: number;
}

interface RecoveryStatus {
  status: 'in_progress' | 'completed' | 'failed';
  estimatedRecoveryTime: number;
  actions: string[];
}

interface OptimizationStrategy {
  type: string;
  description: string;
  expectedGain: number;
}

interface CacheHit {
  key: string;
  hitTime: number;
  resultCount: number;
}

interface PerformanceGains {
  overallGain: number;
  timeReduction: number;
  qualityImprovement: number;
  resourceSavings: number;
}

interface ParallelizationPlan {
  canParallelize: boolean;
  suggestedBatchSize: number;
  estimatedParallelQueries: number;
  preferredSources: string[];
}

interface OperationResult {
  operationId: string;
  sourceId: string;
  status: 'success' | 'error';
  result: any;
  executionTime: number;
  timestamp: string;
}

interface RollbackLog {
  operations: Array<{
    operationId: string;
    sourceId: string;
    rollbackOperation: Operation;
    timestamp: string;
  }>;
}

interface Operation {
  type: string;
  parameters: Record<string, any>;
}

interface ConsistencyCheck {
  status: 'passed' | 'failed';
  errors: string[];
  verifiedAt: string;
}

enum TransactionStatus {
  COMMITTED = 'committed',
  ABORTED = 'aborted',
  IN_PROGRESS = 'in_progress'
}

interface CompatibilityMatrix {
  matrix: Record<string, number>;
}

interface FallbackOptions {
  options: FallbackOption[];
}

interface FallbackOption {
  sourceId: string;
  fallbackReason: string;
  estimatedAvailability: number;
  performanceCharacteristics: {
    responseTime: number;
    throughput: number;
  };
}

// Mock interfaces for source capabilities
interface SourceCapabilities {
  supportedTypes: string[];
  maxResults: number;
  features: string[];
  performanceCharacteristics: {
    averageResponseTime: number;
    maxThroughput: number;
  };
}

interface SourcePerformanceProfile {
  averageResponseTime: number;
  maxThroughput: number;
  reliability: number;
}

interface AuthenticationConfig {
  type: 'none' | 'api_key' | 'oauth' | 'basic';
  credentials?: Record<string, string>;
}

// Mock dependencies
vi.mock('../../../src/utils/logger', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn()
  }
}));

vi.mock('../../../src/db/qdrant', () => ({
  getQdrantClient: () => ({
    search: vi.fn().mockResolvedValue([]),
    upsert: vi.fn().mockResolvedValue({}),
    delete: vi.fn().mockResolvedValue({})
  })
}));

describe('FederatedSearchService - Comprehensive Multi-Source Search Functionality', () => {
  let federatedSearchService: FederatedSearchService;
  let mockDataSources: DataSource[];

  beforeEach(() => {
    federatedSearchService = new MockFederatedSearchService();
    vi.clearAllMocks();

    // Setup mock data sources
    mockDataSources = [
      {
        id: 'knowledge-base-1',
        name: 'Primary Knowledge Base',
        type: SourceType.KNOWLEDGE_BASE,
        endpoint: 'https://kb1.example.com',
        capabilities: {
          supportedTypes: ['entity', 'decision', 'observation'],
          maxResults: 50,
          features: ['semantic_search', 'filtering', 'ranking'],
          performanceCharacteristics: {
            averageResponseTime: 200,
            maxThroughput: 1000
          }
        },
        healthStatus: HealthStatus.HEALTHY,
        performanceProfile: {
          averageResponseTime: 200,
          maxThroughput: 1000,
          reliability: 0.99
        },
        authentication: { type: 'none' },
        priority: 10,
        timeout: 5000
      },
      {
        id: 'document-store-1',
        name: 'Document Repository',
        type: SourceType.DOCUMENT_STORE,
        endpoint: 'https://docs.example.com',
        capabilities: {
          supportedTypes: ['section', 'release_note'],
          maxResults: 100,
          features: ['full_text_search', 'preview'],
          performanceCharacteristics: {
            averageResponseTime: 500,
            maxThroughput: 500
          }
        },
        healthStatus: HealthStatus.HEALTHY,
        performanceProfile: {
          averageResponseTime: 500,
          maxThroughput: 500,
          reliability: 0.95
        },
        authentication: { type: 'api_key' },
        priority: 8,
        timeout: 10000
      },
      {
        id: 'search-engine-1',
        name: 'External Search Engine',
        type: SourceType.SEARCH_ENGINE,
        endpoint: 'https://search.example.com',
        capabilities: {
          supportedTypes: ['entity', 'observation'],
          maxResults: 200,
          features: ['global_search', 'ranking', 'caching'],
          performanceCharacteristics: {
            averageResponseTime: 300,
            maxThroughput: 2000
          }
        },
        healthStatus: HealthStatus.DEGRADED,
        performanceProfile: {
          averageResponseTime: 300,
          maxThroughput: 2000,
          reliability: 0.90
        },
        authentication: { type: 'oauth' },
        priority: 6,
        timeout: 8000
      }
    ];

    // Register mock data sources
    mockDataSources.forEach(source => {
      federatedSearchService.registerDataSource(source);
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // 1. Multi-Source Integration Tests
  describe('Multi-Source Integration', () => {
    it('should perform federated search across multiple data sources', async () => {
      const query: FederatedSearchQuery = {
        query: 'user authentication security',
        types: ['entity', 'decision'],
        sources: ['knowledge-base-1', 'document-store-1'],
        aggregationStrategy: AggregationStrategy.MERGE_AND_RANK,
        distributionMode: DistributionMode.PARALLEL,
        failoverStrategy: FailoverStrategy.GRACEFUL,
        performanceProfile: PerformanceProfile.BALANCED
      };

      const result = await federatedSearchService.performFederatedSearch(query);

      expect(result.results).toBeInstanceOf(Array);
      expect(result.sourceAttribution).toHaveLength(2);
      expect(result.aggregationMetadata.sourceCount).toBe(2);
      expect(result.transactionId).toBeTruthy();
      expect(result.performanceMetrics.totalProcessingTime).toBeGreaterThan(0);
    });

    it('should handle heterogeneous data from different source types', async () => {
      const query: FederatedSearchQuery = {
        query: 'system architecture patterns',
        types: ['entity', 'decision', 'section'],
        sources: ['knowledge-base-1', 'document-store-1', 'search-engine-1'],
        aggregationStrategy: AggregationStrategy.DEDUPLICATE_AND_BOOST,
        distributionMode: DistributionMode.ADAPTIVE,
        failoverStrategy: FailoverStrategy.IMMEDIATE,
        performanceProfile: PerformanceProfile.COMPREHENSIVE
      };

      const result = await federatedSearchService.performFederatedSearch(query);

      // Should include results from different source types
      const sourceTypes = [...new Set(result.sourceAttribution.map(sa => sa.sourceId))];
      expect(sourceTypes.length).toBeGreaterThan(1);

      // Results should be harmonized
      result.results.forEach(searchResult => {
        expect(searchResult.id).toBeTruthy();
        expect(searchResult.kind).toBeTruthy();
        expect(searchResult.data).toBeTruthy();
      });

      // Should handle different capabilities
      expect(result.aggregationMetadata.totalResultsAfterAggregation).toBeGreaterThan(0);
    });

    it('should implement source-specific query optimization', async () => {
      const query: FederatedSearchQuery = {
        query: 'database performance optimization techniques',
        types: ['observation', 'runbook'],
        sources: ['knowledge-base-1', 'search-engine-1'],
        aggregationStrategy: AggregationStrategy.SOURCE_SPECIFIC,
        distributionMode: DistributionMode.PRIORITY_BASED,
        failoverStrategy: FailoverStrategy.CIRCUIT_BREAKER,
        performanceProfile: PerformanceProfile.FAST
      };

      const result = await federatedSearchService.performFederatedSearch(query);

      // Should respect source capabilities
      const knowledgeBaseResults = result.sourceAttribution.find(sa => sa.sourceId === 'knowledge-base-1');
      const searchEngineResults = result.sourceAttribution.find(sa => sa.sourceId === 'search-engine-1');

      expect(knowledgeBaseResults).toBeTruthy();
      expect(searchEngineResults).toBeTruthy();

      // Source-specific optimization should be reflected in processing times
      expect(knowledgeBaseResults.processingTime).toBeLessThanOrEqual(5000);
      expect(searchEngineResults.processingTime).toBeLessThanOrEqual(8000);
    });

    it('should handle cross-source query translation', async () => {
      const technicalQuery: FederatedSearchQuery = {
        query: 'K8s deployment strategies and microservices architecture',
        types: ['entity', 'decision', 'runbook'],
        sources: ['knowledge-base-1', 'document-store-1'],
        aggregationStrategy: AggregationStrategy.WEIGHTED_AVERAGE,
        distributionMode: DistributionMode.LOAD_BALANCED,
        failoverStrategy: FailoverStrategy.CUSTOM,
        performanceProfile: PerformanceProfile.BALANCED
      };

      const result = await federatedSearchService.performFederatedSearch(technicalQuery);

      // Query should be adapted for each source
      expect(result.results.length).toBeGreaterThan(0);

      // Results should handle technical jargon appropriately
      const hasRelevantResults = result.results.some(r =>
        r.data?.title?.toLowerCase().includes('kubernetes') ||
        r.data?.title?.toLowerCase().includes('deployment') ||
        r.data?.title?.toLowerCase().includes('microservices')
      );

      expect(hasRelevantResults).toBe(true);
    });

    it('should handle sources with different capabilities and limits', async () => {
      const query: FederatedSearchQuery = {
        query: 'comprehensive system documentation',
        types: ['entity', 'section', 'decision'],
        limit: 150, // Higher than some sources can handle
        sources: ['knowledge-base-1', 'document-store-1', 'search-engine-1'],
        aggregationStrategy: AggregationStrategy.CONSENSUS_BASED,
        distributionMode: DistributionMode.ADAPTIVE,
        failoverStrategy: FailoverStrategy.DEGRADED,
        performanceProfile: PerformanceProfile.COMPREHENSIVE
      };

      const result = await federatedSearchService.performFederatedSearch(query);

      // Should handle different source limits gracefully
      expect(result.aggregationMetadata.totalResultsBeforeAggregation).toBeGreaterThan(0);
      expect(result.aggregationMetadata.totalResultsAfterAggregation).toBeGreaterThan(0);

      // Source-specific limits should be respected
      const documentStoreResults = result.sourceAttribution.find(sa => sa.sourceId === 'document-store-1');
      if (documentStoreResults) {
        expect(documentStoreResults.resultCount).toBeLessThanOrEqual(100); // Max for document store
      }
    });
  });

  // 2. Result Aggregation Tests
  describe('Result Aggregation', () => {
    it('should implement intelligent result merging across sources', async () => {
      const query: FederatedSearchQuery = {
        query: 'authentication and authorization patterns',
        types: ['decision', 'entity'],
        sources: ['knowledge-base-1', 'search-engine-1'],
        aggregationStrategy: AggregationStrategy.MERGE_AND_RANK,
        distributionMode: DistributionMode.PARALLEL,
        failoverStrategy: FailoverStrategy.GRACEFUL,
        performanceProfile: PerformanceProfile.BALANCED
      };

      const result = await federatedSearchService.performFederatedSearch(query);

      expect(result.results.length).toBeGreaterThan(0);

      // Results should be properly ranked
      if (result.results.length > 1) {
        for (let i = 0; i < result.results.length - 1; i++) {
          expect(result.results[i].confidence_score).toBeGreaterThanOrEqual(
            result.results[i + 1].confidence_score
          );
        }
      }

      // Should include aggregation metadata
      expect(result.aggregationMetadata.aggregationStrategy).toBe(AggregationStrategy.MERGE_AND_RANK);
      expect(result.aggregationMetadata.deduplicationEnabled).toBe(true);
      expect(result.aggregationMetadata.rankingEnabled).toBe(true);
    });

    it('should implement cross-source deduplication', async () => {
      const query: FederatedSearchQuery = {
        query: 'security best practices',
        types: ['entity', 'decision', 'section'],
        sources: ['knowledge-base-1', 'document-store-1', 'search-engine-1'],
        aggregationStrategy: AggregationStrategy.DEDUPLICATE_AND_BOOST,
        distributionMode: DistributionMode.PARALLEL,
        failoverStrategy: FailoverStrategy.IMMEDIATE,
        performanceProfile: PerformanceProfile.COMPREHENSIVE
      };

      const result = await federatedSearchService.performFederatedSearch(query);

      // Should track deduplication statistics
      expect(result.aggregationMetadata.deduplicationEnabled).toBe(true);

      // Results should not contain duplicates
      const titles = result.results.map(r => r.data?.title).filter(Boolean);
      const uniqueTitles = [...new Set(titles)];
      expect(titles.length).toBe(uniqueTitles.length);

      // Should have deduplication statistics in detailed metadata
      expect(result.aggregationMetadata.totalResultsBeforeAggregation).toBeGreaterThanOrEqual(
        result.aggregationMetadata.totalResultsAfterAggregation
      );
    });

    it('should implement result ranking across multiple sources', async () => {
      const query: FederatedSearchQuery = {
        query: 'performance optimization strategies',
        types: ['observation', 'decision', 'runbook'],
        sources: ['knowledge-base-1', 'document-store-1'],
        aggregationStrategy: AggregationStrategy.WEIGHTED_AVERAGE,
        distributionMode: DistributionMode.PRIORITY_BASED,
        failoverStrategy: FailoverStrategy.GRACEFUL,
        performanceProfile: PerformanceProfile.BALANCED
      };

      const result = await federatedSearchService.performFederatedSearch(query);

      expect(result.results.length).toBeGreaterThan(0);

      // Results should be ranked by combined score from multiple sources
      result.results.forEach(searchResult => {
        expect(searchResult.confidence_score).toBeGreaterThan(0);
        expect(searchResult.confidence_score).toBeLessThanOrEqual(1);
      });

      // Higher priority sources should have influence on ranking
      const sourceContribution = result.aggregationMetadata.sourceContribution;
      if (sourceContribution && sourceContribution.length > 0) {
        const totalContribution = sourceContribution.reduce((sum, sc) => sum + sc.contributionPercentage, 0);
        expect(totalContribution).toBeCloseTo(100, 1); // Should sum to ~100%
      }
    });

    it('should provide source attribution and provenance', async () => {
      const query: FederatedSearchQuery = {
        query: 'microservices architecture decisions',
        types: ['decision', 'entity'],
        sources: ['knowledge-base-1', 'search-engine-1'],
        aggregationStrategy: AggregationStrategy.MERGE_AND_RANK,
        distributionMode: DistributionMode.PARALLEL,
        failoverStrategy: FailoverStrategy.GRACEFUL,
        performanceProfile: PerformanceProfile.BALANCED
      };

      const result = await federatedSearchService.performFederatedSearch(query);

      // Should include detailed source attribution
      expect(result.sourceAttribution).toHaveLength(2);

      result.sourceAttribution.forEach(attribution => {
        expect(attribution.sourceId).toBeTruthy();
        expect(attribution.sourceName).toBeTruthy();
        expect(attribution.resultCount).toBeGreaterThan(0);
        expect(attribution.confidence).toBeGreaterThan(0);
        expect(attribution.processingTime).toBeGreaterThan(0);
      });

      // Should include provenance information
      result.results.forEach(searchResult => {
        expect(searchResult.created_at).toBeTruthy();
        expect(searchResult.match_type).toBe('federated');
      });
    });

    it('should handle result quality assessment across sources', async () => {
      const query: FederatedSearchQuery = {
        query: 'database design patterns',
        types: ['decision', 'entity', 'ddl'],
        sources: ['knowledge-base-1', 'document-store-1'],
        aggregationStrategy: AggregationStrategy.CONSENSUS_BASED,
        distributionMode: DistributionMode.ADAPTIVE,
        failoverStrategy: FailoverStrategy.DEGRADED,
        performanceProfile: PerformanceProfile.COMPREHENSIVE
      };

      const result = await federatedSearchService.performFederatedSearch(query);

      // Should assess quality across multiple dimensions
      const qualityMetrics = result.aggregationMetadata.qualityMetrics;
      if (qualityMetrics) {
        expect(qualityMetrics.overallQuality).toBeGreaterThan(0);
        expect(qualityMetrics.diversityScore).toBeGreaterThanOrEqual(0);
        expect(qualityMetrics.freshnessScore).toBeGreaterThanOrEqual(0);
        expect(qualityMetrics.relevanceScore).toBeGreaterThan(0);
        expect(qualityMetrics.completenessScore).toBeGreaterThan(0);
      }

      // Results should meet minimum quality thresholds
      result.results.forEach(searchResult => {
        expect(searchResult.confidence_score).toBeGreaterThan(0.1); // Minimum confidence
      });
    });
  });

  // 3. Query Distribution Tests
  describe('Query Distribution', () => {
    it('should implement intelligent query routing', async () => {
      const query: FederatedSearchQuery = {
        query: 'API security implementation',
        types: ['entity', 'decision', 'runbook'],
        sources: ['knowledge-base-1', 'document-store-1', 'search-engine-1'],
        aggregationStrategy: AggregationStrategy.MERGE_AND_RANK,
        distributionMode: DistributionMode.ADAPTIVE,
        failoverStrategy: FailoverStrategy.GRACEFUL,
        performanceProfile: PerformanceProfile.BALANCED
      };

      const result = await federatedSearchService.performFederatedSearch(query);

      // Should route queries to appropriate sources based on capabilities
      expect(result.sourceAttribution.length).toBeGreaterThan(0);

      // Should consider source priorities and capabilities
      const performanceMetrics = result.performanceMetrics;
      expect(performanceMetrics.totalProcessingTime).toBeGreaterThan(0);
      expect(performanceMetrics.sourceProcessingTimes).toHaveLength(3);

      // Should adapt distribution based on query characteristics
      expect(result.aggregationMetadata.sourceCount).toBeGreaterThan(0);
    });

    it('should handle parallel source querying efficiently', async () => {
      const query: FederatedSearchQuery = {
        query: 'distributed system architecture',
        types: ['entity', 'decision', 'observation'],
        sources: ['knowledge-base-1', 'document-store-1', 'search-engine-1'],
        aggregationStrategy: AggregationStrategy.WEIGHTED_AVERAGE,
        distributionMode: DistributionMode.PARALLEL,
        failoverStrategy: FailoverStrategy.IMMEDIATE,
        performanceProfile: PerformanceProfile.FAST
      };

      const startTime = Date.now();
      const result = await federatedSearchService.performFederatedSearch(query);
      const totalTime = Date.now() - startTime;

      // Parallel execution should be efficient
      expect(totalTime).toBeLessThan(5000); // Should complete within 5 seconds

      // Should utilize all sources in parallel
      expect(result.sourceAttribution.length).toBe(3);

      // Processing times should reflect parallel execution
      const maxSourceTime = Math.max(...result.performanceMetrics.sourceProcessingTimes.map(st => st.processingTime));
      expect(totalTime).toBeLessThan(maxSourceTime * 1.5); // Should be close to max individual time
    });

    it('should implement query optimization per source', async () => {
      const query: FederatedSearchQuery = {
        query: 'machine learning model deployment pipeline',
        types: ['entity', 'decision', 'runbook'],
        sources: ['knowledge-base-1', 'search-engine-1'],
        aggregationStrategy: AggregationStrategy.SOURCE_SPECIFIC,
        distributionMode: DistributionMode.PRIORITY_BASED,
        failoverStrategy: FailoverStrategy.GRACEFUL,
        performanceProfile: PerformanceProfile.BALANCED
      };

      const result = await federatedSearchService.performFederatedSearch(query);

      // Each source should receive optimized queries
      result.sourceAttribution.forEach(attribution => {
        expect(attribution.processingTime).toBeGreaterThan(0);

        // Processing time should be reasonable for source capabilities
        if (attribution.sourceId === 'knowledge-base-1') {
          expect(attribution.processingTime).toBeLessThan(1000);
        }
      });

      // Results should reflect source-specific optimizations
      expect(result.results.length).toBeGreaterThan(0);
      expect(result.aggregationMetadata.totalResultsAfterAggregation).toBeGreaterThan(0);
    });

    it('should implement load balancing across sources', async () => {
      const query: FederatedSearchQuery = {
        query: 'cloud infrastructure management',
        types: ['entity', 'decision', 'observation'],
        sources: ['knowledge-base-1', 'document-store-1', 'search-engine-1'],
        aggregationStrategy: AggregationStrategy.DEDUPLICATE_AND_BOOST,
        distributionMode: DistributionMode.LOAD_BALANCED,
        failoverStrategy: FailoverStrategy.DEGRADED,
        performanceProfile: PerformanceProfile.BALANCED
      };

      const result = await federatedSearchService.performFederatedSearch(query);

      // Load should be distributed based on source capabilities
      const sourceContributions = result.aggregationMetadata.sourceContribution;
      if (sourceContributions) {
        // Higher priority sources should handle more load
        const sortedByContribution = [...sourceContributions].sort((a, b) => b.contributionCount - a.contributionCount);
        expect(sortedByContribution[0].contributionCount).toBeGreaterThan(0);
      }

      // Should balance response times across sources
      const processingTimes = result.performanceMetrics.sourceProcessingTimes.map(st => st.processingTime);
      const maxTime = Math.max(...processingTimes);
      const minTime = Math.min(...processingTimes);

      // Times should be reasonably balanced (within factor of 3)
      expect(maxTime / minTime).toBeLessThan(3);
    });

    it('should handle source-specific query adaptation', async () => {
      const complexQuery: FederatedSearchQuery = {
        query: 'comprehensive guide to implementing secure microservices with API gateway and service mesh',
        types: ['entity', 'decision', 'runbook', 'section'],
        limit: 100,
        sources: ['knowledge-base-1', 'document-store-1'],
        aggregationStrategy: AggregationStrategy.WEIGHTED_AVERAGE,
        distributionMode: DistributionMode.ADAPTIVE,
        failoverStrategy: FailoverStrategy.GRACEFUL,
        performanceProfile: PerformanceProfile.COMPREHENSIVE
      };

      const result = await federatedSearchService.performFederatedSearch(complexQuery);

      // Query should be adapted for each source's capabilities
      expect(result.sourceAttribution.length).toBe(2);

      result.sourceAttribution.forEach(attribution => {
        // Each source should receive appropriate query modifications
        expect(attribution.metadata.queryComplexity).toBeGreaterThan(0);
        expect(attribution.metadata.queryComplexity).toBeLessThanOrEqual(1);
      });

      // Results should respect source-specific limits
      expect(result.aggregationMetadata.totalResultsAfterAggregation).toBeGreaterThan(0);
    });
  });

  // 4. Performance Optimization Tests
  describe('Performance Optimization', () => {
    it('should implement distributed query processing', async () => {
      const query: FederatedSearchQuery = {
        query: 'enterprise security architecture framework',
        types: ['entity', 'decision', 'observation', 'runbook'],
        sources: ['knowledge-base-1', 'document-store-1', 'search-engine-1'],
        aggregationStrategy: AggregationStrategy.MERGE_AND_RANK,
        distributionMode: DistributionMode.PARALLEL,
        failoverStrategy: FailoverStrategy.IMMEDIATE,
        performanceProfile: PerformanceProfile.REAL_TIME
      };

      const startTime = Date.now();
      const result = await federatedSearchService.performFederatedSearch(query);
      const totalTime = Date.now() - startTime;

      // Distributed processing should be fast
      expect(totalTime).toBeLessThan(3000); // Real-time performance

      // Should utilize multiple sources efficiently
      expect(result.sourceAttribution.length).toBe(3);

      // Performance metrics should be comprehensive
      expect(result.performanceMetrics.throughput).toBeGreaterThan(0);
      expect(result.performanceMetrics.cacheHitRate).toBeGreaterThanOrEqual(0);
      expect(result.performanceMetrics.networkLatency).toBeGreaterThan(0);
    });

    it('should implement source-specific caching strategies', async () => {
      const query: FederatedSearchQuery = {
        query: 'database connection pool optimization',
        types: ['entity', 'observation', 'decision'],
        sources: ['knowledge-base-1', 'search-engine-1'],
        aggregationStrategy: AggregationStrategy.DEDUPLICATE_AND_BOOST,
        distributionMode: DistributionMode.PARALLEL,
        failoverStrategy: FailoverStrategy.GRACEFUL,
        performanceProfile: PerformanceProfile.BALANCED
      };

      // First search
      const result1 = await federatedSearchService.performFederatedSearch(query);

      // Second search (should benefit from caching)
      const startTime = Date.now();
      const result2 = await federatedSearchService.performFederatedSearch(query);
      const secondSearchTime = Date.now() - startTime;

      // Second search should be faster due to caching
      expect(secondSearchTime).toBeLessThan(1000);

      // Results should be consistent
      expect(result1.results.length).toBe(result2.results.length);
      expect(result1.transactionId).not.toBe(result2.transactionId); // Different transaction IDs
    });

    it('should handle parallel execution optimization', async () => {
      const queries = Array.from({ length: 5 }, (_, i) => ({
        query: `parallel optimization test query ${i}`,
        types: ['entity', 'decision'] as const,
        sources: ['knowledge-base-1', 'document-store-1', 'search-engine-1'] as const,
        aggregationStrategy: AggregationStrategy.MERGE_AND_RANK as const,
        distributionMode: DistributionMode.PARALLEL as const,
        failoverStrategy: FailoverStrategy.IMMEDIATE as const,
        performanceProfile: PerformanceProfile.FAST as const
      }));

      const startTime = Date.now();
      const results = await Promise.all(
        queries.map(query => federatedSearchService.performFederatedSearch(query))
      );
      const totalTime = Date.now() - startTime;

      // Parallel execution should handle multiple queries efficiently
      expect(results).toHaveLength(5);
      expect(totalTime).toBeLessThan(10000); // Should complete 5 queries within 10 seconds

      // Each result should be complete
      results.forEach(result => {
        expect(result.results.length).toBeGreaterThan(0);
        expect(result.sourceAttribution.length).toBeGreaterThan(0);
        expect(result.transactionId).toBeTruthy();
      });

      // Average time per query should be reasonable
      const avgTimePerQuery = totalTime / queries.length;
      expect(avgTimePerQuery).toBeLessThan(3000);
    });

    it('should handle network latency optimization', async () => {
      const query: FederatedSearchQuery = {
        query: 'distributed caching strategies',
        types: ['entity', 'decision', 'observation'],
        sources: ['knowledge-base-1', 'search-engine-1'], // Include potentially slower source
        aggregationStrategy: AggregationStrategy.WEIGHTED_AVERAGE,
        distributionMode: DistributionMode.ADAPTIVE,
        failoverStrategy: FailoverStrategy.DEGRADED,
        performanceProfile: PerformanceProfile.BALANCED
      };

      const result = await federatedSearchService.performFederatedSearch(query);

      // Should account for network latency
      expect(result.performanceMetrics.networkLatency).toBeGreaterThan(0);

      // Should optimize for latency by prioritizing faster sources
      const fasterSource = result.sourceAttribution.find(sa => sa.sourceId === 'knowledge-base-1');
      const slowerSource = result.sourceAttribution.find(sa => sa.sourceId === 'search-engine-1');

      if (fasterSource && slowerSource) {
        expect(fasterSource.processingTime).toBeLessThanOrEqual(slowerSource.processingTime * 1.5);
      }

      // Overall performance should be acceptable
      expect(result.performanceMetrics.totalProcessingTime).toBeLessThan(5000);
    });

    it('should implement performance profiling and monitoring', async () => {
      const query: FederatedSearchQuery = {
        query: 'system performance monitoring and alerting',
        types: ['entity', 'observation', 'runbook'],
        sources: ['knowledge-base-1', 'document-store-1', 'search-engine-1'],
        aggregationStrategy: AggregationStrategy.CONSENSUS_BASED,
        distributionMode: DistributionMode.LOAD_BALANCED,
        failoverStrategy: FailoverStrategy.GRACEFUL,
        performanceProfile: PerformanceProfile.COMPREHENSIVE
      };

      const result = await federatedSearchService.performFederatedSearch(query);

      // Should provide comprehensive performance metrics
      expect(result.performanceMetrics.totalProcessingTime).toBeGreaterThan(0);
      expect(result.performanceMetrics.aggregationTime).toBeGreaterThan(0);
      expect(result.performanceMetrics.throughput).toBeGreaterThan(0);
      expect(result.performanceMetrics.sourceProcessingTimes).toHaveLength(3);

      // Should track performance at source level
      result.performanceMetrics.sourceProcessingTimes.forEach(sourceTime => {
        expect(sourceTime.sourceId).toBeTruthy();
        expect(sourceTime.processingTime).toBeGreaterThan(0);
      });

      // Should provide performance insights
      expect(result.aggregationMetadata.rankingMetadata.rankingTime).toBeGreaterThan(0);
      expect(result.aggregationMetadata.rankingMetadata.algorithm).toBeTruthy();
    });
  });

  // 5. Source Management Tests
  describe('Source Management', () => {
    it('should handle dynamic source registration', async () => {
      const newSource: DataSource = {
        id: 'dynamic-source-1',
        name: 'Dynamic Knowledge Source',
        type: SourceType.API_ENDPOINT,
        endpoint: 'https://dynamic.example.com',
        capabilities: {
          supportedTypes: ['entity', 'decision'],
          maxResults: 75,
          features: ['real_time_search', 'advanced_filtering'],
          performanceCharacteristics: {
            averageResponseTime: 150,
            maxThroughput: 1500
          }
        },
        healthStatus: HealthStatus.HEALTHY,
        performanceProfile: {
          averageResponseTime: 150,
          maxThroughput: 1500,
          reliability: 0.98
        },
        authentication: { type: 'api_key' },
        priority: 9,
        timeout: 6000
      };

      const registration = await federatedSearchService.registerDataSource(newSource);

      expect(registration.sourceId).toBe(newSource.id);
      expect(registration.status).toBe('active');
      expect(registration.capabilities).toEqual(newSource.capabilities);
      expect(registration.healthCheck.sourceId).toBe(newSource.id);
    });

    it('should implement source health monitoring', async () => {
      const healthReport = await federatedSearchService.monitorSourceHealth();

      expect(healthReport.overallHealth).toBeTruthy();
      expect(Object.keys(healthReport.sourceStatuses)).toHaveLength(3);
      expect(healthReport.sourceStatuses['knowledge-base-1']).toBeTruthy();
      expect(healthReport.sourceStatuses['document-store-1']).toBeTruthy();
      expect(healthReport.sourceStatuses['search-engine-1']).toBeTruthy();

      // Should include performance metrics
      Object.values(healthReport.sourceStatuses).forEach(status => {
        if (status.metrics) {
          expect(status.metrics.responseTime).toBeGreaterThan(0);
          expect(status.metrics.availability).toBeGreaterThan(0);
          expect(status.metrics.throughput).toBeGreaterThan(0);
        }
      });

      // Should provide recommendations for unhealthy sources
      const degradedSources = Object.entries(healthReport.sourceStatuses)
        .filter(([_, status]) => status.status === HealthStatus.DEGRADED);

      if (degradedSources.length > 0) {
        expect(healthReport.recommendations.length).toBeGreaterThan(0);
      }
    });

    it('should handle source capability negotiation', async () => {
      const sources = [
        mockDataSources[0], // knowledge-base-1
        mockDataSources[1]  // document-store-1
      ];

      const negotiation = await federatedSearchService.negotiateSourceCapabilities(sources);

      expect(negotiation.negotiatedCapabilities).toBeTruthy();
      expect(Object.keys(negotiation.negotiatedCapabilities)).toHaveLength(2);

      // Should include compatibility matrix
      expect(negotiation.compatibilityMatrix.matrix).toBeTruthy();

      // Should provide optimized queries per source
      expect(Object.keys(negotiation.optimizedQueries)).toHaveLength(2);

      // Should identify fallback options
      expect(negotiation.fallbackOptions.options).toBeInstanceOf(Array);
    });

    it('should handle source failover scenarios', async () => {
      const failedSources = ['search-engine-1']; // Simulate failure of search engine

      const failoverResponse = await federatedSearchService.handleFailover(failedSources);

      expect(failoverResponse.activatedSources.length).toBeGreaterThan(0);
      expect(failoverResponse.performanceImpact).toBeTruthy();
      expect(failoverResponse.recoveryStatus.status).toBeTruthy();

      // Should identify alternative sources
      expect(failoverResponse.activatedSources.every(sourceId =>
        !failedSources.includes(sourceId)
      )).toBe(true);

      // Should assess performance impact
      expect(failoverResponse.performanceImpact.performanceDegradation).toBeGreaterThan(0);
      expect(failoverResponse.performanceImpact.estimatedRecoveryTime).toBeGreaterThan(0);
    });

    it('should handle source priority management', async () => {
      const query: FederatedSearchQuery = {
        query: 'high priority security information',
        types: ['entity', 'decision'],
        sources: ['knowledge-base-1', 'document-store-1', 'search-engine-1'],
        aggregationStrategy: AggregationStrategy.SOURCE_SPECIFIC,
        distributionMode: DistributionMode.PRIORITY_BASED,
        failoverStrategy: FailoverStrategy.GRACEFUL,
        performanceProfile: PerformanceProfile.FAST
      };

      const result = await federatedSearchService.performFederatedSearch(query);

      // Higher priority sources should be utilized first
      const highPrioritySource = result.sourceAttribution.find(sa => sa.sourceId === 'knowledge-base-1');
      const lowPrioritySource = result.sourceAttribution.find(sa => sa.sourceId === 'search-engine-1');

      if (highPrioritySource && lowPrioritySource) {
        // Higher priority source should have better metrics
        expect(highPrioritySource.confidence).toBeGreaterThanOrEqual(lowPrioritySource.confidence);
      }

      // Should respect source priorities in distribution
      expect(result.sourceAttribution.length).toBeGreaterThan(0);
    });

    it('should handle source capability validation', async () => {
      const query: FederatedSearchQuery = {
        query: 'advanced query with specific requirements',
        types: ['entity', 'decision', 'section', 'runbook'],
        limit: 300, // Exceeds individual source limits
        sources: ['knowledge-base-1', 'document-store-1'],
        aggregationStrategy: AggregationStrategy.DEDUPLICATE_AND_BOOST,
        distributionMode: DistributionMode.ADAPTIVE,
        failoverStrategy: FailoverStrategy.DEGRADED,
        performanceProfile: PerformanceProfile.COMPREHENSIVE
      };

      const result = await federatedSearchService.performFederatedSearch(query);

      // Should validate and adapt to source capabilities
      expect(result.aggregationMetadata.totalResultsAfterAggregation).toBeGreaterThan(0);

      // Should handle capability mismatches gracefully
      result.sourceAttribution.forEach(attribution => {
        expect(attribution.resultCount).toBeGreaterThan(0);
        expect(attribution.processingTime).toBeGreaterThan(0);
      });

      // Should aggregate results respecting individual source limits
      const totalFromSources = result.sourceAttribution.reduce((sum, sa) => sum + sa.resultCount, 0);
      expect(result.aggregationMetadata.totalResultsAfterAggregation).toBeLessThanOrEqual(totalFromSources);
    });
  });

  // 6. Integration and Coordination Tests
  describe('Integration and Coordination', () => {
    it('should handle cross-service communication', async () => {
      const query: FederatedSearchQuery = {
        query: 'cross-service integration patterns',
        types: ['entity', 'decision', 'observation'],
        sources: ['knowledge-base-1', 'document-store-1', 'search-engine-1'],
        aggregationStrategy: AggregationStrategy.MERGE_AND_RANK,
        distributionMode: DistributionMode.PARALLEL,
        failoverStrategy: FailoverStrategy.GRACEFUL,
        performanceProfile: PerformanceProfile.BALANCED
      };

      const result = await federatedSearchService.performFederatedSearch(query);

      // Should coordinate communication across multiple services
      expect(result.sourceAttribution.length).toBe(3);

      // Should track communication metrics
      expect(result.performanceMetrics.networkLatency).toBeGreaterThan(0);
      expect(result.performanceMetrics.sourceProcessingTimes).toHaveLength(3);

      // Should handle service coordination transparently
      result.sourceAttribution.forEach(attribution => {
        expect(attribution.sourceId).toBeTruthy();
        expect(attribution.processingTime).toBeGreaterThan(0);
        expect(attribution.metadata).toBeTruthy();
      });
    });

    it('should handle distributed transaction management', async () => {
      const operations: DistributedOperation[] = [
        {
          operationId: 'op-1',
          sourceId: 'knowledge-base-1',
          operation: { type: 'search', parameters: { query: 'test query 1' } },
          dependencies: [],
          rollbackOperation: { type: 'cleanup', parameters: { operationId: 'op-1' } }
        },
        {
          operationId: 'op-2',
          sourceId: 'document-store-1',
          operation: { type: 'search', parameters: { query: 'test query 2' } },
          dependencies: ['op-1'],
          rollbackOperation: { type: 'cleanup', parameters: { operationId: 'op-2' } }
        }
      ];

      const transactionResult = await federatedSearchService.coordinateDistributedTransaction(operations);

      expect(transactionResult.transactionId).toBeTruthy();
      expect(transactionResult.status).toBe(TransactionStatus.COMMITTED);
      expect(transactionResult.results).toHaveLength(2);
      expect(transactionResult.rollbackLog.operations).toHaveLength(2);
      expect(transactionResult.consistencyCheck.status).toBe('passed');
    });

    it('should handle consistency management across sources', async () => {
      const query: FederatedSearchQuery = {
        query: 'data consistency patterns',
        types: ['entity', 'decision', 'observation'],
        sources: ['knowledge-base-1', 'document-store-1'],
        aggregationStrategy: AggregationStrategy.CONSENSUS_BASED,
        distributionMode: DistributionMode.ADAPTIVE,
        failoverStrategy: FailoverStrategy.DEGRADED,
        performanceProfile: PerformanceProfile.COMPREHENSIVE
      };

      const result = await federatedSearchService.performFederatedSearch(query);

      // Should maintain consistency across federated results
      result.results.forEach(searchResult => {
        expect(searchResult.id).toBeTruthy();
        expect(searchResult.kind).toBeTruthy();
        expect(searchResult.data).toBeTruthy();
        expect(searchResult.created_at).toBeTruthy();
      });

      // Should ensure result consistency
      const uniqueIds = [...new Set(result.results.map(r => r.id))];
      expect(uniqueIds.length).toBe(result.results.length); // No duplicate IDs

      // Should provide consistency metadata
      expect(result.transactionId).toBeTruthy();
    });

    it('should handle service coordination and orchestration', async () => {
      const queries = [
        {
          query: 'service orchestration patterns',
          types: ['entity', 'decision'],
          sources: ['knowledge-base-1'] as const
        },
        {
          query: 'microservices coordination',
          types: ['observation', 'runbook'],
          sources: ['document-store-1'] as const
        }
      ];

      const results = await Promise.all(
        queries.map(q => federatedSearchService.performFederatedSearch({
          ...q,
          aggregationStrategy: AggregationStrategy.MERGE_AND_RANK,
          distributionMode: DistributionMode.PARALLEL,
          failoverStrategy: FailoverStrategy.GRACEFUL,
          performanceProfile: PerformanceProfile.BALANCED
        }))
      );

      // Should coordinate multiple federated searches
      expect(results).toHaveLength(2);

      results.forEach(result => {
        expect(result.transactionId).toBeTruthy();
        expect(result.sourceAttribution.length).toBeGreaterThan(0);
        expect(result.results.length).toBeGreaterThan(0);

        // Each should have unique transaction ID
        expect(results[0].transactionId).not.toBe(results[1].transactionId);
      });

      // Should handle orchestration efficiently
      const processingTimes = results.map(r => r.performanceMetrics.totalProcessingTime);
      const avgProcessingTime = processingTimes.reduce((sum, time) => sum + time, 0) / processingTimes.length;
      expect(avgProcessingTime).toBeLessThan(3000);
    });

    it('should handle error recovery and resilience', async () => {
      const query: FederatedSearchQuery = {
        query: 'error recovery and resilience patterns',
        types: ['entity', 'decision', 'runbook'],
        sources: ['knowledge-base-1', 'search-engine-1'], // Include degraded source
        aggregationStrategy: AggregationStrategy.WEIGHTED_AVERAGE,
        distributionMode: DistributionMode.ADAPTIVE,
        failoverStrategy: FailoverStrategy.CIRCUIT_BREAKER,
        performanceProfile: PerformanceProfile.BALANCED
      };

      const result = await federatedSearchService.performFederatedSearch(query);

      // Should handle degraded sources gracefully
      expect(result.results.length).toBeGreaterThan(0);
      expect(result.sourceHealth.overall).toBeTruthy();

      // Should provide error recovery mechanisms
      const unhealthySources = Object.entries(result.sourceHealth.sources)
        .filter(([_, health]) => health === HealthStatus.UNHEALTHY || health === HealthStatus.DEGRADED);

      if (unhealthySources.length > 0) {
        // Should have recommendations for recovery
        expect(result.sourceHealth.sources[unhealthySources[0][0]]).toBeTruthy();
      }

      // Should maintain functionality despite partial failures
      expect(result.aggregationMetadata.totalResultsAfterAggregation).toBeGreaterThan(0);
    });

    it('should handle scalability and load management', async () => {
      const concurrentQueries = Array.from({ length: 10 }, (_, i) => ({
        query: `scalability test query ${i}`,
        types: ['entity', 'decision'] as const,
        sources: ['knowledge-base-1', 'document-store-1'] as const,
        aggregationStrategy: AggregationStrategy.MERGE_AND_RANK as const,
        distributionMode: DistributionMode.PARALLEL as const,
        failoverStrategy: FailoverStrategy.GRACEFUL as const,
        performanceProfile: PerformanceProfile.BALANCED as const
      }));

      const startTime = Date.now();
      const results = await Promise.all(
        concurrentQueries.map(query => federatedSearchService.performFederatedSearch(query))
      );
      const totalTime = Date.now() - startTime;

      // Should handle concurrent load efficiently
      expect(results).toHaveLength(10);
      expect(totalTime).toBeLessThan(15000); // Should handle 10 queries within 15 seconds

      // Each result should be complete and consistent
      results.forEach(result => {
        expect(result.results.length).toBeGreaterThan(0);
        expect(result.sourceAttribution.length).toBeGreaterThan(0);
        expect(result.transactionId).toBeTruthy();
        expect(result.performanceMetrics.totalProcessingTime).toBeGreaterThan(0);
      });

      // Performance should scale reasonably
      const avgTimePerQuery = totalTime / concurrentQueries.length;
      expect(avgTimePerQuery).toBeLessThan(3000);
    });
  });

  // 7. Advanced Federated Search Capabilities
  describe('Advanced Federated Search Capabilities', () => {
    it('should handle complex aggregation strategies', async () => {
      const strategies = [
        AggregationStrategy.MERGE_AND_RANK,
        AggregationStrategy.DEDUPLICATE_AND_BOOST,
        AggregationStrategy.WEIGHTED_AVERAGE,
        AggregationStrategy.CONSENSUS_BASED
      ];

      for (const strategy of strategies) {
        const query: FederatedSearchQuery = {
          query: 'advanced aggregation strategy test',
          types: ['entity', 'decision'],
          sources: ['knowledge-base-1', 'document-store-1'],
          aggregationStrategy: strategy,
          distributionMode: DistributionMode.PARALLEL,
          failoverStrategy: FailoverStrategy.GRACEFUL,
          performanceProfile: PerformanceProfile.BALANCED
        };

        const result = await federatedSearchService.performFederatedSearch(query);

        expect(result.aggregationMetadata.strategy).toBe(strategy);
        expect(result.results.length).toBeGreaterThan(0);
        expect(result.sourceAttribution.length).toBeGreaterThan(0);
      }
    });

    it('should handle intelligent failover and recovery', async () => {
      const query: FederatedSearchQuery = {
        query: 'intelligent failover mechanisms',
        types: ['entity', 'decision', 'runbook'],
        sources: ['knowledge-base-1', 'document-store-1', 'search-engine-1'],
        aggregationStrategy: AggregationStrategy.SOURCE_SPECIFIC,
        distributionMode: DistributionMode.ADAPTIVE,
        failoverStrategy: FailoverStrategy.CIRCUIT_BREAKER,
        performanceProfile: PerformanceProfile.RESILIENT
      };

      // First, monitor health to identify issues
      const healthReport = await federatedSearchService.monitorSourceHealth();

      // Perform search with failover strategy
      const result = await federatedSearchService.performFederatedSearch(query);

      // Should handle source health issues gracefully
      expect(result.results.length).toBeGreaterThan(0);
      expect(result.sourceHealth.overall).toBeTruthy();

      // Should provide failover metadata
      if (healthReport.overallHealth !== HealthStatus.HEALTHY) {
        expect(result.sourceHealth).toBeTruthy();
      }
    });

    it('should handle performance profiling and optimization', async () => {
      const query: FederatedSearchQuery = {
        query: 'performance profiling and optimization techniques',
        types: ['entity', 'observation', 'decision'],
        sources: ['knowledge-base-1', 'document-store-1', 'search-engine-1'],
        aggregationStrategy: AggregationStrategy.WEIGHTED_AVERAGE,
        distributionMode: DistributionMode.LOAD_BALANCED,
        failoverStrategy: FailoverStrategy.DEGRADED,
        performanceProfile: PerformanceProfile.OPTIMIZED
      };

      const result = await federatedSearchService.performFederatedSearch(query);

      // Should provide comprehensive performance profiling
      expect(result.performanceMetrics.totalProcessingTime).toBeGreaterThan(0);
      expect(result.performanceMetrics.aggregationTime).toBeGreaterThan(0);
      expect(result.performanceMetrics.throughput).toBeGreaterThan(0);

      // Should include optimization metadata
      expect(result.aggregationMetadata.rankingMetadata.rankingTime).toBeGreaterThan(0);
      expect(result.aggregationMetadata.rankingMetadata.factors).toBeInstanceOf(Array);

      // Should provide source-level performance insights
      result.sourceAttribution.forEach(attribution => {
        expect(attribution.processingTime).toBeGreaterThan(0);
        expect(attribution.confidence).toBeGreaterThan(0);
      });
    });

    it('should handle context-aware federated search', async () => {
      const query: FederatedSearchQuery = {
        query: 'context-aware search and personalization',
        types: ['entity', 'decision', 'observation'],
        scope: { project: 'federated-search-demo', org: 'test-org' },
        sources: ['knowledge-base-1', 'document-store-1'],
        aggregationStrategy: AggregationStrategy.CONSENSUS_BASED,
        distributionMode: DistributionMode.ADAPTIVE,
        failoverStrategy: FailoverStrategy.GRACEFUL,
        performanceProfile: PerformanceProfile.PERSONALIZED
      };

      const result = await federatedSearchService.performFederatedSearch(query);

      // Should incorporate context into federated search
      expect(result.results.length).toBeGreaterThan(0);

      // Results should reflect context-specific optimization
      result.results.forEach(searchResult => {
        expect(searchResult.scope).toBeTruthy();
      });

      // Should provide context-aware aggregation
      expect(result.aggregationMetadata.totalResultsAfterAggregation).toBeGreaterThan(0);
    });
  });
});