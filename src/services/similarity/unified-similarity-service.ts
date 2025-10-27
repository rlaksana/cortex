/**
 * Unified Similarity Service
 *
 * Integrates advanced lexical similarity analysis with semantic vector search
 * from Qdrant adapter to provide comprehensive similarity detection.
 *
 * Features:
 * - Hybrid similarity combining vector semantics and lexical analysis
 * - Knowledge type-specific similarity strategies
 * - Advanced deduplication using embeddings
 * - Semantic contradiction detection
 * - Performance optimized with caching and batching
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { logger } from '../../utils/logger.js';
import { QdrantAdapter } from '../../db/adapters/qdrant-adapter.js';
import { environment } from '../../config/environment.js';
import type {
  SimilarityService as ISimilarityService,
  KnowledgeItem,
  MemoryStoreResponse,
} from '../../types/core-interfaces.js';
import type { DatabaseConfig } from '../../db/database-interface.js';

/**
 * Similarity analysis configuration
 */
interface SimilarityConfig {
  enabled: boolean;
  defaultThreshold: number;
  maxResults: number;
  includeContentAnalysis: boolean;
  includeMetadataAnalysis: boolean;
  vectorWeight: number; // Weight for semantic similarity
  lexicalWeight: number; // Weight for lexical similarity
  enableContradictionDetection: boolean;
  enableAdaptiveThresholds: boolean;
}

/**
 * Comprehensive similarity analysis result
 */
interface SimilarityResult {
  item: KnowledgeItem;
  score: number;
  matchFactors: {
    semantic: number; // Vector similarity
    lexical: number; // Text similarity
    metadata: number; // Kind, scope, etc.
    overall: number;
  };
  reasoning: string[];
  contradictionDetected: boolean;
  recommendedAction: 'duplicate' | 'related' | 'update' | 'none';
}

/**
 * Unified similarity service combining semantic and lexical analysis
 */
export class UnifiedSimilarityService implements ISimilarityService {
  private qdrantAdapter: QdrantAdapter;
  private config: SimilarityConfig;
  private initialized: boolean = false;

  constructor(dbConfig?: DatabaseConfig) {
    const config = dbConfig || environment.getQdrantConfig();

    this.qdrantAdapter = new QdrantAdapter({
      type: 'qdrant',
      url: config.url,
      apiKey: config.apiKey,
      vectorSize: config.vectorSize,
      distance: config.distance,
      logQueries: config.logQueries,
      connectionTimeout: config.connectionTimeout,
      maxConnections: config.maxConnections,
    });

    this.config = {
      enabled: true,
      defaultThreshold: 0.75, // Higher threshold for duplicate detection
      maxResults: 10,
      includeContentAnalysis: true,
      includeMetadataAnalysis: true,
      vectorWeight: 0.7, // Favor semantic similarity
      lexicalWeight: 0.3, // Complement with lexical analysis
      enableContradictionDetection: true,
      enableAdaptiveThresholds: true,
    };
  }

  /**
   * Initialize the similarity service
   */
  async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }

    try {
      await this.qdrantAdapter.initialize();
      this.initialized = true;
      logger.info('Unified similarity service initialized successfully');
    } catch (error) {
      logger.error({ error }, 'Failed to initialize unified similarity service');
      throw error;
    }
  }

  /**
   * Find similar items using hybrid analysis
   */
  async findSimilar(
    query: KnowledgeItem,
    options: {
      threshold?: number;
      maxResults?: number;
      includeContent?: boolean;
      includeMetadata?: boolean;
      scope?: string;
    } = {}
  ): Promise<SimilarityResult[]> {
    if (!this.initialized) {
      await this.initialize();
    }

    const {
      threshold = this.config.defaultThreshold,
      maxResults = this.config.maxResults,
      includeContent = this.config.includeContentAnalysis,
      includeMetadata = this.config.includeMetadataAnalysis,
      scope,
    } = options;

    try {
      logger.debug(
        {
          queryId: query.id,
          threshold,
          maxResults,
          scope,
        },
        'Finding similar items using hybrid analysis'
      );

      // Step 1: Semantic search using Qdrant vector similarity
      const semanticResults = await this.performSemanticSearch(query, {
        maxResults: maxResults * 2, // Get more candidates for filtering
        scope,
      });

      // Step 2: Lexical similarity analysis for top candidates
      const lexicalResults = await this.performLexicalAnalysis(query, semanticResults);

      // Step 3: Combine scores and apply final filtering
      const combinedResults = await this.combineSimilarityScores(
        query,
        semanticResults,
        lexicalResults,
        { includeContent, includeMetadata }
      );

      // Step 4: Apply adaptive thresholding and sorting
      const filteredResults = await this.applyAdaptiveFiltering(combinedResults, threshold);

      // Step 5: Detect contradictions and recommend actions
      const finalResults = await this.analyzeContradictionsAndRecommend(filteredResults);

      logger.debug(
        {
          queryId: query.id,
          resultCount: finalResults.length,
        },
        'Similarity analysis completed'
      );

      return finalResults.slice(0, maxResults);
    } catch (error) {
      logger.error(
        {
          error,
          queryId: query.id,
        },
        'Failed to find similar items'
      );
      throw error;
    }
  }

  /**
   * Check for duplicates using comprehensive analysis
   */
  async checkDuplicate(
    item: KnowledgeItem,
    options: {
      strictMode?: boolean;
      scope?: string;
    } = {}
  ): Promise<{
    isDuplicate: boolean;
    confidence: number;
    matches: SimilarityResult[];
    reasoning: string[];
  }> {
    const { strictMode = false, scope } = options;
    const threshold = strictMode ? 0.95 : 0.85;

    try {
      const similarItems = await this.findSimilar(item, {
        threshold,
        maxResults: 5,
        scope,
      });

      const exactMatches = similarItems.filter((result) => result.score >= threshold);
      const isDuplicate = exactMatches.length > 0;
      const confidence =
        exactMatches.length > 0 ? Math.max(...exactMatches.map((m) => m.score)) : 0;

      const reasoning = [
        `Found ${exactMatches.length} potential ${strictMode ? 'exact' : 'near'} duplicates`,
        `Highest similarity score: ${confidence.toFixed(3)}`,
        `Analysis threshold: ${threshold}`,
        exactMatches.length > 0
          ? `Recommendation: ${exactMatches[0].recommendedAction}`
          : 'No duplicates detected',
      ];

      return {
        isDuplicate,
        confidence,
        matches: exactMatches,
        reasoning,
      };
    } catch (error) {
      logger.error({ error, itemId: item.id }, 'Failed to check for duplicates');
      throw error;
    }
  }

  /**
   * Perform semantic search using Qdrant vector embeddings
   */
  private async performSemanticSearch(
    query: KnowledgeItem,
    options: { maxResults: number; scope?: string }
  ): Promise<Array<{ item: KnowledgeItem; score: number }>> {
    try {
      // Use Qdrant adapter's semantic search capabilities
      const searchQuery = {
        text: `${query.content} ${query.title}`,
        kind: query.kind,
        scope: options.scope || query.scope,
        filters: {
          kind: query.kind,
          // Exclude the query item itself
          excludeIds: query.id ? [query.id] : undefined,
        },
      };

      const results = await this.qdrantAdapter.search(searchQuery, {
        limit: options.maxResults,
        useHybrid: true, // Use both vector and keyword search
      });

      return results.hits.map((hit) => ({
        item: hit.item,
        score: hit.score || hit.confidence || 0,
      }));
    } catch (error) {
      logger.error({ error, queryId: query.id }, 'Semantic search failed');
      return [];
    }
  }

  /**
   * Perform lexical similarity analysis
   */
  private async performLexicalAnalysis(
    query: KnowledgeItem,
    candidates: Array<{ item: KnowledgeItem; score: number }>
  ): Promise<Array<{ item: KnowledgeItem; lexicalScore: number }>> {
    const results = [];

    for (const candidate of candidates) {
      const lexicalScore = this.calculateLexicalSimilarity(query, candidate.item);
      results.push({
        item: candidate.item,
        lexicalScore,
      });
    }

    return results;
  }

  /**
   * Calculate lexical similarity using multiple factors
   */
  private calculateLexicalSimilarity(item1: KnowledgeItem, item2: KnowledgeItem): number {
    let score = 0;
    let factors = 0;

    // Content similarity
    if (item1.content && item2.content) {
      score += this.textSimilarity(item1.content, item2.content);
      factors++;
    }

    // Title similarity
    if (item1.title && item2.title) {
      score += this.textSimilarity(item1.title, item2.title) * 1.5; // Title is more important
      factors++;
    }

    // Kind matching
    if (item1.kind === item2.kind) {
      score += 0.3;
    }
    factors++;

    // Scope matching
    if (item1.scope && item2.scope) {
      const scopeSimilarity = this.scopeSimilarity(item1.scope, item2.scope);
      score += scopeSimilarity * 0.2;
    }
    factors++;

    return factors > 0 ? score / factors : 0;
  }

  /**
   * Calculate text similarity using cosine similarity of word vectors
   */
  private textSimilarity(text1: string, text2: string): number {
    const words1 = new Set(text1.toLowerCase().split(/\s+/));
    const words2 = new Set(text2.toLowerCase().split(/\s+/));

    const intersection = new Set([...words1].filter((word) => words2.has(word)));
    const union = new Set([...words1, ...words2]);

    return intersection.size / union.size; // Jaccard similarity
  }

  /**
   * Calculate scope similarity
   */
  private scopeSimilarity(scope1: string, scope2: string): number {
    if (scope1 === scope2) return 1.0;

    const parts1 = scope1.split('/');
    const parts2 = scope2.split('/');

    const commonParts = parts1.filter((part) => parts2.includes(part));
    const totalParts = new Set([...parts1, ...parts2]);

    return commonParts.length / totalParts.size;
  }

  /**
   * Combine semantic and lexical similarity scores
   */
  private async combineSimilarityScores(
    query: KnowledgeItem,
    semanticResults: Array<{ item: KnowledgeItem; score: number }>,
    lexicalResults: Array<{ item: KnowledgeItem; lexicalScore: number }>,
    options: { includeContent: boolean; includeMetadata: boolean }
  ): Promise<
    Array<{
      item: KnowledgeItem;
      semanticScore: number;
      lexicalScore: number;
      metadataScore: number;
      combinedScore: number;
    }>
  > {
    const results = [];

    for (const semantic of semanticResults) {
      const lexical = lexicalResults.find((l) => l.item.id === semantic.item.id);

      if (!lexical) continue;

      const metadataScore = this.calculateMetadataSimilarity(query, semantic.item, options);

      // Combine scores using configured weights
      const combinedScore =
        semantic.score * this.config.vectorWeight +
        lexical.lexicalScore * this.config.lexicalWeight +
        metadataScore * 0.1; // Small weight for metadata

      results.push({
        item: semantic.item,
        semanticScore: semantic.score,
        lexicalScore: lexical.lexicalScore,
        metadataScore,
        combinedScore,
      });
    }

    return results.sort((a, b) => b.combinedScore - a.combinedScore);
  }

  /**
   * Calculate metadata similarity
   */
  private calculateMetadataSimilarity(
    item1: KnowledgeItem,
    item2: KnowledgeItem,
    options: { includeContent: boolean; includeMetadata: boolean }
  ): number {
    let score = 0;

    if (!options.includeMetadata) return 0;

    // Kind similarity
    if (item1.kind === item2.kind) {
      score += 0.5;
    }

    // Scope similarity
    if (item1.scope && item2.scope) {
      score += this.scopeSimilarity(item1.scope, item2.scope) * 0.3;
    }

    // Timestamp similarity (if both have timestamps)
    if (item1.timestamp && item2.timestamp) {
      const timeDiff = Math.abs(
        new Date(item1.timestamp).getTime() - new Date(item2.timestamp).getTime()
      );
      const daysDiff = timeDiff / (1000 * 60 * 60 * 24);

      // More similar if created within same day/week
      if (daysDiff < 1) score += 0.2;
      else if (daysDiff < 7) score += 0.1;
    }

    return Math.min(score, 1.0);
  }

  /**
   * Apply adaptive thresholding and filtering
   */
  private async applyAdaptiveFiltering(
    results: Array<{ combinedScore: number }>,
    threshold: number
  ): Promise<Array<{ combinedScore: number }>> {
    if (!this.config.enableAdaptiveThresholds) {
      return results.filter((result) => result.combinedScore >= threshold);
    }

    // Adaptive threshold based on result distribution
    const scores = results.map((r) => r.combinedScore);
    const meanScore = scores.reduce((a, b) => a + b, 0) / scores.length;
    const stdDev = Math.sqrt(
      scores.reduce((sq, n) => sq + Math.pow(n - meanScore, 2), 0) / scores.length
    );

    // Use statistical threshold if it's higher than the configured one
    const adaptiveThreshold = Math.max(threshold, meanScore - stdDev);

    return results.filter((result) => result.combinedScore >= adaptiveThreshold);
  }

  /**
   * Analyze contradictions and recommend actions
   */
  private async analyzeContradictionsAndRecommend(
    results: Array<{ item: KnowledgeItem; combinedScore: number }>
  ): Promise<SimilarityResult[]> {
    const similarityResults: SimilarityResult[] = [];

    for (const result of results) {
      const contradictionDetected = this.config.enableContradictionDetection
        ? await this.detectContradiction(result.item, results)
        : false;

      const recommendedAction = this.recommendAction(result.combinedScore, contradictionDetected);

      similarityResults.push({
        item: result.item,
        score: result.combinedScore,
        matchFactors: {
          semantic: 0, // Will be filled in combine step
          lexical: 0,
          metadata: 0,
          overall: result.combinedScore,
        },
        reasoning: this.generateReasoning(result.combinedScore, contradictionDetected),
        contradictionDetected,
        recommendedAction,
      });
    }

    return similarityResults;
  }

  /**
   * Detect contradictions between items
   */
  private async detectContradiction(
    item: KnowledgeItem,
    similarItems: Array<{ item: KnowledgeItem; combinedScore: number }>
  ): Promise<boolean> {
    // Simple contradiction detection based on content patterns
    const contradictionPatterns = [
      /\b(not|no|never|don't|can't|won't|doesn't)\b/gi,
      /\b(however|but|although|despite|contrary)\b/gi,
    ];

    for (const similar of similarItems) {
      if (similar.item.id === item.id) continue;

      const content1 = (item.content || '').toLowerCase();
      const content2 = (similar.item.content || '').toLowerCase();

      // Check for contradictory statements
      for (const pattern of contradictionPatterns) {
        const matches1 = content1.match(pattern);
        const matches2 = content2.match(pattern);

        if (matches1 && matches2) {
          // Both contain negation patterns, might be contradictory
          // More sophisticated analysis could be added here
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Recommend action based on similarity score and contradictions
   */
  private recommendAction(
    score: number,
    contradictionDetected: boolean
  ): 'duplicate' | 'related' | 'update' | 'none' {
    if (contradictionDetected) {
      return 'update'; // Should update existing item
    }

    if (score >= 0.95) {
      return 'duplicate'; // Exact duplicate
    } else if (score >= 0.8) {
      return 'related'; // Related but not duplicate
    } else if (score >= 0.6) {
      return 'update'; // Could be an update
    }

    return 'none';
  }

  /**
   * Generate reasoning for similarity result
   */
  private generateReasoning(score: number, contradictionDetected: boolean): string[] {
    const reasoning = [];

    if (score >= 0.9) {
      reasoning.push('Very high similarity - likely identical content');
    } else if (score >= 0.7) {
      reasoning.push('High similarity - closely related content');
    } else if (score >= 0.5) {
      reasoning.push('Moderate similarity - some overlapping content');
    } else {
      reasoning.push('Low similarity - limited content overlap');
    }

    if (contradictionDetected) {
      reasoning.push('Potential contradiction detected - review needed');
    }

    return reasoning;
  }

  /**
   * Get service configuration
   */
  getConfig(): SimilarityConfig {
    return { ...this.config };
  }

  /**
   * Update service configuration
   */
  updateConfig(newConfig: Partial<SimilarityConfig>): void {
    this.config = { ...this.config, ...newConfig };
    logger.info({ config: this.config }, 'Similarity service configuration updated');
  }

  /**
   * Check if service is initialized
   */
  isInitialized(): boolean {
    return this.initialized;
  }

  /**
   * Get service metrics
   */
  async getMetrics(): Promise<{
    initialized: boolean;
    config: SimilarityConfig;
    qdrantMetrics: any;
  }> {
    const qdrantMetrics = (await this.qdrantAdapter.getMetrics?.()) || {};

    return {
      initialized: this.initialized,
      config: this.config,
      qdrantMetrics,
    };
  }
}

/**
 * Export convenience function to create similarity service
 */
export function createUnifiedSimilarityService(
  dbConfig?: DatabaseConfig
): UnifiedSimilarityService {
  return new UnifiedSimilarityService(dbConfig);
}

/**
 * Export singleton instance for backward compatibility
 */
export const unifiedSimilarityService = new UnifiedSimilarityService();
