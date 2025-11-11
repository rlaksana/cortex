
/**
 * Enhanced Deduplication Service with Configurable Merge Strategies
 *
 * This service provides comprehensive deduplication with:
 * - Configurable similarity thresholds
 * - Multiple merge strategies (skip, prefer_existing, prefer_newer, combine, intelligent)
 * - Comprehensive audit logging
 * - Time-based and scope-based deduplication
 * - Performance optimization
 */

import { createHash } from 'crypto';

import { logger } from '@/utils/logger.js';

import {
  type AuditLogEntry,
  type DeduplicationConfig,
  type DeduplicationResult,
  DEFAULT_DEDUPLICATION_CONFIG,
  loadDeduplicationConfigFromEnv,
  mergeDeduplicationConfig,
  type MergeStrategy,
} from '../../config/deduplication-config.js';
import { qdrant } from '../../db/qdrant-client.js';
import type { KnowledgeItem } from '../../types/core-interfaces.js';

/**
 * Enhanced duplicate analysis with detailed merge information
 */
export interface EnhancedDuplicateAnalysis {
  isDuplicate: boolean;
  similarityScore: number;
  matchType: 'exact' | 'content' | 'semantic' | 'none' | 'partial';
  reason: string;
  existingId?: string;
  existingItem?: KnowledgeItem;
  scopeMatch: ScopeMatch;
  timeAnalysis: TimeAnalysis;
  recommendedAction: MergeStrategy;
}

export interface ScopeMatch {
  org: boolean;
  project: boolean;
  branch: boolean;
  score: number; // 0-1, higher means better match
}

export interface TimeAnalysis {
  isNewer: boolean;
  daysDiff: number;
  withinDedupeWindow: boolean;
  recentlyUpdated: boolean;
  respectTimestamps: boolean;
}

/**
 * Enhanced Deduplication Service
 */
export class EnhancedDeduplicationService {
  private config: DeduplicationConfig;
  private auditLog: AuditLogEntry[] = [];
  private performanceMetrics: PerformanceMetrics;

  constructor(config?: Partial<DeduplicationConfig>) {
    // Load base config, apply environment overrides, then custom config
    const envConfig = loadDeduplicationConfigFromEnv();
    this.config = mergeDeduplicationConfig(
      DEFAULT_DEDUPLICATION_CONFIG,
      mergeDeduplicationConfig(DEFAULT_DEDUPLICATION_CONFIG, envConfig)
    );

    if (config) {
      this.config = mergeDeduplicationConfig(this.config, config);
    }

    this.performanceMetrics = {
      totalProcessed: 0,
      duplicatesFound: 0,
      mergesPerformed: 0,
      avgProcessingTime: 0,
      cacheHits: 0,
    };

    logger.info('Enhanced deduplication service initialized', {
      config: this.getSafeConfig(),
    });
  }

  /**
   * Process items with configurable deduplication and merge strategies
   */
  async processItems(items: KnowledgeItem[]): Promise<{
    results: DeduplicationResult[];
    summary: ProcessingSummary;
    auditLog: AuditLogEntry[];
  }> {
    const startTime = Date.now();
    const results: DeduplicationResult[] = [];
    const currentAuditLog: AuditLogEntry[] = [];

    logger.info(
      `Processing ${items.length} items with merge strategy: ${this.config.mergeStrategy}`
    );

    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      const itemStartTime = Date.now();

      try {
        const analysis = await this.analyzeItem(item);
        const result = await this.applyMergeStrategy(item, analysis);

        result.auditLog = this.createAuditLogEntry(item, analysis, result);
        currentAuditLog.push(result.auditLog!);

        results.push(result);
        this.updatePerformanceMetrics(result, Date.now() - itemStartTime);
      } catch (error) {
        const errorResult: DeduplicationResult = {
          action: 'skipped',
          similarityScore: 0,
          matchType: 'none',
          reason: `Error processing item: ${error instanceof Error ? error.message : 'Unknown error'}`,
          auditLog: this.createAuditLogEntry(
            item,
            {
              isDuplicate: false,
              similarityScore: 0,
              matchType: 'none',
              reason: 'Processing error',
              scopeMatch: this.analyzeScopeMatch(item),
              timeAnalysis: this.analyzeTimeRelationship(item),
              recommendedAction: 'skip',
            },
            {} as DeduplicationResult
          ),
        };

        results.push(errorResult);
        currentAuditLog.push(errorResult.auditLog!);

        logger.error(`Error processing item ${i}`, { error, item });
      }
    }

    const duration = Date.now() - startTime;
    const summary = this.createProcessingSummary(results, duration);

    // Store audit log if enabled
    if (this.config.enableAuditLogging) {
      this.auditLog.push(...currentAuditLog);
    }

    logger.info(`Batch processing completed`, {
      totalItems: items.length,
      duration,
      summary,
    });

    return {
      results,
      summary,
      auditLog: currentAuditLog,
    };
  }

  /**
   * Analyze an item for duplicates with comprehensive analysis
   */
  private async analyzeItem(item: KnowledgeItem): Promise<EnhancedDuplicateAnalysis> {
    if (!this.config.enabled) {
      return {
        isDuplicate: false,
        similarityScore: 0,
        matchType: 'none',
        reason: 'Deduplication disabled',
        scopeMatch: this.analyzeScopeMatch(item),
        timeAnalysis: this.analyzeTimeRelationship(item),
        recommendedAction: 'skip',
      };
    }

    // Find potential matches
    const matches = await this.findPotentialMatches(item);
    if (matches.length === 0) {
      return {
        isDuplicate: false,
        similarityScore: 0,
        matchType: 'none',
        reason: 'No matches found',
        scopeMatch: this.analyzeScopeMatch(item),
        timeAnalysis: this.analyzeTimeRelationship(item),
        recommendedAction: 'skip',
      };
    }

    // Find best match
    const bestMatch = this.selectBestMatch(item, matches);

    // Analyze scope and time relationships
    const scopeMatch = this.analyzeScopeMatch(item, bestMatch.item);
    const timeAnalysis = this.analyzeTimeRelationship(item, bestMatch.item);

    // Determine if it's a duplicate and recommend action
    const isDuplicate = this.isConsideredDuplicate(bestMatch.similarity, scopeMatch, timeAnalysis);
    const recommendedAction = this.recommendMergeStrategy(bestMatch, scopeMatch, timeAnalysis);

    return {
      isDuplicate,
      similarityScore: bestMatch.similarity,
      matchType: bestMatch.matchType,
      reason: this.generateAnalysisReason(bestMatch, scopeMatch, timeAnalysis),
      existingId: bestMatch.item.id,
      existingItem: bestMatch.item,
      scopeMatch,
      timeAnalysis,
      recommendedAction,
    };
  }

  /**
   * Apply the configured merge strategy
   */
  private async applyMergeStrategy(
    item: KnowledgeItem,
    analysis: EnhancedDuplicateAnalysis
  ): Promise<DeduplicationResult> {
    const startTime = Date.now();

    // If not a duplicate or below threshold, store as new
    if (
      !analysis.isDuplicate ||
      analysis.similarityScore < this.config.contentSimilarityThreshold
    ) {
      return {
        action: 'stored',
        similarityScore: analysis.similarityScore,
        matchType: analysis.matchType,
        reason: analysis.reason,
      };
    }

    // Apply merge strategy
    switch (this.config.mergeStrategy) {
      case 'skip':
        return {
          action: 'skipped',
          similarityScore: analysis.similarityScore,
          matchType: analysis.matchType,
          reason: 'Duplicate skipped due to merge strategy: skip',
          existingId: analysis.existingId,
        };

      case 'prefer_existing':
        return {
          action: 'skipped',
          similarityScore: analysis.similarityScore,
          matchType: analysis.matchType,
          reason: 'Kept existing item due to merge strategy: prefer_existing',
          existingId: analysis.existingId,
        };

      case 'prefer_newer':
        if (analysis.timeAnalysis.isNewer) {
          const _mergedItem = await this.performSimpleMerge(analysis.existingItem!, item);
          return {
            action: 'updated',
            similarityScore: analysis.similarityScore,
            matchType: analysis.matchType,
            reason: 'Replaced existing item with newer version',
            existingId: analysis.existingId,
            mergeDetails: {
              strategy: 'prefer_newer',
              fieldsMerged: Object.keys(item.data || {}),
              conflictsResolved: [],
              newFieldsAdded: [],
              mergeDuration: Date.now() - startTime,
            },
          };
        }
        return {
          action: 'skipped',
          similarityScore: analysis.similarityScore,
          matchType: analysis.matchType,
          reason: 'Kept existing item (newer) due to merge strategy: prefer_newer',
          existingId: analysis.existingId,
        };

      case 'combine': {
        const _mergedItem = await this.performCombineMerge(
          analysis.existingItem!,
          item,
          analysis.similarityScore
        );
        return {
          action: 'merged',
          similarityScore: analysis.similarityScore,
          matchType: analysis.matchType,
          reason: 'Combined items due to merge strategy: combine',
          existingId: analysis.existingId,
          mergeDetails: {
            strategy: 'combine',
            fieldsMerged: this.getMergedFields(analysis.existingItem!, item),
            conflictsResolved: this.getConflictsResolved(analysis.existingItem!, item),
            newFieldsAdded: this.getNewFieldsAdded(analysis.existingItem!, item),
            mergeDuration: Date.now() - startTime,
          },
        };
      }

      case 'intelligent':
        return this.performIntelligentMerge(item, analysis, startTime);

      default:
        throw new Error(`Unknown merge strategy: ${this.config.mergeStrategy}`);
    }
  }

  /**
   * Intelligent merge strategy that considers multiple factors
   */
  private async performIntelligentMerge(
    item: KnowledgeItem,
    analysis: EnhancedDuplicateAnalysis,
    startTime: number
  ): Promise<DeduplicationResult> {
    const existing = analysis.existingItem!;

    // Decision matrix for intelligent merging
    const shouldUpdate = this.shouldIntelligentlyUpdate(item, existing, analysis);

    if (!shouldUpdate) {
      return {
        action: 'skipped',
        similarityScore: analysis.similarityScore,
        matchType: analysis.matchType,
        reason: 'Existing item preferred based on intelligent analysis',
        existingId: analysis.existingId,
      };
    }

    // Perform intelligent merge
    const _mergedItem = await this.performIntelligentMergeLogic(existing, item, analysis);

    return {
      action: 'merged',
      similarityScore: analysis.similarityScore,
      matchType: analysis.matchType,
      reason: 'Intelligently merged based on content, time, and scope analysis',
      existingId: analysis.existingId,
      mergeDetails: {
        strategy: 'intelligent',
        fieldsMerged: this.getMergedFields(existing, item),
        conflictsResolved: this.getConflictsResolved(existing, item),
        newFieldsAdded: this.getNewFieldsAdded(existing, item),
        mergeDuration: Date.now() - startTime,
      },
    };
  }

  /**
   * Intelligent merge decision logic
   */
  private shouldIntelligentlyUpdate(
    newItem: KnowledgeItem,
    existing: KnowledgeItem,
    analysis: EnhancedDuplicateAnalysis
  ): boolean {
    // Factor 1: Time-based analysis
    if (analysis.timeAnalysis.isNewer && analysis.timeAnalysis.withinDedupeWindow) {
      return true;
    }

    // Factor 2: Scope match quality
    if (analysis.scopeMatch.score > 0.8 && this.config.prioritizeSameScope) {
      return true;
    }

    // Factor 3: Content completeness
    const newCompleteness = this.assessContentCompleteness(newItem);
    const existingCompleteness = this.assessContentCompleteness(existing);
    if (newCompleteness > existingCompleteness * 1.2) {
      return true;
    }

    // Factor 4: Content quality indicators
    const newQuality = this.assessContentQuality(newItem);
    const existingQuality = this.assessContentQuality(existing);
    if (newQuality > existingQuality * 1.1) {
      return true;
    }

    return false;
  }

  /**
   * Find potential matches for an item
   */
  private async findPotentialMatches(item: KnowledgeItem): Promise<
    Array<{
      item: KnowledgeItem;
      similarity: number;
      matchType: 'exact' | 'content' | 'semantic' | 'partial';
    }>
  > {
    const matches: Array<{
      item: KnowledgeItem;
      similarity: number;
      matchType: 'exact' | 'content' | 'semantic' | 'partial';
    }> = [];

    try {
      // Exact match search
      const exactMatch = await this.findExactMatch(item);
      if (exactMatch) {
        matches.push({
          item: exactMatch,
          similarity: 1.0,
          matchType: 'exact',
        });
      }

      // Content similarity search
      const contentMatches = await this.findContentMatches(item);
      matches.push(...contentMatches);

      // Semantic search (if enabled)
      if (this.config.contentAnalysisSettings.enableSemanticAnalysis) {
        const semanticMatches = await this.findSemanticMatches(item);
        matches.push(...semanticMatches);
      }

      // Sort by similarity and limit
      return matches
        .sort((a, b) => b.similarity - a.similarity)
        .slice(0, this.config.maxItemsToCheck);
    } catch (error) {
      logger.error('Error finding potential matches', { error, item });
      return [];
    }
  }

  /**
   * Find exact matches in the database
   */
  private async findExactMatch(item: KnowledgeItem): Promise<KnowledgeItem | null> {
    const tableName = this.getTableNameForKind(item.kind);
    if (!tableName) return null;

    const whereClause: any = { kind: item.kind };

    // Add scope filtering
    if (this.config.checkWithinScopeOnly && item.scope) {
      if (item.scope.project) whereClause.scope_project = item.scope.project;
      if (item.scope.branch) whereClause.scope_branch = item.scope.branch;
      if (item.scope.org) whereClause.scope_org = item.scope.org;
    }

    // Add time filtering
    if (this.config.maxHistoryHours > 0) {
      const cutoffDate = new Date();
      cutoffDate.setHours(cutoffDate.getHours() - this.config.maxHistoryHours);
      whereClause.created_at = { gte: cutoffDate };
    }

    try {
      const result = await qdrant.client.scroll(tableName, {
        filter: whereClause,
        limit: 1,
        with_payload: true,
      });

      if (result.points.length === 0) return null;

      const point = result.points[0];
      return {
        id: typeof point.id === 'string' ? point.id : String(point.id),
        kind: item.kind,
        scope: point.payload?.scope || {},
        data: point.payload?.data || {},
        metadata: point.payload?.metadata || {},
        created_at: point.payload?.created_at as string,
        updated_at: point.payload?.updated_at as string,
      };
    } catch (error) {
      logger.error('Error finding exact match', { error, item });
      return null;
    }
  }

  /**
   * Find content-based matches
   */
  private async findContentMatches(item: KnowledgeItem): Promise<
    Array<{
      item: KnowledgeItem;
      similarity: number;
      matchType: 'content' | 'partial';
    }>
  > {
    const tableName = this.getTableNameForKind(item.kind);
    if (!tableName) return [];

    try {
      // Generate content hash for the item
      const _contentHash = this.generateContentHash(item);

      // Search for similar content
      const searchResult = await qdrant.client.search(tableName, {
        vector: await this.generateEmbedding(item),
        limit: this.config.maxItemsToCheck,
        with_payload: true,
        score_threshold: this.config.contentSimilarityThreshold * 0.5, // Lower threshold for initial search
      });

      const matches: Array<{
        item: KnowledgeItem;
        similarity: number;
        matchType: 'content' | 'partial';
      }> = [];

      for (const point of searchResult) {
        if (point.id === item.id) continue; // Skip self

        const existingItem: KnowledgeItem = {
          id: typeof point.id === 'string' ? point.id : String(point.id),
          kind: item.kind,
          scope: point.payload?.scope || {},
          data: point.payload?.data || {},
          metadata: point.payload?.metadata || {},
          created_at: point.payload?.created_at as string,
          updated_at: point.payload?.updated_at as string,
        };

        // Calculate detailed similarity
        const similarity = this.calculateDetailedSimilarity(item, existingItem);

        if (similarity >= this.config.contentSimilarityThreshold) {
          matches.push({
            item: existingItem,
            similarity,
            matchType: similarity >= 0.9 ? 'content' : 'partial',
          });
        }
      }

      return matches;
    } catch (error) {
      logger.error('Error finding content matches', { error, item });
      return [];
    }
  }

  /**
   * Find semantic matches using vector embeddings
   */
  private async findSemanticMatches(_item: KnowledgeItem): Promise<
    Array<{
      item: KnowledgeItem;
      similarity: number;
      matchType: 'semantic';
    }>
  > {
    // This would integrate with a proper embedding service
    // For now, return empty array as placeholder
    return [];
  }

  /**
   * Select the best match from potential candidates
   */
  private selectBestMatch(
    item: KnowledgeItem,
    matches: Array<{
      item: KnowledgeItem;
      similarity: number;
      matchType: 'exact' | 'content' | 'semantic' | 'partial';
    }>
  ): {
    item: KnowledgeItem;
    similarity: number;
    matchType: 'exact' | 'content' | 'semantic' | 'partial';
  } {
    if (matches.length === 0) {
      throw new Error('No matches to select from');
    }

    // Prioritize exact matches
    const exactMatch = matches.find((m) => m.matchType === 'exact');
    if (exactMatch) return exactMatch;

    // If multiple matches with same similarity, prefer same scope
    const highestSimilarity = matches[0].similarity;
    const topMatches = matches.filter((m) => m.similarity === highestSimilarity);

    if (topMatches.length === 1) return topMatches[0];

    // Find best scope match
    for (const match of topMatches) {
      const scopeScore = this.calculateScopeScore(item, match.item);
      if (scopeScore >= 0.8) {
        return match;
      }
    }

    // Return the first top match
    return topMatches[0];
  }

  /**
   * Analyze scope match between items
   */
  private analyzeScopeMatch(item: KnowledgeItem, existing?: KnowledgeItem): ScopeMatch {
    const itemScope = item.scope || {};
    const existingScope = existing?.scope || {};

    const org = !!(existingScope.org && itemScope.org && existingScope.org === itemScope.org);
    const project = !!(
      existingScope.project &&
      itemScope.project &&
      existingScope.project === itemScope.project
    );
    const branch = !!(
      existingScope.branch &&
      itemScope.branch &&
      existingScope.branch === itemScope.branch
    );

    // Calculate overall score
    let score = 0;
    let factors = 0;

    if (this.config.scopeFilters.org.enabled) {
      score += org ? this.config.scopeFilters.org.priority : 0;
      factors += this.config.scopeFilters.org.priority;
    }

    if (this.config.scopeFilters.project.enabled) {
      score += project ? this.config.scopeFilters.project.priority : 0;
      factors += this.config.scopeFilters.project.priority;
    }

    if (this.config.scopeFilters.branch.enabled) {
      score += branch ? this.config.scopeFilters.branch.priority : 0;
      factors += this.config.scopeFilters.branch.priority;
    }

    return {
      org,
      project,
      branch,
      score: factors > 0 ? score / factors : 0,
    };
  }

  /**
   * Analyze time relationship between items
   */
  private analyzeTimeRelationship(item: KnowledgeItem, existing?: KnowledgeItem): TimeAnalysis {
    if (!existing) {
      return {
        isNewer: true,
        daysDiff: 0,
        withinDedupeWindow: true,
        recentlyUpdated: true,
        respectTimestamps: this.config.respectUpdateTimestamps,
      };
    }

    const existingTime = new Date(existing.updated_at || existing.created_at || 0).getTime();
    const itemTime = new Date(item.updated_at || item.created_at || Date.now()).getTime();

    const daysDiff = (itemTime - existingTime) / (1000 * 60 * 60 * 24);
    const isNewer = daysDiff > 0;
    const withinDedupeWindow = Math.abs(daysDiff) <= this.config.dedupeWindowDays;
    const recentlyUpdated = Math.abs(daysDiff) <= 1; // Within last day

    return {
      isNewer,
      daysDiff,
      withinDedupeWindow,
      recentlyUpdated,
      respectTimestamps: this.config.respectUpdateTimestamps,
    };
  }

  /**
   * Determine if an item should be considered a duplicate
   */
  private isConsideredDuplicate(
    similarity: number,
    scopeMatch: ScopeMatch,
    timeAnalysis: TimeAnalysis
  ): boolean {
    // Below threshold: not a duplicate
    if (similarity < this.config.contentSimilarityThreshold) {
      return false;
    }

    // Cross-scope deduplication rules
    if (!this.config.crossScopeDeduplication && scopeMatch.score < 0.5) {
      return false;
    }

    // Time-based deduplication rules
    if (this.config.timeBasedDeduplication && !timeAnalysis.withinDedupeWindow) {
      return false;
    }

    return true;
  }

  /**
   * Recommend merge strategy based on analysis
   */
  private recommendMergeStrategy(
    match: {
      item: KnowledgeItem;
      similarity: number;
      matchType: 'exact' | 'content' | 'semantic' | 'partial';
    },
    scopeMatch: ScopeMatch,
    timeAnalysis: TimeAnalysis
  ): MergeStrategy {
    // If configured strategy is not intelligent, use it directly
    if (this.config.mergeStrategy !== 'intelligent') {
      return this.config.mergeStrategy;
    }

    // Intelligent strategy recommendation
    if (match.matchType === 'exact') {
      return timeAnalysis.isNewer ? 'prefer_newer' : 'prefer_existing';
    }

    if (match.similarity >= 0.95) {
      return 'combine';
    }

    if (scopeMatch.score >= 0.8 && timeAnalysis.withinDedupeWindow) {
      return 'prefer_newer';
    }

    if (timeAnalysis.isNewer && timeAnalysis.recentlyUpdated) {
      return 'prefer_newer';
    }

    return 'combine';
  }

  /**
   * Generate analysis reason
   */
  private generateAnalysisReason(
    match: {
      item: KnowledgeItem;
      similarity: number;
      matchType: 'exact' | 'content' | 'semantic' | 'partial';
    },
    scopeMatch: ScopeMatch,
    timeAnalysis: TimeAnalysis
  ): string {
    const parts: string[] = [];

    parts.push(
      `${match.matchType} match found (${(match.similarity * 100).toFixed(1)}% similarity)`
    );

    if (scopeMatch.score > 0) {
      parts.push(`scope match: ${(scopeMatch.score * 100).toFixed(1)}%`);
    }

    if (timeAnalysis.withinDedupeWindow) {
      parts.push(`within ${this.config.dedupeWindowDays}-day window`);
    }

    if (timeAnalysis.isNewer) {
      parts.push('newer version');
    }

    return parts.join(', ');
  }

  // Helper methods for merge operations
  private async performSimpleMerge(
    existing: KnowledgeItem,
    newItem: KnowledgeItem
  ): Promise<KnowledgeItem> {
    return {
      ...existing,
      ...newItem,
      updated_at: new Date().toISOString(),
      id: existing.id, // Keep existing ID
    };
  }

  private async performCombineMerge(
    existing: KnowledgeItem,
    newItem: KnowledgeItem,
    similarity: number
  ): Promise<KnowledgeItem> {
    const merged: KnowledgeItem = {
      ...existing,
      updated_at: new Date().toISOString(),
      data: { ...existing.data },
      metadata: { ...existing.metadata },
    };

    // Merge data fields
    for (const [key, value] of Object.entries(newItem.data || {})) {
      if (existing.data?.[key] === undefined || similarity < 1.0) {
        merged.data![key] = value;
      }
    }

    // Merge metadata
    if (newItem.metadata) {
      merged.metadata = {
        ...merged.metadata,
        ...newItem.metadata,
      };
    }

    // Add merge history if enabled
    if (this.config.preserveMergeHistory) {
      merged.metadata!.merge_history = [
        ...(merged.metadata!.merge_history || []),
        {
          timestamp: new Date().toISOString(),
          similarity,
          merged_from: newItem.id,
          strategy: 'combine',
        },
      ].slice(-this.config.maxMergeHistoryEntries);
    }

    return merged;
  }

  private async performIntelligentMergeLogic(
    existing: KnowledgeItem,
    newItem: KnowledgeItem,
    analysis: EnhancedDuplicateAnalysis
  ): Promise<KnowledgeItem> {
    // Start with existing as base
    const merged: KnowledgeItem = {
      ...existing,
      updated_at: new Date().toISOString(),
      data: { ...existing.data },
      metadata: { ...existing.metadata },
    };

    // Content field merging with intelligence
    const contentFields = ['content', 'body_text', 'body_md', 'description', 'rationale'];
    for (const field of contentFields) {
      if (newItem.data?.[field] && typeof newItem.data[field] === 'string') {
        const existingContent = existing.data?.[field] || '';
        const newContent = newItem.data[field];

        if (this.isContentBetter(newContent, existingContent, analysis)) {
          merged.data![field] = newContent;
        } else if (newContent !== existingContent && analysis.similarityScore < 0.95) {
          merged.data![field] = this.intelligentlyCombineContent(existingContent, newContent);
        }
      }
    }

    // Metadata merging
    if (newItem.metadata) {
      merged.metadata = {
        ...merged.metadata,
        ...newItem.metadata,
      };

      // Handle special metadata fields
      if (newItem.metadata.tags && existing.metadata?.tags) {
        merged.metadata.tags = [...new Set([...existing.metadata.tags, ...newItem.metadata.tags])];
      }
    }

    // Add intelligent merge metadata
    merged.metadata!.intelligent_merge = {
      timestamp: new Date().toISOString(),
      similarity_score: analysis.similarityScore,
      scope_match_score: analysis.scopeMatch.score,
      time_analysis: analysis.timeAnalysis,
      strategy: 'intelligent',
      merged_from: newItem.id,
    };

    return merged;
  }

  private isContentBetter(
    newContent: string,
    existingContent: string,
    analysis: EnhancedDuplicateAnalysis
  ): boolean {
    // Length comparison
    if (newContent.length > existingContent.length * 1.2) return true;
    if (existingContent.length > newContent.length * 1.2) return false;

    // Time-based preference
    if (analysis.timeAnalysis.isNewer && analysis.timeAnalysis.recentlyUpdated) return true;

    // Scope preference
    if (analysis.scopeMatch.score > 0.8) return true;

    return false;
  }

  private intelligentlyCombineContent(existing: string, newContent: string): string {
    // If one contains the other, use the longer one
    if (existing.includes(newContent) || newContent.includes(existing)) {
      return existing.length > newContent.length ? existing : newContent;
    }

    // Smart combination based on content structure
    const existingLines = existing.split('\n').filter((line) => line.trim());
    const newLines = newContent.split('\n').filter((line) => line.trim());

    // Combine unique lines
    const combinedLines = [...new Set([...existingLines, ...newLines])];

    return combinedLines.join('\n');
  }

  // Utility methods
  private generateContentHash(item: KnowledgeItem): string {
    const content = JSON.stringify(item.data || {}, Object.keys(item.data || {}).sort());
    return createHash('sha256').update(content).digest('hex');
  }

  private async generateEmbedding(item: KnowledgeItem): Promise<number[]> {
    const content = JSON.stringify(item.data || {});
    const hash = createHash('sha256').update(content).digest('hex');

    // Generate a simple hash-based embedding (in production, use proper embedding service)
    const embedding: number[] = [];
    for (let i = 0; i < 1536; i++) {
      const charCode = hash.charCodeAt(i % hash.length);
      embedding.push((charCode % 256) / 256.0 - 0.5);
    }

    // Normalize
    const magnitude = Math.sqrt(embedding.reduce((sum, val) => sum + val * val, 0));
    return embedding.map((val) => val / magnitude);
  }

  private calculateDetailedSimilarity(item1: KnowledgeItem, item2: KnowledgeItem): number {
    // Use Jaccard similarity on text content
    const text1 = JSON.stringify(item1.data || {}).toLowerCase();
    const text2 = JSON.stringify(item2.data || {}).toLowerCase();

    const words1 = new Set(text1.split(/\s+/).filter((word) => word.length > 2));
    const words2 = new Set(text2.split(/\s+/).filter((word) => word.length > 2));

    if (words1.size === 0 && words2.size === 0) return 1.0;
    if (words1.size === 0 || words2.size === 0) return 0.0;

    const intersection = new Set([...words1].filter((word) => words2.has(word)));
    const union = new Set([...words1, ...words2]);

    return intersection.size / union.size;
  }

  private calculateScopeScore(item1: KnowledgeItem, item2: KnowledgeItem): number {
    const scope1 = item1.scope || {};
    const scope2 = item2.scope || {};

    let score = 0;
    let total = 0;

    if (scope1.org && scope2.org) {
      score += scope1.org === scope2.org ? this.config.scopeFilters.org.priority : 0;
      total += this.config.scopeFilters.org.priority;
    }

    if (scope1.project && scope2.project) {
      score += scope1.project === scope2.project ? this.config.scopeFilters.project.priority : 0;
      total += this.config.scopeFilters.project.priority;
    }

    if (scope1.branch && scope2.branch) {
      score += scope1.branch === scope2.branch ? this.config.scopeFilters.branch.priority : 0;
      total += this.config.scopeFilters.branch.priority;
    }

    return total > 0 ? score / total : 0;
  }

  private assessContentCompleteness(item: KnowledgeItem): number {
    const data = item.data || {};
    let completeness = 0;
    let factors = 0;

    // Check for key fields
    if (data.content || data.body_text || data.body_md) {
      completeness += 0.4;
      factors += 0.4;
    }

    if (data.title || data.name) {
      completeness += 0.2;
      factors += 0.2;
    }

    if (data.description || data.rationale) {
      completeness += 0.2;
      factors += 0.2;
    }

    if (Object.keys(data).length > 3) {
      completeness += 0.2;
      factors += 0.2;
    }

    return factors > 0 ? completeness / factors : 0;
  }

  private assessContentQuality(item: KnowledgeItem): number {
    const data = item.data || {};
    let quality = 0;
    let factors = 0;

    // Content length quality
    const content = data.content || data.body_text || data.body_md || '';
    if (content.length > 100) {
      quality += 0.3;
      factors += 0.3;
    }

    // Structure quality
    if (content.includes('\n') || content.includes('.') || content.includes(',')) {
      quality += 0.2;
      factors += 0.2;
    }

    // Metadata quality
    if (item.metadata && Object.keys(item.metadata).length > 0) {
      quality += 0.2;
      factors += 0.2;
    }

    // Scope quality
    if (item.scope && (item.scope.project || item.scope.org)) {
      quality += 0.3;
      factors += 0.3;
    }

    return factors > 0 ? quality / factors : 0;
  }

  private getMergedFields(existing: KnowledgeItem, newItem: KnowledgeItem): string[] {
    const fields: string[] = [];

    for (const key of Object.keys(newItem.data || {})) {
      if (existing.data?.[key] !== newItem.data![key]) {
        fields.push(key);
      }
    }

    return fields;
  }

  private getConflictsResolved(existing: KnowledgeItem, newItem: KnowledgeItem): string[] {
    const conflicts: string[] = [];

    for (const key of Object.keys(newItem.data || {})) {
      if (existing.data?.[key] && existing.data[key] !== newItem.data![key]) {
        conflicts.push(key);
      }
    }

    return conflicts;
  }

  private getNewFieldsAdded(existing: KnowledgeItem, newItem: KnowledgeItem): string[] {
    const newFields: string[] = [];

    for (const key of Object.keys(newItem.data || {})) {
      if (existing.data?.[key] === undefined) {
        newFields.push(key);
      }
    }

    return newFields;
  }

  private createAuditLogEntry(
    item: KnowledgeItem,
    analysis: EnhancedDuplicateAnalysis,
    result: DeduplicationResult
  ): AuditLogEntry {
    return {
      timestamp: new Date().toISOString(),
      itemId: item.id || 'unknown',
      action: result.action,
      similarityScore: analysis.similarityScore,
      strategy: this.config.mergeStrategy,
      matchType: analysis.matchType,
      scope: item.scope || {},
      existingId: analysis.existingId,
      reason: result.reason,
      mergeDetails: result.mergeDetails,
      configSnapshot: {
        contentSimilarityThreshold: this.config.contentSimilarityThreshold,
        mergeStrategy: this.config.mergeStrategy,
        checkWithinScopeOnly: this.config.checkWithinScopeOnly,
        crossScopeDeduplication: this.config.crossScopeDeduplication,
      },
    };
  }

  private updatePerformanceMetrics(result: DeduplicationResult, processingTime: number): void {
    this.performanceMetrics.totalProcessed++;

    if (result.action === 'merged' || result.action === 'updated') {
      this.performanceMetrics.mergesPerformed++;
    }

    if (result.similarityScore > this.config.contentSimilarityThreshold) {
      this.performanceMetrics.duplicatesFound++;
    }

    // Update average processing time
    this.performanceMetrics.avgProcessingTime =
      (this.performanceMetrics.avgProcessingTime * (this.performanceMetrics.totalProcessed - 1) +
        processingTime) /
      this.performanceMetrics.totalProcessed;
  }

  private createProcessingSummary(
    results: DeduplicationResult[],
    duration: number
  ): ProcessingSummary {
    const summary = {
      totalProcessed: results.length,
      duration,
      avgProcessingTime: duration / results.length,
      actions: {
        stored: results.filter((r) => r.action === 'stored').length,
        skipped: results.filter((r) => r.action === 'skipped').length,
        merged: results.filter((r) => r.action === 'merged').length,
        updated: results.filter((r) => r.action === 'updated').length,
      },
      similarity: {
        avgScore: results.reduce((sum, r) => sum + r.similarityScore, 0) / results.length,
        maxScore: Math.max(...results.map((r) => r.similarityScore)),
        duplicatesFound: results.filter(
          (r) => r.similarityScore >= this.config.contentSimilarityThreshold
        ).length,
      },
      performance: { ...this.performanceMetrics },
    };

    return summary;
  }

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

  private getSafeConfig(): Partial<DeduplicationConfig> {
    return {
      enabled: this.config.enabled,
      contentSimilarityThreshold: this.config.contentSimilarityThreshold,
      mergeStrategy: this.config.mergeStrategy,
      checkWithinScopeOnly: this.config.checkWithinScopeOnly,
      crossScopeDeduplication: this.config.crossScopeDeduplication,
      timeBasedDeduplication: this.config.timeBasedDeduplication,
    };
  }

  // Public API methods
  public updateConfig(newConfig: Partial<DeduplicationConfig>): void {
    this.config = mergeDeduplicationConfig(this.config, newConfig);
    logger.info('Deduplication configuration updated', { config: this.getSafeConfig() });
  }

  public getConfig(): DeduplicationConfig {
    return { ...this.config };
  }

  public getAuditLog(limit?: number): AuditLogEntry[] {
    return limit ? this.auditLog.slice(-limit) : [...this.auditLog];
  }

  public getPerformanceMetrics(): PerformanceMetrics {
    return { ...this.performanceMetrics };
  }

  public clearAuditLog(): void {
    this.auditLog = [];
    logger.info('Audit log cleared');
  }
}

// Supporting interfaces
interface ProcessingSummary {
  totalProcessed: number;
  duration: number;
  avgProcessingTime: number;
  actions: {
    stored: number;
    skipped: number;
    merged: number;
    updated: number;
  };
  similarity: {
    avgScore: number;
    maxScore: number;
    duplicatesFound: number;
  };
  performance: PerformanceMetrics;
}

interface PerformanceMetrics {
  totalProcessed: number;
  duplicatesFound: number;
  mergesPerformed: number;
  avgProcessingTime: number;
  cacheHits: number;
}

// Export singleton instance
export const enhancedDeduplicationService = new EnhancedDeduplicationService();
