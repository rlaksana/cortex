/**
 * Intelligent Deduplication Strategy
 *
 * Advanced strategy that uses semantic similarity, content analysis,
 * and machine learning-inspired heuristics for sophisticated deduplication.
 */

import {
  DeduplicationStrategy,
  type DeduplicationResult,
  type DeduplicationStrategyConfig,
  type DuplicateAnalysis,
} from './base-strategy.js';
import type { KnowledgeItem } from '../../../types/core-interfaces.js';
import { logger } from '../../../utils/logger.js';

export interface IntelligentStrategyConfig extends DeduplicationStrategyConfig {
  similarityThreshold?: number;
  semanticThreshold?: number; // Higher threshold for semantic matching
  contentThreshold?: number; // Lower threshold for content matching
  enableSemanticAnalysis?: boolean;
  enableKeywordExtraction?: boolean;
  weightingFactors?: {
    title: number;
    content: number;
    metadata: number;
  };
  maxHistoryHours?: number;
  crossScopeDeduplication?: boolean;
  prioritizeSameScope?: boolean;
}

export class IntelligentStrategy extends DeduplicationStrategy {
  private stopWords: Set<string>;

  constructor(config: IntelligentStrategyConfig = {}) {
    super({
      similarityThreshold: 0.75,
      semanticThreshold: 0.8,
      contentThreshold: 0.6,
      enableSemanticAnalysis: true,
      enableKeywordExtraction: true,
      weightingFactors: {
        title: 2.0,
        content: 1.0,
        metadata: 0.5,
      },
      maxHistoryHours: 24 * 7, // 1 week
      crossScopeDeduplication: false,
      prioritizeSameScope: true,
      ...config,
    });

    // Initialize common English stop words
    this.stopWords = new Set([
      'the',
      'be',
      'to',
      'of',
      'and',
      'a',
      'in',
      'that',
      'have',
      'i',
      'it',
      'for',
      'not',
      'on',
      'with',
      'he',
      'as',
      'you',
      'do',
      'at',
      'this',
      'but',
      'his',
      'by',
      'from',
      'is',
      'was',
      'are',
      'been',
      'or',
      'had',
      'its',
      'an',
      'will',
      'my',
      'would',
      'there',
      'their',
      'what',
      'so',
      'if',
      'about',
      'which',
      'them',
    ]);
  }

  getStrategyName(): string {
    return 'intelligent';
  }

  /**
   * Process items with intelligent deduplication
   */
  async process(
    items: KnowledgeItem[],
    existingItems: KnowledgeItem[]
  ): Promise<DeduplicationResult[]> {
    const results: DeduplicationResult[] = [];
    const threshold = this.config.similarityThreshold as number;

    for (const item of items) {
      const analysis = await this.checkDuplicate(item, existingItems);

      if (analysis.isDuplicate && analysis.similarityScore >= threshold) {
        // Use intelligent decision making for action
        const action = this.determineAction(analysis, item, existingItems);

        results.push({
          action,
          reason: `Intelligent deduplication (similarity: ${analysis.similarityScore.toFixed(3)}, type: ${analysis.matchType})`,
          existingId: analysis.existingId,
          similarityScore: analysis.similarityScore,
          mergeDetails:
            action === 'merged'
              ? {
                  fieldsMerged: this.getPotentialMergedFields(item, existingItems),
                  conflictsResolved: this.getPotentialConflicts(item, existingItems),
                }
              : undefined,
        });
      } else {
        results.push({
          action: 'stored',
          reason: analysis.isDuplicate
            ? `Similarity ${analysis.similarityScore.toFixed(3)} below threshold ${threshold}`
            : 'No duplicate found',
        });
      }
    }

    if (this.config.logResults) {
      const stored = results.filter((r) => r.action === 'stored').length;
      const skipped = results.filter((r) => r.action === 'skipped').length;
      const merged = results.filter((r) => r.action === 'merged').length;

      logger.info(
        {
          strategy: this.getStrategyName(),
          totalItems: items.length,
          storedCount: stored,
          skippedCount: skipped,
          mergedCount: merged,
          threshold,
        },
        'Intelligent strategy processed items'
      );
    }

    return results;
  }

  /**
   * Intelligent duplicate checking with semantic analysis
   */
  async checkDuplicate(
    item: KnowledgeItem,
    existingItems: KnowledgeItem[]
  ): Promise<DuplicateAnalysis> {
    // Perform basic validation
    if (this.config.performBasicValidation && !this.validateItem(item)) {
      return {
        isDuplicate: false,
        similarityScore: 0,
        matchType: 'none',
        reason: 'Item failed basic validation',
      };
    }

    const enableSemantic = this.config.enableSemanticAnalysis as boolean;
    const weighting = this.config.weightingFactors as any;
    let bestMatch: {
      similarity: number;
      existingItem: KnowledgeItem;
      matchType: 'exact' | 'content' | 'semantic' | 'partial';
      detailedAnalysis: {
        titleSimilarity: number;
        contentSimilarity: number;
        metadataSimilarity: number;
        semanticSimilarity: number;
      };
    } | null = null;

    // Check each existing item for similarity
    for (const existing of existingItems) {
      // Apply scope filtering rules
      if (!this.shouldCompareItems(item, existing)) {
        continue;
      }

      // Apply time filtering
      if (!this.isWithinTimeWindow(item, existing)) {
        continue;
      }

      // Perform detailed similarity analysis
      const detailedAnalysis = this.performDetailedSimilarityAnalysis(item, existing);
      const weightedSimilarity = this.calculateWeightedSimilarity(detailedAnalysis, weighting);

      let matchType: 'exact' | 'content' | 'semantic' | 'partial';
      if (detailedAnalysis.titleSimilarity >= 0.95 && detailedAnalysis.contentSimilarity >= 0.9) {
        matchType = 'exact';
      } else if (detailedAnalysis.contentSimilarity >= 0.8) {
        matchType = 'content';
      } else if (
        enableSemantic &&
        detailedAnalysis.semanticSimilarity >= (this.config.semanticThreshold as number)
      ) {
        matchType = 'semantic';
      } else if (weightedSimilarity >= (this.config.contentThreshold as number)) {
        matchType = 'partial';
      } else {
        continue; // Skip items that don't meet minimum similarity
      }

      // Update best match if this is more similar
      if (!bestMatch || weightedSimilarity > bestMatch.similarity) {
        bestMatch = {
          similarity: weightedSimilarity,
          existingItem: existing,
          matchType,
          detailedAnalysis,
        };
      }
    }

    // Determine if it's a duplicate based on intelligent criteria
    if (bestMatch) {
      const threshold = this.getAdaptiveThreshold(bestMatch.matchType, item.kind);
      const isDuplicate = bestMatch.similarity >= threshold;

      return {
        isDuplicate,
        similarityScore: bestMatch.similarity,
        matchType: bestMatch.matchType,
        reason: isDuplicate
          ? `Intelligent match: ${bestMatch.matchType} (similarity: ${bestMatch.similarity.toFixed(3)}) >= adaptive threshold ${threshold}`
          : `Similarity ${bestMatch.similarity.toFixed(3)} below adaptive threshold ${threshold}`,
        existingId: bestMatch.existingItem.id,
        existingCreatedAt: bestMatch.existingItem.created_at,
        isNewerVersion: this.isItemNewer(item, bestMatch.existingItem),
        scopeMatch: this.analyzeScopeMatch(item),
      };
    }

    return {
      isDuplicate: false,
      similarityScore: 0,
      matchType: 'none',
      reason: 'No significant matches found',
      scopeMatch: this.analyzeScopeMatch(item),
    };
  }

  /**
   * Perform detailed similarity analysis between two items
   */
  private performDetailedSimilarityAnalysis(
    item1: KnowledgeItem,
    item2: KnowledgeItem
  ): {
    titleSimilarity: number;
    contentSimilarity: number;
    metadataSimilarity: number;
    semanticSimilarity: number;
  } {
    const data1 = item1.data || {};
    const data2 = item2.data || {};

    // Title similarity (check various title fields)
    const title1 = data1.title || data1.name || data1.subject || '';
    const title2 = data2.title || data2.name || data2.subject || '';
    const titleSimilarity = title1 && title2 ? this.calculateTextSimilarity(title1, title2) : 0;

    // Content similarity (check content fields)
    const content1 = data1.content || data1.body_text || data1.description || data1.text || '';
    const content2 = data2.content || data2.body_text || data2.description || data2.text || '';
    const contentSimilarity =
      content1 && content2 ? this.calculateTextSimilarity(content1, content2) : 0;

    // Metadata similarity
    const metadata1 = JSON.stringify(item1.metadata || {});
    const metadata2 = JSON.stringify(item2.metadata || {});
    const metadataSimilarity = this.calculateTextSimilarity(metadata1, metadata2);

    // Semantic similarity (keyword-based approximation)
    const semanticSimilarity = this.config.enableSemanticAnalysis
      ? this.calculateSemanticSimilarity(data1, data2)
      : 0;

    return {
      titleSimilarity,
      contentSimilarity,
      metadataSimilarity,
      semanticSimilarity,
    };
  }

  /**
   * Calculate weighted similarity based on configured factors
   */
  private calculateWeightedSimilarity(
    analysis: {
      titleSimilarity: number;
      contentSimilarity: number;
      metadataSimilarity: number;
      semanticSimilarity: number;
    },
    weighting: { title: number; content: number; metadata: number }
  ): number {
    const totalWeight = weighting.title + weighting.content + weighting.metadata;

    const weightedScore =
      (analysis.titleSimilarity * weighting.title +
        analysis.contentSimilarity * weighting.content +
        analysis.metadataSimilarity * weighting.metadata) /
      totalWeight;

    // Incorporate semantic similarity if it's significant
    if (analysis.semanticSimilarity > 0.7) {
      return Math.max(weightedScore, analysis.semanticSimilarity);
    }

    return weightedScore;
  }

  /**
   * Calculate semantic similarity using keyword extraction
   */
  private calculateSemanticSimilarity(
    data1: Record<string, any>,
    data2: Record<string, any>
  ): number {
    if (!this.config.enableKeywordExtraction) {
      return 0;
    }

    // Extract keywords from both items
    const keywords1 = this.extractKeywords(data1);
    const keywords2 = this.extractKeywords(data2);

    // Calculate Jaccard similarity of keywords
    if (keywords1.size === 0 && keywords2.size === 0) return 1.0;
    if (keywords1.size === 0 || keywords2.size === 0) return 0.0;

    const intersection = new Set([...keywords1].filter((word) => keywords2.has(word)));
    const union = new Set([...keywords1, ...keywords2]);

    return intersection.size / union.size;
  }

  /**
   * Extract keywords from data object
   */
  private extractKeywords(data: Record<string, any>): Set<string> {
    const keywords = new Set<string>();

    for (const [key, value] of Object.entries(data)) {
      if (typeof value === 'string') {
        // Extract words from string values
        const words = value
          .toLowerCase()
          .split(/\W+/)
          .filter((word) => word.length > 3 && !this.stopWords.has(word));
        words.forEach((word) => keywords.add(word));
      }
    }

    return keywords;
  }

  /**
   * Get adaptive threshold based on match type and item kind
   */
  private getAdaptiveThreshold(matchType: string, kind?: string): number {
    const baseThreshold = this.config.similarityThreshold as number;

    // Adjust threshold based on match type
    const typeAdjustment: Record<string, number> = {
      exact: -0.1, // Lower threshold for exact matches
      content: 0, // Base threshold for content matches
      semantic: 0.1, // Higher threshold for semantic matches
      partial: 0.2, // Much higher threshold for partial matches
    };

    // Adjust threshold based on item kind
    const kindAdjustment: Record<string, number> = {
      decision: 0.05, // Be more strict with decisions
      issue: 0, // Base for issues
      todo: -0.05, // Be more lenient with todos
      incident: 0.1, // Be very strict with incidents
      entity: 0.02, // Slightly stricter with entities
    };

    let threshold = baseThreshold + (typeAdjustment[matchType] || 0);
    if (kind && kindAdjustment[kind] !== undefined) {
      threshold += kindAdjustment[kind];
    }

    // Ensure threshold stays within reasonable bounds
    return Math.max(0.5, Math.min(0.95, threshold));
  }

  /**
   * Determine what action to take based on analysis
   */
  private determineAction(
    analysis: DuplicateAnalysis,
    item: KnowledgeItem,
    existingItems: KnowledgeItem[]
  ): 'stored' | 'skipped' | 'merged' | 'updated' {
    // High similarity exact matches: skip
    if (analysis.matchType === 'exact' && analysis.similarityScore > 0.95) {
      return analysis.isNewerVersion ? 'updated' : 'skipped';
    }

    // Content matches with high similarity: merge
    if (analysis.matchType === 'content' && analysis.similarityScore > 0.85) {
      return 'merged';
    }

    // Semantic matches: check if newer
    if (analysis.matchType === 'semantic') {
      return analysis.isNewerVersion ? 'updated' : 'skipped';
    }

    // Partial matches: store if above threshold
    return analysis.similarityScore > (this.config.contentThreshold as number)
      ? 'merged'
      : 'stored';
  }

  /**
   * Check if we should compare two items based on scope rules
   */
  private shouldCompareItems(item1: KnowledgeItem, item2: KnowledgeItem): boolean {
    const crossScope = this.config.crossScopeDeduplication as boolean;
    const prioritizeSameScope = this.config.prioritizeSameScope as boolean;

    if (crossScope) {
      return true; // Compare across all scopes
    }

    const scope1 = item1.scope || {};
    const scope2 = item2.scope || {};

    // If prioritize same scope, only compare if scopes match
    if (prioritizeSameScope) {
      return scope1.org === scope2.org && scope1.project === scope2.project;
    }

    return true;
  }

  /**
   * Check if items are within time window for comparison
   */
  private isWithinTimeWindow(item1: KnowledgeItem, item2: KnowledgeItem): boolean {
    const maxHistory = this.config.maxHistoryHours as number;
    if (maxHistory <= 0) return true;

    const time1 = item1.created_at ? new Date(item1.created_at).getTime() : Date.now();
    const time2 = item2.created_at ? new Date(item2.created_at).getTime() : Date.now();

    const timeDiffHours = Math.abs(time1 - time2) / (1000 * 60 * 60);

    return timeDiffHours <= maxHistory;
  }

  /**
   * Check if new item is newer than existing
   */
  private isItemNewer(newItem: KnowledgeItem, existingItem: KnowledgeItem): boolean {
    const newTime = newItem.updated_at || newItem.created_at;
    const existingTime = existingItem.updated_at || existingItem.created_at;

    if (!newTime || !existingTime) {
      return false;
    }

    return new Date(newTime).getTime() > new Date(existingTime).getTime();
  }

  /**
   * Get potentially merged fields for reporting
   */
  private getPotentialMergedFields(item: KnowledgeItem, existingItems: KnowledgeItem[]): string[] {
    const fields: string[] = [];
    if (item.data) {
      fields.push(...Object.keys(item.data));
    }
    return fields;
  }

  /**
   * Get potential conflicts for reporting
   */
  private getPotentialConflicts(item: KnowledgeItem, existingItems: KnowledgeItem[]): string[] {
    // Simplified conflict detection
    return Object.keys(item.data || {}).filter((key) => {
      return existingItems.some(
        (existing) =>
          existing.data &&
          key in existing.data &&
          JSON.stringify(existing.data[key]) !== JSON.stringify(item.data![key])
      );
    });
  }

  /**
   * Analyze scope matching for reporting
   */
  private analyzeScopeMatch(item: KnowledgeItem) {
    const itemScope = item.scope || {};
    return {
      org: !!itemScope.org,
      project: !!itemScope.project,
      branch: !!itemScope.branch,
    };
  }
}
