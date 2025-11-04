/**
 * Prefer Existing Deduplication Strategy
 *
 * Strategy that keeps existing items and skips new duplicates.
 * When a duplicate is found, the new item is discarded in favor of the existing one.
 */

import { DeduplicationStrategy, type DeduplicationResult, type DeduplicationStrategyConfig, type DuplicateAnalysis } from './base-strategy.js';
import type { KnowledgeItem } from '../../../types/core-interfaces.js';
import { logger } from '../../../utils/logger.js';

export interface PreferExistingStrategyConfig extends DeduplicationStrategyConfig {
  similarityThreshold?: number;
  checkWithinScopeOnly?: boolean;
  respectTimestamps?: boolean;
}

export class PreferExistingStrategy extends DeduplicationStrategy {
  constructor(config: PreferExistingStrategyConfig = {}) {
    super({
      similarityThreshold: 0.85,
      checkWithinScopeOnly: true,
      respectTimestamps: true,
      ...config
    });
  }

  getStrategyName(): string {
    return 'prefer_existing';
  }

  /**
   * Process items, keeping existing ones and skipping new duplicates
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
        results.push({
          action: 'skipped',
          reason: `Duplicate found (similarity: ${analysis.similarityScore.toFixed(3)}), preferring existing item`,
          existingId: analysis.existingId,
          similarityScore: analysis.similarityScore
        });
      } else {
        results.push({
          action: 'stored',
          reason: analysis.isDuplicate
            ? `Similarity ${analysis.similarityScore.toFixed(3)} below threshold ${threshold}`
            : 'No duplicate found'
        });
      }
    }

    if (this.config.logResults) {
      const stored = results.filter(r => r.action === 'stored').length;
      const skipped = results.filter(r => r.action === 'skipped').length;

      logger.info(
        {
          strategy: this.getStrategyName(),
          totalItems: items.length,
          storedCount: stored,
          skippedCount: skipped,
          threshold
        },
        'Prefer existing strategy processed items'
      );
    }

    return results;
  }

  /**
   * Check if item is a duplicate of existing items
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
        reason: 'Item failed basic validation'
      };
    }

    const threshold = this.config.similarityThreshold as number;
    let bestMatch: {
      similarity: number;
      existingItem: KnowledgeItem;
      matchType: 'exact' | 'content' | 'semantic' | 'partial';
    } | null = null;

    // Check each existing item for similarity
    for (const existing of existingItems) {
      // Skip if checking within scope only and scopes don't match
      if (this.config.checkWithinScopeOnly && !this.scopesMatch(item, existing)) {
        continue;
      }

      const similarity = this.calculateSimilarity(item, existing);

      let matchType: 'exact' | 'content' | 'semantic' | 'partial';
      if (similarity >= 0.95) {
        matchType = 'exact';
      } else if (similarity >= 0.8) {
        matchType = 'content';
      } else if (similarity >= 0.6) {
        matchType = 'semantic';
      } else {
        matchType = 'partial';
      }

      // Update best match if this is more similar
      if (!bestMatch || similarity > bestMatch.similarity) {
        bestMatch = { similarity, existingItem: existing, matchType };
      }
    }

    // Determine if it's a duplicate based on threshold
    if (bestMatch && bestMatch.similarity >= threshold) {
      return {
        isDuplicate: true,
        similarityScore: bestMatch.similarity,
        matchType: bestMatch.matchType,
        reason: `Duplicate found (similarity: ${bestMatch.similarity.toFixed(3)}) >= threshold ${threshold}`,
        existingId: bestMatch.existingItem.id,
        existingCreatedAt: bestMatch.existingItem.created_at,
        scopeMatch: this.analyzeScopeMatch(item)
      };
    }

    return {
      isDuplicate: false,
      similarityScore: bestMatch?.similarity || 0,
      matchType: bestMatch?.matchType || 'none',
      reason: bestMatch
        ? `Similarity ${bestMatch.similarity.toFixed(3)} below threshold ${threshold}`
        : 'No similar items found',
      scopeMatch: this.analyzeScopeMatch(item)
    };
  }

  /**
   * Check if scopes match between two items
   */
  private scopesMatch(item1: KnowledgeItem, item2: KnowledgeItem): boolean {
    const scope1 = item1.scope || {};
    const scope2 = item2.scope || {};

    // If both have org, they must match
    if (scope1.org && scope2.org && scope1.org !== scope2.org) {
      return false;
    }

    // If both have project, they must match
    if (scope1.project && scope2.project && scope1.project !== scope2.project) {
      return false;
    }

    // Branch matching is optional
    return true;
  }

  /**
   * Analyze scope matching for reporting
   */
  private analyzeScopeMatch(item: KnowledgeItem) {
    const itemScope = item.scope || {};
    return {
      org: !!itemScope.org,
      project: !!itemScope.project,
      branch: !!itemScope.branch
    };
  }
}