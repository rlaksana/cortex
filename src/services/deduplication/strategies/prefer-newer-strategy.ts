/**
 * Prefer Newer Deduplication Strategy
 *
 * Strategy that keeps newer items based on timestamp comparison.
 * When duplicates are found, the newer item (based on creation/update time) is preferred.
 */

import { logger } from '@/utils/logger.js';

import {
  type DeduplicationResult,
  DeduplicationStrategy,
  type DeduplicationStrategyConfig,
  type DuplicateAnalysis,
} from './base-strategy.js';
import type { KnowledgeItem } from '../../../types/core-interfaces.js';

export interface PreferNewerStrategyConfig extends DeduplicationStrategyConfig {
  similarityThreshold?: number;
  checkWithinScopeOnly?: boolean;
  respectUpdateTimestamps?: boolean;
  timeWindowHours?: number; // Only consider items within this time window for comparison
}

export class PreferNewerStrategy extends DeduplicationStrategy {
  constructor(config: PreferNewerStrategyConfig = {}) {
    super({
      similarityThreshold: 0.85,
      checkWithinScopeOnly: true,
      respectUpdateTimestamps: true,
      timeWindowHours: 24 * 7, // 1 week default
      ...config,
    });
  }

  getStrategyName(): string {
    return 'prefer_newer';
  }

  /**
   * Process items, preferring newer ones over existing duplicates
   */
  async process(
    items: KnowledgeItem[],
    existingItems: KnowledgeItem[]
  ): Promise<DeduplicationResult[]> {
    const results: DeduplicationResult[] = [];
    const threshold = this.config.similarityThreshold as number;
    const timeWindow = this.config.timeWindowHours as number;

    for (const item of items) {
      const analysis = await this.checkDuplicate(item, existingItems);

      if (analysis.isDuplicate && analysis.similarityScore >= threshold) {
        // Check if new item is newer than existing
        const isNewer = this.isItemNewer(item, analysis);

        if (isNewer) {
          results.push({
            action: 'stored',
            reason: `Newer version of existing item (similarity: ${analysis.similarityScore.toFixed(3)})`,
            existingId: analysis.existingId,
            similarityScore: analysis.similarityScore,
          });
        } else {
          results.push({
            action: 'skipped',
            reason: `Existing item is newer or same age (similarity: ${analysis.similarityScore.toFixed(3)})`,
            existingId: analysis.existingId,
            similarityScore: analysis.similarityScore,
          });
        }
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

      logger.info(
        {
          strategy: this.getStrategyName(),
          totalItems: items.length,
          storedCount: stored,
          skippedCount: skipped,
          threshold,
          timeWindow,
        },
        'Prefer newer strategy processed items'
      );
    }

    return results;
  }

  /**
   * Check if item is a duplicate and determine which version to keep
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

    const threshold = this.config.similarityThreshold as number;
    const timeWindow = this.config.timeWindowHours as number;
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

      // Skip if outside time window
      if (!this.isWithinTimeWindow(item, existing, timeWindow)) {
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
        isNewerVersion: this.isItemNewer(item, {
          existingId: bestMatch.existingItem.id,
          existingCreatedAt: bestMatch.existingItem.created_at,
        }),
        scopeMatch: this.analyzeScopeMatch(item),
      };
    }

    return {
      isDuplicate: false,
      similarityScore: bestMatch?.similarity || 0,
      matchType: bestMatch?.matchType || 'none',
      reason: bestMatch
        ? `Similarity ${bestMatch.similarity.toFixed(3)} below threshold ${threshold}`
        : 'No similar items found',
      scopeMatch: this.analyzeScopeMatch(item),
    };
  }

  /**
   * Determine if new item is newer than existing item
   */
  private isItemNewer(
    newItem: KnowledgeItem,
    analysis: { existingId?: string; existingCreatedAt?: string }
  ): boolean {
    if (!analysis.existingCreatedAt) {
      return true; // Assume new if no timestamp
    }

    const respectUpdateTimestamps = this.config.respectUpdateTimestamps as boolean;
    const newTime = this.getItemTimestamp(newItem, respectUpdateTimestamps);
    const existingTime = new Date(analysis.existingCreatedAt).getTime();

    return newTime > existingTime;
  }

  /**
   * Get the relevant timestamp for an item
   */
  private getItemTimestamp(item: KnowledgeItem, respectUpdate: boolean): number {
    if (respectUpdate && item.updated_at) {
      return new Date(item.updated_at).getTime();
    }
    if (item.created_at) {
      return new Date(item.created_at).getTime();
    }
    return Date.now(); // Use current time if no timestamp
  }

  /**
   * Check if items are within the configured time window for comparison
   */
  private isWithinTimeWindow(
    item1: KnowledgeItem,
    item2: KnowledgeItem,
    timeWindowHours: number
  ): boolean {
    const respectUpdateTimestamps = this.config.respectUpdateTimestamps as boolean;
    const time1 = this.getItemTimestamp(item1, respectUpdateTimestamps);
    const time2 = this.getItemTimestamp(item2, respectUpdateTimestamps);

    const timeDiffHours = Math.abs(time1 - time2) / (1000 * 60 * 60);

    return timeDiffHours <= timeWindowHours;
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
      branch: !!itemScope.branch,
    };
  }
}
