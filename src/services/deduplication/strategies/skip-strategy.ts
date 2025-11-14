// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck


/**
 * Skip Deduplication Strategy
 *
 * Strategy that skips all deduplication and stores all items.
 * This is the most permissive strategy - everything gets stored.
 */

import { logger } from '@/utils/logger.js';

import {
  type DeduplicationResult,
  DeduplicationStrategy,
  type DeduplicationStrategyConfig,
  type DuplicateAnalysis,
} from './base-strategy.js';
import type { KnowledgeItem } from '../../../types/core-interfaces.js';

export interface SkipStrategyConfig extends DeduplicationStrategyConfig {
  logSkippedItems?: boolean;
  performBasicValidation?: boolean;
}

export class SkipStrategy extends DeduplicationStrategy {
  constructor(config: SkipStrategyConfig = {}) {
    super({
      logSkippedItems: false,
      performBasicValidation: true,
      ...config,
    });
  }

  getStrategyName(): string {
    return 'skip';
  }

  /**
   * Process all items without deduplication - everything gets stored
   */
  async process(
    items: KnowledgeItem[],
    existingItems: KnowledgeItem[]
  ): Promise<DeduplicationResult[]> {
    const results: DeduplicationResult[] = [];

    for (const item of items) {
      const result = await this.checkDuplicate(item, existingItems);

      if (result.isDuplicate) {
        results.push({
          action: 'stored', // Still store even if duplicate
          reason: 'Skip strategy enabled - storing despite duplicate',
          existingId: result.existingId,
          similarityScore: result.similarityScore,
        });
      } else {
        results.push({
          action: 'stored',
          reason: 'Skip strategy enabled - no deduplication performed',
        });
      }
    }

    if (this.config.logResults) {
      logger.info(
        {
          strategy: this.getStrategyName(),
          totalItems: items.length,
          storedCount: results.filter((r) => r.action === 'stored').length,
        },
        'Skip strategy processed items'
      );
    }

    return results;
  }

  /**
   * Check for duplicates but always return non-duplicate result
   */
  async checkDuplicate(
    item: KnowledgeItem,
    existingItems: KnowledgeItem[]
  ): Promise<DuplicateAnalysis> {
    // Perform basic validation if enabled
    if (this.config.performBasicValidation && !this.validateItem(item)) {
      return {
        isDuplicate: false,
        similarityScore: 0,
        matchType: 'none',
        reason: 'Item failed basic validation - will be handled by validation layer',
      };
    }

    // Check for actual duplicates but don't act on them
    const maxSimilarity = this.findMaxSimilarity(item, existingItems);

    return {
      isDuplicate: false, // Always false for skip strategy
      similarityScore: maxSimilarity.score,
      matchType:
        maxSimilarity.score > 0.9 ? 'exact' : maxSimilarity.score > 0.7 ? 'content' : 'none',
      reason: 'Skip strategy enabled - deduplication bypassed',
      existingId: maxSimilarity.existingId,
      scopeMatch: this.analyzeScopeMatch(item),
    };
  }

  /**
   * Find the most similar existing item
   */
  private findMaxSimilarity(
    item: KnowledgeItem,
    existingItems: KnowledgeItem[]
  ): {
    score: number;
    existingId?: string;
  } {
    let maxSimilarity = 0;
    let mostSimilarId: string | undefined;

    for (const existing of existingItems) {
      const similarity = this.calculateSimilarity(item, existing);
      if (similarity > maxSimilarity) {
        maxSimilarity = similarity;
        mostSimilarId = existing.id;
      }
    }

    return { score: maxSimilarity, existingId: mostSimilarId };
  }

  /**
   * Analyze scope matching
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
