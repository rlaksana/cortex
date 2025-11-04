/**
 * Combine Deduplication Strategy
 *
 * Strategy that merges duplicate items intelligently.
 * When duplicates are found, combines the best aspects of both items.
 */

import {
  DeduplicationStrategy,
  type DeduplicationResult,
  type DeduplicationStrategyConfig,
  type DuplicateAnalysis,
} from './base-strategy.js';
import type { KnowledgeItem } from '../../../types/core-interfaces.js';
import { logger } from '../../../utils/logger.js';

export interface CombineStrategyConfig extends DeduplicationStrategyConfig {
  similarityThreshold?: number;
  checkWithinScopeOnly?: boolean;
  mergeConflictResolution?: 'prefer_newer' | 'prefer_existing' | 'combine';
  preserveMergeHistory?: boolean;
  maxMergeHistoryEntries?: number;
}

export class CombineStrategy extends DeduplicationStrategy {
  constructor(config: CombineStrategyConfig = {}) {
    super({
      similarityThreshold: 0.8,
      checkWithinScopeOnly: true,
      mergeConflictResolution: 'prefer_newer',
      preserveMergeHistory: true,
      maxMergeHistoryEntries: 10,
      ...config,
    });
  }

  getStrategyName(): string {
    return 'combine';
  }

  /**
   * Process items, merging duplicates when found
   */
  async process(
    items: KnowledgeItem[],
    existingItems: KnowledgeItem[]
  ): Promise<DeduplicationResult[]> {
    const results: DeduplicationResult[] = [];
    const threshold = this.config.similarityThreshold as number;

    for (const item of items) {
      const analysis = await this.checkDuplicate(item, existingItems);

      if (analysis.isDuplicate && analysis.similarityScore >= threshold && analysis.existingId) {
        // Find the existing item for merging
        const existingItem = existingItems.find((e) => e.id === analysis.existingId);
        if (existingItem) {
          const mergedItem = this.mergeItems(existingItem, item);
          results.push({
            action: 'merged',
            reason: `Combined duplicate items (similarity: ${analysis.similarityScore.toFixed(3)})`,
            existingId: analysis.existingId,
            similarityScore: analysis.similarityScore,
            mergeDetails: {
              fieldsMerged: this.getMergedFields(existingItem, item),
              conflictsResolved: this.getConflictsResolved(existingItem, item),
            },
          });
        } else {
          // Existing item not found, store new one
          results.push({
            action: 'stored',
            reason: 'Existing item for merge not found, storing new item',
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
      const merged = results.filter((r) => r.action === 'merged').length;

      logger.info(
        {
          strategy: this.getStrategyName(),
          totalItems: items.length,
          storedCount: stored,
          mergedCount: merged,
          threshold,
        },
        'Combine strategy processed items'
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
        reason: 'Item failed basic validation',
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
   * Merge two items intelligently
   */
  private mergeItems(existing: KnowledgeItem, newItem: KnowledgeItem): KnowledgeItem {
    const resolution = this.config.mergeConflictResolution as string;
    const preserveHistory = this.config.preserveMergeHistory as boolean;

    const merged: KnowledgeItem = {
      ...existing,
      updated_at: new Date().toISOString(),
      data: { ...existing.data },
      metadata: { ...existing.metadata },
    };

    // Merge data fields based on conflict resolution strategy
    if (resolution === 'prefer_newer') {
      // Prefer newer item's data
      merged.data = { ...existing.data, ...newItem.data };
    } else if (resolution === 'prefer_existing') {
      // Keep existing data, but add new fields that don't exist
      Object.keys(newItem.data || {}).forEach((key) => {
        if (!(key in existing.data)) {
          merged.data[key] = newItem.data[key];
        }
      });
    } else if (resolution === 'combine') {
      // Intelligently combine fields
      this.combineDataFields(existing, newItem, merged);
    }

    // Merge metadata
    if (newItem.metadata) {
      merged.metadata = {
        ...merged.metadata,
        ...newItem.metadata,
      };

      // Add merge history if enabled
      if (preserveHistory) {
        const maxEntries = this.config.maxMergeHistoryEntries as number;
        const historyEntry = {
          timestamp: new Date().toISOString(),
          merged_from: newItem.id,
          existing_id: existing.id,
          strategy: this.getStrategyName(),
        };

        merged.metadata.merge_history = [
          ...(merged.metadata.merge_history || []),
          historyEntry,
        ].slice(-maxEntries); // Keep only the last N entries
      }
    }

    // Update scope with most specific values
    if (newItem.scope) {
      merged.scope = {
        ...merged.scope,
        ...newItem.scope,
      };
    }

    return merged;
  }

  /**
   * Intelligently combine data fields from both items
   */
  private combineDataFields(
    existing: KnowledgeItem,
    newItem: KnowledgeItem,
    merged: KnowledgeItem
  ): void {
    const contentFields = ['content', 'body_text', 'body_md', 'description', 'rationale', 'text'];

    for (const [key, value] of Object.entries(newItem.data || {})) {
      if (!existing.data || !(key in existing.data)) {
        // Field doesn't exist in existing, use it
        merged.data![key] = value;
      } else if (
        contentFields.includes(key) &&
        typeof value === 'string' &&
        typeof existing.data[key] === 'string'
      ) {
        // Combine content fields intelligently
        merged.data![key] = this.combineContent(existing.data[key] as string, value);
      } else if (Array.isArray(value) && Array.isArray(existing.data[key])) {
        // Merge arrays, deduplicating entries
        merged.data![key] = [...new Set([...existing.data[key], ...value])];
      } else if (
        typeof value === 'object' &&
        typeof existing.data[key] === 'object' &&
        value !== null &&
        existing.data[key] !== null
      ) {
        // Merge objects
        merged.data![key] = { ...existing.data[key], ...value };
      } else {
        // For other types, prefer the newer value
        merged.data![key] = value;
      }
    }
  }

  /**
   * Combine two content strings intelligently
   */
  private combineContent(existingContent: string, newContent: string): string {
    // Remove duplicates and whitespace
    const existingLines = existingContent
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line);
    const newLines = newContent
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line);

    // Combine and deduplicate
    const allLines = [...existingLines, ...newLines];
    const uniqueLines = [...new Set(allLines)];

    return uniqueLines.join('\n');
  }

  /**
   * Get list of fields that were merged
   */
  private getMergedFields(existing: KnowledgeItem, newItem: KnowledgeItem): string[] {
    const mergedFields: string[] = [];

    if (newItem.data) {
      Object.keys(newItem.data).forEach((key) => {
        if (existing.data && key in existing.data) {
          mergedFields.push(key);
        }
      });
    }

    return mergedFields;
  }

  /**
   * Get list of conflicts that were resolved
   */
  private getConflictsResolved(existing: KnowledgeItem, newItem: KnowledgeItem): string[] {
    const conflicts: string[] = [];

    if (existing.data && newItem.data) {
      Object.keys(newItem.data).forEach((key) => {
        if (
          key in existing.data &&
          JSON.stringify(existing.data[key]) !== JSON.stringify(newItem.data[key])
        ) {
          conflicts.push(key);
        }
      });
    }

    return conflicts;
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
