/**
 * Base Deduplication Strategy Interface
 *
 * Defines the common interface that all deduplication strategies must implement.
 * This ensures consistency and enables easy strategy swapping.
 */

import type { KnowledgeItem } from '../../../types/core-interfaces.js';

export interface DeduplicationStrategyConfig {
  // Common configuration options
  enabled?: boolean;
  logResults?: boolean;
  performBasicValidation?: boolean;
  similarityThreshold?: number;

  // Strategy-specific options can be added by individual strategies
  [key: string]: unknown;
}

export interface DeduplicationResult {
  action: 'stored' | 'skipped' | 'merged' | 'updated';
  reason: string;
  existingId?: string;
  similarityScore?: number;
  mergeDetails?: {
    fieldsMerged: string[];
    conflictsResolved: string[];
  };
}

export interface DuplicateAnalysis {
  isDuplicate: boolean;
  similarityScore: number;
  matchType: 'none' | 'exact' | 'content' | 'semantic' | 'partial';
  reason: string;
  existingId?: string;
  isNewerVersion?: boolean;
  existingCreatedAt?: string;
  scopeMatch?: {
    org: boolean;
    project: boolean;
    branch: boolean;
  };
}

/**
 * Abstract base class for deduplication strategies
 */
export abstract class DeduplicationStrategy {
  protected config: DeduplicationStrategyConfig;

  constructor(config: DeduplicationStrategyConfig = {}) {
    this.config = {
      enabled: true,
      logResults: true,
      performBasicValidation: true,
      ...config,
    };
  }

  /**
   * Process items for deduplication
   * @param items Items to process
   * @param existingItems Existing items in the database
   * @returns Promise<DeduplicationResult> Results for each item
   */
  abstract process(
    items: KnowledgeItem[],
    existingItems: KnowledgeItem[]
  ): Promise<DeduplicationResult[]>;

  /**
   * Check if a single item is a duplicate
   * @param item Item to check
   * @param existingItems Existing items to compare against
   * @returns Promise<DuplicateAnalysis> Analysis of the duplicate check
   */
  abstract checkDuplicate(
    item: KnowledgeItem,
    existingItems: KnowledgeItem[]
  ): Promise<DuplicateAnalysis>;

  /**
   * Get the strategy name for logging/debugging
   */
  abstract getStrategyName(): string;

  /**
   * Update strategy configuration
   */
  updateConfig(newConfig: Partial<DeduplicationStrategyConfig>): void {
    this.config = { ...this.config, ...newConfig };
  }

  /**
   * Get current configuration
   */
  getConfig(): DeduplicationStrategyConfig {
    return { ...this.config };
  }

  /**
   * Perform basic validation on an item
   */
  protected validateItem(item: KnowledgeItem): boolean {
    if (!this.config.performBasicValidation) {
      return true;
    }

    return !!(
      item &&
      item.kind &&
      typeof item.kind === 'string' &&
      item.data &&
      typeof item.data === 'object'
    );
  }

  /**
   * Create a unique signature for an item for comparison
   */
  protected createItemSignature(item: KnowledgeItem): string {
    const signatureData = {
      kind: item.kind,
      scope: item.scope || {},
      data: Object.keys(item.data || {})
        .sort()
        .reduce(
          (result, key) => {
            result[key] = item.data![key];
            return result;
          },
          {} as Record<string, unknown>
        ),
    };

    return JSON.stringify(signatureData);
  }

  /**
   * Calculate basic similarity between two items
   */
  protected calculateSimilarity(item1: KnowledgeItem, item2: KnowledgeItem): number {
    const sig1 = this.createItemSignature(item1);
    const sig2 = this.createItemSignature(item2);

    // Exact match
    if (sig1 === sig2) {
      return 1.0;
    }

    // Content similarity (simplified)
    const content1 = JSON.stringify(item1.data || {}).toLowerCase();
    const content2 = JSON.stringify(item2.data || {}).toLowerCase();

    return this.calculateTextSimilarity(content1, content2);
  }

  /**
   * Calculate text similarity using Jaccard similarity
   */
  protected calculateTextSimilarity(text1: string, text2: string): number {
    const words1 = new Set(text1.split(/\s+/).filter((word) => word.length > 2));
    const words2 = new Set(text2.split(/\s+/).filter((word) => word.length > 2));

    if (words1.size === 0 && words2.size === 0) return 1.0;
    if (words1.size === 0 || words2.size === 0) return 0.0;

    const intersection = new Set([...words1].filter((word) => words2.has(word)));
    const union = new Set([...words1, ...words2]);

    return intersection.size / union.size;
  }
}
