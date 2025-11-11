/**
 * Deduplication Service Adapter
 *
 * Adapts the DeduplicationService to implement the IDeduplicationService interface.
 * Bridges interface gaps while maintaining backward compatibility.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { type DeduplicationService } from '../../services/deduplication/deduplication-service.js';
import type { KnowledgeItem } from '../../types/core-interfaces.js';
import type { IDeduplicationService } from '../service-interfaces.js';

/**
 * Adapter for Deduplication service
 */
export class DeduplicationServiceAdapter implements IDeduplicationService {
  constructor(private deduplicationService: DeduplicationService) {}

  /**
   * Detect duplicates in a list of knowledge items
   */
  async detectDuplicates(items: KnowledgeItem[]): Promise<
    Array<{
      original: KnowledgeItem;
      duplicates: KnowledgeItem[];
      similarity: number;
    }>
  > {
    // Use the deduplication service's checkDuplicates method
    const { duplicates, originals } = await this.deduplicationService.checkDuplicates(items);

    // Convert to the expected interface format
    const results: Array<{
      original: KnowledgeItem;
      duplicates: KnowledgeItem[];
      similarity: number;
    }> = [];

    // For each original item, find its duplicates
    for (const original of originals) {
      // Find duplicates that are similar to this original
      const similarDuplicates = duplicates.filter(
        (dup) => this.calculateSimilarity(original, dup) > 0.8
      );

      if (similarDuplicates.length > 0) {
        results.push({
          original,
          duplicates: similarDuplicates,
          similarity: this.calculateAverageSimilarity(original, similarDuplicates),
        });
      }
    }

    return results;
  }

  /**
   * Merge knowledge items using a specific strategy
   */
  async merge(items: KnowledgeItem[], strategy: string): Promise<KnowledgeItem> {
    if (items.length === 0) {
      throw new Error('Cannot merge empty list of items');
    }

    if (items.length === 1) {
      return items[0];
    }

    // For now, implement a simple merge strategy
    // In a full implementation, you'd have different merge strategies
    switch (strategy.toLowerCase()) {
      case 'latest':
        // Return the most recently updated item
        return items.reduce((latest, current) => {
          const latestTime = new Date(
            latest.updated_at || latest.created_at || '1970-01-01'
          ).getTime();
          const currentTime = new Date(
            current.updated_at || current.created_at || '1970-01-01'
          ).getTime();
          return currentTime > latestTime ? current : latest;
        });

      case 'combine':
        // Combine data from all items
        return this.combineItems(items);

      case 'first':
      default:
        // Return the first item
        return items[0];
    }
  }

  /**
   * Calculate similarity between two knowledge items
   */
  private calculateSimilarity(item1: KnowledgeItem, item2: KnowledgeItem): number {
    // Simple similarity calculation based on kind and data
    if (item1.kind !== item2.kind) {
      return 0;
    }

    // Calculate text similarity
    const text1 = JSON.stringify(item1.data || {}).toLowerCase();
    const text2 = JSON.stringify(item2.data || {}).toLowerCase();

    // Simple Jaccard similarity
    const words1 = new Set(text1.split(/\s+/).filter((word) => word.length > 2));
    const words2 = new Set(text2.split(/\s+/).filter((word) => word.length > 2));

    if (words1.size === 0 && words2.size === 0) return 1.0;
    if (words1.size === 0 || words2.size === 0) return 0.0;

    const intersection = new Set([...words1].filter((word) => words2.has(word)));
    const union = new Set([...words1, ...words2]);

    return intersection.size / union.size;
  }

  /**
   * Calculate average similarity between an original and its duplicates
   */
  private calculateAverageSimilarity(original: KnowledgeItem, duplicates: KnowledgeItem[]): number {
    if (duplicates.length === 0) return 0;

    const totalSimilarity = duplicates.reduce(
      (sum, duplicate) => sum + this.calculateSimilarity(original, duplicate),
      0
    );

    return totalSimilarity / duplicates.length;
  }

  /**
   * Combine multiple knowledge items into one
   */
  private combineItems(items: KnowledgeItem[]): KnowledgeItem {
    if (items.length === 0) {
      throw new Error('Cannot combine empty list of items');
    }

    // Use the first item as the base
    const combined: KnowledgeItem = {
      ...items[0],
      updated_at: new Date().toISOString(),
      data: { ...items[0].data },
      metadata: {
        ...items[0].metadata,
        merged_from: items.slice(1).map((item) => item.id),
        merge_count: items.length,
        merge_timestamp: new Date().toISOString(),
      },
    };

    // Merge data from other items
    for (let i = 1; i < items.length; i++) {
      const item = items[i];

      // Merge data fields, preferring non-null values
      if (item.data) {
        for (const [key, value] of Object.entries(item.data)) {
          if (value !== undefined && value !== null && value !== '') {
            combined.data[key] = value;
          }
        }
      }

      // Merge metadata
      if (item.metadata) {
        combined.metadata = { ...combined.metadata, ...item.metadata };
      }
    }

    // Update scope if provided
    const scopes = items.map((item) => item.scope).filter(Boolean);
    if (scopes.length > 0) {
      combined.scope = {
        org: scopes.find((s) => s.org)?.org,
        project: scopes.find((s) => s.project)?.project,
        branch: scopes.find((s) => s.branch)?.branch,
      };
    }

    return combined;
  }
}
