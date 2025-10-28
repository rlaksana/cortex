import { logger } from '../../utils/logger';
import { qdrant } from '../../db/qdrant-client';
import type {
  SimilarityService as ISimilarityService,
  KnowledgeItem,
} from '../../types/core-interfaces';

/**
 * Configuration for similarity detection
 */
interface SimilarityConfig {
  enabled: boolean;
  defaultThreshold: number;
  maxResults: number;
  includeContentAnalysis: boolean;
  includeMetadataAnalysis: boolean;
  weighting: {
    content: number;
    title: number;
    kind: number;
    scope: number;
  };
}

/**
 * Similarity analysis result
 */
interface SimilarityResult {
  item: KnowledgeItem;
  score: number;
  matchFactors: {
    content: number;
    title: number;
    kind: number;
    scope: number;
    overall: number;
  };
  reasoning: string[];
}

/**
 * Service for detecting similar knowledge items
 */
export class SimilarityService implements ISimilarityService {
  private config: SimilarityConfig = {
    enabled: true,
    defaultThreshold: 0.3,
    maxResults: 10,
    includeContentAnalysis: true,
    includeMetadataAnalysis: true,
    weighting: {
      content: 0.5,
      title: 0.2,
      kind: 0.1,
      scope: 0.2,
    },
  };

  /**
   * Find items similar to the given item
   */
  async findSimilar(
    item: KnowledgeItem,
    threshold: number = this.config.defaultThreshold
  ): Promise<KnowledgeItem[]> {
    if (!this.config.enabled) {
      return [];
    }

    try {
      const similarResults = await this.analyzeSimilarity(item, threshold);

      // Sort by similarity score descending
      similarResults.sort((a, b) => b.score - a.score);

      // Limit results
      const limitedResults = similarResults.slice(0, this.config.maxResults);

      logger.info(
        {
          itemKind: item.kind,
          threshold,
          candidatesFound: similarResults.length,
          resultsReturned: limitedResults.length,
        },
        'Similarity search completed'
      );

      return limitedResults.map((result) => result.item);
    } catch (error) {
      logger.error({ error, item }, 'Error finding similar items');
      return [];
    }
  }

  /**
   * Calculate similarity between two items
   */
  async calculateSimilarity(item1: KnowledgeItem, item2: KnowledgeItem): Promise<number> {
    if (!this.config.enabled) {
      return 0;
    }

    try {
      const similarity = await this.computeSimilarityScore(item1, item2);
      return similarity.overall;
    } catch (error) {
      logger.error({ error, item1, item2 }, 'Error calculating similarity');
      return 0;
    }
  }

  /**
   * Perform comprehensive similarity analysis
   */
  private async analyzeSimilarity(
    item: KnowledgeItem,
    threshold: number
  ): Promise<SimilarityResult[]> {
    const results: SimilarityResult[] = [];

    // Build database query for similar items
    const candidates = await this.getCandidateItems(item);

    for (const candidate of candidates) {
      const similarity = await this.computeSimilarityScore(item, candidate);

      if (similarity.overall >= threshold) {
        results.push({
          item: candidate,
          score: similarity.overall,
          matchFactors: similarity,
          reasoning: this.generateReasoning(similarity),
        });
      }
    }

    return results;
  }

  /**
   * Get candidate items from database for similarity comparison
   */
  private async getCandidateItems(item: KnowledgeItem): Promise<KnowledgeItem[]> {
    try {
      // Build the where clause for KnowledgeEntity table
      const whereClause: any = {
        deleted_at: null, // Exclude soft-deleted records
      };

      // Prioritize same entity_type (kind) items
      if (item.kind) {
        whereClause.entity_type = item.kind;
      }

      // Add scope filtering based on metadata or data fields
      if (item.scope?.project) {
        whereClause.OR = [
          {
            metadata: {
              path: ['scope', 'project'],
              equals: item.scope.project,
            },
          },
          {
            data: {
              path: ['scope', 'project'],
              equals: item.scope.project,
            },
          },
          {
            metadata: {
              path: ['org'],
              equals: item.scope.org || '',
            },
          },
        ];
      }

      // Limit to recent items for performance (last 30 days)
      const recentCutoff = new Date();
      recentCutoff.setDate(recentCutoff.getDate() - 30);
      whereClause.created_at = { gte: recentCutoff };

      // Query the KnowledgeEntity table
      const candidates = await qdrant.getClient().knowledgeEntity.findMany({
        where: whereClause,
        select: {
          id: true,
          entity_type: true,
          name: true,
          data: true,
          metadata: true,
          created_at: true,
          updated_at: true,
          tags: true,
        },
        orderBy: { created_at: 'desc' },
        take: 50, // Limit candidates for performance
      });

      // Map database rows to KnowledgeItem interface
      return candidates.map((row: any) => this.mapRowToKnowledgeItem(row));
    } catch (error) {
      logger.error(
        { error, itemKind: item.kind },
        'Error fetching candidate items from KnowledgeEntity table'
      );
      return [];
    }
  }

  /**
   * Map database row to KnowledgeItem interface
   */
  private mapRowToKnowledgeItem(row: any): KnowledgeItem {
    // Extract scope information from metadata or data fields
    let scope: { project?: string; branch?: string; org?: string } = {};

    // Try to get scope from metadata first
    if (row.metadata?.scope) {
      scope = {
        project: row.metadata.scope.project,
        branch: row.metadata.scope.branch,
        org: row.metadata.scope.org,
      };
    } else if (row.data?.scope) {
      // Fallback to data field
      scope = {
        project: row.data.scope.project,
        branch: row.data.scope.branch,
        org: row.data.scope.org,
      };
    }

    return {
      id: row.id,
      kind: row.entity_type, // Map entity_type to kind
      scope,
      data: row.data || {},
      created_at: row.created_at?.toISOString(),
      updated_at: row.updated_at?.toISOString(),
    };
  }

  /**
   * Compute detailed similarity score between two items
   */
  private async computeSimilarityScore(
    item1: KnowledgeItem,
    item2: KnowledgeItem
  ): Promise<{
    content: number;
    title: number;
    kind: number;
    scope: number;
    overall: number;
  }> {
    const factors = {
      content: 0,
      title: 0,
      kind: 0,
      scope: 0,
      overall: 0,
    };

    // Content similarity
    if (this.config.includeContentAnalysis) {
      factors.content = this.calculateContentSimilarity(item1.data, item2.data);
    }

    // Title similarity (if available)
    factors.title = this.calculateTitleSimilarity(item1.data, item2.data);

    // Kind similarity
    factors.kind = item1.kind === item2.kind ? 1.0 : 0.0;

    // Scope similarity
    factors.scope = this.calculateScopeSimilarity(item1.scope, item2.scope);

    // Calculate weighted overall score
    factors.overall =
      factors.content * this.config.weighting.content +
      factors.title * this.config.weighting.title +
      factors.kind * this.config.weighting.kind +
      factors.scope * this.config.weighting.scope;

    return factors;
  }

  /**
   * Calculate content similarity using multiple methods
   */
  private calculateContentSimilarity(
    data1: Record<string, any>,
    data2: Record<string, any>
  ): number {
    try {
      const text1 = JSON.stringify(data1).toLowerCase();
      const text2 = JSON.stringify(data2).toLowerCase();

      // Jaccard similarity on word tokens
      const words1 = new Set(this.extractWords(text1));
      const words2 = new Set(this.extractWords(text2));

      if (words1.size === 0 && words2.size === 0) return 1.0;
      if (words1.size === 0 || words2.size === 0) return 0.0;

      const intersection = new Set([...words1].filter((word) => words2.has(word)));
      const union = new Set([...words1, ...words2]);

      return intersection.size / union.size;
    } catch (error) {
      logger.error({ error }, 'Error calculating content similarity');
      return 0;
    }
  }

  /**
   * Calculate title similarity
   */
  private calculateTitleSimilarity(data1: Record<string, any>, data2: Record<string, any>): number {
    const title1 = this.extractTitle(data1);
    const title2 = this.extractTitle(data2);

    if (!title1 || !title2) return 0.0;

    return this.calculateStringSimilarity(title1.toLowerCase(), title2.toLowerCase());
  }

  /**
   * Calculate scope similarity
   */
  private calculateScopeSimilarity(scope1: any, scope2: any): number {
    if (!scope1 || !scope2) return 0.0;

    let similarity = 0;
    let factors = 0;

    if (scope1.project && scope2.project) {
      similarity += scope1.project === scope2.project ? 1 : 0;
      factors++;
    }

    if (scope1.branch && scope2.branch) {
      similarity += scope1.branch === scope2.branch ? 1 : 0;
      factors++;
    }

    if (scope1.org && scope2.org) {
      similarity += scope1.org === scope2.org ? 1 : 0;
      factors++;
    }

    return factors > 0 ? similarity / factors : 0;
  }

  /**
   * Extract meaningful words from text
   */
  private extractWords(text: string): string[] {
    return text
      .split(/\s+/)
      .filter((word) => word.length > 3) // Filter out very short words
      .filter((word) => !/^\d+$/.test(word)) // Filter out pure numbers
      .filter((word) => !this.isStopWord(word)); // Filter out common stop words
  }

  /**
   * Basic stop word filtering
   */
  private isStopWord(word: string): boolean {
    const stopWords = new Set([
      'the',
      'and',
      'for',
      'are',
      'but',
      'not',
      'you',
      'all',
      'can',
      'had',
      'her',
      'was',
      'one',
      'our',
      'out',
      'day',
      'get',
      'has',
      'him',
      'his',
      'how',
      'its',
      'may',
      'new',
      'now',
      'old',
      'see',
      'two',
      'way',
      'who',
      'boy',
      'did',
      'she',
      'use',
      'her',
      'many',
      'then',
      'them',
      'these',
      'want',
      'were',
      'will',
      'with',
      'your',
      'from',
      'have',
      'they',
      'been',
      'call',
      'come',
      'could',
      'does',
      'don',
      'into',
      'just',
      'like',
      'made',
      'make',
      'must',
      'over',
      'such',
      'that',
      'their',
      'there',
      'thing',
      'think',
      'time',
      'very',
      'when',
      'more',
      'much',
      'some',
      'said',
      'still',
      'than',
      'them',
      'well',
      'were',
      'what',
      'will',
      'with',
      'would',
      'your',
    ]);
    return stopWords.has(word);
  }

  /**
   * Extract title from data object
   */
  private extractTitle(data: Record<string, any>): string | null {
    // Try common title fields
    const titleFields = ['title', 'name', 'subject', 'heading', 'label'];

    for (const field of titleFields) {
      if (data[field] && typeof data[field] === 'string') {
        return data[field];
      }
    }

    return null;
  }

  /**
   * Calculate string similarity using Levenshtein distance
   */
  private calculateStringSimilarity(str1: string, str2: string): number {
    const matrix: number[][] = [];
    const len1 = str1.length;
    const len2 = str2.length;

    if (len1 === 0) return len2 === 0 ? 1 : 0;
    if (len2 === 0) return 0;

    // Initialize matrix
    for (let i = 0; i <= len1; i++) {
      matrix[i] = [i];
    }
    for (let j = 0; j <= len2; j++) {
      matrix[0][j] = j;
    }

    // Fill matrix
    for (let i = 1; i <= len1; i++) {
      for (let j = 1; j <= len2; j++) {
        const cost = str1[i - 1] === str2[j - 1] ? 0 : 1;
        matrix[i][j] = Math.min(
          matrix[i - 1][j] + 1, // deletion
          matrix[i][j - 1] + 1, // insertion
          matrix[i - 1][j - 1] + cost // substitution
        );
      }
    }

    const maxLen = Math.max(len1, len2);
    return (maxLen - matrix[len1][len2]) / maxLen;
  }

  /**
   * Generate human-readable reasoning for similarity
   */
  private generateReasoning(similarity: {
    content: number;
    title: number;
    kind: number;
    scope: number;
    overall: number;
  }): string[] {
    const reasoning: string[] = [];

    if (similarity.kind > 0) {
      reasoning.push('Same type of knowledge');
    }

    if (similarity.scope > 0.5) {
      reasoning.push('Related scope/context');
    }

    if (similarity.title > 0.7) {
      reasoning.push('Similar titles');
    }

    if (similarity.content > 0.5) {
      reasoning.push('Similar content');
    }

    if (reasoning.length === 0) {
      reasoning.push('Some similarity detected');
    }

    return reasoning;
  }

  /**
   * Update similarity configuration
   */
  updateConfig(newConfig: Partial<SimilarityConfig>): void {
    this.config = {
      ...this.config,
      ...newConfig,
      weighting: { ...this.config.weighting, ...newConfig.weighting },
    };
    logger.info({ config: this.config }, 'Similarity configuration updated');
  }

  /**
   * Get current configuration
   */
  getConfig(): SimilarityConfig {
    return JSON.parse(JSON.stringify(this.config));
  }
}

// Export singleton instance
export const similarityService = new SimilarityService();
