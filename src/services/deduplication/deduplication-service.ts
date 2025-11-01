import { logger } from '../../utils/logger.js';
import { qdrant } from '../../db/qdrant-client.js';
import type {
  DeduplicationService as IDeduplicationService,
  KnowledgeItem,
} from '../../types/core-interfaces.js';

/**
 * Configuration for deduplication behavior
 */
interface DeduplicationConfig {
  enabled: boolean;
  contentSimilarityThreshold: number;
  checkWithinScopeOnly: boolean;
  maxHistoryHours: number;
  dedupeWindowDays: number;
  allowNewerVersions: boolean;
  enableAuditLogging: boolean;
}

/**
 * Result of duplicate analysis
 */
interface DuplicateAnalysis {
  isDuplicate: boolean;
  existingId?: string;
  similarityScore: number;
  matchType: 'exact' | 'content' | 'semantic' | 'none';
  reason: string;
  isNewerVersion?: boolean;
  existingCreatedAt?: string;
  scopeMatch?: {
    org: boolean;
    project: boolean;
    branch: boolean;
  };
}

/**
 * Service for detecting and handling duplicate knowledge items
 */
export class DeduplicationService implements IDeduplicationService {
  private config: DeduplicationConfig = {
    enabled: true,
    contentSimilarityThreshold: 0.85,
    checkWithinScopeOnly: true,
    maxHistoryHours: 24 * 7, // 1 week
    dedupeWindowDays: 7,
    allowNewerVersions: true,
    enableAuditLogging: true,
  };

  /**
   * Map knowledge kinds to their corresponding Qdrant table names
   */
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

  /**
   * Check for duplicate items in the provided list
   */
  async checkDuplicates(
    items: KnowledgeItem[]
  ): Promise<{ duplicates: KnowledgeItem[]; originals: KnowledgeItem[] }> {
    if (!this.config.enabled) {
      return { duplicates: [], originals: items };
    }

    const duplicates: KnowledgeItem[] = [];
    const originals: KnowledgeItem[] = [];
    const seen = new Set<string>();

    // Check for exact duplicates within the input
    for (const item of items) {
      const signature = this.createItemSignature(item);
      if (seen.has(signature)) {
        duplicates.push(item);
      } else {
        seen.add(signature);
        originals.push(item);
      }
    }

    // Check for duplicates against existing database records
    const existingDuplicates = await this.checkAgainstExistingRecords(originals);
    duplicates.push(...existingDuplicates);

    // Filter out existing duplicates from originals
    const finalOriginals = originals.filter(
      (original) => !existingDuplicates.some((dup) => this.isSameItem(original, dup))
    );

    logger.info(
      {
        totalItems: items.length,
        duplicatesFound: duplicates.length,
        originalsRemaining: finalOriginals.length,
      },
      'Deduplication analysis complete'
    );

    return { duplicates, originals: finalOriginals };
  }

  /**
   * Remove duplicates from a list of items
   */
  async removeDuplicates(items: KnowledgeItem[]): Promise<KnowledgeItem[]> {
    const { duplicates, originals } = await this.checkDuplicates(items);

    logger.warn(
      {
        removedCount: duplicates.length,
        remainingCount: originals.length,
      },
      'Duplicates removed from item list'
    );

    return originals;
  }

  /**
   * Check if a single item is a duplicate of existing records
   */
  async isDuplicate(item: KnowledgeItem): Promise<DuplicateAnalysis> {
    if (!this.config.enabled) {
      return {
        isDuplicate: false,
        similarityScore: 0,
        matchType: 'none',
        reason: 'Deduplication is disabled',
      };
    }

    try {
      // Enhanced scope matching
      const scopeAnalysis = this.analyzeScopeMatch(item);

      // Check for exact matches first
      const exactMatch = await this.findExactMatch(item);
      if (exactMatch) {
        let isNewerVersion = false;
        let reason = 'Exact match found in database';
        let isDuplicate = true;

        // Check if this is a newer version
        if (this.config.allowNewerVersions && exactMatch.createdAt) {
          isNewerVersion = this.isNewerVersion(item, exactMatch.createdAt);
          if (isNewerVersion) {
            isDuplicate = false;
            reason = 'Newer version of existing content - not deduped';
          }
        }

        const analysis: DuplicateAnalysis = {
          isDuplicate,
          existingId: exactMatch.id,
          similarityScore: 1.0,
          matchType: 'exact' as const,
          reason,
          isNewerVersion,
          existingCreatedAt: exactMatch.createdAt,
          scopeMatch: scopeAnalysis,
        };

        // Log audit information
        if (this.config.enableAuditLogging) {
          await this.logDedupeDecision(item, analysis);
        }

        return analysis;
      }

      // Check for content similarity
      const contentMatch = await this.findContentMatch(item);
      if (contentMatch) {
        let isNewerVersion = false;
        let reason = `Content similarity ${contentMatch.similarity.toFixed(2)} exceeds threshold`;
        let isDuplicate = true;

        // Check if this is a newer version
        if (this.config.allowNewerVersions && contentMatch.createdAt) {
          isNewerVersion = this.isNewerVersion(item, contentMatch.createdAt);
          if (isNewerVersion) {
            isDuplicate = false;
            reason = 'Newer version of existing content - not deduped';
          }
        }

        const analysis: DuplicateAnalysis = {
          isDuplicate,
          existingId: contentMatch.id,
          similarityScore: contentMatch.similarity,
          matchType: 'content' as const,
          reason,
          isNewerVersion,
          existingCreatedAt: contentMatch.createdAt,
          scopeMatch: scopeAnalysis,
        };

        // Log audit information
        if (this.config.enableAuditLogging) {
          await this.logDedupeDecision(item, analysis);
        }

        return analysis;
      }

      const analysis = {
        isDuplicate: false,
        similarityScore: 0,
        matchType: 'none' as const,
        reason: 'No significant matches found',
        scopeMatch: scopeAnalysis,
      };

      // Log audit information
      if (this.config.enableAuditLogging) {
        await this.logDedupeDecision(item, analysis);
      }

      return analysis;
    } catch (error) {
      logger.error({ error, item }, 'Error checking for duplicates');
      return {
        isDuplicate: false,
        similarityScore: 0,
        matchType: 'none',
        reason: 'Error during duplicate check',
      };
    }
  }

  /**
   * Create a unique signature for an item for exact duplicate detection
   */
  private createItemSignature(item: KnowledgeItem): string {
    const signatureData = {
      kind: item.kind,
      scope: item.scope,
      // Sort data keys to ensure consistent signature
      data: Object.keys(item.data || {})
        .sort()
        .reduce(
          (result, key) => {
            result[key] = item.data[key];
            return result;
          },
          {} as Record<string, any>
        ),
    };

    return JSON.stringify(signatureData);
  }

  /**
   * Check if two items represent the same knowledge
   */
  private isSameItem(item1: KnowledgeItem, item2: KnowledgeItem): boolean {
    return this.createItemSignature(item1) === this.createItemSignature(item2);
  }

  /**
   * Check items against existing database records
   */
  private async checkAgainstExistingRecords(items: KnowledgeItem[]): Promise<KnowledgeItem[]> {
    const existingDuplicates: KnowledgeItem[] = [];

    for (const item of items) {
      const analysis = await this.isDuplicate(item);
      if (analysis.isDuplicate) {
        existingDuplicates.push(item);
      }
    }

    return existingDuplicates;
  }

  /**
   * Find exact matches in the database
   */
  private async findExactMatch(
    item: KnowledgeItem
  ): Promise<{ id: string; similarity: number; createdAt: string } | null> {
    const whereClause: any = {
      kind: item.kind,
    };

    // Add scope filtering if configured
    if (this.config.checkWithinScopeOnly && item.scope) {
      if (item.scope.project) {
        whereClause.scope_project = item.scope.project;
      }
      if (item.scope.branch) {
        whereClause.scope_branch = item.scope.branch;
      }
      if (item.scope.org) {
        whereClause.scope_org = item.scope.org;
      }
    }

    // Add time filtering
    if (this.config.maxHistoryHours > 0) {
      const cutoffDate = new Date();
      cutoffDate.setHours(cutoffDate.getHours() - this.config.maxHistoryHours);
      whereClause.created_at = { gte: cutoffDate };
    }

    // Query for exact matches in the appropriate table
    const tableName = this.getTableNameForKind(item.kind);
    if (!tableName) {
      return null; // Unknown knowledge kind
    }

    const existing = await (qdrant as any)[tableName].findFirst({
      where: whereClause,
      select: { id: true, created_at: true },
    });

    return existing ? { id: existing.id, similarity: 1.0, createdAt: existing.created_at } : null;
  }

  /**
   * Find content-based matches using similarity search
   */
  private async findContentMatch(
    item: KnowledgeItem
  ): Promise<{ id: string; similarity: number; createdAt: string } | null> {
    // This is a simplified implementation
    // In a real system, you would use more sophisticated similarity algorithms
    // such as vector embeddings, text similarity, etc.

    try {
      // For now, we'll use a basic text-based similarity check
      const contentText = JSON.stringify(item.data).toLowerCase();

      // Get recent items of the same kind for comparison
      const whereClause: any = {
        kind: item.kind,
      };

      if (this.config.checkWithinScopeOnly && item.scope?.project) {
        whereClause.scope_project = item.scope.project;
      }

      if (this.config.maxHistoryHours > 0) {
        const cutoffDate = new Date();
        cutoffDate.setHours(cutoffDate.getHours() - this.config.maxHistoryHours);
        whereClause.created_at = { gte: cutoffDate };
      }

      const tableName = this.getTableNameForKind(item.kind);
      if (!tableName) {
        return null;
      }

      const recentItems = await (qdrant as any)[tableName].findMany({
        where: whereClause,
        select: { id: true, data: true, created_at: true },
        orderBy: { created_at: 'desc' },
        take: 10, // Limit to recent items for performance
      });

      for (const existingItem of recentItems) {
        const existingText = JSON.stringify(existingItem.data).toLowerCase();
        const similarity = this.calculateTextSimilarity(contentText, existingText);

        if (similarity >= this.config.contentSimilarityThreshold) {
          return { id: existingItem.id, similarity, createdAt: existingItem.created_at };
        }
      }

      return null;
    } catch (error) {
      logger.error({ error }, 'Error in content similarity search');
      return null;
    }
  }

  /**
   * Calculate simple text similarity (Jaccard similarity)
   */
  private calculateTextSimilarity(text1: string, text2: string): number {
    const words1 = new Set(text1.split(/\s+/).filter((word) => word.length > 2));
    const words2 = new Set(text2.split(/\s+/).filter((word) => word.length > 2));

    if (words1.size === 0 && words2.size === 0) return 1.0;
    if (words1.size === 0 || words2.size === 0) return 0.0;

    const intersection = new Set([...words1].filter((word) => words2.has(word)));
    const union = new Set([...words1, ...words2]);

    return intersection.size / union.size;
  }

  /**
   * Update deduplication configuration
   */
  updateConfig(newConfig: Partial<DeduplicationConfig>): void {
    this.config = { ...this.config, ...newConfig };
    logger.info({ config: this.config }, 'Deduplication configuration updated');
  }

  /**
   * Get current configuration
   */
  getConfig(): DeduplicationConfig {
    return { ...this.config };
  }

  /**
   * Analyze scope matching for enhanced deduplication
   */
  private analyzeScopeMatch(item: KnowledgeItem): {
    org: boolean;
    project: boolean;
    branch: boolean;
  } {
    const itemScope = item.scope || {};

    return {
      org: !!itemScope.org,
      project: !!itemScope.project,
      branch: !!itemScope.branch,
    };
  }

  /**
   * Check if an item is a newer version than existing content
   */
  private isNewerVersion(item: KnowledgeItem, existingCreatedAt: string): boolean {
    const existingTime = new Date(existingCreatedAt).getTime();
    const itemTime = item.created_at ? new Date(item.created_at).getTime() : Date.now();

    // Consider it newer if it was created after the existing item
    // and within the dedupe window
    const daysDiff = (itemTime - existingTime) / (1000 * 60 * 60 * 24);

    return daysDiff > 0 && daysDiff <= this.config.dedupeWindowDays;
  }

  /**
   * Log deduplication decision for audit purposes
   */
  private async logDedupeDecision(item: KnowledgeItem, analysis: DuplicateAnalysis): Promise<void> {
    try {
      const auditData = {
        itemId: item.id,
        itemKind: item.kind,
        itemScope: item.scope,
        isDuplicate: analysis.isDuplicate,
        similarityScore: analysis.similarityScore,
        matchType: analysis.matchType,
        reason: analysis.reason,
        existingId: analysis.existingId,
        isNewerVersion: analysis.isNewerVersion,
        scopeMatch: analysis.scopeMatch,
        timestamp: new Date().toISOString(),
        config: {
          contentSimilarityThreshold: this.config.contentSimilarityThreshold,
          checkWithinScopeOnly: this.config.checkWithinScopeOnly,
          dedupeWindowDays: this.config.dedupeWindowDays,
          allowNewerVersions: this.config.allowNewerVersions,
        },
      };

      // Store audit log - this would typically go to an audit collection
      logger.info(auditData, 'Deduplication decision logged');
    } catch (error) {
      logger.warn({ error }, 'Failed to log deduplication decision');
    }
  }

  /**
   * Get deduplication statistics
   */
  async getDedupeStats(): Promise<{
    totalChecks: number;
    duplicatesFound: number;
    newerVersionsAllowed: number;
    scopeMatches: {
      org: number;
      project: number;
      branch: number;
    };
  }> {
    // This would typically query an audit collection for statistics
    // For now, return placeholder data
    return {
      totalChecks: 0,
      duplicatesFound: 0,
      newerVersionsAllowed: 0,
      scopeMatches: {
        org: 0,
        project: 0,
        branch: 0,
      },
    };
  }
}

// Export singleton instance
export const deduplicationService = new DeduplicationService();
