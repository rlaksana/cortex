/**
 * TTL Management Service
 *
 * Comprehensive TTL (Time-To-Live) management for Cortex Memory.
 * Integrates with existing systems to provide policy application,
 * expiry checking, and bulk operations.
 *
 * Features:
 * - TTL policy application and enforcement
 * - Automatic expiry checking and cleanup
 * - Bulk TTL operations for performance
 * - Integration with memory store/find services
 * - Comprehensive audit logging
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

import { logger } from '../../utils/logger.js';
import {
  ttlPolicyService,
  type TTLPolicyOptions,
  type TTLCalculationResult,
} from './ttl-policy-service.js';
import {
  enhancedExpiryUtils,
  type ExpiryCalculationOptions,
} from '../../utils/enhanced-expiry-utils.js';
import { QdrantOnlyDatabaseLayer } from '../../db/unified-database-layer-v2.js';
import type {
  KnowledgeItem,
  StoreResult,
  SearchQuery,
  MemoryFindResponse,
} from '../../types/core-interfaces.js';

/**
 * TTL management operation result interface
 */
export interface TTLOperationResult {
  success: boolean;
  processed: number;
  updated: number;
  errors: string[];
  warnings: string[];
  duration: number;
  details?: {
    itemsProcessed: string[];
    policiesApplied: Record<string, number>;
    expiriesCalculated: Array<{
      itemId: string;
      oldExpiry?: string;
      newExpiry: string;
      policy: string;
    }>;
  };
}

/**
 * TTL bulk operation options interface
 */
export interface TTLBulkOperationOptions {
  /** Batch size for processing */
  batchSize?: number;
  /** Continue processing on errors */
  continueOnError?: boolean;
  /** Dry run mode - don't actually apply changes */
  dryRun?: boolean;
  /** Include detailed results */
  verbose?: boolean;
  /** Apply TTL validation */
  validatePolicies?: boolean;
  /** Generate audit log */
  generateAudit?: boolean;
}

/**
 * TTL statistics interface
 */
export interface TTLStatistics {
  totalItems: number;
  itemsWithExpiry: number;
  itemsWithoutExpiry: number;
  permanentItems: number;
  expiredItems: number;
  expiringSoon: number; // Next 24 hours
  policyDistribution: Record<string, number>;
  averageTTL: number; // in days
  storageImpact: {
    totalSize: number;
    expiredSize: number;
    potentialReclaimable: number;
  };
}

/**
 * TTL Management Service
 *
 * Centralized service for TTL operations, policy management, and expiry handling.
 */
export class TTLManagementService {
  private db: QdrantOnlyDatabaseLayer;
  private auditLog: Array<{
    timestamp: string;
    operation: string;
    details: any;
    result: any;
  }> = [];

  constructor(database: QdrantOnlyDatabaseLayer) {
    this.db = database;
    logger.info('TTL Management Service initialized');
  }

  /**
   * Apply TTL policy to knowledge items
   */
  async applyTTLPolicy(
    items: KnowledgeItem[],
    policyOptions: TTLPolicyOptions = {},
    bulkOptions: TTLBulkOperationOptions = {}
  ): Promise<TTLOperationResult> {
    const startTime = Date.now();
    const result: TTLOperationResult = {
      success: true,
      processed: 0,
      updated: 0,
      errors: [],
      warnings: [],
      duration: 0,
      details: {
        itemsProcessed: [],
        policiesApplied: {},
        expiriesCalculated: [],
      },
    };

    const batchSize = bulkOptions.batchSize || 50;
    const dryRun = bulkOptions.dryRun || false;

    try {
      logger.info('Starting TTL policy application', {
        itemCount: items.length,
        policyOptions,
        bulkOptions,
      });

      // Process items in batches
      for (let i = 0; i < items.length; i += batchSize) {
        const batch = items.slice(i, i + batchSize);
        await this.processBatch(batch, policyOptions, bulkOptions, result);

        if (result.errors.length > 0 && !bulkOptions.continueOnError) {
          result.success = false;
          break;
        }
      }

      // Store items if not dry run
      if (!dryRun && result.updated > 0) {
        const itemsToStore = items.filter((item, index) =>
          result.details?.expiriesCalculated.some((calc) => calc.itemId === item.id)
        );

        await this.db.store(itemsToStore);
        logger.info('Stored items with applied TTL policies', {
          count: itemsToStore.length,
        });
      }

      // Generate audit log if requested
      if (bulkOptions.generateAudit) {
        this.addToAuditLog('apply_ttl_policy', {
          itemCount: items.length,
          policyOptions,
          bulkOptions,
          result,
        });
      }
    } catch (error) {
      result.success = false;
      result.errors.push(
        `TTL policy application failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
      logger.error('TTL policy application failed', { error, items: items.length });
    }

    result.duration = Date.now() - startTime;

    logger.info('TTL policy application completed', {
      success: result.success,
      processed: result.processed,
      updated: result.updated,
      errors: result.errors.length,
      warnings: result.warnings.length,
      duration: result.duration,
    });

    return result;
  }

  /**
   * Check and cleanup expired items
   */
  async cleanupExpiredItems(
    bulkOptions: TTLBulkOperationOptions = {}
  ): Promise<TTLOperationResult> {
    const startTime = Date.now();
    const result: TTLOperationResult = {
      success: true,
      processed: 0,
      updated: 0,
      errors: [],
      warnings: [],
      duration: 0,
      details: {
        itemsProcessed: [],
        policiesApplied: {},
        expiriesCalculated: [],
      },
    };

    const dryRun = bulkOptions.dryRun || false;

    try {
      logger.info('Starting expired items cleanup', { bulkOptions });

      // Find expired items using enhanced filter
      const expiredQuery: SearchQuery = {
        query: '*',
        limit: 10000, // Large batch for cleanup
      };

      // Build filter for expired items
      const now = new Date().toISOString();
      const expiredItems = await this.findExpiredItems(now);

      result.processed = expiredItems.length;

      if (expiredItems.length === 0) {
        logger.info('No expired items found');
        result.duration = Date.now() - startTime;
        return result;
      }

      // Delete expired items
      if (!dryRun) {
        const idsToDelete = expiredItems.map((item) => item.id).filter(Boolean);
        const deleteResult = await this.db.delete(idsToDelete);

        result.updated = deleteResult.deleted;
        result.details!.itemsProcessed = idsToDelete;

        logger.info('Deleted expired items', {
          deleted: result.updated,
          totalProcessed: result.processed,
        });
      } else {
        result.warnings.push(`Dry run: Would delete ${expiredItems.length} expired items`);
        result.details!.itemsProcessed = expiredItems.map((item) => item.id).filter(Boolean);
      }

      // Generate audit log
      if (bulkOptions.generateAudit) {
        this.addToAuditLog('cleanup_expired_items', {
          expiredCount: expiredItems.length,
          deletedCount: result.updated,
          dryRun,
          result,
        });
      }
    } catch (error) {
      result.success = false;
      result.errors.push(
        `Expired items cleanup failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
      logger.error('Expired items cleanup failed', { error });
    }

    result.duration = Date.now() - startTime;

    logger.info('Expired items cleanup completed', {
      success: result.success,
      processed: result.processed,
      updated: result.updated,
      duration: result.duration,
    });

    return result;
  }

  /**
   * Update TTL for existing items
   */
  async updateItemTTL(
    itemIds: string[],
    newPolicy: TTLPolicyOptions,
    bulkOptions: TTLBulkOperationOptions = {}
  ): Promise<TTLOperationResult> {
    const startTime = Date.now();
    const result: TTLOperationResult = {
      success: true,
      processed: 0,
      updated: 0,
      errors: [],
      warnings: [],
      duration: 0,
      details: {
        itemsProcessed: [],
        policiesApplied: {},
        expiriesCalculated: [],
      },
    };

    const dryRun = bulkOptions.dryRun || false;

    try {
      logger.info('Starting TTL update for items', {
        itemCount: itemIds.length,
        newPolicy,
      });

      // Find items by IDs
      const findResponse = await this.db.findById(itemIds);
      const items = findResponse.results;

      result.processed = items.length;

      // Apply new TTL policy to items
      for (const item of items) {
        try {
          // Convert SearchResult to KnowledgeItem
          const knowledgeItem: KnowledgeItem = {
            id: item.id,
            kind: item.kind,
            scope: item.scope as any,
            data: item.data,
            created_at: item.created_at,
          };

          // Calculate new expiry
          const expiryResult = ttlPolicyService.calculateExpiry(knowledgeItem, newPolicy);

          if (expiryResult.validationErrors.length > 0) {
            result.errors.push(`Item ${item.id}: ${expiryResult.validationErrors.join(', ')}`);
            continue;
          }

          // Update item with new expiry
          knowledgeItem.expiry_at = expiryResult.expiryAt;
          knowledgeItem.data = {
            ...knowledgeItem.data,
            ttl_policy: expiryResult.policyApplied,
            ttl_duration_ms: expiryResult.durationMs,
            expiry_updated_at: new Date().toISOString(),
          };

          result.details!.expiriesCalculated.push({
            itemId: item.id,
            oldExpiry: knowledgeItem.expiry_at,
            newExpiry: expiryResult.expiryAt,
            policy: expiryResult.policyApplied,
          });

          if (expiryResult.warnings.length > 0) {
            result.warnings.push(`Item ${item.id}: ${expiryResult.warnings.join(', ')}`);
          }

          result.updated++;
        } catch (error) {
          result.errors.push(
            `Item ${item.id}: ${error instanceof Error ? error.message : 'Unknown error'}`
          );
          if (!bulkOptions.continueOnError) {
            result.success = false;
            break;
          }
        }
      }

      // Store updated items if not dry run
      if (!dryRun && result.updated > 0) {
        const itemsToUpdate = result
          .details!.expiriesCalculated.map((calc) => {
            const originalItem = items.find((item) => item.id === calc.itemId);
            if (!originalItem) return null;

            return {
              id: calc.itemId,
              kind: originalItem.kind,
              scope: originalItem.scope as any,
              data: {
                ...originalItem.data,
                expiry_at: calc.newExpiry,
                ttl_policy: calc.policy,
                ttl_updated_at: new Date().toISOString(),
              },
              expiry_at: calc.newExpiry,
            };
          })
          .filter(Boolean) as KnowledgeItem[];

        await this.db.store(itemsToUpdate);
        logger.info('Updated items with new TTL', { count: itemsToUpdate.length });
      }

      // Generate audit log
      if (bulkOptions.generateAudit) {
        this.addToAuditLog('update_item_ttl', {
          itemCount: itemIds.length,
          newPolicy,
          bulkOptions,
          result,
        });
      }
    } catch (error) {
      result.success = false;
      result.errors.push(
        `TTL update failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
      logger.error('TTL update failed', { error, itemIds });
    }

    result.duration = Date.now() - startTime;

    logger.info('TTL update completed', {
      success: result.success,
      processed: result.processed,
      updated: result.updated,
      duration: result.duration,
    });

    return result;
  }

  /**
   * Get comprehensive TTL statistics
   */
  async getTTLStatistics(scope?: any): Promise<TTLStatistics> {
    try {
      logger.info('Generating TTL statistics', { scope });

      // Get total items count
      const totalItemsResponse = await this.db.search({
        query: '*',
        limit: 1,
        scope,
      });

      // Get items with expiry
      const itemsWithExpiryResponse = await this.db.search({
        query: '*',
        limit: 10000,
        scope,
      });

      // This is a simplified version - in practice, you'd want to use database aggregation
      const items = itemsWithExpiryResponse.results;
      const now = new Date();
      const tomorrow = new Date(now.getTime() + 24 * 60 * 60 * 1000);

      let itemsWithExpiry = 0;
      let itemsWithoutExpiry = 0;
      let permanentItems = 0;
      let expiredItems = 0;
      let expiringSoon = 0;
      const policyDistribution: Record<string, number> = {};
      let totalTTLDays = 0;
      let ttlCount = 0;

      for (const item of items) {
        const expiryTime = item.data?.expiry_at;

        if (expiryTime) {
          itemsWithExpiry++;

          if (expiryTime === '9999-12-31T23:59:59.999Z') {
            permanentItems++;
          } else {
            const expiryDate = new Date(expiryTime);

            if (expiryDate < now) {
              expiredItems++;
            } else if (expiryDate < tomorrow) {
              expiringSoon++;
            }

            // Calculate TTL in days
            const ttlDays = Math.ceil(
              (expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
            );
            if (ttlDays > 0 && ttlDays < 3650) {
              // Reasonable range
              totalTTLDays += ttlDays;
              ttlCount++;
            }
          }

          // Count policy distribution
          const policy = item.data?.ttl_policy || 'unknown';
          policyDistribution[policy] = (policyDistribution[policy] || 0) + 1;
        } else {
          itemsWithoutExpiry++;
        }
      }

      const averageTTL = ttlCount > 0 ? totalTTLDays / ttlCount : 0;

      const statistics: TTLStatistics = {
        totalItems: items.length,
        itemsWithExpiry,
        itemsWithoutExpiry,
        permanentItems,
        expiredItems,
        expiringSoon,
        policyDistribution,
        averageTTL,
        storageImpact: {
          totalSize: 0, // Would need actual storage metrics
          expiredSize: 0,
          potentialReclaimable: expiredItems * 1024, // Rough estimate
        },
      };

      logger.info('TTL statistics generated', {
        totalItems: statistics.totalItems,
        expiredItems: statistics.expiredItems,
        expiringSoon: statistics.expiringSoon,
        averageTTL: statistics.averageTTL,
      });

      return statistics;
    } catch (error) {
      logger.error('Failed to generate TTL statistics', { error, scope });
      throw error;
    }
  }

  /**
   * Get audit log entries
   */
  getAuditLog(limit?: number): Array<{
    timestamp: string;
    operation: string;
    details: any;
    result: any;
  }> {
    const log = [...this.auditLog].reverse(); // Most recent first
    return limit ? log.slice(0, limit) : log;
  }

  /**
   * Clear audit log
   */
  clearAuditLog(): void {
    this.auditLog = [];
    logger.info('TTL audit log cleared');
  }

  /**
   * Process a batch of items for TTL application
   */
  private async processBatch(
    batch: KnowledgeItem[],
    policyOptions: TTLPolicyOptions,
    bulkOptions: TTLBulkOperationOptions,
    result: TTLOperationResult
  ): Promise<void> {
    for (const item of batch) {
      try {
        result.processed++;

        // Calculate expiry using policy service
        const expiryResult = ttlPolicyService.calculateExpiry(item, policyOptions);

        if (expiryResult.validationErrors.length > 0) {
          result.errors.push(`Item ${item.id}: ${expiryResult.validationErrors.join(', ')}`);
          continue;
        }

        // Update item with expiry information
        item.expiry_at = expiryResult.expiryAt;
        item.data = {
          ...item.data,
          ttl_policy: expiryResult.policyApplied,
          ttl_duration_ms: expiryResult.durationMs,
          expiry_calculated_at: new Date().toISOString(),
        };

        result.details!.expiriesCalculated.push({
          itemId: item.id || `item_${result.processed}`,
          newExpiry: expiryResult.expiryAt,
          policy: expiryResult.policyApplied,
        });

        // Count policy applications
        result.details!.policiesApplied[expiryResult.policyApplied] =
          (result.details!.policiesApplied[expiryResult.policyApplied] || 0) + 1;

        if (expiryResult.warnings.length > 0) {
          result.warnings.push(`Item ${item.id}: ${expiryResult.warnings.join(', ')}`);
        }

        result.updated++;
      } catch (error) {
        result.errors.push(
          `Item ${item.id}: ${error instanceof Error ? error.message : 'Unknown error'}`
        );
        if (!bulkOptions.continueOnError) {
          throw error;
        }
      }
    }
  }

  /**
   * Find expired items using enhanced filtering
   */
  private async findExpiredItems(
    expiryBefore: string
  ): Promise<Array<{ id: string; kind: string }>> {
    try {
      // Use the Qdrant adapter's search method with expiry filter
      const searchResponse = await this.db.search(
        {
          query: '*',
          limit: 10000,
        },
        {
          // Pass custom filter options through SearchOptions (would need to extend this)
        }
      );

      // Filter expired items in application layer
      return searchResponse.results
        .filter((item) => {
          const expiryTime = item.data?.expiry_at;
          return expiryTime && new Date(expiryTime) < new Date(expiryBefore);
        })
        .map((item) => ({
          id: item.id,
          kind: item.kind,
        }));
    } catch (error) {
      logger.error('Failed to find expired items', { error });
      throw error;
    }
  }

  /**
   * Add entry to audit log
   */
  private addToAuditLog(operation: string, details: any, result?: any): void {
    this.auditLog.push({
      timestamp: new Date().toISOString(),
      operation,
      details,
      result,
    });

    // Keep audit log size manageable (keep last 1000 entries)
    if (this.auditLog.length > 1000) {
      this.auditLog = this.auditLog.slice(-1000);
    }
  }
}

// Export factory function
export function createTTLManagementService(
  database: QdrantOnlyDatabaseLayer
): TTLManagementService {
  return new TTLManagementService(database);
}
