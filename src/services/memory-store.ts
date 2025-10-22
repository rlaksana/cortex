import { logger } from '../utils/logger.js';
import { memoryStoreOrchestrator } from './orchestrators/memory-store-orchestrator.js';
import type { MemoryStoreResponse } from '../types/core-interfaces.js';

/**
 * Main entry point for memory store operations
 *
 * This function has been refactored to use the MemoryStoreOrchestrator
 * which coordinates validation, deduplication, similarity detection,
 * and storage operations across multiple services.
 *
 * The original 825-line function has been broken down into:
 * - ValidationService: Input validation and business rule enforcement
 * - DeduplicationService: Duplicate detection and handling
 * - SimilarityService: Content similarity analysis
 * - AuditService: Comprehensive audit logging
 * - MemoryStoreOrchestrator: Coordinates all services
 *
 * Each service now has a single responsibility and functions
 * are under 50 lines as required.
 */
export async function memoryStore(items: unknown[]): Promise<MemoryStoreResponse> {
  try {
    logger.info({ itemCount: items.length }, 'Memory store operation started');

    // Delegate to the orchestrator which handles all the complex logic
    const result = await memoryStoreOrchestrator.storeItems(items);

    logger.info({
      itemsStored: result.stored.length,
      errors: result.errors.length,
      duration: Date.now()
    }, 'Memory store operation completed');

    return result;

  } catch (error) {
    logger.error({ error, itemCount: items.length }, 'Memory store operation failed');

    // Return a formatted error response
    return {
      stored: [],
      errors: [{
        index: 0,
        error_code: 'SYSTEM_ERROR',
        message: error instanceof Error ? error.message : 'Unknown system error'
      }],
      autonomous_context: {
        action_performed: 'skipped',
        similar_items_checked: 0,
        duplicates_found: 0,
        contradictions_detected: false,
        recommendation: 'System error occurred - please try again',
        reasoning: 'Critical system error during memory store operation',
        user_message_suggestion: '❌ System error occurred'
      }
    };
  }
}