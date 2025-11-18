/**
 * Memory Store Service - Class Wrapper for Memory Store Functionality
 *
 * Provides a class-based interface for memory store operations to match
 * test expectations while wrapping the existing functional implementation.
 *
 * This class acts as a wrapper around the memory store function and
 * orchestrator, providing a more traditional object-oriented interface.
 *
 * Features:
 * - Class-based interface matching test expectations
 * - Wraps existing memory store functionality
 * - Database manager integration
 * - Chunking service coordination
 * - Compatible with existing test patterns
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { logger } from '@/utils/logger.js';

import { memoryStore } from './memory-store.js';
import type { MemoryStoreResponse } from '../types/core-interfaces.js';

/**
 * Memory Store Service provides a class-based interface for memory storage
 *
 * This class wraps the functional memory store implementation to provide
 * the interface expected by tests.
 */
export class MemoryStoreService {
  private databaseManager: unknown;
  private chunkingService: unknown;

  constructor(databaseManager: unknown, chunkingService?: unknown) {
    this.databaseManager = databaseManager;
    this.chunkingService = chunkingService;
  }

  /**
   * Store items in memory
   */
  async store(items: unknown[], options?: unknown): Promise<MemoryStoreResponse> {
    try {
      logger.info({ itemCount: items.length }, 'MemoryStoreService.store called');

      // Delegate to the functional memory store implementation
      const result = await memoryStore(items, options);

      return result;
    } catch (error) {
      logger.error({ error, itemCount: items.length }, 'MemoryStoreService.store failed');
      throw error;
    }
  }

  /**
   * Store a single item
   */
  async storeItem(item: unknown, options?: unknown): Promise<MemoryStoreResponse> {
    return this.store([item], options);
  }

  /**
   * Store items with insight generation
   */
  async storeWithInsights(items: unknown[], options?: unknown): Promise<MemoryStoreResponse> {
    return this.store(items, { ...options, insight: true });
  }

  /**
   * Get the database manager
   */
  getDatabaseManager(): unknown {
    return this.databaseManager;
  }

  /**
   * Get the chunking service
   */
  getChunkingService(): unknown {
    return this.chunkingService;
  }

  /**
   * Health check for the service
   */
  async healthCheck(): Promise<boolean> {
    try {
      if (this.databaseManager) {
        return await this.databaseManager.healthCheck();
      }
      return true;
    } catch (error) {
      logger.error({ error }, 'MemoryStoreService health check failed');
      return false;
    }
  }

  /**
   * Get service metrics
   */
  async getMetrics(): Promise<unknown> {
    try {
      if (this.databaseManager) {
        return await this.databaseManager.getMetrics();
      }
      return {};
    } catch (error) {
      logger.error({ error }, 'MemoryStoreService getMetrics failed');
      return {};
    }
  }
}
