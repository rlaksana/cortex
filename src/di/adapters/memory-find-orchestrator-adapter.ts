/**
 * Memory Find Orchestrator Adapter
 *
 * Adapts the MemoryFindOrchestrator to implement the IMemoryFindOrchestrator interface.
 * Bridges interface gaps while maintaining backward compatibility.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { type MemoryFindOrchestrator } from '../../services/orchestrators/memory-find-orchestrator.js';
import type {
  KnowledgeItem,
  MemoryFindResponse,
  SearchQuery,
  SearchResult,
} from '../../types/core-interfaces.js';
import type { IMemoryFindOrchestrator } from '../service-interfaces.js';

/**
 * Adapter for Memory Find Orchestrator service
 */
export class MemoryFindOrchestratorAdapter implements IMemoryFindOrchestrator {
  constructor(private orchestrator: MemoryFindOrchestrator) {}

  /**
   * Find knowledge items using the orchestrator
   */
  async find(query: SearchQuery): Promise<MemoryFindResponse> {
    return this.orchestrator.findItems(query);
  }

  /**
   * Search knowledge items with filters
   */
  async search(filters: Record<string, any>): Promise<SearchResult[]> {
    // Convert filters to SearchQuery format
    const query: SearchQuery = {
      query: filters.query || '',
      types: filters.types,
      scope: filters.scope,
      limit: filters.limit,
      expand: filters.expand,
      mode: filters.mode || 'fulltext',
    };

    const response = await this.find(query);
    return response.results;
  }

  /**
   * Get knowledge item by ID
   */
  async getById(id: string): Promise<KnowledgeItem | null> {
    // Search for specific ID
    const query: SearchQuery = {
      query: `id:${id}`,
      limit: 1,
    };

    const response = await this.find(query);
    return response.results.length > 0 ? (response.results[0] as KnowledgeItem) : null;
  }

  /**
   * Get knowledge items by type
   */
  async getByType(type: string): Promise<KnowledgeItem[]> {
    const query: SearchQuery = {
      query: '',
      types: [type],
      limit: 100,
    };

    const response = await this.find(query);
    return response.results as KnowledgeItem[];
  }
}
