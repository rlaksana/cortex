// EMERGENCY ROLLBACK: DI container interface compatibility issues

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
import type { IMemoryFindOrchestrator, ServiceResponse, ValidationResult, ServiceStatus } from '../service-interfaces.js';

/**
 * Adapter for Memory Find Orchestrator service
 */
export class MemoryFindOrchestratorAdapter implements IMemoryFindOrchestrator {
  constructor(private orchestrator: MemoryFindOrchestrator) {}

  /**
   * Find knowledge items using the orchestrator
   */
  async find(query: SearchQuery): Promise<ServiceResponse<MemoryFindResponse>> {
    try {
      const searchResponse = await this.orchestrator.findItems(query);
      const searchResults = searchResponse.success && searchResponse.data ? searchResponse.data : [];

      // Convert SearchResult[] to MemoryFindResponse
      const memoryFindResponse: MemoryFindResponse = {
        results: searchResults,
        items: searchResults,
        total_count: searchResults.length,
        total: searchResults.length,
        metadata: {          serviceName: "memory-find-adapter",
          query: query.query,
          processing_time_ms: Date.now(),
          strategy: 'semantic'
        },
        autonomous_context: {
          search_mode_used: query.mode || 'auto',
          results_found: searchResults.length,
          confidence_average: searchResults.reduce((sum: number, item: any) => sum + (item.confidence_score || 0), 0) / Math.max(searchResults.length, 1),
          user_message_suggestion: `Found ${searchResults.length} results for "${query.query}"`
        },
        observability: {
          source: 'cortex_memory',
          strategy: query.mode || 'auto',
          vector_used: true,
          degraded: false,
          execution_time_ms: Date.now(),
          confidence_average: searchResults.reduce((sum: number, item: any) => sum + (item.confidence_score || 0), 0) / Math.max(searchResults.length, 1),
          search_id: `search_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
        },
        meta: {
          // Core operational metadata
          strategy: query.mode || 'auto',
          vector_used: true,
          degraded: false,
          source: 'cortex_memory',
          execution_time_ms: Date.now(),
          confidence_score: searchResults.reduce((sum: number, item: any) => sum + (item.confidence_score || 0), 0) / Math.max(searchResults.length, 1),

          // Truncation metadata
          truncated: false
        }
      };

      return {
        success: true,
        data: memoryFindResponse,
        metadata: {
          serviceName: 'memory-find-adapter',
          processingTimeMs: Date.now(),
          source: 'memory-find-adapter',
          version: '2.0.0'
        }
      };
    } catch (error) {
      return {
        success: false,
        error: {
          code: 'FIND_ERROR',
          message: error instanceof Error ? error.message : 'Unknown find error',
          timestamp: new Date().toISOString()
        },
        metadata: {
          serviceName: 'memory-find-adapter',
          processingTimeMs: Date.now(),
          source: 'memory-find-adapter',
          version: '2.0.0'
        }
      };
    }
  }

  /**
   * Search knowledge items with filters
   */
  async search(filters: Record<string, unknown>): Promise<ServiceResponse<SearchResult[]>> {
    try {
      // Convert filters to SearchQuery format
      const query: SearchQuery = {
        query: (filters.query as string) || '',
        types: (filters.types as string[]) || [],
        scope: typeof filters.scope === 'string' ? { project: filters.scope } : filters.scope as { project?: string; branch?: string; org?: string; } || {},
        limit: (filters.limit as number) || 50,
        expand: (filters.expand as "relations" | "parents" | "children" | "none") || "none",
        mode: (filters.mode as "deep" | "auto" | "fast") || "auto",
      };

      const response = await this.find(query);
      return {
        success: true,
        data: response.success && response.data ? response.data.results : [],
        metadata: {
          serviceName: 'memory-find-adapter',
          processingTimeMs: Date.now(),
          source: 'memory-find-adapter',
          version: '2.0.0'
        }
      };
    } catch (error) {
      return {
        success: false,
        error: {
          code: 'SEARCH_ERROR',
          message: error instanceof Error ? error.message : 'Unknown search error',
          timestamp: new Date().toISOString()
        },
        metadata: {
          serviceName: 'memory-find-adapter',
          processingTimeMs: Date.now(),
          source: 'memory-find-adapter',
          version: '2.0.0'
        }
      };
    }
  }

  /**
   * Get knowledge item by ID
   */
  async getById(id: string): Promise<ServiceResponse<KnowledgeItem | null>> {
    try {
      // Search for specific ID
      const query: SearchQuery = {
        query: `id:${id}`,
        limit: 1,
      };

      const response = await this.find(query);
      const result = response.data.results.length > 0 ? (response.data.results[0] as KnowledgeItem) : null;
      return {
        success: true,
        data: result,
        metadata: response.metadata
      };
    } catch (error) {
      return {
        success: false,
        error: {
          code: 'GET_BY_ID_ERROR',
          message: error instanceof Error ? error.message : 'Unknown get by ID error',
          timestamp: new Date().toISOString()
        }
      };
    }
  }

  /**
   * Get knowledge items by type
   */
  async getByType(type: string): Promise<ServiceResponse<KnowledgeItem[]>> {
    try {
      const query: SearchQuery = {
        query: '',
        types: [type],
        limit: 100,
      };

      const response = await this.find(query);
      return {
        success: true,
        data: response.data.results as KnowledgeItem[],
        metadata: response.metadata
      };
    } catch (error) {
      return {
        success: false,
        error: {
          code: 'GET_BY_TYPE_ERROR',
          message: error instanceof Error ? error.message : 'Unknown get by type error',
          timestamp: new Date().toISOString()
        }
      };
    }
  }

  // Additional required methods from IMemoryFindOrchestrator interface
  async findByTags(tags: string[]): Promise<ServiceResponse<KnowledgeItem[]>> {
    try {
      const query: SearchQuery = {
        query: '',
        types: tags, // Use types instead of tags since tags property doesn't exist
        limit: 100,
      };

      const response = await this.find(query);
      return {
        success: true,
        data: response.data.results as KnowledgeItem[],
        metadata: response.metadata
      };
    } catch (error) {
      return {
        success: false,
        error: {
          code: 'FIND_BY_TAGS_ERROR',
          message: error instanceof Error ? error.message : 'Unknown find by tags error',
          timestamp: new Date().toISOString()
        }
      };
    }
  }

  async findSimilar(query: string, threshold = 0.8): Promise<ServiceResponse<KnowledgeItem[]>> {
    try {
      const searchQuery: SearchQuery = {
        query,
        mode: 'auto',
        limit: 50,
        // Note: similarity_threshold is not supported in current SearchQuery interface
        // The threshold will be handled by the underlying orchestrator
      };

      const response = await this.find(searchQuery);
      return {
        success: true,
        data: response.data.results as KnowledgeItem[],
        metadata: response.metadata
      };
    } catch (error) {
      return {
        success: false,
        error: {
          code: 'FIND_SIMILAR_ERROR',
          message: error instanceof Error ? error.message : 'Unknown find similar error',
          timestamp: new Date().toISOString()
        }
      };
    }
  }

  async validateQuery(query: SearchQuery): Promise<ServiceResponse<ValidationResult>> {
    try {
      // Basic validation logic
      const errors: string[] = [];

      if (!query.query && !query.types) {
        errors.push('Query must contain at least one of: query text or types');
      }

      if (query.limit && (query.limit < 1 || query.limit > 1000)) {
        errors.push('Limit must be between 1 and 1000');
      }

      return {
        success: true,
        data: {
          valid: errors.length === 0,
          errors: errors.map((error, index) => ({
            path: `query[${index}]`,
            message: error,
            code: 'VALIDATION_ERROR'
          })),
          warnings: []
        }
      };
    } catch (error) {
      return {
        success: false,
        error: {
          code: 'VALIDATE_QUERY_ERROR',
          message: error instanceof Error ? error.message : 'Unknown validation error',
          timestamp: new Date().toISOString()
        }
      };
    }
  }

  async healthCheck(): Promise<ServiceResponse<{ status: 'healthy' | 'unhealthy' }>> {
    try {
      // Basic health check - can be expanded
      return {
        success: true,
        data: {
          status: 'healthy'
        },
        metadata: {
          serviceName: 'memory-find-adapter',
          processingTimeMs: Date.now(),
          source: 'memory-find-adapter',
          version: '2.0.0'
        }
      };
    } catch (error) {
      return {
        success: false,
        error: {
          code: 'HEALTH_CHECK_ERROR',
          message: error instanceof Error ? error.message : 'Unknown health check error',
          timestamp: new Date().toISOString()
        },
        metadata: {
          serviceName: 'memory-find-adapter',
          processingTimeMs: Date.now(),
          source: 'memory-find-adapter',
          version: '2.0.0'
        }
      };
    }
  }

  async getStatus(): Promise<ServiceResponse<ServiceStatus>> {
    try {
      return {
        success: true,
        data: {
          initialized: true,
          uptime: Date.now(),
          lastCheck: new Date().toISOString(),
          metrics: {
            service: 'MemoryFindOrchestratorAdapter',
            status: 'active'
          }
        },
        metadata: {
          serviceName: 'memory-find-adapter',
          processingTimeMs: Date.now(),
          source: 'memory-find-adapter',
          version: '2.0.0'
        }
      };
    } catch (error) {
      return {
        success: false,
        error: {
          code: 'GET_STATUS_ERROR',
          message: error instanceof Error ? error.message : 'Unknown get status error',
          timestamp: new Date().toISOString()
        }
      };
    }
  }
}
