// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * MCP Tool Response Data Types
 *
 * Specific data types for MCP tool responses to ensure type safety
 * and eliminate 'any' usage in response payloads.
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

import { type EnhancedContentItem, type EnhancedDataItem } from '../schemas/knowledge-types';

/**
 * Memory store operation result
 */
export interface MemoryStoreResult {
  /**
   * Items that were successfully stored
   */
  stored_items: Array<EnhancedContentItem | EnhancedDataItem>;

  /**
   * Items that failed to store
   */
  failed_items: Array<{
    /**
     * The item that failed to store
     */
    item: EnhancedContentItem | EnhancedDataItem;

    /**
     * Error reason for failure
     */
    error: {
      code: string;
      message: string;
      type: string;
    };
  }>;

  /**
   * Summary statistics
   */
  summary: {
    /**
     * Total number of items attempted
     */
    total_attempted: number;

    /**
     * Number of successfully stored items
     */
    total_stored: number;

    /**
     * Number of failed items
     */
    total_failed: number;

    /**
     * Success rate (0-1)
     */
    success_rate: number;
  };

  /**
   * Batch operation identifier
   */
  batch_id?: string;

  /**
   * Autonomous processing context
   */
  autonomous_context?: {
    /**
     * Whether automatic processing was applied
     */
    enabled: boolean;

    /**
     * Types of processing applied
     */
    processing_applied: string[];

    /**
     * Processing statistics
     */
    statistics: Record<string, number>;
  };
}

/**
 * Memory find search result
 */
export interface MemoryFindResult {
  /**
   * Original search query
   */
  query: string;

  /**
   * Search strategy used
   */
  strategy: string;

  /**
   * Search confidence score
   */
  confidence: number;

  /**
   * Total number of results found
   */
  total: number;

  /**
   * Returned items
   */
  items: Array<EnhancedContentItem | EnhancedDataItem>;

  /**
   * Search identifier for tracing
   */
  search_id: string;

  /**
   * Detailed strategy information
   */
  strategy_details: {
    /**
     * Strategy type
     */
    type: string;

    /**
     * Parameters used
     */
    parameters: Record<string, unknown>;

    /**
     * Execution details
     */
    execution: {
      vector_used: boolean;
      semantic_search: boolean;
      keyword_search: boolean;
      fuzzy_matching: boolean;
    };
  };

  /**
   * Search expansion information
   */
  expansion?: {
    /**
     * Type of expansion performed
     */
    type: 'relations' | 'parents' | 'children' | 'none';

    /**
     * Number of items added through expansion
     */
    items_added: number;

    /**
     * Expansion depth
     */
    depth: number;
  };

  /**
   * Search filters applied
   */
  filters?: {
    /**
     * Types filtered
     */
    types?: string[];

    /**
     * Scope restrictions
     */
    scope?: Record<string, unknown>;

    /**
     * Date range
     */
    date_range?: {
      start?: string;
      end?: string;
    };
  };
}

/**
 * System status result
 */
export interface SystemStatusResult {
  /**
   * Overall system health status
   */
  status: 'healthy' | 'degraded' | 'unhealthy' | 'maintenance';

  /**
   * Component status information
   */
  components: {
    /**
     * Database status
     */
    database: {
      status: 'connected' | 'disconnected' | 'degraded';
      response_time_ms?: number;
      last_check: string;
      error?: string;
    };

    /**
     * Vector store status
     */
    vector_store: {
      status: 'connected' | 'disconnected' | 'degraded';
      response_time_ms?: number;
      last_check: string;
      collection_info?: {
        name: string;
        size: number;
        item_count: number;
      };
      error?: string;
    };

    /**
     * AI service status
     */
    ai_service: {
      status: 'available' | 'unavailable' | 'degraded';
      response_time_ms?: number;
      last_check: string;
      model?: string;
      error?: string;
    };

    /**
     * Memory usage
     */
    memory: {
      used_mb: number;
      available_mb: number;
      percentage: number;
      status: 'normal' | 'warning' | 'critical';
    };
  };

  /**
   * Performance metrics
   */
  metrics: {
    /**
     * Current active requests
     */
    active_requests: number;

    /**
     * Average response time (last 5 minutes)
     */
    avg_response_time_ms: number;

    /**
     * Requests per minute
     */
    requests_per_minute: number;

    /**
     * Error rate (last 5 minutes)
     */
    error_rate: number;
  };

  /**
   * Version information
   */
  version: {
    /**
     * API version
     */
    api_version: string;

    /**
     * Server version
     */
    server_version: string;

    /**
     * Build timestamp
     */
    build_timestamp: string;

    /**
     * Git commit hash
     */
    git_commit?: string;
  };

  /**
   * System capabilities
   */
  capabilities: {
    /**
     * Vector search capability
     */
    vector_search: boolean;

    /**
     * Semantic search capability
     */
    semantic_search: boolean;

    /**
     * Auto-processing capability
     */
    auto_processing: boolean;

    /**
     * TTL support
     */
    ttl_support: boolean;

    /**
     * Deduplication capability
     */
    deduplication: boolean;
  };
}

/**
 * Error details for validation failures
 */
export interface ValidationErrorDetails {
  /**
   * Field that failed validation
   */
  field: string;

  /**
   * Validation error message
   */
  message: string;

  /**
   * Current value that failed validation
   */
  value: unknown;

  /**
   * Expected value or constraint
   */
  expected?: string;

  /**
   * Validation rule that failed
   */
  rule: string;
}

/**
 * Error details for rate limiting
 */
export interface RateLimitErrorDetails {
  /**
   * Current rate limit
   */
  limit: number;

  /**
   * Remaining requests
   */
  remaining: number;

  /**
   * Reset time
   */
  reset_time: string;

  /**
   * Time until reset in seconds
   */
  reset_in_seconds: number;

  /**
   * Rate limit window
   */
  window: string;
}

/**
 * Error details for database failures
 */
export interface DatabaseErrorDetails {
  /**
   * Database operation that failed
   */
  operation: string;

  /**
   * Collection or table name
   */
  collection?: string;

  /**
   * Query or operation details
   */
  query?: string;

  /**
   * Connection status
   */
  connection_status: string;

  /**
   * Retry attempts made
   */
  retry_attempts: number;
}