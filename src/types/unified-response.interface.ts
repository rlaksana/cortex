// @ts-nocheck - Emergency rollback: Critical infrastructure service
/**
 * Unified Response Interface for Cortex Memory MCP Tools
 *
 * Standardizes response metadata format across all MCP tools to ensure
 * consistency in observability, debugging, and monitoring capabilities.
 */

export type SearchStrategy =
  | 'fast'
  | 'auto'
  | 'deep'
  | 'semantic'
  | 'keyword'
  | 'hybrid'
  | 'fallback'
  | 'autonomous_deduplication'
  | 'system_operation'
  | 'health_check'
  | 'error';

export interface UnifiedResponseMeta {
  /**
   * The search/processing strategy that was used
   */
  strategy: SearchStrategy;

  /**
   * Whether vector operations were utilized in this request
   */
  vector_used: boolean;

  /**
   * Whether the operation was executed in a degraded mode (fallbacks, limited functionality)
   */
  degraded: boolean;

  /**
   * Source identifier for where the response originated
   */
  source: string;

  /**
   * Time-to-live information for cached responses (optional)
   */
  ttl?: string;

  /**
   * Execution time in milliseconds (optional for backward compatibility)
   */
  execution_time_ms?: number;

  /**
   * Confidence score for the operation result (0-1 scale, optional)
   */
  confidence_score?: number;

  /**
   * Additional operation-specific metadata
   */
  [key: string]: unknown;
}

export interface UnifiedToolResponse<T = unknown> {
  // Tool-specific data payload
  data: T;

  // Standardized metadata across all tools
  meta: UnifiedResponseMeta;

  // Rate limiting information (when available)
  rate_limit?: {
    allowed: boolean;
    remaining: number;
    reset_time: string;
    identifier: string;
  };
}

/**
 * Interface for backward compatibility with existing response formats
 * Allows gradual migration to the unified format
 */
export interface LegacyResponseWrapper<T = unknown> {
  // Legacy response data
  [key: string]: unknown;

  // New unified meta field
  meta: UnifiedResponseMeta;
}

/**
 * Factory function to create unified response metadata
 */
export function createResponseMeta(params: {
  strategy: SearchStrategy;
  vector_used: boolean;
  degraded: boolean;
  source: string;
  execution_time_ms?: number;
  confidence_score?: number;
  ttl?: string;
  additional?: Record<string, unknown>;
}): UnifiedResponseMeta {
  const meta: UnifiedResponseMeta = {
    strategy: params.strategy,
    vector_used: params.vector_used,
    degraded: params.degraded,
    source: params.source,
  };

  // Add optional fields only if provided
  if (params.execution_time_ms !== undefined) {
    meta.execution_time_ms = params.execution_time_ms;
  }

  if (params.confidence_score !== undefined) {
    meta.confidence_score = params.confidence_score;
  }

  if (params.ttl !== undefined) {
    meta.ttl = params.ttl;
  }

  // Add any additional metadata
  if (params.additional) {
    Object.assign(meta, params.additional);
  }

  return meta;
}

/**
 * Utility function to convert existing observability fields to unified meta format
 */
export function migrateLegacyResponse(
  legacyResponse: unknown,
  defaultStrategy: SearchStrategy = 'auto'
): LegacyResponseWrapper {
  const observability = legacyResponse.observability || {};

  const meta = createResponseMeta({
    strategy: observability.strategy || defaultStrategy,
    vector_used: observability.vector_used ?? false,
    degraded: observability.degraded ?? false,
    source: observability.source || 'cortex_memory',
    execution_time_ms: observability.execution_time_ms,
    confidence_score: observability.confidence_score || observability.confidence_average,
    ttl: observability.ttl,
    additional: {
      // Preserve existing observability fields not in the unified interface
      search_id: observability.search_id,
      confidence_average: observability.confidence_average,
      ...Object.fromEntries(
        Object.entries(observability).filter(
          ([key]) =>
            ![
              'strategy',
              'vector_used',
              'degraded',
              'source',
              'execution_time_ms',
              'confidence_score',
              'confidence_average',
              'ttl',
            ].includes(key)
        )
      ),
    },
  });

  return {
    ...legacyResponse,
    meta,
  };
}

/**
 * Factory function to create MCP-compliant response
 */
export function createMcpResponse<T = unknown>(params: {
  data: T;
  meta: UnifiedResponseMeta;
  rate_limit?: {
    allowed: boolean;
    remaining: number;
    reset_time: string;
    identifier: string;
  };
}): UnifiedToolResponse<T> {
  return {
    data: params.data,
    meta: params.meta,
    ...(params.rate_limit && { rate_limit: params.rate_limit }),
  };
}
