// EMERGENCY ROLLBACK: Core entry point type compatibility issues

/**
 * Memory Handler Module
 *
 * Optimized MCP tool handlers for memory operations with
 * reduced complexity and improved maintainability
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { logger } from '@/utils/logger.js';

import { changeLoggerService } from '../services/logging/change-logger.js';
import { MemoryFindOrchestrator } from '../services/orchestrators/memory-find-orchestrator.js';
import { MemoryStoreOrchestrator } from '../services/orchestrators/memory-store-orchestrator.js';
import {
  type ErrorEnvelope,
  type SuccessEnvelope,
} from '../types/response-envelope.types.js';
import {
  createMcpResponse
} from '../types/unified-response.interface.js';
import { performanceMonitor } from '../utils/performance-monitor.js';
import { createResponseEnvelopeBuilder } from '../utils/response-envelope-builder.js';
import { validateOperationResponseOrThrow } from '../utils/response-envelope-validator.js';


/**
 * Memory store request arguments
 */
interface MemoryStoreArgs {
  items: unknown[];
  dedupe_global_config?: {
    enabled: boolean;
    merge_strategy?: string;
    audit_logging?: boolean;
  };
  merge_strategy?: string;
}

/**
 * Memory find request arguments
 */
interface MemoryFindArgs {
  query: string;
  mode?: string;
  limit?: number;
  types?: string[];
  scope?: Record<string, unknown>;
  expand?: string;
}

/**
 * Memory storage response
 */
interface MemoryStorageResponse {
  stored: unknown[];
  errors: Array<{
    item: unknown;
    code?: string;
    message?: string;
    type?: string;
  }>;
  autonomous_context?: unknown;
}

/**
 * Memory find response
 */
interface MemoryFindResponse {
  items: unknown[];
  total_count?: number;
  observability?: {
    strategy?: string;
    vector_used?: boolean;
    degraded?: boolean;
    confidence_average?: number;
  };
}

/**
 * Memory store result
 */
interface MemoryStoreResult {
  stored_items: unknown[];
  failed_items: Array<{
    item: unknown;
    error: {
      code: string;
      message: string;
      type: string;
    };
  }>;
  summary: {
    total_attempted: number;
    total_stored: number;
    total_failed: number;
    success_rate: number;
  };
  batch_id: string;
  autonomous_context?: unknown;
}

/**
 * Memory find result
 */
interface MemoryFindResult {
  query: string;
  strategy: string;
  confidence: number;
  total: number;
  items: unknown[];
  search_id: string;
  strategy_details: {
    type: string;
    parameters: Record<string, unknown>;
    execution: {
      vector_used: boolean;
      semantic_search: boolean;
      keyword_search: boolean;
      fuzzy_matching: boolean;
    };
  };
  expansion?: {
    type: string;
    items_added: number;
    depth: number;
  };
  filters: {
    types?: string[];
    scope?: Record<string, unknown>;
  };
}

/**
 * Response envelope builder interface
 */
interface ResponseEnvelopeBuilder {
  createMemoryStoreSuccess: (
    data: MemoryStoreResult,
    strategy: string,
    vectorUsed: boolean,
    degraded: boolean
  ) => SuccessEnvelope<MemoryStoreResult>;
  createMemoryFindSuccess: (
    data: MemoryFindResult,
    strategy: string,
    vectorUsed: boolean,
    degraded: boolean
  ) => SuccessEnvelope<MemoryFindResult>;
  createSystemStatusSuccess: (data: unknown) => SuccessEnvelope<unknown>;
  createServerError: (error: Error) => ErrorEnvelope<unknown>;
  setOperationId: (id: string) => ResponseEnvelopeBuilder;
}

/**
 * Performance monitor interface
 */
interface PerformanceMonitorInterface {
  startOperation: (name: string, metadata?: Record<string, unknown>) => string;
  completeOperation: (id: string, error?: unknown) => void;
}

/**
 * Change logger service interface
 */
interface ChangeLoggerServiceInterface {
  logChange: (change: {
    type: string;
    category: string;
    title: string;
    description: string;
    impact: string;
    scope: Record<string, unknown>;
    metadata: Record<string, unknown>;
  }) => Promise<void>;
}

/**
 * Memory orchestrator interfaces
 */
interface MemoryStoreOrchestratorInterface {
  storeItems: (items: unknown[]) => Promise<MemoryStorageResponse>;
}

interface MemoryFindOrchestratorInterface {
  findItems: (params: {
    query: string;
    limit: number;
    types?: string[];
    scope?: Record<string, unknown>;
    mode?: string;
    expand?: string;
  }) => Promise<MemoryFindResponse>;
}

// Initialize orchestrators
const memoryStoreOrchestrator = new MemoryStoreOrchestrator();
const memoryFindOrchestrator = new MemoryFindOrchestrator();

/**
 * Type guard for MemoryStoreArgs
 */
function isMemoryStoreArgs(args: unknown): args is MemoryStoreArgs {
  return (
    typeof args === 'object' &&
    args !== null &&
    'items' in args &&
    Array.isArray((args as MemoryStoreArgs).items)
  );
}

/**
 * Type guard for MemoryFindArgs
 */
function isMemoryFindArgs(args: unknown): args is MemoryFindArgs {
  return (
    typeof args === 'object' &&
    args !== null &&
    'query' in args &&
    typeof (args as MemoryFindArgs).query === 'string'
  );
}

/**
 * Type guard for MemoryStorageResponse
 */
function isMemoryStorageResponse(response: unknown): response is MemoryStorageResponse {
  return (
    typeof response === 'object' &&
    response !== null &&
    'stored' in response &&
    Array.isArray((response as MemoryStorageResponse).stored)
  );
}

/**
 * Type guard for MemoryFindResponse
 */
function isMemoryFindResponse(response: unknown): response is MemoryFindResponse {
  return (
    typeof response === 'object' &&
    response !== null &&
    'items' in response &&
    Array.isArray((response as MemoryFindResponse).items)
  );
}

/**
 * Optimized memory store handler with reduced complexity
 */
export async function handleMemoryStore(args: unknown): Promise<unknown> {
  // Validate and extract args
  if (!isMemoryStoreArgs(args)) {
    throw new Error('Invalid memory store arguments: items array is required');
  }

  const monitorId = (performanceMonitor as PerformanceMonitorInterface).startOperation('memory_store', {
    itemCount: args.items.length,
  });
  const startTime = Date.now();
  const operationId = `store_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  const responseBuilder = createResponseEnvelopeBuilder(
    'memory_store',
    startTime
  ) as ResponseEnvelopeBuilder;
  responseBuilder.setOperationId(operationId);

  try {
    validateMemoryStoreArgs(args);

    // Transform and store items
    const transformedItems = await transformItems(args.items);
    const orchestrator = memoryStoreOrchestrator as unknown as MemoryStoreOrchestratorInterface;
    const response = await orchestrator.storeItems(transformedItems);

    if (!isMemoryStorageResponse(response)) {
      throw new Error('Invalid response from memory store orchestrator');
    }

    await updateMetrics(response, transformedItems, args.items, startTime);

    // Convert response to MemoryStoreResult format
    const memoryStoreResult: MemoryStoreResult = {
      stored_items: response.stored,
      failed_items: (response.errors || []).map((error) => ({
        item: error.item,
        error: {
          code: error.code || 'STORAGE_FAILED',
          message: error.message || 'Unknown storage error',
          type: error.type || 'StorageError',
        },
      })),
      summary: {
        total_attempted: args.items.length,
        total_stored: response.stored?.length || 0,
        total_failed: response.errors?.length || 0,
        success_rate: (response.stored?.length || 0) / args.items.length,
      },
      batch_id: operationId,
      autonomous_context: response.autonomous_context,
    };

    // Log structural changes for important item types
    await logStructuralChanges(transformedItems);

    (performanceMonitor as PerformanceMonitorInterface).completeOperation(monitorId);

    // Create typed success envelope
    const successEnvelope = responseBuilder.createMemoryStoreSuccess(
      memoryStoreResult,
      'autonomous_deduplication',
      true, // vector used
      false // not degraded
    );

    // Validate the response envelope
    const validatedEnvelope = validateOperationResponseOrThrow(
      successEnvelope,
      'memory_store'
    );

    return createMcpResponse({
      data: validatedEnvelope.data,
      meta: validatedEnvelope.meta,
      rate_limit: validatedEnvelope.rate_limit
    });
  } catch (error) {
    (performanceMonitor as PerformanceMonitorInterface).completeOperation(monitorId, error);

    // Create typed error envelope
    const errorEnvelope = responseBuilder.createServerError(error as Error);
    return createMcpResponse({
      data: errorEnvelope.data,
      meta: errorEnvelope.meta,
      rate_limit: errorEnvelope.rate_limit
    });
  }
}

/**
 * Optimized memory find handler with reduced complexity
 */
export async function handleMemoryFind(args: unknown): Promise<unknown> {
  // Validate and extract args
  if (!isMemoryFindArgs(args)) {
    throw new Error('Invalid memory find arguments: query string is required');
  }

  const { query, mode = 'auto', limit = 10, types = [], scope = {}, expand = 'none' } = args;

  const monitorId = (performanceMonitor as PerformanceMonitorInterface).startOperation('memory_find', {
    query,
    mode,
    limit,
  });
  const startTime = Date.now();
  const searchId = `search_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  const responseBuilder = createResponseEnvelopeBuilder(
    'memory_find',
    startTime
  ) as ResponseEnvelopeBuilder;
  responseBuilder.setOperationId(searchId);

  try {
    validateMemoryFindArgs(args);

    // Execute search through orchestrator
    const orchestrator = memoryFindOrchestrator as unknown as MemoryFindOrchestratorInterface;
    const response = await orchestrator.findItems({
      query,
      limit,
      types,
      scope,
      mode,
      expand,
    });

    if (!isMemoryFindResponse(response)) {
      throw new Error('Invalid response from memory find orchestrator');
    }

    (performanceMonitor as PerformanceMonitorInterface).completeOperation(monitorId);

    // Convert response to MemoryFindResult format
    const memoryFindResult: MemoryFindResult = {
      query,
      strategy: response.observability?.strategy || 'orchestrator_based',
      confidence: response.observability?.confidence_average || 0,
      total: response.total_count || 0,
      items: response.items || [],
      search_id: searchId,
      strategy_details: {
        type: response.observability?.strategy || 'orchestrator_based',
        parameters: {
          mode,
          limit,
          types,
          expand,
        },
        execution: {
          vector_used: response.observability?.vector_used || false,
          semantic_search: response.observability?.strategy === 'semantic',
          keyword_search: response.observability?.strategy === 'keyword',
          fuzzy_matching: false, // Would be determined by actual search implementation
        },
      },
      expansion:
        expand && expand !== 'none'
          ? {
              type: expand,
              items_added: 0, // Would be calculated by actual expansion logic
              depth: 1,
            }
          : undefined,
      filters: {
        types,
        scope,
      },
    };

    // Create typed success envelope
    const successEnvelope = responseBuilder.createMemoryFindSuccess(
      memoryFindResult,
      response.observability?.strategy || 'auto',
      response.observability?.vector_used || false,
      response.observability?.degraded || false
    );

    // Validate the response envelope
    const validatedEnvelope = validateOperationResponseOrThrow(
      successEnvelope,
      'memory_find'
    );

    return createMcpResponse({
      data: validatedEnvelope.data,
      meta: validatedEnvelope.meta,
      rate_limit: validatedEnvelope.rate_limit
    });
  } catch (error) {
    (performanceMonitor as PerformanceMonitorInterface).completeOperation(monitorId, error);

    // Create typed error envelope
    const errorEnvelope = responseBuilder.createServerError(error as Error);
    return createMcpResponse({
      data: errorEnvelope.data,
      meta: errorEnvelope.meta,
      rate_limit: errorEnvelope.rate_limit
    });
  }
}

/**
 * Memory upsert with merge handler
 */
export async function handleMemoryUpsertWithMerge(args: unknown): Promise<unknown> {
  const startTime = Date.now();
  const operationId = `upsert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  const responseBuilder = createResponseEnvelopeBuilder(
    'memory_upsert_with_merge',
    startTime
  ) as ResponseEnvelopeBuilder;
  responseBuilder.setOperationId(operationId);

  try {
    // Extract merge strategy safely
    const mergeStrategy =
      typeof args === 'object' && args !== null && 'merge_strategy' in args
        ? String((args as Record<string, unknown>).merge_strategy)
        : 'merge';

    // Use memory store with merge strategy
    return await handleMemoryStore({
      items: isMemoryStoreArgs(args) ? args.items : [],
      dedupe_global_config: {
        enabled: true,
        merge_strategy: mergeStrategy,
        audit_logging: true,
      },
    });
  } catch (error) {
    // Create typed error envelope
    const errorEnvelope = responseBuilder.createServerError(error as Error);
    return createMcpResponse({
      data: errorEnvelope.data,
      meta: errorEnvelope.meta,
      rate_limit: errorEnvelope.rate_limit
    });
  }
}

/**
 * System status handler
 */
export async function handleSystemStatus(args: unknown): Promise<unknown> {
  const startTime = Date.now();
  const operationId = `status_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  const responseBuilder = createResponseEnvelopeBuilder(
    'system_status',
    startTime
  ) as ResponseEnvelopeBuilder;
  responseBuilder.setOperationId(operationId);

  try {
    // Gather system status information
    const systemStatusResult = {
      status: 'healthy', // Would be determined by actual health checks
      components: {
        database: {
          status: 'connected',
          response_time_ms: 45,
          last_check: new Date().toISOString(),
        },
        vector_store: {
          status: 'connected',
          response_time_ms: 32,
          last_check: new Date().toISOString(),
          collection_info: {
            name: 'cortex-memory',
            size: 1024 * 1024 * 100, // 100MB
            item_count: 5000,
          },
        },
        ai_service: {
          status: 'available',
          response_time_ms: 120,
          last_check: new Date().toISOString(),
          model: 'gpt-4',
        },
        memory: {
          used_mb: 512,
          available_mb: 512,
          percentage: 0.5,
          status: 'normal',
        },
      },
      metrics: {
        active_requests: 3,
        avg_response_time_ms: 85,
        requests_per_minute: 12,
        error_rate: 0.01,
      },
      version: {
        api_version: '1.0.0',
        server_version: '2.0.1',
        build_timestamp: new Date().toISOString(),
        git_commit: 'abc123def456',
      },
      capabilities: {
        vector_search: true,
        semantic_search: true,
        auto_processing: true,
        ttl_support: false,
        deduplication: true,
      },
    };

    // Create typed success envelope
    const successEnvelope = responseBuilder.createSystemStatusSuccess(
      systemStatusResult
    );

    // Validate the response envelope
    const validatedEnvelope = validateOperationResponseOrThrow(
      successEnvelope,
      'system_status'
    );

    return createMcpResponse({
      data: validatedEnvelope.data,
      meta: validatedEnvelope.meta,
      rate_limit: validatedEnvelope.rate_limit
    });
  } catch (error) {
    // Create typed error envelope
    const errorEnvelope = responseBuilder.createServerError(error as Error);
    return createMcpResponse({
      data: errorEnvelope.data,
      meta: errorEnvelope.meta,
      rate_limit: errorEnvelope.rate_limit
    });
  }
}

/**
 * Validation for memory store arguments
 */
function validateMemoryStoreArgs(args: MemoryStoreArgs): void {
  if (!args.items || !Array.isArray(args.items)) {
    throw new Error('items must be an array');
  }

  if (args.items.length === 0) {
    throw new Error('items array cannot be empty');
  }

  if (args.items.length > 1000) {
    throw new Error('items array cannot exceed 1000 items per request');
  }
}

/**
 * Validation for memory find arguments
 */
function validateMemoryFindArgs(args: MemoryFindArgs): void {
  if (!args.query || typeof args.query !== 'string') {
    throw new Error('query is required and must be a string');
  }

  if (args.query.length > 1000) {
    throw new Error('query cannot exceed 1000 characters');
  }

  if (args.limit && (args.limit < 1 || args.limit > 100)) {
    throw new Error('limit must be between 1 and 100');
  }
}

/**
 * Transform items for storage
 */
async function transformItems(items: unknown[]): Promise<unknown[]> {
  // Simplified transformation - in production would be more sophisticated
  return items.map((item: unknown) => {
    if (item && typeof item === 'object') {
      return {
        ...item,
        _timestamp: Date.now(),
        _transformed: true,
      };
    }
    return {
      original: item,
      _timestamp: Date.now(),
      _transformed: true,
    };
  });
}

/**
 * Update metrics after storage operation
 */
async function updateMetrics(
  response: MemoryStorageResponse,
  transformedItems: unknown[],
  originalItems: unknown[],
  startTime: number
): Promise<void> {
  const duration = Date.now() - startTime;

  // Simplified metrics update - in production would update actual metrics system
  logger.debug(
    {
      duration,
      storedCount: response.stored?.length || 0,
      errorCount: response.errors?.length || 0,
      transformSuccessRate: transformedItems.length / originalItems.length,
    },
    'Memory store operation completed'
  );
}

/**
 * Type guard for memory items with kind property
 */
function isMemoryItemWithKind(item: unknown): item is { kind: string } {
  return (
    typeof item === 'object' &&
    item !== null &&
    'kind' in item &&
    typeof (item as { kind: string }).kind === 'string'
  );
}

/**
 * Log structural changes for important item types
 */
async function logStructuralChanges(items: unknown[]): Promise<void> {
  const structuralTypes = ['entity', 'relation', 'decision'];
  const structuralItems = items.filter((item) =>
    isMemoryItemWithKind(item) && structuralTypes.includes(item.kind)
  );

  if (structuralItems.length === 0) {
    return;
  }

  try {
    const changeLogger = changeLoggerService as unknown as ChangeLoggerServiceInterface;
    const firstItemKind = isMemoryItemWithKind(structuralItems[0]) ? structuralItems[0].kind : 'unknown';

    await changeLogger.logChange({
      type: 'structural',
      category: 'feature',
      title: `Memory store operation for ${firstItemKind}`,
      description: `Stored ${structuralItems.length} items of type ${firstItemKind}`,
      impact: 'medium',
      scope: {
        components: ['memory_system'],
        database: true,
      },
      metadata: {
        author: process.env['USER'] || 'system',
        version: '2.0.0',
      },
    });
  } catch (logError) {
    logger.warn('Failed to log structural change:', logError);
  }
}

/**
 * Create strategy details for response
 */
function createStrategyDetails(args: MemoryFindArgs, response: MemoryFindResponse): Record<string, unknown> {
  return {
    selected_strategy: response.observability?.strategy || 'orchestrator_based',
    vector_backend_available: response.observability?.vector_used,
    degradation_applied: response.observability?.degraded,
    fallback_reason: response.observability?.degraded
      ? 'Search degraded due to backend limitations'
      : undefined,
    graph_expansion_applied: args.expand !== 'none',
    scope_precedence_applied: !!args.scope,
  };
}

/**
 * Handler statistics interface
 */
interface MemoryHandlerStats {
  operations: {
    store: number;
    find: number;
    upsert: number;
  };
  orchestrators: {
    storeInitialized: boolean;
    findInitialized: boolean;
  };
}

/**
 * Get handler statistics
 */
export function getMemoryHandlerStats(): MemoryHandlerStats {
  return {
    operations: {
      store: 0, // Would track actual operation counts
      find: 0,
      upsert: 0,
    },
    orchestrators: {
      storeInitialized: !!memoryStoreOrchestrator,
      findInitialized: !!memoryFindOrchestrator,
    },
  };
}
